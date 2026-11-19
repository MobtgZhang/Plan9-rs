//! Polling virtio keyboard driver for the QEMU virt machines. AArch64 and
//! RISC-V use virtio-mmio; LoongArch uses modern virtio PCI.
//!
//! The driver is deliberately minimal and interrupt-free: one event queue
//! backed by a static vring, every buffer pre-queued at init, and `poll`
//! drains the used ring on each call — the same polling model the PS/2
//! path uses when IRQs are masked.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use alloc::vec::Vec;
use crate::plan9_common::sync::Mutex;

// ---------------------------------------------------------------------------
// virtio-mmio register layout (each register is 4 bytes, little endian)
// ---------------------------------------------------------------------------

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod reg {
    pub const MAGIC: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const HOST_FEATURES: u64 = 0x010;
    pub const HOST_FEATURES_SEL: u64 = 0x014;
    pub const GUEST_FEATURES: u64 = 0x020;
    pub const GUEST_FEATURES_SEL: u64 = 0x024;
    pub const GUEST_PAGE_SIZE: u64 = 0x028;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_ALIGN: u64 = 0x03c;
    pub const QUEUE_PFN: u64 = 0x040;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_AVAIL_LOW: u64 = 0x090;
    pub const QUEUE_USED_LOW: u64 = 0x098;
}

/// Device status register bits.
const S_ACKNOWLEDGE: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;
const S_FEATURES_OK: u8 = 8;
const S_FAILED: u8 = 0x80;

/// Descriptor flag: the device writes into this buffer.
const DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Static vring
// ---------------------------------------------------------------------------

/// Queue size.  Small is fine: every buffer is handed straight back to the
/// device as soon as the used ring reports it consumed.
const QUEUE_SIZE: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const DESC_OFF: usize = 0;
const AVAIL_OFF: usize = DESC_OFF + core::mem::size_of::<Desc>() * QUEUE_SIZE;
/// The used ring must follow the avail ring at the queue alignment (4096
/// for both the legacy and the modern layout we support).  The avail ring
/// is {flags, idx, ring[QUEUE_SIZE], used_event}.
const USED_OFF: usize = (AVAIL_OFF + 4 + 2 * QUEUE_SIZE + 2 + 4095) & !4095;
const EVENTS_OFF: usize = USED_OFF + 4 + 8 * QUEUE_SIZE;
const VRING_TOTAL: usize = (EVENTS_OFF + 8 * QUEUE_SIZE + 4095) & !4095;

/// One page-aligned blob holding descriptors, avail/used rings and the
/// event buffers.  The aarch64 kernel runs identity-mapped (VA == PA) for
/// its own image, so the blob's address doubles as its physical address
/// for the queue PFN / 64-bit address registers.
#[repr(C, align(4096))]
struct VringMem([u8; VRING_TOTAL]);

static mut VRING: VringMem = VringMem([0; VRING_TOTAL]);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static NOTIFY: AtomicU64 = AtomicU64::new(0);
/// Our position in the used ring (device-owned tail is read live).
static LAST_USED: AtomicU16 = AtomicU16::new(0);

/// Translated keystrokes waiting for a consumer.
static PENDING: Mutex<Vec<u8>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline]
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
unsafe fn rd32(base: u64, off: u64) -> u32 {
    core::ptr::read_volatile((base + off) as *const u32)
}

#[inline]
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
unsafe fn wr32(base: u64, off: u64, val: u32) {
    core::ptr::write_volatile((base + off) as *mut u32, val);
}

#[inline]
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
unsafe fn wr_addr(base: u64, off: u64, val: u64) {
    wr32(base, off, val as u32);
    wr32(base, off + 4, (val >> 32) as u32);
}

#[inline]
fn vring_base() -> *mut u8 {
    (&raw mut VRING) as *mut VringMem as *mut u8
}

/// Scan the virt board's virtio-mmio transports for an input device.
///
/// Returns the register base of the first hit.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn init_transport() -> Option<u64> {
    #[cfg(target_arch = "aarch64")]
    let transports = (0..32).map(|slot| 0x0a00_0000 + slot * 0x200);
    #[cfg(target_arch = "riscv64")]
    let transports = (0..8).map(|slot| 0x1000_1000 + slot * 0x1000);
    let base = transports.into_iter().find(|&base| unsafe {
        rd32(base, reg::MAGIC) == 0x7472_6976 && rd32(base, reg::DEVICE_ID) == 18
    })?;
    unsafe {
        let modern = rd32(base, reg::VERSION) >= 2;
        wr32(base, reg::STATUS, 0);
        let status = u32::from(S_ACKNOWLEDGE | S_DRIVER);
        wr32(base, reg::STATUS, status);
        wr32(base, reg::GUEST_FEATURES_SEL, 0);
        wr32(base, reg::GUEST_FEATURES, 0);
        let mut status = status;
        if modern {
            wr32(base, reg::HOST_FEATURES_SEL, 1);
            if rd32(base, reg::HOST_FEATURES) & 1 == 0 {
                wr32(base, reg::STATUS, status | u32::from(S_FAILED));
                return None;
            }
            wr32(base, reg::GUEST_FEATURES_SEL, 1);
            wr32(base, reg::GUEST_FEATURES, 1);
            status |= u32::from(S_FEATURES_OK);
            wr32(base, reg::STATUS, status);
            if rd32(base, reg::STATUS) & u32::from(S_FEATURES_OK) == 0 {
                wr32(base, reg::STATUS, status | u32::from(S_FAILED));
                return None;
            }
        }

        // Bring up event queue 0.
        wr32(base, reg::QUEUE_SEL, 0);
        if rd32(base, reg::QUEUE_NUM_MAX) < QUEUE_SIZE as u32 {
            wr32(base, reg::STATUS, status | u32::from(S_FAILED));
            return None;
        }
        wr32(base, reg::QUEUE_NUM, QUEUE_SIZE as u32);

        let vb = vring_base();
        if modern {
            wr_addr(base, reg::QUEUE_DESC_LOW, vb as u64 + DESC_OFF as u64);
            wr_addr(base, reg::QUEUE_AVAIL_LOW, vb as u64 + AVAIL_OFF as u64);
            wr_addr(base, reg::QUEUE_USED_LOW, vb as u64 + USED_OFF as u64);
            wr32(base, reg::QUEUE_READY, 1);
        } else {
            // PFN units are guest pages: the transport converts
            // PFN -> address with `value << guest_page_shift`, and the
            // shift comes from the GUEST_PAGE_SIZE register.  Write it
            // before the PFN or the device reads the vring from the
            // wrong (sub-page) address.
            wr32(base, reg::GUEST_PAGE_SIZE, 4096);
            wr32(base, reg::QUEUE_ALIGN, 4096);
            wr32(base, reg::QUEUE_PFN, (vb as u64 >> 12) as u32);
        }

        wr32(base, reg::STATUS, status | u32::from(S_DRIVER_OK));
    }
    Some(base + reg::QUEUE_NOTIFY)
}

#[cfg(target_arch = "loongarch64")]
#[path = "vkey/pci.rs"]
mod pci;
#[cfg(target_arch = "loongarch64")]
use pci::init_transport;

fn notify_queue(address: u64) {
    core::sync::atomic::fence(Ordering::SeqCst);
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    unsafe { (address as *mut u32).write_volatile(0); }
    #[cfg(target_arch = "loongarch64")]
    unsafe { (address as *mut u16).write_volatile(0); }
}

/// Initialise the keyboard and post receive buffers to its event queue.
pub fn init() -> bool {
    let Some(notify) = init_transport() else { return false };
    let ring = vring_base();
    for index in 0..QUEUE_SIZE {
        unsafe {
            let desc = ring.add(DESC_OFF + index * core::mem::size_of::<Desc>()) as *mut Desc;
            core::ptr::write_volatile(
                desc,
                Desc {
                    addr: event_buf_addr(index),
                    len: 8,
                    flags: DESC_F_WRITE,
                    next: 0,
                },
            );
        }
        avail_push(index as u16);
    }
    NOTIFY.store(notify, Ordering::Release);
    notify_queue(notify);
    crate::serial::put_bytes(b"[vkey] virtio-keyboard ready\n");
    true
}

#[inline]
fn event_buf_addr(i: usize) -> u64 {
    vring_base() as u64 + (EVENTS_OFF + i * 8) as u64
}

/// Push a descriptor id onto the avail ring.
fn avail_push(id: u16) {
    unsafe {
        let avail = vring_base().add(AVAIL_OFF) as *mut u16;
        // avail: { flags: u16, idx: u16, ring: [u16; QUEUE_SIZE] }
        let idx = core::ptr::read_volatile(avail.add(1));
        core::ptr::write_volatile(
            avail.add(2 + idx as usize % QUEUE_SIZE),
            id,
        );
        core::sync::atomic::fence(Ordering::SeqCst);
        core::ptr::write_volatile(avail.add(1), idx.wrapping_add(1));
    }
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/// Drain the used ring, handing consumed event buffers back to the device
/// and translating each input event into console input bytes.
pub fn poll() {
    let notify = NOTIFY.load(Ordering::Acquire);
    if notify == 0 {
        return;
    }
    let vb = vring_base();
    let used = unsafe { vb.add(USED_OFF) as *const u16 };
    // used: { flags: u16, idx: u16, ring: [{id: u32, len: u32}; QUEUE_SIZE] }
    let used_tail = unsafe { core::ptr::read_volatile(used.add(1)) } as usize;

    let mut last = LAST_USED.load(Ordering::SeqCst) as usize;
    let mut count = 0usize;
    while last != used_tail {
        let entry = unsafe { vb.add(USED_OFF + 4 + (last % QUEUE_SIZE) * 8) as *const u32 };
        let id = unsafe { core::ptr::read_volatile(entry) } as usize;
        if id >= QUEUE_SIZE {
            break;
        }

        // virtio_input_event { type: u16, code: u16, value: u32 }, little endian.
        let raw = unsafe {
            core::ptr::read_volatile(vb.add(EVENTS_OFF + id * 8) as *const u64)
        };
        let bytes = raw.to_le_bytes();
        let etype = u16::from_le_bytes([bytes[0], bytes[1]]);
        let code = u16::from_le_bytes([bytes[2], bytes[3]]);
        let value = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut out = Vec::new();
        handle_event(etype, code, value, &mut out);
        for b in out {
            PENDING.lock().push(b);
        }

        // Hand the buffer straight back to the device.
        avail_push(id as u16);
        last = (last + 1) & 0xffff;
        count += 1;
    }
    if count > 0 {
        LAST_USED.store(last as u16, Ordering::SeqCst);
        notify_queue(notify);
    }
}

/// Pop one translated keystroke byte, polling the device when the queue
/// has run dry.
pub fn get_byte() -> Option<u8> {
    if NOTIFY.load(Ordering::Acquire) == 0 {
        return None;
    }
    {
        let mut guard = PENDING.lock();
        if !guard.is_empty() {
            return Some(guard.remove(0));
        }
    }
    poll();
    let mut guard = PENDING.lock();
    if guard.is_empty() { None } else { Some(guard.remove(0)) }
}

// ---------------------------------------------------------------------------
// Input event -> console input translation
// ---------------------------------------------------------------------------

const EV_KEY: u16 = 0x01;

/// Modifier tracking.
static SHIFT: AtomicBool = AtomicBool::new(false);
static CAPS: AtomicBool = AtomicBool::new(false);

const SHIFT_LEFT: u16 = 42;
const SHIFT_RIGHT: u16 = 54;

/// One virtio input event -> console input bytes appended to `out`.
///
/// Byte conventions match the PS/2 keymap (`crate::keymap`): Enter
/// delivers '\n', Backspace DEL (0x7f), arrows ANSI escape sequences.
/// Mouse buttons and other non-key events are ignored.
fn handle_event(etype: u16, code: u16, value: u32, out: &mut Vec<u8>) {
    if etype != EV_KEY {
        return;
    }

    // Shift keys honour release events so that "Shift+U" leaves SHIFT
    // clear afterwards.
    if code == SHIFT_LEFT || code == SHIFT_RIGHT {
        SHIFT.store(value == 1, Ordering::Relaxed);
        return;
    }

    if value == 0 {
        return; // ignore release events for everything else
    }

    let shift = SHIFT.swap(false, Ordering::Relaxed);
    let caps = CAPS.load(Ordering::Relaxed);

    match code {
        58 => {
            // Caps Lock toggles on each press.
            CAPS.store(!caps, Ordering::Relaxed);
        }
        29 | 56 | 97 | 100 => {} // ctrl / alt / right-ctrl / compose

        1 => out.push(0x1b),  // Esc
        14 => out.push(0x7f), // Backspace
        15 => out.push(b'\t'),
        28 => out.push(b'\n'),
        57 => out.push(b' '),

        102 => out.extend_from_slice(b"\x1bO[H"), // Home
        103 => out.extend_from_slice(b"\x1b[A"),  // Up
        104 => out.extend_from_slice(b"\x1b[5~"), // PgUp
        105 => out.extend_from_slice(b"\x1b[D"),  // Left
        106 => out.extend_from_slice(b"\x1b[C"),  // Right
        107 => out.extend_from_slice(b"\x1b[F"),  // End
        108 => out.extend_from_slice(b"\x1b[B"),  // Down
        109 => out.extend_from_slice(b"\x1b[6~"), // PgDn
        110 => out.extend_from_slice(b"\x1b[2~"), // Insert
        111 => out.extend_from_slice(b"\x1b[3~"), // Delete

        // Digits (row above the letters).
        2 => out.push(if shift { b'!' } else { b'1' }),
        3 => out.push(if shift { b'@' } else { b'2' }),
        4 => out.push(if shift { b'#' } else { b'3' }),
        5 => out.push(if shift { b'$' } else { b'4' }),
        6 => out.push(if shift { b'%' } else { b'5' }),
        7 => out.push(if shift { b'^' } else { b'6' }),
        8 => out.push(if shift { b'&' } else { b'7' }),
        9 => out.push(if shift { b'*' } else { b'8' }),
        10 => out.push(if shift { b'(' } else { b'9' }),
        11 => out.push(if shift { b')' } else { b'0' }),
        12 => out.push(if shift { b'_' } else { b'-' }),
        13 => out.push(if shift { b'+' } else { b'=' }),

        // Letters, applying Shift and Caps Lock.
        16..=25 => out.push(letter(b"qwertyuiop"[(code - 16) as usize], shift, caps)),
        30..=38 => out.push(letter(b"asdfghjkl"[(code - 30) as usize], shift, caps)),
        44..=50 => out.push(letter(b"zxcvbnm"[(code - 44) as usize], shift, caps)),

        26 => out.push(if shift { b'{' } else { b'[' }),
        27 => out.push(if shift { b'}' } else { b']' }),
        39 => out.push(if shift { b':' } else { b';' }),
        40 => out.push(if shift { b'"' } else { b'\'' }),
        41 => out.push(if shift { b'~' } else { b'`' }),
        43 => out.push(if shift { b'|' } else { b'\\' }),
        51 => out.push(if shift { b'<' } else { b',' }),
        52 => out.push(if shift { b'>' } else { b'.' }),
        53 => out.push(if shift { b'?' } else { b'/' }),

        // Buttons (>= 0x100, e.g. a companion virtio-mouse) are not text.
        _ => {}
    }
}

/// Apply Shift and Caps Lock to a letter key.
#[inline]
fn letter(lower: u8, shift: bool, caps: bool) -> u8 {
    if shift != caps { lower.to_ascii_uppercase() } else { lower }
}

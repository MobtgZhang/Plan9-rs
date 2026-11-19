//! Plan 9 from Outer Space — self-hosted UEFI boot loader (Rust).
//!
//! Replaces GRUB for **all four** architectures:
//!
//! | arch        | rustc target                     | kernel entry contract           |
//! |-------------|----------------------------------|---------------------------------|
//! | x86_64      | x86_64-unknown-uefi             | RAX=magic, RBX=info; long mode, paging on |
//! | aarch64     | aarch64-unknown-uefi            | x0=magic, x1=info; EL1, MMU off |
//! | riscv64     | riscv64gc-unknown-none-elf      | a0=magic, a1=info; S-mode, MMU off |
//! | loongarch64 | loongarch64-unknown-none        | $a0=magic, $a1=info; PLV0, direct addressing |
//!
//! riscv64/loongarch64 have no official `*-unknown-uefi` rustc target, so
//! those two build as plain bare-metal ELF and are wrapped into PE32+
//! images by the ELF→PE packager in `build_tool`.  The wrapper's entry
//! stub self-relocates the payload, restores the CPU state the kernel
//! expects, and jumps to the ELF entry — see `wrap.rs` in build_tool.
//!
//! Flow (identical for every arch):
//!   1. Print a banner and open the ESP via SimpleFileSystem.
//!   2. Show the interactive **Boot Menu** (↑/↓/number/Enter, countdown,
//!      "q" = firmware) and let the user pick an entry.
//!   3. Reserve and load the kernel's ELF segments at their physical addresses.
//!   4. Build a Multiboot2 info block (memmap, framebuffer, modules,
//!      bootloader name) inside a BootServicesData page.
//!   5. GetMemoryMap, ExitBootServices.
//!   6. Hand off: arch-specific CPU state + jump.

#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::size_of;

// ===========================================================================
// Minimal UEFI API surface
// ===========================================================================

pub const EFI_SUCCESS: usize = 0;
const EFI_LOAD_ERROR: usize = 1 | (1 << 63);
const EFI_INVALID_PARAMETER: usize = 2 | (1 << 63);
const EFI_UNSUPPORTED: usize = 3 | (1 << 63);
const EFI_BUFFER_TOO_SMALL: usize = 5 | (1 << 63);
const EFI_NOT_FOUND: usize = 14 | (1 << 63);

pub type EfiHandle = usize;

#[repr(C)]
pub struct SystemTable {
    hdr: [u64; 3],
    firmware_vendor: u64,
    firmware_revision: u32,
    _pad: u32,
    console_in_handle: EfiHandle,
    con_in: *const SimpleInput,
    console_out_handle: EfiHandle,
    con_out: *const SimpleTextOut,
    standard_err_handle: EfiHandle,
    std_err: *const SimpleTextOut,
    runtime_services: *const u64,
    boot_services: *const BootServices,
}

#[repr(C)]
pub struct SimpleTextOut {
    reset: u64,
    output_string: extern "efiapi" fn(*const SimpleTextOut, *const u16) -> usize,
    test_string: u64,
    query_mode: u64,
    set_mode: u64,
    clear_screen: extern "efiapi" fn(*const SimpleTextOut) -> usize,
    set_attribute: extern "efiapi" fn(*const SimpleTextOut, usize) -> usize,
    mode: *const u8,
    cursor_x: i32,
    cursor_y: i32,
}

#[repr(C)]
pub struct SimpleInput {
    reset: u64,
    read_key_stroke: extern "efiapi" fn(*const SimpleInput, *mut InputKey) -> usize,
    wait_for_key: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputKey {
    pub scan_code: u16,
    pub unicode_char: u16,
}

const SCAN_NULL: u16 = 0x00;
const SCAN_UP: u16 = 0x01;
const SCAN_DOWN: u16 = 0x02;
const SCAN_ESC: u16 = 0x17;

const CHAR_CR: u16 = 0x0D;
const CHAR_LF: u16 = 0x0A;
const CHAR_1: u16 = 0x31;
const CHAR_Q: u16 = 0x71;

// GetMemoryMap / AllocatePages / AllocatePool / LocateHandle /
// HandleProtocol / LocateHandleBuffer / ExitBootServices are reached by
// fixed slot indexes in the raw BootServices pointer array — the UEFI spec
// fixes the order, so this is ABI-safe and avoids typing out the whole
// 100-member struct.
//
// Spec function-pointer order (0-based, after the 24-byte table header
// which occupies 3 slots):
//   0 RaiseTPL           1 RestoreTPL
//   2 AllocatePages      3 FreePages        4 GetMemoryMap
//   5 AllocatePool       6 FreePool
//   ...
//  24 LocateHandleBuffer                    25 LocateProtocol
//  26 InstallMultipleProtocolInterfaces ...
//  27 HandleProtocol
//  ...
//  19+... careful: ExitBootServices is index 17 among "boot services"
//   functions but 3 header slots offset it.  We verified against the spec:
//   ExitBootServices = raw slot 16+3 = 19?  See EBS_SLOT below.
const SLOT_ALLOCATE_PAGES: usize = 2 + 3;
const SLOT_GET_MEMORY_MAP: usize = 4 + 3;
const SLOT_ALLOCATE_POOL: usize = 5 + 3;
const SLOT_WAIT_FOR_EVENT: usize = 9 + 3;
const SLOT_HANDLE_PROTOCOL: usize = 16 + 3; // spec index 16 = HandleProtocol
const SLOT_LOCATE_HANDLE_BUFFER: usize = 36 + 3; // spec index 36 = LocateHandleBuffer
const SLOT_EXIT_BOOT_SERVICES: usize = 26 + 3;
const SLOT_STALL: usize = 28 + 3; // spec index 28 = Stall (microseconds) // spec index 26 = ExitBootServices

#[repr(C)]
pub struct BootServices {
    hdr: [u64; 3],
}

// Memory descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub kind: u32,
    _pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub pages: u64,
    pub attribute: u64,
}

const MEM_TYPE_LOADER_DATA: usize = 2;
const MEM_TYPE_BOOT_SERVICES_DATA: usize = 4;
const ALLOCATE_ANY_PAGES: usize = 0;
const ALLOCATE_ADDRESS: usize = 2;

// SimpleFileSystem protocol.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiGuid {
    pub a: u32,
    pub b: u16,
    pub c: u16,
    pub d: [u8; 8],
}

impl EfiGuid {
    const fn new(a: u32, b: u16, c: u16, d: [u8; 8]) -> Self {
        Self { a, b, c, d }
    }
}

const SIMPLE_FS_GUID: EfiGuid =
    EfiGuid::new(0x964e5b22, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);

const FILE_INFO_GUID: EfiGuid = EfiGuid::new(
    0x09576e92,
    0x6d3f,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

const GOP_GUID: EfiGuid = EfiGuid::new(
    0x9042a9de,
    0x23dc,
    0x4a38,
    [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);

#[repr(C)]
pub struct SimpleFileSystemProtocol {
    revision: u64,
    open_volume: extern "efiapi" fn(*const SimpleFileSystemProtocol, *mut *mut FileProto) -> usize,
}

#[repr(C)]
pub struct FileProto {
    revision: u64,
    open: extern "efiapi" fn(*const FileProto, *mut *mut FileProto, *const u16, u64, u64) -> usize,
    close: extern "efiapi" fn(*const FileProto) -> usize,
    delete: u64,
    read: extern "efiapi" fn(*const FileProto, *mut usize, *mut u8) -> usize,
    write: u64,
    get_position: u64,
    set_position: u64,
    get_info: extern "efiapi" fn(*const FileProto, *const EfiGuid, *mut usize, *mut u8) -> usize,
    _pad: [u64; 4],
}

const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;
const BY_PROTOCOL: usize = 2;

// ===========================================================================
// Globals + helpers
// ===========================================================================

static mut ST_PTR: *const SystemTable = core::ptr::null();

fn st() -> &'static SystemTable {
    unsafe { &*ST_PTR }
}

fn bs_raw() -> *const u64 {
    st().boot_services as *const u64
}

fn bs_call<T: Copy>(slot: usize) -> T {
    unsafe { core::mem::transmute_copy::<u64, T>(&*bs_raw().add(slot)) }
}

fn con_out() -> &'static SimpleTextOut {
    unsafe { &*st().con_out }
}

fn con_in() -> &'static SimpleInput {
    unsafe { &*st().con_in }
}

fn out(s: &str) {
    let mut buf = [0u16; 256];
    let mut n = 0usize;
    for ch in s.chars() {
        if n + 1 >= buf.len() {
            break;
        }
        buf[n] = ch as u32 as u16;
        n += 1;
    }
    buf[n] = 0;
    (con_out().output_string)(con_out(), buf.as_ptr());
}

fn outln(s: &str) {
    out(s);
    out("\r\n");
}

const ATTR_DEFAULT: usize = 0x07;
const ATTR_GREEN: usize = 0x0A;
const ATTR_YELLOW: usize = 0x0E;

fn set_color(attr: usize) {
    (con_out().set_attribute)(con_out(), attr);
}

fn clear_screen() {
    (con_out().clear_screen)(con_out());
}

fn read_key() -> Option<InputKey> {
    let mut k = InputKey::default();
    let rc = (con_in().read_key_stroke)(con_in(), &mut k);
    if rc == EFI_SUCCESS {
        Some(k)
    } else {
        None
    }
}

fn wait_key() -> InputKey {
    // WaitForKey is the third field of SimpleInput (an event).
    let ev = con_in().wait_for_key;
    let mut idx: usize = 0;
    let events = [ev];
    let wait_for_event: extern "efiapi" fn(usize, *const usize, *mut usize) -> usize =
        bs_call(SLOT_WAIT_FOR_EVENT);
    let _ = wait_for_event(1, events.as_ptr(), &mut idx);
    read_key().unwrap_or(InputKey::default())
}

// ===========================================================================
// Number formatting (byte-array based; no alloc)
// ===========================================================================

fn utoa(mut v: usize, out: &mut [u8]) -> &str {
    if v == 0 && !out.is_empty() {
        out[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&out[..1]) };
    }
    let mut n = 0usize;
    while v > 0 && n < out.len() {
        out[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n / 2 {
        out.swap(i, n - 1 - i);
    }
    unsafe { core::str::from_utf8_unchecked(&out[..n]) }
}

fn out_hex(mut value: usize) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 2 + size_of::<usize>() * 2];
    let mut start = buf.len();
    loop {
        start -= 1;
        buf[start] = DIGITS[value & 0xf];
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    buf[start - 2..start].copy_from_slice(b"0x");
    out(unsafe { core::str::from_utf8_unchecked(&buf[start - 2..]) });
}

// ===========================================================================
// GOP framebuffer graphics — modern boot menu (reference-image style)
// ===========================================================================

struct Gfx {
    /// GOP protocol interface (raw pointer array; Blt is slot 2).
    gop: *const u64,
    w: u32,
    h: u32,
    framebuffer: Option<LinearFramebuffer>,
}

#[derive(Clone, Copy)]
struct LinearFramebuffer {
    address: u64,
    pitch: u32,
    width: u32,
    height: u32,
    red_position: u8,
}

impl Gfx {
    unsafe fn from_protocol(gop: *const u64) -> Option<Self> {
        let mode = *gop.add(3) as *const u64;
        if mode.is_null() {
            return None;
        }
        let info = *mode.add(1) as *const u32;
        if info.is_null() || *mode.add(2) < 36 {
            return None;
        }
        let w = *info.add(1);
        let h = *info.add(2);
        if w == 0 || h == 0 {
            return None;
        }

        let framebuffer = match *info.add(3) {
            format @ (0 | 1) => {
                let address = *mode.add(3);
                let stride = *info.add(8);
                stride.checked_mul(4).and_then(|pitch| {
                    (address != 0 && stride >= w && u64::from(pitch) * u64::from(h) <= *mode.add(4))
                        .then_some(LinearFramebuffer {
                            address,
                            pitch,
                            width: w,
                            height: h,
                            red_position: if format == 0 { 0 } else { 16 },
                        })
                })
            }
            _ => None,
        };
        Some(Self { gop, w, h, framebuffer })
    }
}

/// Probe the GOP.  QEMU's virtio-gpu firmware exposes a *Blt-only* GOP
/// (no linear framebuffer), so all drawing is routed through GOP->Blt,
/// which works for every pixel format and for real framebuffers alike.
fn gfx_init() -> Option<Gfx> {
    let handles = locate_handles(&GOP_GUID)?;
    let mut selected = None;
    for &handle in handles.iter().rev() {
        let Some(iface) = handle_protocol(handle, &GOP_GUID) else { continue };
        let Some(gfx) = (unsafe { Gfx::from_protocol(iface.cast()) }) else { continue };
        if gfx.framebuffer.is_some() {
            return Some(gfx);
        }
        if selected.is_none() {
            selected = Some(gfx);
        }
    }
    selected
}
// Generated from DejaVuSansMono.ttf 13px, 8x16 cells, ASCII 32..126.
// Each glyph is 16 bytes, MSB = leftmost pixel.
pub const FONT8X16: [[u8; 16]; 95] = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // space
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00], // !
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x2C, 0x2C, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // "
    [0x00, 0x00, 0x00, 0x00, 0x12, 0x16, 0x14, 0x7F, 0x24, 0x2C, 0xFE, 0x68, 0x48, 0x48, 0x00, 0x00], // #
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3C, 0x6E, 0x68, 0x38, 0x1E, 0x0A, 0x4E, 0x3C, 0x08, 0x08], // $
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x90, 0x90, 0x76, 0x18, 0x6E, 0x0B, 0x0B, 0x0E, 0x00, 0x00], // %
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x60, 0x20, 0x30, 0x5B, 0xCB, 0xC6, 0x66, 0x3B, 0x00, 0x00], // &
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // '
    [0x00, 0x00, 0x00, 0x08, 0x08, 0x18, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x18, 0x08, 0x0C, 0x00], // (
    [0x00, 0x00, 0x00, 0x30, 0x10, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x18, 0x18, 0x10, 0x30, 0x00], // )
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x56, 0x3C, 0x3C, 0x56, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00], // *
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0xFE, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00], // +
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x10, 0x10], // ,
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00], // -
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00], // .
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x04, 0x0C, 0x08, 0x18, 0x10, 0x10, 0x30, 0x20, 0x60, 0x40], // /
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x66, 0x46, 0x5A, 0x46, 0x66, 0x66, 0x3C, 0x00, 0x00], // 0
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00, 0x00], // 1
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x06, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00, 0x00], // 2
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x06, 0x04, 0x3C, 0x06, 0x06, 0x46, 0x3C, 0x00, 0x00], // 3
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x1C, 0x14, 0x24, 0x64, 0x44, 0x7E, 0x04, 0x04, 0x00, 0x00], // 4
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x60, 0x60, 0x7C, 0x04, 0x06, 0x06, 0x44, 0x7C, 0x00, 0x00], // 5
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x60, 0x40, 0x7C, 0x66, 0x42, 0x42, 0x66, 0x3C, 0x00, 0x00], // 6
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x06, 0x04, 0x0C, 0x08, 0x18, 0x18, 0x10, 0x30, 0x00, 0x00], // 7
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x46, 0x66, 0x3C, 0x66, 0x42, 0x66, 0x3C, 0x00, 0x00], // 8
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x46, 0x46, 0x66, 0x3E, 0x06, 0x44, 0x38, 0x00, 0x00], // 9
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00], // :
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x10, 0x10], // ;
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1C, 0x70, 0x70, 0x1C, 0x02, 0x00, 0x00, 0x00], // <
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00], // =
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x78, 0x0E, 0x0E, 0x78, 0xC0, 0x00, 0x00, 0x00], // >
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x10, 0x00, 0x10, 0x10, 0x00, 0x00], // ?
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x62, 0x42, 0xDF, 0x93, 0x93, 0x93, 0xDF, 0x40, 0x60, 0x1E], // @
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x3C, 0x2C, 0x24, 0x66, 0x7E, 0x42, 0xC3, 0x00, 0x00], // A
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x46, 0x46, 0x46, 0x7C, 0x46, 0x42, 0x46, 0x7C, 0x00, 0x00], // B
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x22, 0x60, 0x40, 0x40, 0x40, 0x60, 0x22, 0x1C, 0x00, 0x00], // C
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x4C, 0x46, 0x46, 0x42, 0x46, 0x46, 0x4C, 0x78, 0x00, 0x00], // D
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x60, 0x60, 0x60, 0x7E, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00], // E
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x60, 0x60, 0x60, 0x7E, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00], // F
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x62, 0x40, 0x40, 0x4E, 0x42, 0x42, 0x66, 0x3E, 0x00, 0x00], // G
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x42, 0x00, 0x00], // H
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00], // I
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x4C, 0x78, 0x00, 0x00], // J
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x44, 0x48, 0x70, 0x78, 0x48, 0x4C, 0x46, 0x43, 0x00, 0x00], // K
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00], // L
    [0x00, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xE6, 0xE6, 0xFA, 0xDA, 0xDA, 0xC2, 0xC2, 0xC2, 0x00, 0x00], // M
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x62, 0x72, 0x52, 0x5A, 0x4A, 0x4E, 0x46, 0x46, 0x00, 0x00], // N
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x46, 0x42, 0x42, 0x42, 0x46, 0x66, 0x3C, 0x00, 0x00], // O
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x62, 0x62, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00, 0x00], // P
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x46, 0x42, 0x42, 0x42, 0x46, 0x66, 0x3C, 0x0C, 0x04], // Q
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x46, 0x46, 0x46, 0x7C, 0x4C, 0x46, 0x42, 0x43, 0x00, 0x00], // R
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x64, 0x40, 0x60, 0x3C, 0x06, 0x02, 0x46, 0x3C, 0x00, 0x00], // S
    [0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00], // T
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x66, 0x3C, 0x00, 0x00], // U
    [0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x42, 0x66, 0x66, 0x24, 0x2C, 0x3C, 0x18, 0x18, 0x00, 0x00], // V
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC3, 0xC3, 0xDA, 0x5A, 0x5A, 0x6E, 0x66, 0x66, 0x00, 0x00], // W
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x66, 0x3C, 0x18, 0x18, 0x3C, 0x24, 0x66, 0xC3, 0x00, 0x00], // X
    [0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x66, 0x24, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00], // Y
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x06, 0x04, 0x0C, 0x18, 0x10, 0x30, 0x60, 0x7F, 0x00, 0x00], // Z
    [0x00, 0x00, 0x00, 0x1C, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1C, 0x00], // [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x60, 0x20, 0x30, 0x10, 0x10, 0x18, 0x08, 0x0C, 0x04, 0x06], // backslash
    [0x00, 0x00, 0x00, 0x38, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x38, 0x00], // ]
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3C, 0x64, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // ^
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // _
    [0x00, 0x00, 0x00, 0x00, 0x30, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // `
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x46, 0x06, 0x3E, 0x46, 0x46, 0x7E, 0x00, 0x00], // a
    [0x00, 0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x7C, 0x66, 0x62, 0x62, 0x62, 0x66, 0x7C, 0x00, 0x00], // b
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x22, 0x60, 0x60, 0x60, 0x22, 0x1C, 0x00, 0x00], // c
    [0x00, 0x00, 0x00, 0x06, 0x06, 0x06, 0x06, 0x3E, 0x66, 0x46, 0x46, 0x46, 0x66, 0x3E, 0x00, 0x00], // d
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x42, 0x7E, 0x40, 0x62, 0x3C, 0x00, 0x00], // e
    [0x00, 0x00, 0x00, 0x0E, 0x18, 0x10, 0x10, 0x7E, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x00, 0x00], // f
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x66, 0x46, 0x46, 0x46, 0x66, 0x3E, 0x06, 0x04], // g
    [0x00, 0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00], // h
    [0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00], // i
    [0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x38, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x18], // j
    [0x00, 0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x62, 0x00, 0x00], // k
    [0x00, 0x00, 0x00, 0x70, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x18, 0x0E, 0x00, 0x00], // l
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x00, 0x00], // m
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00], // n
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x46, 0x42, 0x46, 0x66, 0x3C, 0x00, 0x00], // o
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x62, 0x62, 0x62, 0x66, 0x7C, 0x40, 0x40], // p
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x66, 0x46, 0x46, 0x46, 0x66, 0x3E, 0x06, 0x06], // q
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00], // r
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x64, 0x60, 0x3C, 0x06, 0x46, 0x3C, 0x00, 0x00], // s
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x7E, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1E, 0x00, 0x00], // t
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00, 0x00], // u
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x46, 0x64, 0x24, 0x3C, 0x38, 0x18, 0x00, 0x00], // v
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC3, 0xDA, 0x5A, 0x7E, 0x6E, 0x64, 0x00, 0x00], // w
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x24, 0x18, 0x18, 0x3C, 0x24, 0x46, 0x00, 0x00], // x
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x66, 0x64, 0x24, 0x3C, 0x18, 0x18, 0x18, 0x10], // y
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x04, 0x0C, 0x18, 0x30, 0x20, 0x7E, 0x00, 0x00], // z
    [0x00, 0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x18, 0x70, 0x10, 0x18, 0x18, 0x18, 0x18, 0x0E, 0x00], // {
    [0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18], // |
    [0x00, 0x00, 0x00, 0x70, 0x10, 0x18, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x18, 0x18, 0x10, 0x70, 0x00], // }
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00], // ~
];

type Rgb = (u8, u8, u8);

/// Deep-blue menu palette (reference image).
const C_BG_TOP: Rgb = (6, 13, 43); // near-black navy
const C_BG_BOT: Rgb = (22, 53, 127); // lighter blue
const C_CARD: Rgb = (20, 34, 78); // unselected card
const C_CARD_SEL: Rgb = (42, 74, 168); // selected card
const C_BORDER_SEL: Rgb = (128, 168, 255); // selected card border
const C_WHITE: Rgb = (240, 244, 255);
const C_GRAY: Rgb = (170, 184, 220);
const C_BAR: Rgb = (5, 9, 30); // hint bar

/// EFI_GRAPHICS_OUTPUT_BLT_PIXEL: byte order is Blue, Green, Red, Reserved.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BltPixel {
    b: u8,
    g: u8,
    r: u8,
    res: u8,
}

const BLT_VIDEO_FILL: usize = 0;

type BltFn = unsafe extern "efiapi" fn(
    *const u64, // This
    *mut BltPixel,
    usize, // operation
    usize, // SourceX
    usize, // SourceY
    usize, // DestinationX
    usize, // DestinationY
    usize, // Width
    usize, // Height
    usize, // Delta (source row stride in bytes)
) -> usize;

/// Fill a rectangle via GOP->Blt (works for Blt-only GOPs too).
unsafe fn gfill(g: &Gfx, x: u32, y: u32, w: u32, h: u32, c: Rgb) {
    if x >= g.w || y >= g.h || w == 0 || h == 0 {
        return;
    }
    let blt: BltFn = unsafe { core::mem::transmute(*g.gop.add(2)) };
    let px = BltPixel { b: c.2, g: c.1, r: c.0, res: 0 };
    let rc = blt(
        g.gop,
        &px as *const BltPixel as *mut BltPixel,
        BLT_VIDEO_FILL,
        0,
        0,
        x as usize,
        y as usize,
        w.min(g.w - x) as usize,
        h.min(g.h - y) as usize,
        0,
    );
    let _ = rc;
}

/// Single-pixel fill: per-pixel drawing is routed through Blt so the menu
/// renders identically on Blt-only and linear-framebuffer GOPs.
#[inline]
unsafe fn gpix(g: &Gfx, x: u32, y: u32, c: Rgb) {
    gfill(g, x, y, 1, 1, c);
}

/// Rectangle with rounded corners (radius `r`).
unsafe fn grownd(g: &Gfx, x: u32, y: u32, w: u32, h: u32, r: u32, c: Rgb) {
    if w < 2 * r || h < 2 * r {
        gfill(g, x, y, w, h, c);
        return;
    }
    gfill(g, x, y + r, w, h - 2 * r, c);
    gfill(g, x + r, y, w - 2 * r, r, c);
    gfill(g, x + r, y + h - r, w - 2 * r, r, c);
    // Quarter-disks in the four corners.
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                let (lx, ty) = (x + r - 1 - dx, y + r - 1 - dy);
                gpix(g, lx, ty, c);
                gpix(g, x + w - r + dx, ty, c);
                gpix(g, lx, y + h - r + dy, c);
                gpix(g, x + w - r + dx, y + h - r + dy, c);
            }
        }
    }
}

/// Outlined rounded rectangle (2 px border).
#[allow(dead_code)]
unsafe fn grownd_outline(g: &Gfx, x: u32, y: u32, w: u32, h: u32, r: u32, c: Rgb) {
    grownd(g, x, y, w, h, r, c);
}

unsafe fn gcircle_ring(g: &Gfx, cx: i32, cy: i32, r_in: i32, r_out: i32, c: Rgb) {
    for dy in -r_out..=r_out {
        for dx in -r_out..=r_out {
            let d2 = dx * dx + dy * dy;
            if d2 >= r_in * r_in && d2 <= r_out * r_out {
                gpix(g, (cx + dx) as u32, (cy + dy) as u32, c);
            }
        }
    }
}

/// Draw an 8x16 font string; `scale` multiples the cell size.  Horizontal
/// runs of set pixels are filled in one Blt each to limit firmware calls.
unsafe fn gtext(g: &Gfx, x: u32, y: u32, s: &str, c: Rgb, scale: u32) {
    let mut cx = x;
    for ch in s.chars() {
        let code = ch as usize;
        if code < 32 || code > 126 {
            cx += 8 * scale;
            continue;
        }
        let glyph = FONT8X16[code - 32];
        for (row, bits) in glyph.iter().enumerate() {
            let py = y + (row as u32) * scale;
            let mut run0: Option<usize> = None; // run start (col)
            for col in 0..9usize {
                let set = col < 8 && (bits & (1u8 << (7 - col))) != 0;
                if !set && run0.is_some() {
                    // flush run [run0, col)
                    let r = run0.unwrap();
                    gfill(
                        g,
                        cx + (r as u32) * scale,
                        py,
                        ((col - r) as u32) * scale,
                        scale,
                        c,
                    );
                    run0 = None;
                } else if set && run0.is_none() {
                    run0 = Some(col);
                }
            }
        }
        cx += 8 * scale;
    }
}

fn gtext_width(s: &str, scale: u32) -> u32 {
    (s.chars().count() as u32) * 8 * scale
}

/// Small monitor icon (white outline) with stand, bottom-left at (x, y).
unsafe fn gdraw_monitor(g: &Gfx, x: u32, y: u32, c: Rgb) {
    let (iw, ih, t) = (44u32, 30u32, 3u32);
    // Screen outline.
    gfill(g, x, y, iw, t, c);
    gfill(g, x, y + ih - t, iw, t, c);
    gfill(g, x, y, t, ih, c);
    gfill(g, x + iw - t, y, t, ih, c);
    // Subtle screen glow.
    gfill(g, x + t + 2, y + t + 2, iw - 2 * t - 4, ih - 2 * t - 4, (36, 52, 108));
    // Stand + base.
    gfill(g, x + iw / 2 - 4, y + ih, 8, 5, c);
    gfill(g, x + iw / 2 - 13, y + ih + 5, 26, 4, c);
}

/// Small gear icon, 24x24, centred at (cx, cy).
unsafe fn gdraw_gear(g: &Gfx, cx: i32, cy: i32, c: Rgb) {
    gcircle_ring(g, cx, cy, 4, 9, c);
    // Eight teeth at 45-degree steps; cos/sin values for 0/45/90... are
    // exactly {1, 0.707, 0} so integer offsets suffice.
    let teeth: [(i32, i32); 8] = [
        (10, 0), (7, 7), (0, 10), (-7, 7), (-10, 0), (-7, -7), (0, -10), (7, -7),
    ];
    for (dx, dy) in teeth.iter() {
        let tx = (cx + dx - 3) as u32;
        let ty = (cy + dy - 3) as u32;
        gfill(g, tx, ty, 6, 6, c);
    }
}

/// Right-pointing chevron, 12x24, top-left at (x, y).
unsafe fn gdraw_chevron(g: &Gfx, x: u32, y: u32, c: Rgb) {
    for t in 0..4u32 {
        for i in 0..11u32 {
            gpix(g, x + i, y + i + t, c);
            gpix(g, x + i, y + 23 - i - t, c);
        }
    }
}

/// Tiny up+down chevron pair for the "Select" hint, 8x14.
unsafe fn gdraw_updown(g: &Gfx, x: u32, y: u32, c: Rgb) {
    for i in 0..4u32 {
        for k in 0..=i {
            gpix(g, x + 3 - k, y + i, c); // up chevron
            gpix(g, x + 4 + k, y + i, c);
            gpix(g, x + 3 - k, y + 13 - i, c); // down chevron
            gpix(g, x + 4 + k, y + 13 - i, c);
        }
    }
}

/// Graphical boot menu, mirroring the reference design: full-screen deep
/// blue gradient, monitor icon + centred title, highlighted selected card
/// with logo and right arrow, gear-icon secondary entries, bottom key hints.
unsafe fn draw_menu_gfx(g: &Gfx, selected: usize, countdown: Option<i32>) {
    // Full-screen vertical gradient (one Blt per row).
    let (w, h) = (g.w, g.h);
    for y in 0..h {
        let t = (y as u64 * 255 / (h.max(2) as u64 - 1)) as u32;
        let c = (
            (C_BG_TOP.0 as u32 + ((C_BG_BOT.0 as u32 - C_BG_TOP.0 as u32) * t) / 255) as u8,
            (C_BG_TOP.1 as u32 + ((C_BG_BOT.1 as u32 - C_BG_TOP.1 as u32) * t) / 255) as u8,
            (C_BG_TOP.2 as u32 + ((C_BG_BOT.2 as u32 - C_BG_TOP.2 as u32) * t) / 255) as u8,
        );
        gfill(g, 0, y, w, 1, c);
    }

    // ---- Title: monitor icon + "Select Operating System" ----
    let t_scale = if w >= 720 { 2 } else { 1 };
    let title = "Select Operating System";
    let tw = gtext_width(title, t_scale);
    let icon_w = 44 + 16;
    let group_w = icon_w + tw;
    let gx = (w / 2).saturating_sub(group_w / 2);
    let gy = h / 8;
    gdraw_monitor(g, gx, gy, C_WHITE);
    gtext(g, gx + icon_w, gy + 6, title, C_WHITE, t_scale);

    // ---- Entries ----
    let card_w = if w >= 900 { 720 } else { w * 3 / 4 };
    let card_h = 64u32;
    let gap = 16u32;
    let cy0 = h * 3 / 10;
    let cx = (w / 2).saturating_sub(card_w / 2);
    for (i, e) in MENU.iter().enumerate() {
        let cy = cy0 + (card_h + gap) * i as u32;
        let is_sel = i == selected;
        if is_sel {
            grownd(g, cx, cy, card_w, card_h, 12, C_CARD_SEL);
            grownd(g, cx + 2, cy + 2, card_w - 4, card_h - 4, 10, C_CARD_SEL);
            grownd(g, cx, cy, card_w, card_h, 12, C_BORDER_SEL);
            grownd(g, cx + 3, cy + 3, card_w - 6, card_h - 6, 10, C_CARD_SEL);
            // Logo: white rounded tile with a dark "9".
            grownd(g, cx + 14, cy + 12, 40, 40, 8, C_WHITE);
            gtext(g, cx + 14 + 12, cy + 12 + 4, "9", (10, 20, 60), 2);
            // Title + right chevron.
            let ts = if card_w >= 600 { 2 } else { 1 };
            gtext(g, cx + 70, cy + card_h / 2 - 8 * ts, e.title, C_WHITE, ts);
            gdraw_chevron(g, cx + card_w - 44, cy + card_h / 2 - 12, C_WHITE);
        } else {
            grownd(g, cx, cy, card_w, card_h, 12, C_CARD);
            gdraw_gear(g, (cx + 34) as i32, (cy + card_h / 2) as i32, C_GRAY);
            gtext(g, cx + 64, cy + card_h / 2 - 8, e.title, C_GRAY, 1);
        }
    }

    // ---- Countdown (optional) ----
    if let Some(s) = countdown {
        let mut nb = [0u8; 24];
        let num = utoa(s.max(0) as usize, &mut nb);
        let mut buf = [0u8; 48];
        buf[..16].copy_from_slice(b"Auto-booting in ");
        let n = num.as_bytes();
        buf[16..16 + n.len()].copy_from_slice(n);
        buf[16 + n.len()] = b's';
        let text = unsafe { core::str::from_utf8_unchecked(&buf[..17 + n.len()]) };
        gtext(
            &g,
            (w / 2).saturating_sub(gtext_width(text, 1) / 2),
            h - 108,
            text,
            C_GRAY,
            1,
        );
    }

    // ---- Bottom hint bar ----
    gfill(g, 0, h - 48, w, 48, C_BAR);
    gfill(g, 0, h - 48, w, 2, (40, 64, 140));
    // Items: ⌃⌄ Select   Enter Boot   Esc Exit — centred as a group.
    let (sel_s, eb_s, ee_s) = ("Select", "Enter Boot", "Esc Exit");
    let total = 16 + 8 + gtext_width(sel_s, 1)
        + 40 + gtext_width(eb_s, 1)
        + 40 + gtext_width(ee_s, 1);
    let mut hx = (w / 2).saturating_sub(total / 2);
    let hy = h - 48 + 17;
    gdraw_updown(g, hx, hy - 2, C_WHITE);
    hx += 16 + 8;
    gtext(g, hx, hy, sel_s, C_WHITE, 1);
    hx += gtext_width(sel_s, 1) + 40;
    gtext(g, hx, hy, eb_s, C_WHITE, 1);
    hx += gtext_width(eb_s, 1) + 40;
    gtext(g, hx, hy, ee_s, C_WHITE, 1);
}

/// Minimal fixed-capacity string (no_std, no alloc).
// (removed: countdown text is built with plain buffers now)

// ===========================================================================
// Boot menu — modern, Plan 9-inspired UI (text-mode, UEFI SimpleTextOut)
// ===========================================================================

struct MenuEntry {
    /// Icon shown to the left of the title (text-mode approximation).
    icon: &'static str,
    title: &'static str,
    subtitle: &'static str,
}

const MENU: [MenuEntry; 3] = [
    MenuEntry {
        icon: "▶",
        title: "Boot Plan 9 (Rust kernel)",
        subtitle: "9kernel.elf from the boot volume",
    },
    MenuEntry {
        icon: "▶",
        title: "Boot Plan 9 (verbose)",
        subtitle: "same kernel, extra boot-time chatter",
    },
    MenuEntry {
        icon: "⚙",
        title: "Return to UEFI firmware",
        subtitle: "exit to the boot manager",
    },
];

const MENU_TIMEOUT_S: i32 = 5;

/// Attribute pairs: (normal, selected).  Selected uses inverse video so the
/// whole option row looks like a highlighted button (as in the reference UI).
const ATTR_MENU_NORMAL: usize = 0x0F;   // bright white on black
const ATTR_MENU_SEL_BG: usize = 0x1F;   // bright white on blue (highlighted row)
const ATTR_TITLE: usize = 0x0F;         // bright white
const ATTR_SUBTITLE: usize = 0x0B;      // cyan
const ATTR_HINT: usize = 0x08;          // gray
const ATTR_BORDER: usize = 0x01;        // blue

/// Print a horizontal separator line using box-drawing characters.
fn hline() {
    outln("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

/// Draw the boot menu through GOP, or use the firmware text console.
fn draw_menu(gfx: Option<&Gfx>, selected: usize, countdown: Option<i32>) {
    if let Some(gfx) = gfx {
        unsafe { draw_menu_gfx(gfx, selected, countdown) };
        return;
    }
    text_draw_menu(selected, countdown);
}

/// Text-mode fallback menu (firmware console without a usable GOP).
fn text_draw_menu(selected: usize, countdown: Option<i32>) {
    clear_screen();

    // --- Header ---
    set_color(ATTR_TITLE);
    outln("   ⌂  Select Operating System");
    set_color(ATTR_BORDER);
    hline();
    set_color(ATTR_DEFAULT);
    outln("");

    // --- Menu entries ---
    for (i, e) in MENU.iter().enumerate() {
        let is_sel = i == selected;
        if is_sel {
            set_color(ATTR_MENU_SEL_BG);
        } else {
            set_color(ATTR_MENU_NORMAL);
        }

        // Left edge of the "button".
        out("  ");
        if is_sel {
            out("◆ ");
        } else {
            out("◇ ");
        }
        set_color(if is_sel { ATTR_MENU_SEL_BG } else { ATTR_TITLE });
        out(e.icon);
        out("  ");
        out(e.title);

        // Pad to fixed width then draw subtitle on the selected row only.
        let _ = is_sel;
        if is_sel {
            set_color(ATTR_SUBTITLE);
            out("    ");
            out(e.subtitle);
            out("   ➤");
        }

        outln("");
        set_color(ATTR_DEFAULT);
    }

    // --- Footer hints ---
    set_color(ATTR_DEFAULT);
    outln("");
    set_color(ATTR_HINT);
    outln("  ↑/↓  Select     Enter  Boot     Esc  Exit");
    set_color(ATTR_DEFAULT);

    // --- Countdown ---
    if let Some(s) = countdown {
        set_color(ATTR_HINT);
        let mut nb = [0u8; 24];
        out("  Auto-booting in ");
        out(utoa(s.max(0) as usize, &mut nb));
        outln(" seconds...");
    }
    set_color(ATTR_DEFAULT);
}

fn handle_char(c: u16, selected: &mut usize) -> Option<usize> {
    if c == CHAR_CR || c == CHAR_LF {
        return Some(*selected);
    }
    if c >= CHAR_1 && c <= CHAR_1 + (MENU.len() as u16 - 1) {
        return Some((c - CHAR_1) as usize);
    }
    if c == CHAR_Q || c == (CHAR_Q - 32) {
        return Some(MENU.len() - 1);
    }
    None
}

fn menu_interactive(gfx: Option<&Gfx>, mut selected: usize) -> usize {
    loop {
        let k = wait_key();
        match k.scan_code {
            SCAN_UP => {
                selected = if selected == 0 { MENU.len() - 1 } else { selected - 1 };
                draw_menu(gfx, selected, None);
            }
            SCAN_DOWN => {
                selected = (selected + 1) % MENU.len();
                draw_menu(gfx, selected, None);
            }
            SCAN_ESC => return MENU.len() - 1,
            SCAN_NULL => {
                if let Some(sel) = handle_char(k.unicode_char, &mut selected) {
                    return sel;
                }
            }
            _ => {}
        }
    }
}

/// Boot-services Stall: busy-wait `us` microseconds through the firmware.
fn stall(us: u64) {
    let st: extern "efiapi" fn(u64) -> usize = bs_call(SLOT_STALL);
    let _ = st(us);
}

fn run_menu(gfx: Option<&Gfx>) -> usize {
    let mut selected = 0usize;
    draw_menu(gfx, selected, Some(MENU_TIMEOUT_S));

    // Countdown in real 100 ms ticks (firmware Stall, not CPU spins — a
    // warm TCG cache would otherwise race through the "seconds").
    let mut ticks = MENU_TIMEOUT_S * 10;
    while ticks > 0 {
        let mut waited = 0;
        // Poll keys every ~5 ms for the duration of one tick.
        while waited < 100_000 {
            stall(5_000);
            waited += 5_000;
            if let Some(k) = read_key() {
                match k.scan_code {
                    SCAN_UP => {
                        selected = if selected == 0 { MENU.len() - 1 } else { selected - 1 };
                    }
                    SCAN_DOWN => {
                        selected = (selected + 1) % MENU.len();
                    }
                    SCAN_ESC => return MENU.len() - 1,
                    SCAN_NULL => {
                        if let Some(sel) = handle_char(k.unicode_char, &mut selected) {
                            return sel;
                        }
                    }
                    _ => {}
                }
                draw_menu(gfx, selected, None);
                return menu_interactive(gfx, selected);
            }
        }
        ticks -= 1;
        if ticks % 10 == 0 {
            draw_menu(gfx, selected, Some(ticks / 10));
        }
    }
    selected
}

// ===========================================================================
// ELF64 loader
// ===========================================================================

#[repr(C)]
struct Elf64Ehdr {
    ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    _rest: [u8; 6],
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;

#[cfg(target_arch = "x86_64")]
const ELF_MACHINE: u16 = 62;
#[cfg(target_arch = "aarch64")]
const ELF_MACHINE: u16 = 183;
#[cfg(target_arch = "riscv64")]
const ELF_MACHINE: u16 = 243;
#[cfg(target_arch = "loongarch64")]
const ELF_MACHINE: u16 = 258;

/// Copy every PT_LOAD segment of `elf` to its physical address (p_paddr),
/// zero-filling BSS.  Returns the entry point.
unsafe fn load_elf(elf: &[u8]) -> Result<u64, usize> {
    if elf.len() < size_of::<Elf64Ehdr>() || &elf[..7] != b"\x7fELF\x02\x01\x01" {
        return Err(EFI_LOAD_ERROR);
    }
    let eh = core::ptr::read_unaligned(elf.as_ptr().cast::<Elf64Ehdr>());
    if eh.e_type != ET_EXEC || eh.e_machine != ELF_MACHINE {
        return Err(EFI_UNSUPPORTED);
    }

    let phdr_off = eh.e_phoff as usize;
    let phnum = eh.e_phnum as usize;
    let phentsize = eh.e_phentsize as usize;
    if phentsize != size_of::<Elf64Phdr>()
        || elf.len().saturating_sub(phdr_off) < phnum * phentsize
    {
        return Err(EFI_LOAD_ERROR);
    }

    let segments = || {
        (0..phnum)
            .map(|index| {
                core::ptr::read_unaligned(
                    elf.as_ptr().add(phdr_off + index * phentsize).cast::<Elf64Phdr>(),
                )
            })
            .filter(|p| p.p_type == PT_LOAD && p.p_memsz != 0)
    };
    const PAGE_SIZE: u64 = 4096;
    let mut start = u64::MAX;
    let mut end = 0;
    let mut entry_loaded = false;
    for p in segments() {
        if p.p_filesz > p.p_memsz
            || p.p_offset.checked_add(p.p_filesz).is_none_or(|end| end > elf.len() as u64)
            || p.p_paddr < PAGE_SIZE
        {
            return Err(EFI_LOAD_ERROR);
        }
        let segment_end = p.p_paddr.checked_add(p.p_memsz).ok_or(EFI_LOAD_ERROR)?;
        start = start.min(p.p_paddr & !(PAGE_SIZE - 1));
        end = end.max(segment_end);
        entry_loaded |= p.p_flags & 1 != 0 && (p.p_paddr..segment_end).contains(&eh.e_entry);
    }
    if !entry_loaded {
        return Err(EFI_LOAD_ERROR);
    }
    let pages = (end - start).div_ceil(PAGE_SIZE) as usize;
    let mut addr = start as usize;
    let allocate: extern "efiapi" fn(usize, usize, usize, *mut usize) -> usize =
        bs_call(SLOT_ALLOCATE_PAGES);
    let rc = allocate(ALLOCATE_ADDRESS, MEM_TYPE_LOADER_DATA, pages, &mut addr);
    if rc != EFI_SUCCESS {
        return Err(rc);
    }

    for p in segments() {
        let dst = p.p_paddr as *mut u8;
        let filesz = p.p_filesz as usize;
        core::ptr::copy_nonoverlapping(elf.as_ptr().add(p.p_offset as usize), dst, filesz);
        if p.p_memsz > p.p_filesz {
            core::ptr::write_bytes(dst.add(filesz), 0, (p.p_memsz - p.p_filesz) as usize);
        }
    }
    Ok(eh.e_entry)
}

// ===========================================================================
// File access
// ===========================================================================

fn ascii_to_utf16(s: &str, out_buf: &mut [u16]) -> usize {
    let mut n = 0usize;
    for b in s.bytes() {
        if n + 1 >= out_buf.len() {
            break;
        }
        out_buf[n] = b as u16;
        n += 1;
    }
    out_buf[n] = 0;
    n
}

fn handle_protocol(handle: EfiHandle, guid: &EfiGuid) -> Option<*mut u8> {
    let hp: extern "efiapi" fn(EfiHandle, *const u64, *mut *mut u8) -> usize = bs_call(SLOT_HANDLE_PROTOCOL);
    let mut iface: *mut u8 = core::ptr::null_mut();
    // The spec signature takes EFI_GUID*; pack the struct by reference.
    let rc = hp(handle, guid as *const EfiGuid as *const u64, &mut iface);
    if rc == EFI_SUCCESS && !iface.is_null() {
        Some(iface)
    } else {
        None
    }
}

fn locate_handles(guid: &EfiGuid) -> Option<&'static [EfiHandle]> {
    let lhb: extern "efiapi" fn(
        usize,
        *const u64,
        *const u8,
        *mut usize,
        *mut *mut EfiHandle,
    ) -> usize = bs_call(SLOT_LOCATE_HANDLE_BUFFER);
    let mut n = 0usize;
    let mut hs: *mut EfiHandle = core::ptr::null_mut();
    let rc = lhb(BY_PROTOCOL, guid as *const EfiGuid as *const u64, core::ptr::null(), &mut n, &mut hs);
    if rc != EFI_SUCCESS {
        set_color(ATTR_YELLOW);
        out("  LocateHandleBuffer rc=");
        out_hex(rc);
        outln("");
        set_color(ATTR_DEFAULT);
    }
    if rc == EFI_SUCCESS && n > 0 && !hs.is_null() {
        Some(unsafe { core::slice::from_raw_parts(hs, n) })
    } else {
        None
    }
}

fn open_boot_volume() -> Option<&'static SimpleFileSystemProtocol> {
    let handles = match locate_handles(&SIMPLE_FS_GUID) {
        Some(h) => h,
        None => {
            set_color(ATTR_YELLOW);
            outln("  LocateHandleBuffer(BY_PROTOCOL, SFS) returned no handles");
            set_color(ATTR_DEFAULT);
            return None;
        }
    };
    out("  SFS volumes: ");
    let mut nb = [0u8; 8];
    out(utoa(handles.len(), &mut nb));
    outln("");
    // OVMF may expose several SimpleFileSystem volumes (the El Torito FAT
    // image, the ISO9660 track, ...).  Pick the first one that can actually
    // open \boot\9kernel.elf.
    for &h in handles {
        if let Some(iface) = handle_protocol(h, &SIMPLE_FS_GUID) {
            let fs = unsafe { &*(iface as *const SimpleFileSystemProtocol) };
            let rc = read_probe(fs, "\\boot\\9kernel.elf");
            if rc == EFI_SUCCESS {
                return Some(fs);
            }
        }
    }
    set_color(ATTR_YELLOW);
    outln("  no SFS volume contains \\boot\\9kernel.elf");
    set_color(ATTR_DEFAULT);
    None
}

/// Cheap existence probe: open the path, close it immediately.
/// Returns the Open() status code (EFI_SUCCESS on success).
fn read_probe(fs: &SimpleFileSystemProtocol, path: &str) -> usize {
    let mut wpath = [0u16; 128];
    ascii_to_utf16(path, &mut wpath);
    let mut root: *mut FileProto = core::ptr::null_mut();
    if (fs.open_volume)(fs as *const SimpleFileSystemProtocol, &mut root) != EFI_SUCCESS {
        return EFI_LOAD_ERROR;
    }
    let root = unsafe { &mut *root };
    let mut file: *mut FileProto = core::ptr::null_mut();
    let rc = (root.open)(
        root as *const FileProto,
        &mut file,
        wpath.as_ptr(),
        EFI_FILE_MODE_READ,
        0,
    );
    if rc == EFI_SUCCESS {
        let f = unsafe { &mut *file };
        (f.close)(f as *mut FileProto);
    }
    rc
}

/// Read a whole file from the boot volume into fresh loader-data pages.
fn read_file(fs: &SimpleFileSystemProtocol, path: &str) -> Result<&'static mut [u8], usize> {
    let mut wpath = [0u16; 128];
    ascii_to_utf16(path, &mut wpath);

    let mut root: *mut FileProto = core::ptr::null_mut();
    let rc = (fs.open_volume)(fs as *const SimpleFileSystemProtocol, &mut root);
    if rc != EFI_SUCCESS {
        return Err(rc);
    }
    let root = unsafe { &mut *root };

    let mut file: *mut FileProto = core::ptr::null_mut();
    let rc = (root.open)(
        root as *const FileProto,
        &mut file,
        wpath.as_ptr(),
        EFI_FILE_MODE_READ,
        0,
    );
    (root.close)(root as *const FileProto);
    if rc != EFI_SUCCESS {
        return Err(EFI_NOT_FOUND);
    }
    let file = unsafe { &mut *file };

    let mut info_buf = [0u8; 256];
    let mut info_size = info_buf.len();
    let rc = (file.get_info)(
        file as *const FileProto,
        &FILE_INFO_GUID as *const EfiGuid,
        &mut info_size,
        info_buf.as_mut_ptr(),
    );
    if rc != EFI_SUCCESS {
        (file.close)(file as *const FileProto);
        return Err(rc);
    }
    // EFI_FILE_INFO: u64 Size, u64 FileSize, ...
    let file_size = unsafe { core::ptr::read_unaligned(info_buf.as_ptr().add(8) as *const u64) } as usize;
    if file_size == 0 || file_size > 64 * 1024 * 1024 {
        (file.close)(file as *const FileProto);
        return Err(EFI_LOAD_ERROR);
    }

    let pages = (file_size + 0xFFF) / 0x1000;
    let mut buf: usize = 0;
    let alloc_pages: extern "efiapi" fn(usize, usize, usize, *mut usize) -> usize =
        bs_call(SLOT_ALLOCATE_PAGES);
    let rc = alloc_pages(ALLOCATE_ANY_PAGES, MEM_TYPE_LOADER_DATA, pages, &mut buf);
    if rc != EFI_SUCCESS {
        (file.close)(file as *const FileProto);
        return Err(rc);
    }

    let mut got = file_size;
    let rc = (file.read)(file as *const FileProto, &mut got, buf as *mut u8);
    let ok = rc == EFI_SUCCESS && got == file_size;
    (file.close)(file as *const FileProto);
    if !ok {
        return Err(EFI_LOAD_ERROR);
    }
    Ok(unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, file_size) })
}

// ===========================================================================
// Multiboot2 info construction
// ===========================================================================

const MB2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

struct TagWriter {
    buf: *mut u8,
    len: usize,
    cap: usize,
}

impl TagWriter {
    unsafe fn w32(&mut self, v: u32) {
        if self.len + 4 <= self.cap {
            core::ptr::write_unaligned(self.buf.add(self.len) as *mut u32, v);
        }
        self.len += 4;
    }
    unsafe fn w64(&mut self, v: u64) {
        if self.len + 8 <= self.cap {
            core::ptr::write_unaligned(self.buf.add(self.len) as *mut u64, v);
        }
        self.len += 8;
    }
    unsafe fn bytes(&mut self, b: &[u8]) {
        for &c in b {
            if self.len < self.cap {
                core::ptr::write(self.buf.add(self.len), c);
            }
            self.len += 1;
        }
    }
    unsafe fn align8(&mut self) {
        while self.len % 8 != 0 {
            self.len += 1;
        }
    }
}

/// Build the Multiboot2 info block: BOOT_LOADER_NAME, BASIC_MEMINFO,
/// MEMMAP (the EFI memory map), FRAMEBUFFER and MODULE tags.
unsafe fn build_mb2_info(
    scratch: *mut u8,
    cap: usize,
    memmap: &[EfiMemoryDescriptor],
    fb: Option<LinearFramebuffer>,
    modules: &[(u64, u64, &str)],
) -> u64 {
    let mut w = TagWriter { buf: scratch, len: 8, cap };
    core::ptr::write_bytes(scratch, 0, 8);

    // BOOT_LOADER_NAME (type 2)
    let name = b"Plan9RustUEFI\0";
    w.w32(2);
    w.w32((8 + name.len()) as u32);
    w.bytes(name);
    w.align8();

    // BASIC_MEMINFO (type 4) — placeholder values, MEMMAP is authoritative.
    w.w32(4);
    w.w32(16);
    w.w32(639);
    w.w32(0x3FFF);
    w.align8();

    // MEMMAP (type 6)
    // The kernel's MmapEntry is MB1-style: [size u32][pad u32][addr u64]
    // [len u64][type u32][pad u32] (32 bytes with alignment), entries
    // starting immediately after the 8-byte tag header.
    let tag_start = w.len;
    w.w32(6);
    // After w32(type), w.len points at the tag's size field.
    let size_pos = w.len;
    w.w32(0);
    for e in memmap {
        w.w32(24); // entry size (MB1 convention, includes this field)
        w.w32(0);  // alignment pad
        w.w64(e.phys_start);
        w.w64(e.pages * 4096);
        w.w32(e.kind);
        w.w32(0);
    }
    // Tag size = bytes from tag_start to here (w.len is block-relative).
    core::ptr::write_unaligned(scratch.add(size_pos) as *mut u32, (w.len - tag_start) as u32);
    w.align8();

    // FRAMEBUFFER (type 8)
    // Kernel's FramebufferInfo: [addr u64][pitch u32][width u32][height u32]
    // [bpp u8][fb_type u8][reserved u16] = 24 bytes after the tag header.
    if let Some(fb) = fb {
        w.w32(8);
        w.w32(38);
        w.w64(fb.address);
        w.w32(fb.pitch);
        w.w32(fb.width);
        w.w32(fb.height);
        w.bytes(&[32, 1, 0, 0]);
        w.bytes(&[fb.red_position, 8, 8, 8, 16 - fb.red_position, 8]);
        w.align8();
    }

    // MODULE (type 3)
    for (s, e, name) in modules {
        let tag_start = w.len;
        w.w32(3);
        // After w32(type), w.len points at the tag's size field.
        let sz_pos = w.len;
        w.w32(0);
        w.w32(*s as u32);
        w.w32(*e as u32);
        let mut nb = [0u8; 64];
        let nbts = name.as_bytes();
        let n = nbts.len().min(63);
        nb[..n].copy_from_slice(&nbts[..n]);
        nb[n] = 0;
        w.bytes(&nb[..n + 1]);
        core::ptr::write_unaligned(
            scratch.add(sz_pos) as *mut u32,
            (w.len - tag_start) as u32,
        );
        w.align8();
    }

    // END (type 0)
    w.w32(0);
    w.w32(8);
    w.align8();

    core::ptr::write_unaligned(scratch as *mut u32, w.len as u32);
    core::ptr::write_unaligned(scratch.add(4) as *mut u32, 0);
    scratch as u64
}

// ===========================================================================
// Memory map + ExitBootServices
// ===========================================================================

/// AllocatePool slot helper.
fn allocate_pool(kind: usize, size: usize) -> Result<usize, usize> {
    let ap: extern "efiapi" fn(usize, usize, *mut *mut u8) -> usize = bs_call(SLOT_ALLOCATE_POOL);
    let mut p: *mut u8 = core::ptr::null_mut();
    let rc = ap(kind, size, &mut p);
    if rc == EFI_SUCCESS {
        Ok(p as usize)
    } else {
        Err(rc)
    }
}

/// GetMemoryMap with retry; returns (key, entries) with the entries
/// borrowed from a BootServicesData pool allocation.
unsafe fn get_memmap() -> Result<(usize, &'static [EfiMemoryDescriptor]), usize> {
    let gmm: extern "efiapi" fn(
        *mut usize,
        *mut EfiMemoryDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> usize = bs_call(SLOT_GET_MEMORY_MAP);

    let mut size = 0usize;
    let mut key = 0usize;
    let mut dsize = 0usize;
    let mut dver = 0u32;
    // Learn the needed size.
    let _ = gmm(&mut size, core::ptr::null_mut(), &mut key, &mut dsize, &mut dver);
    let mut buf = allocate_pool(MEM_TYPE_BOOT_SERVICES_DATA, size + 4096)?;

    loop {
        let mut sz = size + 4096;
        let rc = gmm(
            &mut sz,
            buf as *mut EfiMemoryDescriptor,
            &mut key,
            &mut dsize,
            &mut dver,
        );
        if rc == EFI_SUCCESS && dsize > 0 {
            let n = sz / dsize;
            // The firmware may report a descriptor stride (DescriptorSize)
            // larger than sizeof(EfiMemoryDescriptor) — this OVMF build
            // reports 48 instead of 40.  Compact the descriptors in place
            // (forward copy is safe: 40 < stride, dst always trails src).
            // NOTE: no AllocatePool or console output may happen after
            // GetMemoryMap — either can change the memory map and make
            // the returned key stale, so ExitBootServices fails with
            // EFI_INVALID_PARAMETER.
            let src = buf as *const u8;
            let dst = buf as *mut u8;
            for i in 0..n {
                core::ptr::copy(
                    src.add(i * dsize),
                    dst.add(i * core::mem::size_of::<EfiMemoryDescriptor>()),
                    core::mem::size_of::<EfiMemoryDescriptor>(),
                );
            }
            return Ok((key, core::slice::from_raw_parts(buf as *const EfiMemoryDescriptor, n)));
        }
        if rc == EFI_BUFFER_TOO_SMALL || rc == EFI_INVALID_PARAMETER {
            size = sz + 4096;
            buf = allocate_pool(MEM_TYPE_BOOT_SERVICES_DATA, size)?;
            continue;
        }
        return Err(rc);
    }
}

// ===========================================================================
// Arch hand-off
// ===========================================================================

/// x86_64: the kernel's `_start64` runs in long mode with our firmware
/// page tables still active (the kernel installs its own early PML4 before
/// touching anything else).  RAX = MB2 magic, RBX = info pointer.
#[cfg(target_arch = "x86_64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    // Zero the IDT: after ExitBootServices a stray firmware interrupt must
    // not vector into firmware code (the kernel installs its own IDT).
    let idtr: [u16; 5] = [0; 5];
    asm!("cli", "lidt [{idt}]", idt = in(reg) idtr.as_ptr(), options(nostack));
    // Mask the legacy PICs.
    asm!("out 0x21, al", in("al") 0xFFu8, options(nostack, nomem));
    asm!("out 0xA1, al", in("al") 0xFFu8, options(nostack, nomem));
    asm!(
        "mov rbx, rdx",
        "jmp rcx",
        in("rax") MB2_BOOTLOADER_MAGIC as u64,
        in("rdx") mb2_info,
        in("rcx") kernel_entry,
        options(noreturn)
    );
}

/// aarch64: disable the MMU + caches, then branch with x0=magic, x1=info.
#[cfg(target_arch = "aarch64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    // Pass the Multiboot2 magic in x0 and the info pointer in x1 — the
    // kernel's boot.S forwards them to kstart().  A plain `-kernel` boot
    // (no loader) puts the DTB pointer in x0 instead, which fails the
    // magic check and sends the kernel down its non-bootinfo bring-up
    // path, so both entry paths stay compatible.
    asm!(
        "msr daifset, #0xf",
        "dsb sy",
        "ic iallu",
        "dsb sy",
        "isb",
        "msr sctlr_el1, xzr",
        "dsb sy",
        "isb",
        "br x2",
        in("x0") MB2_BOOTLOADER_MAGIC as u64,
        in("x1") mb2_info,
        in("x2") kernel_entry,
        options(noreturn)
    );
}

/// riscv64: bare MMU mode + jump with a0=magic, a1=info (the kernel's
/// boot.S forwards them to kstart; an OpenSBI boot puts the hart id in
/// a0 instead, which fails the magic check and selects the fallback
/// bring-up path, so both entry paths stay compatible).
#[cfg(target_arch = "riscv64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    asm!(
        "sfence.vma",
        "csrw satp, zero",
        "sfence.vma",
        "jr a2",
        in("a0") MB2_BOOTLOADER_MAGIC as u64,
        in("a1") mb2_info,
        in("a2") kernel_entry,
        options(noreturn)
    );
}

/// loongarch64: back to direct address translation (CRMD.DA=1, PG=0), then
/// jump — the kernel's boot.S re-installs its DMW windows itself.  The
/// Multiboot2 magic goes in $a0 and the info pointer in $a1; the kernel's
/// boot.S forwards them to kstart().
#[cfg(target_arch = "loongarch64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    asm!(
        "li.d $t0, 0xb0",
        "csrwr $t0, 0x0",
        "dbar 0",
        "ibar 0",
        "jr $a2",
        in("$a0") MB2_BOOTLOADER_MAGIC as u64,
        in("$a1") mb2_info,
        in("$a2") kernel_entry,
        options(noreturn)
    );
}

// ===========================================================================
// Entry point
// ===========================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *const SystemTable) -> usize {
    // Bare-metal `none` targets have no Rust-provided entry glue, so the
    // firmware jumps to `_start` (see the per-arch stubs below) which then
    // calls this function with the UEFI arguments in the arch's registers.
    efi_main_impl(image_handle, system_table)
}

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    .type _start, @function
_start:
    /* Set up the loader's own stack (from the linker script, in .bss). */
    la      sp, _bootstack_top
    /* UEFI passes ImageHandle in a0 and the SystemTable pointer in a1.
     * efi_main(image_handle, system_table) -> status. */
    call    efi_main
    /* The loader never returns to the firmware; park if it does. */
1:  wfi
    j       1b
    .size _start, . - _start
"#
);

#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    .type _start, @function
_start:
    /* Set up the loader's own stack (from the linker script, in .bss). */
    la.pcrel $sp, _bootstack_top
    /* UEFI passes ImageHandle in a0 and the SystemTable pointer in a1.
     * efi_main(image_handle, system_table) -> status. */
    bl      efi_main
    /* The loader never returns to the firmware; park if it does. */
1:  idle 0
    b       1b
    .size _start, . - _start
"#
);

#[inline(never)]
fn efi_main_impl(image_handle: EfiHandle, system_table: *const SystemTable) -> usize {
    unsafe {
        ST_PTR = system_table;
    }

    clear_screen();
    set_color(ATTR_GREEN);
    outln("  Plan 9 from Outer Space");
    set_color(ATTR_DEFAULT);
    outln("  Rust UEFI Boot Loader (GRUB-free)\n");

    let gfx = gfx_init();

    let fs = match open_boot_volume() {
        Some(f) => f,
        None => {
            set_color(ATTR_YELLOW);
            outln("!! No SimpleFileSystem volume found.");
            set_color(ATTR_DEFAULT);
            outln("Press any key to return to firmware.");
            let _ = wait_key();
            return EFI_NOT_FOUND;
        }
    };

    // ---- Menu ------------------------------------------------------------
    if gfx.is_some() {
        outln("bootloader: GOP menu");
    }
    let choice = run_menu(gfx.as_ref());
    // The graphical menu was drawn straight onto the GOP; wipe it (Blt-only
    // GOPs ignore the text console's ClearScreen) so boot messages start
    // from a clean screen.
    if let Some(gfx) = gfx.as_ref() {
        unsafe { gfill(gfx, 0, 0, gfx.w, gfx.h, C_BG_TOP) };
    }
    clear_screen();
    if choice == MENU.len() - 1 {
        outln("\nReturning to UEFI boot manager...");
        return EFI_UNSUPPORTED;
    }
    out("bootloader: selected ");
    outln(MENU[choice].title);

    // ---- Load kernel -----------------------------------------------------
    out("Loading \\boot\\9kernel.elf ... ");
    let kernel_elf = match read_file(fs, "\\boot\\9kernel.elf") {
        Ok(b) => b,
        Err(e) => {
            outln("FAILED");
            out("  error: ");
            out_hex(e);
            outln("");
            outln("Press any key to return to firmware.");
            let _ = wait_key();
            return e;
        }
    };
    outln("ok");

    if kernel_elf.len() < 20 || &kernel_elf[..4] != b"\x7fELF" {
        outln("!! boot\\9kernel.elf is not an ELF image.");
        let _ = wait_key();
        return EFI_LOAD_ERROR;
    }
    let em = unsafe { core::ptr::read_unaligned(kernel_elf.as_ptr().add(18) as *const u16) };
    if em != ELF_MACHINE {
        out("!! kernel ELF machine mismatch: got ");
        let mut nb = [0u8; 8];
        out(utoa(em as usize, &mut nb));
        out(", want ");
        out(utoa(ELF_MACHINE as usize, &mut nb));
        outln("");
        outln("This ISO was built for a different architecture.");
        let _ = wait_key();
        return EFI_UNSUPPORTED;
    }

    let entry = match unsafe { load_elf(kernel_elf) } {
        Ok(v) => v,
        Err(e) => {
            out("!! ELF load failed: ");
            out_hex(e);
            outln("");
            let _ = wait_key();
            return e;
        }
    };

    // ---- Modules (init + rootfs.cpio as MB2 MODULE tags) ---------------
    // x86_64 passes them through Multiboot2 from GRUB/OVMF; every other
    // arch gets the same MB2 module tags from this loader (the kernel's
    // init_loader consumes them on the bootinfo path).
    let mut mods: [(u64, u64, &'static str); 4] = [(0, 0, ""); 4];
    let mut nmods = 0usize;

    {
        for (path, name) in [("\\boot\\init", "init"), ("\\boot\\rootfs.cpio", "rootfs.cpio")] {
            match read_file(fs, path) {
                Ok(data) => {
                    let start = data.as_ptr() as u64;
                    let end = start + data.len() as u64;
                    mods[nmods] = (start, end, name);
                    nmods += 1;
                    let mut nb = [0u8; 24];
                    out("Loaded ");
                    out(path);
                    out(" (");
                    out(utoa(data.len(), &mut nb));
                    outln(" bytes)");
                }
                Err(_) => {
                    out("warning: ");
                    out(path);
                    outln(" not found on boot volume");
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (&mut mods, &mut nmods);
    }

    let framebuffer = gfx.and_then(|gfx| gfx.framebuffer);
    if framebuffer.is_some() {
        outln("bootloader: GOP linear framebuffer found");
    }

    // ---- Final memory map → MB2 info → ExitBootServices → jump -----------
    unsafe {
        // All boot-services allocations MUST happen before the final
        // GetMemoryMap, otherwise the returned map key goes stale and
        // ExitBootServices fails with EFI_INVALID_PARAMETER.
        let mut mb2_page: usize = 0;
        let alloc_pages: extern "efiapi" fn(usize, usize, usize, *mut usize) -> usize =
            bs_call(SLOT_ALLOCATE_PAGES);
        let rc = alloc_pages(ALLOCATE_ANY_PAGES, MEM_TYPE_BOOT_SERVICES_DATA, 8, &mut mb2_page);
        if rc != EFI_SUCCESS {
            outln("!! allocate_pages(MB2) failed.");
            let _ = wait_key();
            return rc;
        }

        let (_, mmap) = match get_memmap() {
            Ok(v) => v,
            Err(e) => {
                outln("!! GetMemoryMap failed.");
                let _ = wait_key();
                return e;
            }
        };

        let info = build_mb2_info(
            mb2_page as *mut u8,
            8 * 4096,
            mmap,
            framebuffer,
            &mods[..nmods],
        );

        // Re-fetch the memory map QUIETLY right before ExitBootServices:
        // console output can change the memory map and invalidate the
        // earlier key.  There must be zero console output between this
        // GetMemoryMap and the ExitBootServices call.
        let (key, _) = match get_memmap() {
            Ok(v) => v,
            Err(e) => {
                outln("!! GetMemoryMap (fresh) failed.");
                let _ = wait_key();
                return e;
            }
        };

        let ebs: extern "efiapi" fn(EfiHandle, usize) -> usize = bs_call(SLOT_EXIT_BOOT_SERVICES);
        let mut rc = ebs(image_handle, key);
        if rc != EFI_SUCCESS {
            // The map may have grown; retry exactly once per spec.
            // Keep zero console output between the fresh GetMemoryMap and
            // the retry ExitBootServices call.
            let (key2, _) = match get_memmap() {
                Ok(v) => v,
                Err(e2) => return e2,
            };
            rc = ebs(image_handle, key2);
            if rc != EFI_SUCCESS {
                return rc;
            }
        }

        handoff(entry, info);
    }
}

#[panic_handler]
fn ph(_info: &core::panic::PanicInfo) -> ! {
    out("\r\n[uefiboot] PANIC\r\n");
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { asm!("hlt", options(nostack, preserves_flags)) };
        #[cfg(not(target_arch = "x86_64"))]
        loop {}
    }
}

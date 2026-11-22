//! Modern PCI VirtIO Ethernet with polled split virtqueues.

use core::{ptr, sync::atomic::{fence, Ordering}};
use plan9_common::{error::{Error, Result}, types::PhysAddr};

use crate::pci::{pci_config_read, pci_config_write, PciConfigAddr};

const SLOTS: usize = 8;
const AVAIL: u64 = 128;
const USED: u64 = 152;
const HEADER: usize = 12;
const BUFFER: usize = 2048;
const MAC: u32 = 1 << 5;
const QUEUE_PAGES: usize = 1 + SLOTS / 2;
pub const DMA_PAGES: usize = 2 * QUEUE_PAGES;

struct Region {
    base: u64,
    length: u32,
}

fn regions(config: impl Fn(u8) -> u32, map: impl Fn(u64, u32) -> Option<u64>) -> Option<(Region, Region, u32, Region)> {
    if config(4) & (1 << 20) == 0 {
        return None;
    }
    let mut offset = config(0x34) as u8 & !3;
    let (mut common, mut notify, mut device) = (None, None, None);
    for _ in 0..48 {
        if !(0x40..=0xfc).contains(&offset) {
            break;
        }
        let [id, next, length, kind] = config(offset).to_le_bytes();
        if id == 9 && length >= 16 && u16::from(offset) + u16::from(length) <= 256 {
            let bar_index = config(offset + 4) as u8;
            if bar_index < 6 {
                let bar_offset = 0x10 + 4 * bar_index;
                let low = config(bar_offset);
                let high = match low & 7 {
                    0 => Some(0),
                    4 if bar_index < 5 => Some(u64::from(config(bar_offset + 4)) << 32),
                    _ => None,
                };
                if let Some(high) = high {
                    let bar = high | u64::from(low & !15);
                    let length_bytes = config(offset + 12);
                    let base = bar.checked_add(u64::from(config(offset + 8)))?;
                    base.checked_add(u64::from(length_bytes))?;
                    if bar != 0 && low != u32::MAX && matches!(kind, 1 | 2 | 4) {
                        let region = Region { base: map(base, length_bytes)?, length: length_bytes };
                        match kind {
                            1 if length_bytes >= 56 && base % 8 == 0 => common = Some(region),
                            2 if length >= 20 => notify = Some((region, config(offset + 16))),
                            4 if length_bytes >= 6 => device = Some(region),
                            _ => {}
                        }
                    }
                }
            }
        }
        offset = next & !3;
    }
    let (notify, stride) = notify?;
    Some((common?, notify, stride, device?))
}

fn read16(address: u64) -> u16 {
    u16::from_le(unsafe { ptr::read_volatile(address as *const u16) })
}

fn read32(address: u64) -> u32 {
    u32::from_le(unsafe { ptr::read_volatile(address as *const u32) })
}

fn write16(address: u64, value: u16) {
    unsafe { ptr::write_volatile(address as *mut u16, value.to_le()) }
}

fn write32(address: u64, value: u32) {
    unsafe { ptr::write_volatile(address as *mut u32, value.to_le()) }
}

fn write64(address: u64, value: u64) {
    write32(address, value as u32);
    write32(address + 4, (value >> 32) as u32);
}

struct Queue {
    ring: u64,
    buffers: [u64; SLOTS],
    notify: u64,
    index: u16,
    avail: u16,
    used: u16,
}

impl Queue {
    fn configure(common: u64, notify: &Region, stride: u32, index: u16, pages: &[PhysAddr]) -> Option<Self> {
        write16(common + 22, index);
        if usize::from(read16(common + 24)) < SLOTS || read16(common + 28) != 0 {
            return None;
        }
        let delta = u64::from(read16(common + 30)) * u64::from(stride);
        let notify_address = notify.base.checked_add(delta)?;
        if delta + 2 > u64::from(notify.length) || notify_address % 2 != 0 {
            return None;
        }
        let ring = pages[0].as_u64();
        let buffers = core::array::from_fn(|slot| pages[1 + slot / 2].as_u64() + (slot % 2 * BUFFER) as u64);
        write16(ring + AVAIL, 1);
        write16(common + 24, SLOTS as u16);
        write16(common + 26, u16::MAX);
        write64(common + 32, ring);
        write64(common + 40, ring + AVAIL);
        write64(common + 48, ring + USED);
        write16(common + 28, 1);
        Some(Self { ring, buffers, notify: notify_address, index, avail: 0, used: 0 })
    }

    fn enqueue(&mut self, slot: usize, length: usize, writable: bool) {
        let descriptor = self.ring + (slot * 16) as u64;
        write64(descriptor, self.buffers[slot]);
        write32(descriptor + 8, length as u32);
        write16(descriptor + 12, if writable { 2 } else { 0 });
        write16(self.ring + AVAIL + 4 + 2 * (u64::from(self.avail) % SLOTS as u64), slot as u16);
        self.avail = self.avail.wrapping_add(1);
        fence(Ordering::SeqCst);
        write16(self.ring + AVAIL + 2, self.avail);
    }

    fn kick(&self) {
        fence(Ordering::SeqCst);
        write16(self.notify, self.index);
    }

    fn complete(&mut self) -> Option<(usize, usize)> {
        if self.used == read16(self.ring + USED + 2) {
            return None;
        }
        fence(Ordering::SeqCst);
        let entry = self.ring + USED + 4 + 8 * (u64::from(self.used) % SLOTS as u64);
        self.used = self.used.wrapping_add(1);
        Some((read32(entry) as usize, read32(entry + 4) as usize))
    }
}

pub struct VirtioNet {
    mac: [u8; 6],
    rx: Queue,
    tx: Queue,
    tx_free: u8,
}

impl VirtioNet {
    /// # Safety
    /// `pages` must be zeroed, identity-mapped DMA frames owned by this device.
    /// The PCI function must be an exclusively owned VirtIO network controller.
    pub unsafe fn attach(bus: u8, slot: u8, function: u8, pages: [PhysAddr; DMA_PAGES], map: impl Fn(u64, u32) -> Option<u64>) -> Option<Self> {
        let address = |offset| PciConfigAddr::new(bus, slot, function, offset);
        let config = |offset| pci_config_read(address(offset));
        let (common, notify, stride, device) = regions(config, map)?;
        let command = config(4) & 0xffff;
        pci_config_write(address(4), (command | 0x402) & !4);
        let status = (common.base + 20) as *mut u8;
        let result = (|| unsafe {
            status.write_volatile(0);
            for _ in 0..1000 {
                if status.read_volatile() == 0 { break; }
                core::hint::spin_loop();
            }
            if status.read_volatile() != 0 { return None; }
            status.write_volatile(1);
            status.write_volatile(3);
            write32(common.base, 1);
            if read32(common.base + 4) & 1 == 0 { return None; }
            write32(common.base, 0);
            if read32(common.base + 4) & MAC == 0 { return None; }
            write32(common.base + 8, 0);
            write32(common.base + 12, MAC);
            write32(common.base + 8, 1);
            write32(common.base + 12, 1);
            status.write_volatile(11);
            if status.read_volatile() & 8 == 0 { return None; }
            let mut rx = Queue::configure(common.base, &notify, stride, 0, &pages[..QUEUE_PAGES])?;
            let tx = Queue::configure(common.base, &notify, stride, 1, &pages[QUEUE_PAGES..])?;
            let mac = core::array::from_fn(|index| ((device.base + index as u64) as *const u8).read_volatile());
            if mac == [0; 6] || mac[0] & 1 != 0 { return None; }
            for slot in 0..SLOTS {
                rx.enqueue(slot, BUFFER, true);
            }
            pci_config_write(address(4), command | 0x406);
            fence(Ordering::SeqCst);
            status.write_volatile(15);
            rx.kick();
            Some(Self { mac, rx, tx, tx_free: u8::MAX })
        })();
        if result.is_none() {
            unsafe { status.write_volatile(0) };
            pci_config_write(address(4), command & !4);
        }
        result
    }

    pub fn mac_address(&self) -> [u8; 6] { self.mac }

    pub fn tx_ready(&mut self) -> bool {
        for _ in 0..SLOTS {
            let Some((slot, _)) = self.tx.complete() else { break; };
            if slot < SLOTS { self.tx_free |= 1 << slot; }
        }
        self.tx_free != 0
    }

    pub fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() < 14 || frame.len() > 1514 { return Err(Error::Einval); }
        if !self.tx_ready() { return Err(Error::Eagain); }
        let slot = self.tx_free.trailing_zeros() as usize;
        self.tx_free &= !(1 << slot);
        let target = self.tx.buffers[slot] as *mut u8;
        unsafe {
            ptr::write_bytes(target, 0, HEADER);
            ptr::copy_nonoverlapping(frame.as_ptr(), target.add(HEADER), frame.len());
        }
        self.tx.enqueue(slot, HEADER + frame.len(), false);
        self.tx.kick();
        Ok(())
    }

    pub fn receive(&mut self, frame: &mut [u8]) -> Result<usize> {
        for _ in 0..SLOTS {
            let Some((slot, bytes)) = self.rx.complete() else { break; };
            if slot >= SLOTS { continue; }
            let length = bytes.saturating_sub(HEADER);
            let valid = (14..=1514).contains(&length) && length <= frame.len();
            if valid {
                let source = self.rx.buffers[slot] as *const u8;
                unsafe { ptr::copy_nonoverlapping(source.add(HEADER), frame.as_mut_ptr(), length) };
            }
            self.rx.enqueue(slot, BUFFER, true);
            self.rx.kick();
            if valid { return Ok(length); }
        }
        Ok(0)
    }
}

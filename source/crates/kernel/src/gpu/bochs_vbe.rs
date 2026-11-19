//! QEMU Bochs VBE (DISPI) driver via PCI MMIO.
//!
//! On the `q35` machine type, `-vga std` (Bochs VBE) exposes:
//!   - BAR0: framebuffer, 16 MB prefetchable
//!   - BAR2: 4 KB MMIO containing EDID + DISPI registers
//!
//! The DISPI registers are flat-mapped at `BAR2 + 0x500`. Each register
//! is a 16-bit value accessed at `(BAR2 + 0x500 + idx*2)`.
//!
//! We enumerate PCI devices to find vendor `0x1234`, device `0x1111`,
//! then map BAR2 and use it to set a 1024x768x32 linear mode.

use crate::plan9_common::types::PhysAddr;
use crate::serial;
use super::{Color, DisplayEngine, EngineKind, FramebufferInfo, PixelFormat, Rect};

/// PCI vendor/device IDs for QEMU Bochs VBE
const BOCHS_VENDOR_ID: u16 = 0x1234;
// QEMU uses several device IDs for the Bochs-styled VGA adapter:
//   * 0x1111 – classic `-vga std` model
//   * 0x1234 – bundled with q35 (`-M q35`)
//   * 0x9d10 – QXL/Cirrus... actually various
// Match any device under vendor 0x1234; fall through if class-code
// probing rejects it later (display class = 0x03).
const BOCHS_KNOWN_DEVICE_IDS: [u16; 3] = [0x1111, 0x1234, 0x9D10];

/// Bochs DISPI register indices (offset from BAR2 + 0x500)
#[allow(dead_code)]
mod dispicfg {
    pub const ID:         u16 = 0;
    pub const XRES:       u16 = 1;
    pub const YRES:       u16 = 2;
    pub const BPP:        u16 = 3;
    pub const ENABLE:     u16 = 4;
    pub const BANK:       u16 = 5;
    pub const VIRT_WIDTH: u16 = 6;
    pub const VIRT_HEIGHT: u16 = 7;
    pub const X_OFFSET:   u16 = 8;
    pub const Y_OFFSET:   u16 = 9;
}

/// DISPI_ENABLE bits
const DISPI_ENABLE_ENABLE: u16 = 1 << 0;
const DISPI_ENABLE_LFB:   u16 = 1 << 2; // linear framebuffer

/// DISPI ID — must read 0xB0C0 when VBE is active
const DISPI_ID: u16 = 0xB0C0;

/// Bochs VBE engine
pub struct BochsVbeEngine {
    info: FramebufferInfo,
    /// Mapped address of the 4 KB DISPI MMIO register block (BAR2).
    dispicfg_base: u64,
}

impl BochsVbeEngine {
    /// Probe for and initialise the QEMU Bochs VBE device.
    ///
    /// Scans all PCI buses/devices/functions for the Bochs vendor/device ID,
    /// reads BAR2, maps it, and sets 1024x768x32 linear mode.
    ///
    /// Returns `None` if no matching device is found or initialisation fails.
    pub fn new() -> Option<Self> {
        serial::put_bytes(b"[bochs] probing...\n");

        // PCI scan — enumerate all buses, devices, functions
        let (bar0, bar2) = find_bochs_device()?;
        serial::put_bytes(b"[bochs] found at BAR0=");
        serial::put_hex_u64(bar0);
        serial::put_bytes(b" BAR2=");
        serial::put_hex_u64(bar2);
        serial::put_bytes(b"\n");

        // Map the 4 KB DISPI MMIO register block
        let dispicfg_virt = unsafe { crate::vm::map_phys_range(bar2, 0x1000) };
        if dispicfg_virt.is_null() {
            serial::put_bytes(b"[bochs] failed to map BAR2\n");
            return None;
        }
        let dispicfg_base = dispicfg_virt as u64;
        serial::put_bytes(b"[bochs] DISPI MMIO at virt=");
        serial::put_hex_u64(dispicfg_base);
        serial::put_bytes(b"\n");

        // DISPI ID register returns 0xB0C0 (LFB disabled) or 0xB0C5 (LFB enabled).
        let disp_id = dispi_read(dispicfg_base, dispicfg::ID);
        serial::put_bytes(b"[bochs] DISPI ID register=0x");
        serial::put_hex_u32(disp_id as u32);
        serial::put_bytes(b"\n");
        if (disp_id & 0xFFF0) != (DISPI_ID & 0xFFF0) {
            serial::put_bytes(b"[bochs] unexpected DISPI ID, skipping\n");
            return None;
        }

        // Set 1024x768x32 linear framebuffer mode
        let width = 1024u32;
        let height = 768u32;
        let bpp = 32u16;

        dispi_write(dispicfg_base, dispicfg::XRES, width as u16);
        dispi_write(dispicfg_base, dispicfg::YRES, height as u16);
        dispi_write(dispicfg_base, dispicfg::BPP, bpp);
        dispi_write(dispicfg_base, dispicfg::VIRT_WIDTH, width as u16);
        dispi_write(dispicfg_base, dispicfg::VIRT_HEIGHT, height as u16);

        // Enable linear framebuffer mode
        dispi_write(dispicfg_base, dispicfg::ENABLE,
            DISPI_ENABLE_ENABLE | DISPI_ENABLE_LFB);

        serial::put_bytes(b"[bochs] mode set: 1024x768x32 linear\n");

        // Verify the framebuffer is readable at BAR0
        let fb_size: u64 = 16 * 1024 * 1024; // 16 MB BAR0
        let fb_virt = unsafe { crate::vm::map_phys_range(bar0, fb_size) };
        if fb_virt.is_null() {
            serial::put_bytes(b"[bochs] failed to map BAR0 framebuffer\n");
            return None;
        }

        serial::put_bytes(b"[bochs] framebuffer mapped at virt=");
        serial::put_hex_u64(fb_virt as u64);
        serial::put_bytes(b"\n");

        let info = FramebufferInfo {
            phys_addr: PhysAddr::new(bar0),
            virt_addr: fb_virt as u64,
            width,
            height,
            pitch: width * 4, // 32-bit = 4 bytes/pixel
            format: PixelFormat::BGRA8888,
            size_bytes: (width as u64) * (height as u64) * 4,
        };

        Some(Self { info, dispicfg_base })
    }
}

impl DisplayEngine for BochsVbeEngine {
    fn name(&self) -> &'static str { "Bochs VBE" }
    fn kind(&self) -> EngineKind { EngineKind::BochsVbe }
    fn info(&self) -> &FramebufferInfo { &self.info }

    fn put_pixel(&mut self, x: u32, y: u32, color: Color) {
        if !self.info.contains(x, y) {
            return;
        }
        let offset = y * self.info.pitch + x * 4;
        let ptr = (self.info.virt_addr + offset as u64) as *mut u32;
        let pixel = color_to_bgra(color);
        unsafe { core::ptr::write_volatile(ptr, pixel); }
    }

    fn fill_rect(&mut self, rect: Rect, color: Color) {
        let pixel = color_to_bgra(color);
        for dy in 0..rect.height {
            for dx in 0..rect.width {
                let px = rect.x.saturating_add(dx);
                let py = rect.y.saturating_add(dy);
                if !self.info.contains(px, py) {
                    continue;
                }
                let offset = py * self.info.pitch + px * 4;
                let ptr = (self.info.virt_addr + offset as u64) as *mut u32;
                unsafe { core::ptr::write_volatile(ptr, pixel); }
            }
        }
    }

    fn blit_bgra(&mut self, dst_x: u32, dst_y: u32, src: &[u32], src_w: u32, src_h: u32) {
        for row in 0..src_h {
            for col in 0..src_w {
                let px = dst_x.saturating_add(col);
                let py = dst_y.saturating_add(row);
                if !self.info.contains(px, py) {
                    continue;
                }
                let offset = py * self.info.pitch + px * 4;
                let ptr = (self.info.virt_addr + offset as u64) as *mut u32;
                let src_idx = row * src_w + col;
                if (src_idx as usize) < src.len() {
                    unsafe { core::ptr::write_volatile(ptr, src[src_idx as usize]); }
                }
            }
        }
    }

    fn scroll_up(&mut self, rows: u32, fill: Color) {
        if rows == 0 || rows >= self.info.height {
            return self.fill_rect(
                Rect::new(0, 0, self.info.width, self.info.height),
                fill,
            );
        }

        let copy_height = self.info.height - rows;
        let row_bytes = self.info.pitch as usize;
        let virt = self.info.virt_addr as *mut u8;

        for y in 0..copy_height {
            let src_row = (y + rows) as usize * row_bytes;
            let dst_row = y as usize * row_bytes;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    virt.add(src_row),
                    virt.add(dst_row),
                    row_bytes,
                );
            }
        }

        let fill_pixel = color_to_bgra(fill);
        for y in copy_height..self.info.height {
            for x in 0..self.info.width {
                let offset = y * self.info.pitch + x * 4;
                let ptr = (self.info.virt_addr + offset as u64) as *mut u32;
                unsafe { core::ptr::write_volatile(ptr, fill_pixel); }
            }
        }
    }

    fn flush(&mut self) {
        // No-op for MMIO framebuffer
    }
}

/// Read a 16-bit DISPI register at the given base + 0x500 + idx*2.
fn dispi_read(base: u64, idx: u16) -> u16 {
    let addr = base + 0x500 + (idx as u64) * 2;
    let ptr = addr as *const u16;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Write a 16-bit DISPI register.
fn dispi_write(base: u64, idx: u16, val: u16) {
    let addr = base + 0x500 + (idx as u64) * 2;
    let ptr = addr as *mut u16;
    unsafe { core::ptr::write_volatile(ptr, val); }
}

/// Scan PCI buses for the Bochs VBE device and return (BAR0, BAR2).
fn find_bochs_device() -> Option<(u64, u64)> {
    use crate::plan9_arch::hal::outl;
    use crate::plan9_arch::hal::inl;

    let config_addr = 0xCF8u16;
    let config_data = 0xCFCu16;

    let mut found_count: u32 = 0;
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                // PCI config-mechanism #1 address layout:
                //   bit 31:     enable
                //   bits 23-16: bus
                //   bits 15-11: device
                //   bits 10-8:  function
                //   bits 7-2:   register offset (byte address)
                //   bits 1-0:   zero
                let make_addr = |offset: u32| -> u32 {
                    0x80000000u32
                        | ((bus as u32) << 16)
                        | ((dev as u32) << 11)
                        | ((func as u32) << 8)
                        | (offset & 0xFC)
                };
                let addr = make_addr(0);
                outl(config_addr, addr);
                let vendor_raw = inl(config_data);
                let vendor = vendor_raw as u16;
                if found_count == 0 {
                    serial::put_bytes(b"[bochs] first inl from 0xCFC = ");
                    serial::put_hex_u32(vendor_raw);
                    serial::put_bytes(b" addr=");
                    serial::put_hex_u32(addr);
                    serial::put_bytes(b"\n");
                }
                if vendor == 0xFFFF {
                    continue; // empty slot
                }

                // Read device ID at offset 2
                let addr2 = make_addr(2);
                outl(config_addr, addr2);
                let device = inl(config_data) as u16;
                found_count += 1;

                serial::put_bytes(b"[bochs] PCI bus=");
                serial::put_hex_u32(bus as u32);
                serial::put_bytes(b" dev=");
                serial::put_hex_u32(dev as u32);
                serial::put_bytes(b" func=");
                serial::put_hex_u32(func as u32);
                serial::put_bytes(b" ven=");
                serial::put_hex_u32(vendor as u32);
                serial::put_bytes(b" dev=");
                serial::put_hex_u32(device as u32);
                serial::put_bytes(b"\n");

                // Bochs VBE vendor ID. Device IDs vary:
                //   0x1111 – classic Bochs VGA
                //   0x1234 – q35 bundled stdvga
                //   0x9D10 – some Cirrus/Red Hat adapters
                let is_bochs = vendor == BOCHS_VENDOR_ID
                    && BOCHS_KNOWN_DEVICE_IDS.contains(&device);

                if is_bochs {
                    serial::put_bytes(b"[bochs] PCI match bus=");
                    serial::put_hex_u32(bus as u32);
                    serial::put_bytes(b" dev=");
                    serial::put_hex_u32(dev as u32);
                    serial::put_bytes(b" func=");
                    serial::put_hex_u32(func as u32);
                    serial::put_bytes(b"\n");

                    let bar0_val = read_bar_at(&make_addr, 0x10);
                    let bar2_val = read_bar_at(&make_addr, 0x18);

                    if bar0_val != 0 && bar2_val != 0 {
                        // Strip the type/indicator flags from the lower 4 bits of
                        // each BAR so the value is the actual physical address.
                        // For 64-bit MMIO BARs, bit 3 is set; we mask it off.
                        let bar0_phys = bar0_val & !0xFu64;
                        let bar2_phys = bar2_val & !0xFu64;
                        serial::put_bytes(b"[bochs] BAR0=0x");
                        serial::put_hex_u64(bar0_phys);
                        serial::put_bytes(b" BAR2=0x");
                        serial::put_hex_u64(bar2_phys);
                        serial::put_bytes(b"\n");
                        return Some((bar0_phys, bar2_phys));
                    }
                }
            }
        }
    }

    serial::put_bytes(b"[bochs] no device found\n");
    None
}

/// Read a 32-bit BAR from PCI config space.
/// `make_addr` is a closure that takes a byte offset and returns the
/// properly-formatted PCI configuration address for this device.
fn read_bar_at(make_addr: &dyn Fn(u32) -> u32, offset: u32) -> u64 {
    use crate::plan9_arch::hal::outl;
    use crate::plan9_arch::hal::inl;

    let addr = make_addr(offset);
    outl(0xCF8, addr);
    let val = inl(0xCFC);
    val as u64
}

#[inline]
fn color_to_bgra(c: Color) -> u32 {
    (c.b as u32) | ((c.g as u32) << 8) | ((c.r as u32) << 16) | ((c.a as u32) << 24)
}

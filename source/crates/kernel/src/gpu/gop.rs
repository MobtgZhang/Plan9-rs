//! UEFI GOP / Multiboot2 framebuffer engine.
//!
//! The UEFI firmware exposes the linear framebuffer via the Multiboot2
//! FRAMEBUFFER tag (type 8), which is populated by GRUB when the `efi_gop`
//! module is loaded. GRUB translates the GOP mode information into the
//! multiboot2 format.
//!
//! We map the physical framebuffer into kernel virtual memory and expose
//! it through the `DisplayEngine` trait.

use super::{Color, DisplayEngine, EngineKind, FramebufferInfo, PixelFormat, Rect};
use crate::plan9_common::types::PhysAddr;
use crate::serial;
use crate::entry::FramebufferConfig;

/// GOP-derived framebuffer engine.
pub struct GopEngine {
    info: FramebufferInfo,
}

impl GopEngine {
    /// Attempt to create a GOP engine from multiboot2 framebuffer info.
    ///
    /// Returns `None` if the config is invalid (zero size, unknown format).
    pub fn new(fb_config: &FramebufferConfig) -> Option<Self> {
        serial::put_bytes(b"[gop] new: addr=");
        serial::put_hex_u64(fb_config.address);
        serial::put_bytes(b" ");
        serial::put_hex_u32(fb_config.width);
        serial::put_bytes(b"x");
        serial::put_hex_u32(fb_config.height);
        serial::put_bytes(b" bpp=");
        serial::put_hex_u32(fb_config.bpp as u32);
        serial::put_bytes(b"\n");

        if fb_config.width == 0 || fb_config.height == 0 {
            serial::put_bytes(b"[gop] new: zero dimensions, skipping\n");
            return None;
        }

        let format = match fb_config.bpp {
            32 => PixelFormat::BGRA8888, // GOP default is BGRA
            24 => PixelFormat::RGB888,
            16 => PixelFormat::RGB565,
            _ => PixelFormat::Unknown,
        };

        if matches!(format, PixelFormat::Unknown) {
            serial::put_bytes(b"[gop] new: unsupported bpp\n");
            return None;
        }

        let size_bytes = fb_config.pitch as u64 * fb_config.height as u64;

        // Map the physical framebuffer into kernel virtual memory.
        // SAFETY: we trust the firmware gave us a valid framebuffer range.
        let virt = unsafe {
            crate::vm::map_phys_range(fb_config.address, size_bytes)
        };

        if virt.is_null() {
            serial::put_bytes(b"[gop] new: map_phys_range failed\n");
            return None;
        }

        serial::put_bytes(b"[gop] new: mapped virt=");
        serial::put_hex_u64(virt as u64);
        serial::put_bytes(b"\n");

        let info = FramebufferInfo {
            phys_addr: PhysAddr::new(fb_config.address),
            virt_addr: virt as u64,
            width: fb_config.width,
            height: fb_config.height,
            pitch: fb_config.pitch,
            format,
            size_bytes,
        };

        Some(Self { info })
    }
}

impl DisplayEngine for GopEngine {
    fn name(&self) -> &'static str { "GOP" }
    fn kind(&self) -> EngineKind { EngineKind::Gop }
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

        // Copy rows up
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

        // Clear bottom rows
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

#[inline]
fn color_to_bgra(c: Color) -> u32 {
    (c.b as u32) | ((c.g as u32) << 8) | ((c.r as u32) << 16) | ((c.a as u32) << 24)
}

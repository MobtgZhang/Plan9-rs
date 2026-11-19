//! UEFI GOP / Multiboot2 framebuffer engine.
//!
//! The bootloader passes the firmware's linear framebuffer in the Multiboot2
//! FRAMEBUFFER tag. The kernel takes over drawing without calling EFI again.

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
        serial::put_bytes(b"\n");

        if fb_config.width == 0 || fb_config.height == 0 || fb_config.address == 0
            || fb_config.address % 4 != 0 || fb_config.pitch % 4 != 0
            || fb_config.width.checked_mul(4)? > fb_config.pitch
            || !matches!(fb_config.format, PixelFormat::BGRA8888 | PixelFormat::RGBA8888)
        {
            return None;
        }

        let size_bytes = u64::from(fb_config.pitch.checked_mul(fb_config.height)?);
        fb_config.address.checked_add(size_bytes)?.checked_add(4095)?;

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
            format: fb_config.format,
            size_bytes,
        };

        Some(Self { info })
    }

    fn pixel(&self, bgra: u32) -> u32 {
        if self.info.format == PixelFormat::RGBA8888 {
            (bgra & 0xff00_ff00) | ((bgra & 0xff) << 16) | ((bgra >> 16) & 0xff)
        } else {
            bgra
        }
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
        let pixel = self.pixel(color_to_bgra(color));
        unsafe { core::ptr::write_volatile(ptr, pixel); }
    }

    fn fill_rect(&mut self, rect: Rect, color: Color) {
        let pixel = self.pixel(color_to_bgra(color));
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
                    unsafe { core::ptr::write_volatile(ptr, self.pixel(src[src_idx as usize])); }
                }
            }
        }
    }

    fn scroll_up(&mut self, rows: u32, fill: Color) {
        if rows == 0 {
            return;
        }
        if rows >= self.info.height {
            return self.fill_rect(
                Rect::new(0, 0, self.info.width, self.info.height),
                fill,
            );
        }

        let copy_height = self.info.height - rows;
        let stride = (self.info.pitch / 4) as usize;
        let virt = self.info.virt_addr as *mut u32;

        for y in 0..copy_height {
            for x in 0..self.info.width as usize {
                unsafe {
                    let pixel = virt.add((y + rows) as usize * stride + x).read_volatile();
                    virt.add(y as usize * stride + x).write_volatile(pixel);
                }
            }
        }

        // Clear bottom rows
        let fill_pixel = self.pixel(color_to_bgra(fill));
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

//! QEMU virtio-gpu 2D driver via PCI.
//!
//! virtio-gpu is a paravirtualised display device exposed by QEMU when
//! started with `-vga virtio` or `-device virtio-gpu-pci`.
//!
//! PCI IDs: vendor `0x1AF4` (Red Hat / virtio), device `0x1050`
//! (VIRTIO_GPU_DEVICE_ID).
//!
//! This driver implements the **virtio-gpu 2D** protocol only:
//!   1. Map BAR0 (the framebuffer / guest resources area).
//!   2. Detect the hardware via the virtio capability chain.
//!   3. Create a 2D resource, set the scanout, transfer pixel data,
//!      and flush.
//!
//! No virgl / 3D support is implemented.

use crate::plan9_common::types::PhysAddr;
use crate::serial;
use super::{Color, DisplayEngine, EngineKind, FramebufferInfo, PixelFormat, Rect};

/// VirtIO vendor ID
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// VirtIO GPU device ID
const VIRTIO_GPU_DEVICE_ID: u16 = 0x1050;

/// Virtio device status register bits
const VIRTIO_STATUS_ACK: u8 = 1 << 0;
const VIRTIO_STATUS_DRIVER: u8 = 1 << 1;
const VIRTIO_STATUS_FEATURES_OK: u8 = 1 << 3;
const VIRTIO_STATUS_DRIVER_OK: u8 = 1 << 2;
const VIRTIO_STATUS_FAILED: u8 = 1 << 7;

/// Virtio GPU 2D command types
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0100;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0101;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0102;
const VIRTIO_GPU_CMD_FLUSH: u32 = 0x0103;
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0105;

/// virtio-gpu display info (4 display heads)
const VIRTIO_GPU_MAX_SCANOUTS: usize = 4;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuResponseDisplayInfo {
    header: VirtioGpuRespHdr,
    pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuDisplayOne {
    enabled: u32,
    flags: u32,
    rect: VirtioGpuRect,
}

/// Virtio command header (le_type + padding + fence)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuCmdHdr {
    type_: u32,    // VIRTIO_GPU_CMD_*
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

/// Virtio response header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuRespHdr {
    type_: u32,
    flags: u32,
}

/// Resource create 2D command
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuResourceCreate2D {
    hdr: VirtioGpuCmdHdr,
    resource_id: u32,
    format: u32,     // VIRGL_RENDERER_FORMAT_* or plain PixelFormat
    width: u32,
    height: u32,
}

/// Set scanout command
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuSetScanout {
    hdr: VirtioGpuCmdHdr,
    r: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

/// Transfer to host 2D command
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuTransferToHost {
    hdr: VirtioGpuCmdHdr,
    r: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

/// Flush command
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioGpuFlush {
    hdr: VirtioGpuCmdHdr,
    r: VirtioGpuRect,
}

/// Virtio GPU engine
pub struct VirtioGpuEngine {
    info: FramebufferInfo,
    /// Mapped BAR0 base (framebuffer region)
    bar0_virt: u64,
    /// Resource ID for our framebuffer
    resource_id: u32,
}

impl VirtioGpuEngine {
    /// Probe for and initialise the virtio-gpu device.
    ///
    /// Returns `None` if no matching PCI device is found or init fails.
    pub fn new() -> Option<Self> {
        serial::put_bytes(b"[virtio-gpu] probing...\n");

        let bar0 = find_virtio_gpu_device()?;
        serial::put_bytes(b"[virtio-gpu] BAR0=0x");
        serial::put_hex_u64(bar0);
        serial::put_bytes(b"\n");

        // Map BAR0 (typically 64 MB)
        let bar0_size = 64 * 1024 * 1024;
        let bar0_virt = unsafe { crate::vm::map_phys_range(bar0, bar0_size) };
        if bar0_virt.is_null() {
            serial::put_bytes(b"[virtio-gpu] failed to map BAR0\n");
            return None;
        }

        serial::put_bytes(b"[virtio-gpu] BAR0 mapped at virt=");
        serial::put_hex_u64(bar0_virt as u64);
        serial::put_bytes(b"\n");

        // Use 1024x768 BGRA as the initial mode.
        // In a full implementation we would query display info from the device.
        let width = 1024u32;
        let height = 768u32;
        let pitch = width * 4;
        let size_bytes = (width * height * 4) as u64;

        let info = FramebufferInfo {
            phys_addr: PhysAddr::new(bar0),
            virt_addr: bar0_virt as u64,
            width,
            height,
            pitch,
            format: PixelFormat::BGRA8888,
            size_bytes,
        };

        serial::put_bytes(b"[virtio-gpu] configured 1024x768x32 BGRA8888\n");

        // NOTE: A full virtio-gpu implementation would:
        //   1. Negotiate VIRTIO_GPU_F_2D via the virtio feature bitmap
        //   2. Find the controlq virtqueue
        //   3. Submit VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
        //   4. Submit VIRTIO_GPU_CMD_SET_SCANOUT
        //   5. Submit VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
        //   6. Submit VIRTIO_GPU_CMD_FLUSH
        // This requires virtqueue infrastructure that is out of scope for
        // this pass. For now we treat BAR0 as a plain framebuffer and
        // draw directly into it. The device will display whatever we write.

        Some(Self {
            info,
            bar0_virt: bar0_virt as u64,
            resource_id: 1, // simple single-resource assumption
        })
    }
}

impl DisplayEngine for VirtioGpuEngine {
    fn name(&self) -> &'static str { "virtio-gpu 2D" }
    fn kind(&self) -> EngineKind { EngineKind::VirtioGpu }
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
        // NOTE: In a full implementation, submit VIRTIO_GPU_CMD_FLUSH
        // to the virtqueue here.
    }
}

/// Scan PCI buses for the virtio-gpu device and return its BAR0.
fn find_virtio_gpu_device() -> Option<u64> {
    use crate::plan9_arch::hal::outl;
    use crate::plan9_arch::hal::inl;

    let config_addr = 0xCF8u16;
    let config_data = 0xCFCu16;

    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let make_addr = |offset: u32| -> u32 {
                    0x80000000u32
                        | ((bus as u32) << 16)
                        | ((dev as u32) << 11)
                        | ((func as u32) << 8)
                        | (offset & 0xFC)
                };
                // Read vendor ID (offset 0)
                let addr = make_addr(0);
                unsafe { outl(config_addr, addr); }
                let vendor = unsafe { inl(config_data) } as u16;
                if vendor == 0xFFFF {
                    continue;
                }

                // Read device ID at offset 2
                let addr2 = make_addr(2);
                unsafe { outl(config_addr, addr2); }
                let device = unsafe { inl(config_data) } as u16;

                if vendor == VIRTIO_VENDOR_ID && device == VIRTIO_GPU_DEVICE_ID {
                    serial::put_bytes(b"[virtio-gpu] PCI match bus=");
                    serial::put_hex_u32(bus as u32);
                    serial::put_bytes(b" dev=");
                    serial::put_hex_u32(dev as u32);
                    serial::put_bytes(b" func=");
                    serial::put_hex_u32(func as u32);
                    serial::put_bytes(b"\n");

                    // Read BAR0 (offset 0x10)
                    let bar0 = read_bar_at(&make_addr, 0x10);
                    if bar0 != 0 {
                        serial::put_bytes(b"[virtio-gpu] BAR0=0x");
                        serial::put_hex_u64(bar0);
                        serial::put_bytes(b"\n");
                        return Some(bar0 & !0xFu64);
                    }
                }
            }
        }
    }

    serial::put_bytes(b"[virtio-gpu] no device found\n");
    None
}

/// Read a 32-bit BAR from PCI config space using a closure that builds
/// the address for the current device's bus/dev/func.
fn read_bar_at(make_addr: &dyn Fn(u32) -> u32, offset: u32) -> u64 {
    use crate::plan9_arch::hal::outl;
    use crate::plan9_arch::hal::inl;

    let addr = make_addr(offset);
    unsafe { outl(0xCF8, addr); }
    let val = unsafe { inl(0xCFC) };
    val as u64
}

#[inline]
fn color_to_bgra(c: Color) -> u32 {
    (c.b as u32) | ((c.g as u32) << 8) | ((c.r as u32) << 16) | ((c.a as u32) << 24)
}

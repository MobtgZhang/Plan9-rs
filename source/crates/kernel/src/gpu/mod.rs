//! Virtual GPU driver stack
//!
//! Provides a pluggable `DisplayEngine` trait that the on-screen text console
//! can render into. Backends are responsible for discovering the GPU/display
//! device (GOP framebuffer tag, QEMU Bochs DISPI, virtio-gpu PCI device, ...)
//! and exposing a simple pixel-level interface.
//!
//! All backends are safe to call before the heap exists (they only touch
//! already-mapped MMIO/framebuffer physical memory).

pub mod gop;
/// Bochs VBE uses x86 PCI configuration ports (0xCF8/0xCFC); only x86_64
/// has port I/O.  The other architectures use GOP or virtio-gpu instead.
#[cfg(target_arch = "x86_64")]
pub mod bochs_vbe;
pub mod virtio_gpu;
pub mod manager;
pub mod font8x16;

use crate::plan9_common::types::PhysAddr;
use crate::serial;

/// Pixel format used by the display engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit XRGB (R in lowest 8 bits)
    XRGB8888,
    /// 32-bit ARGB
    ARGB8888,
    /// 32-bit BGRA (used by UEFI GOP and QEMU Bochs)
    BGRA8888,
    /// 32-bit RGBA
    RGBA8888,
    /// 24-bit RGB packed
    RGB888,
    /// 16-bit RGB 5:6:5
    RGB565,
    /// Unknown — engine will refuse to draw
    Unknown,
}

impl PixelFormat {
    pub fn bytes_per_pixel(&self) -> u8 {
        match self {
            PixelFormat::XRGB8888 | PixelFormat::ARGB8888
            | PixelFormat::BGRA8888 | PixelFormat::RGBA8888 => 4,
            PixelFormat::RGB888 => 3,
            PixelFormat::RGB565 => 2,
            PixelFormat::Unknown => 0,
        }
    }
}

/// 32-bit RGBA color
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const BLACK: Color = Color { r: 0, g: 0, b: 0, a: 255 };
    pub const WHITE: Color = Color { r: 255, g: 255, b: 255, a: 255 };
    pub const RED: Color = Color { r: 255, g: 0, b: 0, a: 255 };
    pub const GREEN: Color = Color { r: 0, g: 255, b: 0, a: 255 };
    pub const BLUE: Color = Color { r: 0, g: 0, b: 255, a: 255 };
    pub const CYAN: Color = Color { r: 0, g: 255, b: 255, a: 255 };
    pub const YELLOW: Color = Color { r: 255, g: 255, b: 0, a: 255 };
    pub const MAGENTA: Color = Color { r: 255, g: 0, b: 255, a: 255 };
    pub const GRAY: Color = Color { r: 128, g: 128, b: 128, a: 255 };

    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
}

/// Rectangle for blit operations
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }
}

/// Framebuffer description shared by all engines
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub phys_addr: PhysAddr,
    pub virt_addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub format: PixelFormat,
    pub size_bytes: u64,
}

impl FramebufferInfo {
    pub fn bytes_per_pixel(&self) -> u8 { self.format.bytes_per_pixel() }

    pub fn contains(&self, x: u32, y: u32) -> bool {
        x < self.width && y < self.height
    }
}

/// Identifier of the backend that produced this engine. Used by the manager
/// for diagnostic logging only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Gop,        // UEFI GOP-derived
    BochsVbe,   // QEMU Bochs DISPI MMIO
    VirtioGpu,  // QEMU virtio-gpu 2D
    RamFb,      // QEMU ramfb (placeholder)
    None,
}

/// Pluggable display engine. Each backend implements this trait.
///
/// All methods are safe to call only after `init()` has succeeded for the
/// instance. Drawing into an uninitialized engine is undefined.
pub trait DisplayEngine: Send + Sync {
    /// Human-readable name for logs.
    fn name(&self) -> &'static str;

    /// Engine kind.
    fn kind(&self) -> EngineKind;

    /// Framebuffer info.
    fn info(&self) -> &FramebufferInfo;

    /// Draw a single pixel. Coordinates outside the framebuffer are silently
    /// ignored.
    fn put_pixel(&mut self, x: u32, y: u32, color: Color);

    /// Fill a rectangle with a solid color.
    fn fill_rect(&mut self, rect: Rect, color: Color);

    /// Copy a block of pixels from an in-memory BGRA8888 buffer (rows packed,
    /// no padding) to the framebuffer at the given location.
    fn blit_bgra(&mut self, dst_x: u32, dst_y: u32, src: &[u32], src_w: u32, src_h: u32);

    /// Scroll the visible content up by `rows` scanlines, filling the new
    /// bottom rows with `fill`.
    fn scroll_up(&mut self, rows: u32, fill: Color);

    /// Flush any pending hardware operations. For pure framebuffer engines
    /// this is a no-op; for virtio-gpu it submits the `VIRTIO_GPU_CMD_FLUSH`.
    fn flush(&mut self);
}

/// A trivial engine used as a fallback when nothing has been initialised.
/// All drawing operations are no-ops. Used to keep the console code safe
/// before the real engine comes online.
pub struct NullEngine;

impl DisplayEngine for NullEngine {
    fn name(&self) -> &'static str { "null" }
    fn kind(&self) -> EngineKind { EngineKind::None }
    fn info(&self) -> &FramebufferInfo {
        static FB: FramebufferInfo = FramebufferInfo {
            phys_addr: PhysAddr::new(0),
            virt_addr: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Unknown,
            size_bytes: 0,
        };
        &FB
    }
    fn put_pixel(&mut self, _x: u32, _y: u32, _c: Color) {}
    fn fill_rect(&mut self, _rect: Rect, _color: Color) {}
    fn blit_bgra(&mut self, _x: u32, _y: u32, _src: &[u32], _w: u32, _h: u32) {}
    fn scroll_up(&mut self, _rows: u32, _fill: Color) {}
    fn flush(&mut self) {}
}

/// Log helper shared by all GPU backends.
pub(crate) fn gpu_log(msg: &str) {
    serial::put_bytes(b"[gpu] ");
    serial::put_bytes(msg.as_bytes());
    serial::put_bytes(b"\n");
}

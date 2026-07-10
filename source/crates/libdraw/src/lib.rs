//! Plan 9 Graphics Library
//!
//! This crate provides the Plan 9 graphics API including:
//! - Image: Pixel buffer operations
//! - Screen: Display screen management
//! - Display: Connection to graphics device
//! - Font: Text rendering
//! - Point, Rectangle, and other geometry types
//!
//! Reference: sys/src/libdraw/

#![no_std]

extern crate alloc;

extern crate plan9_common;

pub mod geom;
pub mod image;
pub mod image_io;
pub mod screen;
pub mod display;
pub mod font;
pub mod context;
pub mod draw;
pub mod line;
pub mod ellipse;
pub mod poly;
pub mod bezier;
pub mod string;
pub mod border;
pub mod event;
pub mod window;
pub mod math;

// ============================================================================
// Re-exports
// ============================================================================

pub use geom::{Point, Rectangle, Size};
pub use image::{Image, ImageOps};
pub use image_io::{readimage, writeimage, readimage_from_bytes, writeimage_to_bytes, loadimage, unloadimage, ImageData};
pub use screen::{Screen, ScreenOps};
pub use display::{Display, DisplayOps};
pub use font::{Font, FontMetrics};
pub use context::BlendOp;
pub use event::{Mouse, MouseButton, KeyEvent, ResizeEvent, DrawEvent, Modifiers, getmouse, kbdmouse};
pub use window::{WindowInfo, WindowOpts, newwindow, visible, refreshwindow, getscreenrect};

// Drawing function exports
pub use draw::{DrawOp, draw, gendraw, fill as draw_fill, blend_pixels};
pub use line::{line, lineop, polyline, End};
pub use ellipse::{ellipse, ellipseop, fillellipse, arc, arcop, fillarc};
pub use poly::{poly, fillpoly};
pub use bezier::{bezier, fillbezier, bezspline, fillbezspline};
pub use string::{string, stringop, stringwidth, runestring, runestringwidth};
pub use border::{border, borderop};

// ============================================================================
// Display Configuration
// ============================================================================

/// Default display address
pub const DEFAULT_DISPLAY: &str = "/dev screen";

// ============================================================================
// Pixel Formats
// ============================================================================

/// Plan 9 pixel format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 1-bit monochrome
    GREY1,
    /// 2-bit greyscale
    GREY2,
    /// 4-bit greyscale
    GREY4,
    /// 8-bit greyscale
    GREY8,
    /// 8-bit color (RGB332)
    RGB24,
    /// 16-bit color (RGB565)
    RGB16,
    /// 24-bit color (RGB888)
    RGB24True,
    /// 32-bit color (RGBA8888)
    RGBA32,
    /// 24-bit color with alpha (ARGB8888)
    ARGB32,
}

/// Channel descriptors for pixel formats
#[derive(Debug, Clone, Copy)]
pub struct ChannelDesc {
    /// Bits per pixel
    pub bpp: u8,
    /// Red channel shift and width
    pub red: (u8, u8),
    /// Green channel shift and width
    pub green: (u8, u8),
    /// Blue channel shift and width
    pub blue: (u8, u8),
    /// Alpha channel shift and width
    pub alpha: (u8, u8),
    /// Red channel max value
    pub red_max: u32,
    /// Green channel max value
    pub green_max: u32,
    /// Blue channel max value
    pub blue_max: u32,
    /// Alpha channel max value
    pub alpha_max: u32,
}

impl ChannelDesc {
    /// Create a new channel descriptor
    pub fn new(
        bpp: u8,
        red: (u8, u8),
        green: (u8, u8),
        blue: (u8, u8),
        alpha: (u8, u8),
    ) -> Self {
        let red_max = (1u32 << red.1) - 1;
        let green_max = (1u32 << green.1) - 1;
        let blue_max = (1u32 << blue.1) - 1;
        let alpha_max = (1u32 << alpha.1) - 1;

        Self {
            bpp,
            red,
            green,
            blue,
            alpha,
            red_max,
            green_max,
            blue_max,
            alpha_max,
        }
    }

    /// Default GREY8 format
    pub fn grey8() -> Self {
        Self::new(8, (0, 8), (0, 8), (0, 8), (0, 0))
    }

    /// Default RGB24 format
    pub fn rgb24() -> Self {
        Self::new(24, (16, 8), (8, 8), (0, 8), (0, 0))
    }

    /// Default RGBA32 format
    pub fn rgba32() -> Self {
        Self::new(32, (16, 8), (8, 8), (0, 8), (24, 8))
    }
}

// ============================================================================
// ReplType - Replication Types
// ============================================================================

/// Types of replication for drawing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplType {
    /// No replication
    None,
    /// Replicate in X direction
    X,
    /// Replicate in Y direction
    Y,
    /// Replicate in both directions
    XY,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the graphics subsystem
pub fn init() -> Result<Display, DrawError> {
    Display::open(None)
}

/// Initialize with a specific display
pub fn init_display(address: &str) -> Result<Display, DrawError> {
    Display::open(Some(address))
}

// ============================================================================
// Errors
// ============================================================================

/// Drawing error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrawError {
    /// Display not available
    NoDisplay,
    /// Invalid format
    InvalidFormat,
    /// Out of memory
    OutOfMemory,
    /// Invalid rectangle
    InvalidRect,
    /// Invalid point
    InvalidPoint,
    /// Device error
    DeviceError,
    /// Font not found
    FontNotFound,
}

impl core::fmt::Display for DrawError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DrawError::NoDisplay => write!(f, "no display available"),
            DrawError::InvalidFormat => write!(f, "invalid pixel format"),
            DrawError::OutOfMemory => write!(f, "out of memory"),
            DrawError::InvalidRect => write!(f, "invalid rectangle"),
            DrawError::InvalidPoint => write!(f, "invalid point"),
            DrawError::DeviceError => write!(f, "device error"),
            DrawError::FontNotFound => write!(f, "font not found"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_operations() {
        let p = Point::new(10, 20);
        assert_eq!(p.x, 10);
        assert_eq!(p.y, 20);

        let p2 = p + Point::new(5, 5);
        assert_eq!(p2.x, 15);
        assert_eq!(p2.y, 25);
    }

    #[test]
    fn test_rectangle_operations() {
        let r = Rectangle::new(Point::new(0, 0), Point::new(100, 100));
        assert!(r.contains(Point::new(50, 50)));
        assert!(!r.contains(Point::new(150, 150)));

        let r2 = r.inset(10);
        assert_eq!(r2.min.x, 10);
        assert_eq!(r2.max.x, 90);
    }

    #[test]
    fn test_channel_desc() {
        let desc = ChannelDesc::rgba32();
        assert_eq!(desc.bpp, 32);
        assert_eq!(desc.red_max, 255);
        assert_eq!(desc.green_max, 255);
        assert_eq!(desc.blue_max, 255);
        assert_eq!(desc.alpha_max, 255);
    }
}

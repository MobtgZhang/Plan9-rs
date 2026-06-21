//! Framebuffer Graphics Driver
//!
//! Implements framebuffer graphics following Plan 9's devdraw.c
//! Reference: sys/src/9/port/devdraw.c
//!
//! This module provides framebuffer management, basic drawing primitives,
//! and cursor support for the graphics subsystem.

#![allow(dead_code)]

// ============================================================================
// Framebuffer Types
// ============================================================================

/// Color format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8-bit indexed color
    Indexed8,
    /// 15-bit (1-5-5-5) RGB
    RGB555,
    /// 16-bit (5-6-5) RGB
    RGB565,
    /// 24-bit RGB
    RGB888,
    /// 32-bit RGBA
    RGBA8888,
    /// 32-bit BGRA
    BGRA8888,
}

/// Framebuffer information
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub address: usize,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per pixel
    pub bytes_per_pixel: u8,
    /// Total size in bytes
    pub size: usize,
    /// Pixel format
    pub format: PixelFormat,
    /// Row pitch (bytes per scanline)
    pub pitch: u32,
}

impl FramebufferInfo {
    /// Create new framebuffer info
    pub fn new(
        address: usize,
        width: u32,
        height: u32,
        bytes_per_pixel: u8,
        format: PixelFormat,
    ) -> Self {
        let pitch = width * bytes_per_pixel as u32;
        let size = (pitch * height) as usize;
        
        Self {
            address,
            width,
            height,
            bytes_per_pixel,
            size,
            format,
            pitch,
        }
    }
    
    /// Check if coordinates are valid
    pub fn contains(&self, x: u32, y: u32) -> bool {
        x < self.width && y < self.height
    }
    
    /// Calculate pixel offset
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y * self.pitch + x * self.bytes_per_pixel as u32) as usize
    }
    
    /// Get pixel pointer
    pub fn pixel_ptr(&self, x: u32, y: u32) -> *mut u8 {
        (self.address + self.pixel_offset(x, y)) as *mut u8
    }
}

// ============================================================================
// Color Definitions
// ============================================================================

/// RGBA color
#[derive(Debug, Clone, Copy, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
    
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }
    
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
    
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0, a: 255 };
    pub const WHITE: Self = Self { r: 255, g: 255, b: 255, a: 255 };
    pub const RED: Self = Self { r: 255, g: 0, b: 0, a: 255 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0, a: 255 };
    pub const BLUE: Self = Self { r: 0, g: 0, b: 255, a: 255 };
    pub const YELLOW: Self = Self { r: 255, g: 255, b: 0, a: 255 };
    pub const CYAN: Self = Self { r: 0, g: 255, b: 255, a: 255 };
    pub const MAGENTA: Self = Self { r: 255, g: 0, b: 255, a: 255 };
    pub const GRAY: Self = Self { r: 128, g: 128, b: 128, a: 255 };
    
    /// Convert to pixel value based on format
    pub fn to_pixel(&self, format: PixelFormat) -> u32 {
        match format {
            PixelFormat::RGB565 => {
                let r = (self.r >> 3) as u32;
                let g = (self.g >> 2) as u32;
                let b = (self.b >> 3) as u32;
                (r << 11) | (g << 5) | b
            }
            PixelFormat::RGB555 => {
                let r = (self.r >> 3) as u32;
                let g = (self.g >> 3) as u32;
                let b = (self.b >> 3) as u32;
                (r << 10) | (g << 5) | b
            }
            PixelFormat::RGB888 => {
                (self.r as u32) | ((self.g as u32) << 8) | ((self.b as u32) << 16)
            }
            PixelFormat::RGBA8888 => {
                (self.r as u32) | ((self.g as u32) << 8) | 
                ((self.b as u32) << 16) | ((self.a as u32) << 24)
            }
            PixelFormat::BGRA8888 => {
                (self.b as u32) | ((self.g as u32) << 8) | 
                ((self.r as u32) << 16) | ((self.a as u32) << 24)
            }
            _ => 0,
        }
    }
}

// ============================================================================
// Rectangle
// ============================================================================

/// Rectangle for drawing operations
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }
    
    pub const fn from_points(x0: i32, y0: i32, x1: i32, y1: i32) -> Self {
        Self {
            x: x0,
            y: y0,
            width: (x1 - x0) as u32,
            height: (y1 - y0) as u32,
        }
    }
    
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && x < self.x + self.width as i32 &&
        y >= self.y && y < self.y + self.height as i32
    }
    
    pub fn intersects(&self, other: &Rect) -> bool {
        self.x < other.x + other.width as i32 &&
        self.x + self.width as i32 > other.x &&
        self.y < other.y + other.height as i32 &&
        self.y + self.height as i32 > other.y
    }
}

// ============================================================================
// Framebuffer
// ============================================================================

/// Framebuffer device
pub struct Framebuffer {
    /// Framebuffer information
    info: FramebufferInfo,
    /// Software cursor state
    cursor: CursorState,
    /// Clip rectangle
    clip: Rect,
}

impl Framebuffer {
    /// Create new framebuffer
    pub fn new(info: FramebufferInfo) -> Self {
        Self {
            info,
            cursor: CursorState::new(),
            clip: Rect {
                x: 0,
                y: 0,
                width: info.width,
                height: info.height,
            },
        }
    }
    
    /// Get framebuffer info
    pub fn info(&self) -> &FramebufferInfo {
        &self.info
    }
    
    /// Get framebuffer base address
    pub fn base(&self) -> *mut u8 {
        self.info.address as *mut u8
    }
    
    /// Get clip rectangle
    pub fn clip(&self) -> Rect {
        self.clip
    }
    
    /// Set clip rectangle
    pub fn set_clip(&mut self, clip: Rect) {
        self.clip = clip;
    }
    
    /// Write pixel at coordinates
    pub fn write_pixel(&mut self, x: i32, y: i32, color: Color) {
        if !self.clip.contains(x, y) {
            return;
        }
        
        let x = x as u32;
        let y = y as u32;
        
        if !self.info.contains(x, y) {
            return;
        }
        
        let ptr = self.info.pixel_ptr(x, y);
        
        match self.info.format {
            PixelFormat::RGB565 | PixelFormat::RGB555 => {
                let pixel = color.to_pixel(self.info.format);
                let ptr16 = ptr as *mut u16;
                unsafe { ptr16.write_volatile(pixel as u16); }
            }
            PixelFormat::RGB888 => {
                unsafe {
                    ptr.write_volatile(color.r);
                    ptr.add(1).write_volatile(color.g);
                    ptr.add(2).write_volatile(color.b);
                }
            }
            PixelFormat::RGBA8888 | PixelFormat::BGRA8888 => {
                let ptr32 = ptr as *mut u32;
                unsafe { ptr32.write_volatile(color.to_pixel(self.info.format)); }
            }
            _ => {}
        }
    }
    
    /// Read pixel at coordinates
    pub fn read_pixel(&self, x: u32, y: u32) -> Color {
        if !self.info.contains(x, y) {
            return Color::BLACK;
        }
        
        let ptr = self.info.pixel_ptr(x, y);
        
        match self.info.format {
            PixelFormat::RGB565 => {
                let ptr16 = ptr as *const u16;
                let pixel = unsafe { ptr16.read_volatile() };
                Color::new(
                    ((pixel >> 11) & 0x1F) as u8 * 8,
                    ((pixel >> 5) & 0x3F) as u8 * 4,
                    (pixel & 0x1F) as u8 * 8,
                )
            }
            PixelFormat::RGB888 => {
                Color::new(
                    unsafe { ptr.read_volatile() },
                    unsafe { ptr.add(1).read_volatile() },
                    unsafe { ptr.add(2).read_volatile() },
                )
            }
            PixelFormat::RGBA8888 | PixelFormat::BGRA8888 => {
                let ptr32 = ptr as *const u32;
                let pixel = unsafe { ptr32.read_volatile() };
                Color::new(
                    (pixel & 0xFF) as u8,
                    ((pixel >> 8) & 0xFF) as u8,
                    ((pixel >> 16) & 0xFF) as u8,
                )
            }
            _ => Color::BLACK,
        }
    }
    
    /// Fill rectangle with color
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        for dy in 0..rect.height as i32 {
            for dx in 0..rect.width as i32 {
                self.write_pixel(rect.x + dx, rect.y + dy, color);
            }
        }
    }
    
    /// Copy area from one location to another
    pub fn copy_rect(&mut self, src: Rect, dest_x: i32, dest_y: i32) {
        // Handle overlap correctly
        let up = dest_y < src.y as i32;
        let left = dest_x < src.x;
        
        let dy_range: Box<dyn Iterator<Item = i32>> = if up {
            Box::new(0..src.height as i32)
        } else {
            Box::new((src.height as i32 - 1..=0))
        };
        
        let dx_range: Box<dyn Iterator<Item = i32>> = if left {
            Box::new(0..src.width as i32)
        } else {
            Box::new((src.width as i32 - 1..=0))
        };
        
        for dy in dy_range {
            for dx in dx_range.clone() {
                let src_x = src.x + dx;
                let src_y = src.y + dy;
                let color = self.read_pixel(src_x as u32, src_y as u32);
                self.write_pixel(dest_x + dx, dest_y + dy, color);
            }
        }
    }
    
    /// Clear screen with color
    pub fn clear(&mut self, color: Color) {
        self.fill_rect(Rect::new(0, 0, self.info.width, self.info.height), color);
    }
    
    /// Draw horizontal line
    pub fn draw_hline(&mut self, x: i32, y: i32, width: u32, color: Color) {
        for dx in 0..width as i32 {
            self.write_pixel(x + dx, y, color);
        }
    }
    
    /// Draw vertical line
    pub fn draw_vline(&mut self, x: i32, y: i32, height: u32, color: Color) {
        for dy in 0..height as i32 {
            self.write_pixel(x, y + dy, color);
        }
    }
    
    // ========================================================================
    // Cursor Support
    // ========================================================================
    
    /// Get cursor position
    pub fn cursor_pos(&self) -> (i32, i32) {
        (self.cursor.x, self.cursor.y)
    }
    
    /// Set cursor position
    pub fn set_cursor_pos(&mut self, x: i32, y: i32) {
        self.cursor.x = x;
        self.cursor.y = y;
    }
    
    /// Show cursor
    pub fn show_cursor(&mut self) {
        self.cursor.visible = true;
        self.draw_cursor();
    }
    
    /// Hide cursor
    pub fn hide_cursor(&mut self) {
        if self.cursor.visible {
            // Restore background
            self.copy_rect(
                Rect::new(self.cursor.x, self.cursor.y, CURSOR_WIDTH, CURSOR_HEIGHT),
                self.cursor.x,
                self.cursor.y,
            );
        }
        self.cursor.visible = false;
    }
    
    /// Draw cursor at current position
    fn draw_cursor(&mut self) {
        if !self.cursor.visible {
            return;
        }
        
        // Simple crosshair cursor pattern
        let cursor_color = Color::WHITE;
        let x = self.cursor.x;
        let y = self.cursor.y;
        
        // Draw crosshair
        self.fill_rect(Rect::new(x + 4, y + 0, 2, 1), cursor_color);
        self.fill_rect(Rect::new(x + 4, y + 2, 2, 1), cursor_color);
        self.fill_rect(Rect::new(x + 4, y + 4, 2, 1), cursor_color);
        self.fill_rect(Rect::new(x + 4, y + 6, 2, 1), cursor_color);
        self.fill_rect(Rect::new(x + 0, y + 4, 1, 2), cursor_color);
        self.fill_rect(Rect::new(x + 2, y + 4, 1, 2), cursor_color);
        self.fill_rect(Rect::new(x + 6, y + 4, 1, 2), cursor_color);
        self.fill_rect(Rect::new(x + 8, y + 4, 1, 2), cursor_color);
    }
    
    /// Move cursor
    pub fn move_cursor(&mut self, new_x: i32, new_y: i32) {
        // Hide old cursor
        if self.cursor.visible {
            self.copy_rect(
                Rect::new(self.cursor.x, self.cursor.y, CURSOR_WIDTH, CURSOR_HEIGHT),
                self.cursor.x,
                self.cursor.y,
            );
        }
        
        // Update position
        self.cursor.x = new_x;
        self.cursor.y = new_y;
        
        // Show at new position
        if self.cursor.visible {
            self.draw_cursor();
        }
    }
}

const CURSOR_WIDTH: u32 = 10;
const CURSOR_HEIGHT: u32 = 10;

/// Cursor state
struct CursorState {
    x: i32,
    y: i32,
    visible: bool,
}

impl CursorState {
    fn new() -> Self {
        Self {
            x: 0,
            y: 0,
            visible: false,
        }
    }
}

// ============================================================================
// Screen Mode
// ============================================================================

/// Video mode
#[derive(Debug, Clone, Copy)]
pub struct VideoMode {
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub format: PixelFormat,
}

impl VideoMode {
    /// Standard VGA mode 13h (320x200x256)
    pub const MODE_320_200_256: Self = Self {
        width: 320,
        height: 200,
        bpp: 8,
        format: PixelFormat::Indexed8,
    };
    
    /// Standard VBE 800x600x32
    pub const MODE_800_600_32: Self = Self {
        width: 800,
        height: 600,
        bpp: 32,
        format: PixelFormat::RGBA8888,
    };
    
    /// Standard VBE 1024x768x32
    pub const MODE_1024_768_32: Self = Self {
        width: 1024,
        height: 768,
        bpp: 32,
        format: PixelFormat::RGBA8888,
    };
    
    /// Standard VBE 1920x1080x32
    pub const MODE_1920_1080_32: Self = Self {
        width: 1920,
        height: 1080,
        bpp: 32,
        format: PixelFormat::RGBA8888,
    };
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Blend two colors
pub fn blend_colors(src: Color, dst: Color) -> Color {
    let alpha = src.a as f32 / 255.0;
    let inv_alpha = 1.0 - alpha;
    
    Color::rgba(
        (src.r as f32 * alpha + dst.r as f32 * inv_alpha) as u8,
        (src.g as f32 * alpha + dst.g as f32 * inv_alpha) as u8,
        (src.b as f32 * alpha + dst.b as f32 * inv_alpha) as u8,
        255,
    )
}

/// Create framebuffer from VBE info
pub fn create_framebuffer(mode: VideoMode, address: usize) -> Framebuffer {
    let info = FramebufferInfo::new(
        address,
        mode.width,
        mode.height,
        mode.bpp / 8,
        mode.format,
    );
    Framebuffer::new(info)
}

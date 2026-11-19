//! VESA BIOS Extension (VBE) Driver
//!
//! Implements VBE 2.0+ graphics mode support for modern displays.
//! VBE provides standardized access to graphics hardware capabilities.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// VESA error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VesaError {
    /// VBE not supported
    NotSupported,
    /// Invalid mode
    InvalidMode,
    /// Mode not supported
    ModeNotSupported,
    /// Video memory insufficient
    OutOfMemory,
    /// Function failed
    FunctionFailed,
    /// BIOS call failed
    BiosFailed,
}

impl VesaError {
    pub fn from_code(code: u16) -> Self {
        match code {
            0x00 => VesaError::FunctionFailed,
            0x01 => VesaError::NotSupported,
            0x02 => VesaError::ModeNotSupported,
            0x03 => VesaError::InvalidMode,
            0x04 => VesaError::OutOfMemory,
            _ => VesaError::FunctionFailed,
        }
    }
}

/// VESA result type
pub type VesaResult<T> = Result<T, VesaError>;

/// VBE information block
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct VbeInfoBlock {
    /// VBE signature "VESA"
    pub vbe_signature: [u8; 4],
    /// VBE version (BCD)
    pub vbe_version: u16,
    /// OEM string pointer (segment:offset)
    pub oem_string_ptr: u32,
    /// Capabilities
    pub capabilities: u32,
    /// Video mode pointer (segment:offset)
    pub video_mode_ptr: u32,
    /// Total memory (in 64KB blocks)
    pub total_memory: u16,
    /// OEM software revision
    pub oem_sw_rev: u16,
    /// OEM vendor name pointer
    pub oem_string_ptr_2: u32,
    /// OEM product name pointer
    pub oem_product_ptr: u32,
    /// OEM product revision pointer
    pub oem_product_rev_ptr: u32,
    /// Reserved
    pub reserved: [u8; 222],
    /// OEM data
    pub oem_data: [u8; 256],
}

impl VbeInfoBlock {
    /// Check if VBE is supported
    pub fn is_valid(&self) -> bool {
        &self.vbe_signature == b"VESA"
    }
    
    /// Get VBE version major
    pub fn version_major(&self) -> u8 {
        (self.vbe_version >> 8) as u8
    }
    
    /// Get VBE version minor
    pub fn version_minor(&self) -> u8 {
        (self.vbe_version & 0xFF) as u8
    }
    
    /// Get total video memory in bytes
    pub fn total_memory_bytes(&self) -> usize {
        (self.total_memory as usize) * 64 * 1024
    }
    
    /// Check if DAC is 8-bit
    pub fn has_8bit_dac(&self) -> bool {
        (self.capabilities & 0x01) != 0
    }
    
    /// Check if controller is VGA compatible
    pub fn is_vga_compatible(&self) -> bool {
        (self.capabilities & 0x02) != 0
    }
    
    /// Check if RAMDAC supports 8-bit
    pub fn ramdac_8bit(&self) -> bool {
        (self.capabilities & 0x04) != 0
    }
    
    /// Get supported video modes
    pub fn video_modes(&self) -> Vec<u16> {
        let mut modes = Vec::new();
        let ptr = self.video_mode_ptr as *const u16;
        
        // Safety: read up to 256 modes
        for i in 0..256 {
            let mode = unsafe { core::ptr::read_volatile(ptr.add(i)) };
            if mode == 0xFFFF {
                break;
            }
            modes.push(mode);
        }
        
        modes
    }
}

/// VBE mode information block
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct VbeModeInfoBlock {
    /// Mode attributes
    pub mode_attributes: u16,
    /// Window A attributes
    pub window_a_attributes: u8,
    /// Window B attributes
    pub window_b_attributes: u8,
    /// Window granularity (KB)
    pub window_granularity: u16,
    /// Window size (KB)
    pub window_size: u16,
    /// Window A segment
    pub window_a_segment: u16,
    /// Window B segment
    pub window_b_segment: u16,
    /// Window function pointer
    pub window_func_ptr: u32,
    /// Bytes per scan line
    pub bytes_per_scanline: u16,
    /// Resolution
    pub x_resolution: u16,
    pub y_resolution: u16,
    /// Character dimensions
    pub x_char_size: u8,
    pub y_char_size: u8,
    /// Number of planes
    pub number_of_planes: u8,
    /// Bits per pixel
    pub bits_per_pixel: u8,
    /// Number of banks
    pub number_of_banks: u8,
    /// Memory model type
    pub memory_model: u8,
    /// Bank size (KB)
    pub bank_size: u8,
    /// Number of image pages
    pub number_of_image_pages: u8,
    /// Reserved
    pub reserved1: u8,
    /// Direct color mode info
    pub direct_color_mode_info: u8,
    /// Phys base pointer for linear framebuffer
    pub phys_base_ptr: u32,
    /// Reserved
    pub reserved2: u32,
    /// Bytes per scan line (for linear modes)
    pub lin_bytes_per_scanline: u16,
    /// Number of image pages (for linear modes)
    pub lin_number_of_image_pages: u8,
    /// Reserved
    pub lin_red_mask_size: u8,
    pub lin_red_field_position: u8,
    pub lin_green_mask_size: u8,
    pub lin_green_field_position: u8,
    pub lin_blue_mask_size: u8,
    pub lin_blue_field_position: u8,
    pub lin_reserved_mask_size: u8,
    pub lin_reserved_field_position: u8,
    /// Direct color mode attributes
    pub direct_color_mode_attributes: u8,
    /// Reserved
    pub reserved3: [u8; 216],
}

impl VbeModeInfoBlock {
    /// Check if mode is supported
    pub fn is_supported(&self) -> bool {
        (self.mode_attributes & 0x01) != 0
    }
    
    /// Check if mode is color
    pub fn is_color(&self) -> bool {
        (self.mode_attributes & 0x08) != 0
    }
    
    /// Check if mode is graphics
    pub fn is_graphics(&self) -> bool {
        (self.mode_attributes & 0x10) != 0
    }
    
    /// Check if mode supports linear framebuffer
    pub fn supports_lfb(&self) -> bool {
        (self.mode_attributes & 0x80) != 0
    }
    
    /// Check if mode is VGA compatible
    pub fn is_vga_compatible(&self) -> bool {
        (self.mode_attributes & 0x20) != 0
    }
    
    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> usize {
        ((self.bits_per_pixel + 7) / 8) as usize
    }
    
    /// Get framebuffer size
    pub fn framebuffer_size(&self) -> usize {
        (self.y_resolution as usize) * (self.lin_bytes_per_scanline as usize)
    }
    
    /// Get pixel format
    pub fn pixel_format(&self) -> PixelFormat {
        if self.memory_model == 0x04 {
            //packed pixel
            PixelFormat::Indexed
        } else if self.memory_model == 0x06 {
            // direct color
            PixelFormat::Rgb {
                red_mask: (self.lin_red_mask_size as u32, self.lin_red_field_position as u32),
                green_mask: (self.lin_green_mask_size as u32, self.lin_green_field_position as u32),
                blue_mask: (self.lin_blue_mask_size as u32, self.lin_blue_field_position as u32),
            }
        } else {
            PixelFormat::Unknown
        }
    }
    
    /// Get total video memory needed
    pub fn total_memory_needed(&self) -> usize {
        self.framebuffer_size() * self.lin_number_of_image_pages as usize
    }
}

/// Pixel format
#[derive(Debug, Clone, Copy)]
pub enum PixelFormat {
    /// Indexed color (palette)
    Indexed,
    /// RGB format
    Rgb {
        red_mask: (u32, u32),    // (size, position)
        green_mask: (u32, u32),
        blue_mask: (u32, u32),
    },
    /// YUV format
    Yuv,
    /// Unknown format
    Unknown,
}

/// VESA mode attributes
#[derive(Debug, Clone, Copy)]
pub struct VesaModeAttributes {
    pub supported: bool,
    pub color: bool,
    pub graphics: bool,
    pub not_vga_compatible: bool,
    pub vga_compatible_window: bool,
    pub linear_framebuffer: bool,
    pub double_scan: bool,
}

impl From<u16> for VesaModeAttributes {
    fn from(attr: u16) -> Self {
        Self {
            supported: (attr & 0x01) != 0,
            color: (attr & 0x08) != 0,
            graphics: (attr & 0x10) != 0,
            not_vga_compatible: (attr & 0x20) == 0,
            vga_compatible_window: (attr & 0x40) != 0,
            linear_framebuffer: (attr & 0x80) != 0,
            double_scan: (attr & 0x100) != 0,
        }
    }
}

/// Video mode descriptor
#[derive(Debug, Clone)]
pub struct VideoMode {
    /// Mode number
    pub mode: u16,
    /// Width in pixels
    pub width: u16,
    /// Height in pixels
    pub height: u16,
    /// Bits per pixel
    pub bpp: u8,
    /// Linear framebuffer supported
    pub lfb_supported: bool,
    /// Refresh rate hint
    pub refresh_rate: Option<u16>,
}

impl VideoMode {
    /// Get aspect ratio
    pub fn aspect_ratio(&self) -> (u16, u16) {
        match (self.width, self.height) {
            (640, 480) => (4, 3),
            (800, 600) => (4, 3),
            (1024, 768) => (4, 3),
            (1280, 720) => (16, 9),
            (1280, 800) => (16, 10),
            (1280, 1024) => (5, 4),
            (1366, 768) => (16, 9),
            (1440, 900) => (16, 10),
            (1600, 900) => (16, 9),
            (1600, 1200) => (4, 3),
            (1920, 1080) => (16, 9),
            (1920, 1200) => (16, 10),
            (2560, 1440) => (16, 9),
            (2560, 1600) => (16, 10),
            (3840, 2160) => (16, 9),
            _ => (16, 9),
        }
    }
    
    /// Check if mode matches criteria
    pub fn matches(&self, width: u16, height: u16, bpp: u8) -> bool {
        (width == 0 || self.width == width) &&
        (height == 0 || self.height == height) &&
        (bpp == 0 || self.bpp == bpp)
    }
}

/// VESA driver
pub struct VesaDriver {
    /// VBE info block
    vbe_info: VbeInfoBlock,
    /// Available modes
    modes: Vec<VideoMode>,
    /// Current mode
    current_mode: Option<VideoMode>,
    /// Framebuffer address
    framebuffer: usize,
    /// Framebuffer size
    framebuffer_size: usize,
    /// Pitch (bytes per scan line)
    pitch: usize,
    /// Initialized flag
    initialized: AtomicBool,
}

impl VesaDriver {
    /// Create a new VESA driver
    pub fn new() -> Self {
        Self {
            vbe_info: unsafe { core::mem::zeroed() },
            modes: Vec::new(),
            current_mode: None,
            framebuffer: 0,
            framebuffer_size: 0,
            pitch: 0,
            initialized: AtomicBool::new(false),
        }
    }
    
    /// Initialize VESA driver
    pub fn init(&mut self) -> VesaResult<()> {
        // Get VBE info
        self.get_vbe_info()?;
        
        if !self.vbe_info.is_valid() {
            return Err(VesaError::NotSupported);
        }
        
        // Get supported modes
        self.enumerate_modes()?;
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// Get VBE info block
    fn get_vbe_info(&mut self) -> VesaResult<()> {
        // Call VBE function 0x4F00
        // This requires real mode BIOS call
        // For now, return unsupported
        let _ = self;
        Err(VesaError::NotSupported)
    }
    
    /// Get mode info block
    pub fn get_mode_info(&self, mode: u16) -> VesaResult<VbeModeInfoBlock> {
        // Call VBE function 0x4F01
        let _ = mode;
        Err(VesaError::NotSupported)
    }
    
    /// Set video mode
    pub fn set_mode(&mut self, mode: u16) -> VesaResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(VesaError::NotSupported);
        }
        
        // Call VBE function 0x4F02
        let _ = mode;
        Err(VesaError::NotSupported)
    }
    
    /// Set video mode with parameters
    pub fn set_mode_with_params(&mut self, mode: u16, refresh_rate: u16) -> VesaResult<()> {
        let _ = refresh_rate;
        self.set_mode(mode)
    }
    
    /// Enumerate all supported modes
    fn enumerate_modes(&mut self) -> VesaResult<()> {
        let mode_numbers = self.vbe_info.video_modes();
        
        for mode_num in mode_numbers {
            if let Ok(mode_info) = self.get_mode_info(mode_num) {
                if mode_info.is_supported() && mode_info.supports_lfb() {
                    let mode = VideoMode {
                        mode: mode_num,
                        width: mode_info.x_resolution,
                        height: mode_info.y_resolution,
                        bpp: mode_info.bits_per_pixel,
                        lfb_supported: true,
                        refresh_rate: None,
                    };
                    self.modes.push(mode);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get available modes
    pub fn modes(&self) -> &[VideoMode] {
        &self.modes
    }
    
    /// Find best mode for resolution
    pub fn find_mode(&self, width: u16, height: u16, bpp: u8) -> Option<VideoMode> {
        // First try exact match
        for mode in &self.modes {
            if mode.matches(width, height, bpp) {
                return Some(mode.clone());
            }
        }
        
        // Try higher bpp
        if bpp > 0 {
            for mode in &self.modes {
                if mode.width == width && mode.height == height && mode.bpp >= bpp {
                    return Some(mode.clone());
                }
            }
        }
        
        // Try any resolution
        if width > 0 && height > 0 {
            for mode in &self.modes {
                if mode.width >= width && mode.height >= height {
                    return Some(mode.clone());
                }
            }
        }
        
        // Return best available (highest resolution)
        self.modes.iter().max_by_key(|m| m.width * m.height).cloned()
    }
    
    /// Get current mode
    pub fn current_mode(&self) -> Option<&VideoMode> {
        self.current_mode.as_ref()
    }
    
    /// Get framebuffer address
    pub fn framebuffer(&self) -> usize {
        self.framebuffer
    }
    
    /// Get framebuffer size
    pub fn framebuffer_size(&self) -> usize {
        self.framebuffer_size
    }
    
    /// Get pitch (bytes per scan line)
    pub fn pitch(&self) -> usize {
        self.pitch
    }
    
    /// Write pixel (32-bit)
    pub fn write_pixel_32(&self, x: usize, y: usize, color: u32) {
        if x >= (self.current_mode.as_ref().map(|m| m.width).unwrap_or(0) as usize) {
            return;
        }
        if y >= (self.current_mode.as_ref().map(|m| m.height).unwrap_or(0) as usize) {
            return;
        }
        
        let offset = y * self.pitch + x * 4;
        let ptr = (self.framebuffer + offset) as *mut u32;
        unsafe {
            core::ptr::write_volatile(ptr, color);
        }
    }
    
    /// Read pixel (32-bit)
    pub fn read_pixel_32(&self, x: usize, y: usize) -> u32 {
        if x >= (self.current_mode.as_ref().map(|m| m.width).unwrap_or(0) as usize) {
            return 0;
        }
        if y >= (self.current_mode.as_ref().map(|m| m.height).unwrap_or(0) as usize) {
            return 0;
        }
        
        let offset = y * self.pitch + x * 4;
        let ptr = (self.framebuffer + offset) as *const u32;
        unsafe {
            core::ptr::read_volatile(ptr)
        }
    }
    
    /// Fill rectangle with color (32-bit)
    pub fn fill_rect(&self, x: usize, y: usize, width: usize, height: usize, color: u32) {
        let mode_width = self.current_mode.as_ref().map(|m| m.width).unwrap_or(0) as usize;
        let mode_height = self.current_mode.as_ref().map(|m| m.height).unwrap_or(0) as usize;
        
        let x_end = (x + width).min(mode_width);
        let y_end = (y + height).min(mode_height);
        
        for row in y..y_end {
            for col in x..x_end {
                self.write_pixel_32(col, row, color);
            }
        }
    }
    
    /// Copy area (blit)
    pub fn blit(&self, src_x: usize, src_y: usize, dst_x: usize, dst_y: usize, width: usize, height: usize) {
        let mode_width = self.current_mode.as_ref().map(|m| m.width).unwrap_or(0) as usize;
        let mode_height = self.current_mode.as_ref().map(|m| m.height).unwrap_or(0) as usize;
        
        // Limit to visible area
        let x_end = dst_x.saturating_add(width).min(mode_width);
        let y_end = dst_y.saturating_add(height).min(mode_height);
        
        // Read source pixels and write to destination
        for row in 0..(y_end - dst_y) {
            for col in 0..(x_end - dst_x) {
                let pixel = self.read_pixel_32(src_x.saturating_add(col), src_y.saturating_add(row));
                self.write_pixel_32(dst_x.saturating_add(col), dst_y.saturating_add(row), pixel);
            }
        }
    }
    
    /// Scroll screen up
    pub fn scroll_up(&self, lines: usize) {
        let mode_width = self.current_mode.as_ref().map(|m| m.width).unwrap_or(0) as usize;
        let mode_height = self.current_mode.as_ref().map(|m| m.height).unwrap_or(0) as usize;
        
        if lines >= mode_height {
            // Clear entire screen
            self.fill_rect(0, 0, mode_width, mode_height, 0);
            return;
        }
        
        // Copy pixels up
        self.blit(0, lines, 0, 0, mode_width, mode_height - lines);
        
        // Clear bottom lines
        self.fill_rect(0, mode_height - lines, mode_width, lines, 0);
    }
    
    /// Set palette entry (for indexed color modes)
    pub fn set_palette(&self, index: u8, r: u8, g: u8, b: u8) {
        // Call VBE function 0x4F09
        let _ = index;
        let _ = r;
        let _ = g;
        let _ = b;
    }
    
    /// Get VBE info reference
    pub fn vbe_info(&self) -> &VbeInfoBlock {
        &self.vbe_info
    }
    
    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
}

impl Default for VesaDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Common VESA Modes
// ============================================================================

/// Common video modes
pub mod vesa_modes {
    /// Mode 640x480x8 (256 colors)
    pub const V640X480X8: u16 = 0x101;
    /// Mode 640x480x16 (64K colors)
    pub const V640X480X16: u16 = 0x111;
    /// Mode 640x480x24 (16M colors)
    pub const V640X480X24: u16 = 0x112;
    /// Mode 640x480x32 (16M colors)
    pub const V640X480X32: u16 = 0x142;
    
    /// Mode 800x600x8 (256 colors)
    pub const V800X600X8: u16 = 0x103;
    /// Mode 800x600x16 (64K colors)
    pub const V800X600X16: u16 = 0x114;
    /// Mode 800x600x24 (16M colors)
    pub const V800X600X24: u16 = 0x115;
    /// Mode 800x600x32 (16M colors)
    pub const V800X600X32: u16 = 0x11E;
    
    /// Mode 1024x768x8 (256 colors)
    pub const V1024X768X8: u16 = 0x105;
    /// Mode 1024x768x16 (64K colors)
    pub const V1024X768X16: u16 = 0x117;
    /// Mode 1024x768x24 (16M colors)
    pub const V1024X768X24: u16 = 0x118;
    /// Mode 1024x768x32 (16M colors)
    pub const V1024X768X32: u16 = 0x144;
    
    /// Mode 1280x720x16 (HD 720)
    pub const V1280X720X16: u16 = 0x155;
    /// Mode 1280x720x24
    pub const V1280X720X24: u16 = 0x157;
    /// Mode 1280x720x32
    pub const V1280X720X32: u16 = 0x15F;
    
    /// Mode 1280x800x16 (WXGA)
    pub const V1280X800X16: u16 = 0x160;
    /// Mode 1280x800x32
    pub const V1280X800X32: u16 = 0x164;
    
    /// Mode 1280x1024x8 (SXGA)
    pub const V1280X1024X8: u16 = 0x107;
    /// Mode 1280x1024x16
    pub const V1280X1024X16: u16 = 0x11A;
    /// Mode 1280x1024x24
    pub const V1280X1024X24: u16 = 0x11B;
    /// Mode 1280x1024x32
    pub const V1280X1024X32: u16 = 0x11F;
    
    /// Mode 1920x1080x32 (Full HD)
    pub const V1920X1080X32: u16 = 0x1E1;
    
    /// Mode 2560x1440x32 (2K)
    pub const V2560X1440X32: u16 = 0x1E2;
    
    /// Mode 3840x2160x32 (4K UHD)
    pub const V3840X2160X32: u16 = 0x1E3;
    
    /// Get mode name
    pub fn mode_name(mode: u16) -> &'static str {
        match mode {
            V640X480X8 => "640x480x8",
            V640X480X16 => "640x480x16",
            V640X480X24 => "640x480x24",
            V640X480X32 => "640x480x32",
            V800X600X8 => "800x600x8",
            V800X600X16 => "800x600x16",
            V800X600X24 => "800x600x24",
            V800X600X32 => "800x600x32",
            V1024X768X8 => "1024x768x8",
            V1024X768X16 => "1024x768x16",
            V1024X768X24 => "1024x768x24",
            V1024X768X32 => "1024x768x32",
            V1280X720X16 => "1280x720x16",
            V1280X720X24 => "1280x720x24",
            V1280X720X32 => "1280x720x32",
            V1280X800X16 => "1280x800x16",
            V1280X800X32 => "1280x800x32",
            V1280X1024X8 => "1280x1024x8",
            V1280X1024X16 => "1280x1024x16",
            V1280X1024X24 => "1280x1024x24",
            V1280X1024X32 => "1280x1024x32",
            V1920X1080X32 => "1920x1080x32",
            V2560X1440X32 => "2560x1440x32",
            V3840X2160X32 => "3840x2160x32",
            _ => "unknown",
        }
    }
}

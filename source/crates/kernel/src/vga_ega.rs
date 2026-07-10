//! EGA (Enhanced Graphics Adapter) Driver
//!
//! Implements support for EGA graphics modes and registers.
//! 
//! The EGA provides 640x350 resolution with 16 colors from a palette of 64 colors.
//! It also supports CGA and MDA compatibility modes.
//!
//! Reference: EGA Data Sheet, IBM Technical Reference


extern crate alloc;

// use alloc::vec::Vec;
use core::fmt;

/// EGA Register Ports
pub mod ports {
    /// Miscellaneous Output Register
    pub const MISC_OUTPUT: u16 = 0x3C2;
    /// Feature Control Register
    pub const FEATURE_CONTROL: u16 = 0x3DA;
    /// Input Status Register 0
    pub const INPUT_STATUS_0: u16 = 0x3C2;
    /// Input Status Register 1
    pub const INPUT_STATUS_1: u16 = 0x3DA;
}

/// EGA CRT Controller Registers
pub mod crtc {
//     use super::ports::*;
    
    /// Base address for CRT controller registers
    pub const BASE: u16 = 0x3D4;
    /// Data register
    pub const DATA: u16 = 0x3D5;
    
    /// CRT Controller Register Index
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Index {
        /// Horizontal Total
        HorizontalTotal = 0x00,
        /// Horizontal Display Enable End
        HorizontalDisplayEnd = 0x01,
        /// Horizontal Blanking Start
        HorizontalBlankingStart = 0x02,
        /// Horizontal Blanking End
        HorizontalBlankingEnd = 0x03,
        /// Horizontal Retrace Start
        HorizontalRetraceStart = 0x04,
        /// Horizontal Retrace End
        HorizontalRetraceEnd = 0x05,
        /// Vertical Total
        VerticalTotal = 0x06,
        /// Overflow
        Overflow = 0x07,
        /// Preset Row Scan
        PresetRowScan = 0x08,
        /// Maximum Scan Line
        MaximumScanLine = 0x09,
        /// Cursor Start
        CursorStart = 0x0A,
        /// Cursor End
        CursorEnd = 0x0B,
        /// Start Address High
        StartAddressHigh = 0x0C,
        /// Start Address Low
        StartAddressLow = 0x0D,
        /// Cursor Location High
        CursorLocationHigh = 0x0E,
        /// Cursor Location Low
        CursorLocationLow = 0x0F,
        /// Vertical Retrace Start
        VerticalRetraceStart = 0x10,
        /// Vertical Retrace End
        VerticalRetraceEnd = 0x11,
        /// Vertical Display Enable End
        VerticalDisplayEnd = 0x12,
        /// Offset
        Offset = 0x13,
        /// Underline Location
        UnderlineLocation = 0x14,
        /// Vertical Blanking Start
        VerticalBlankingStart = 0x15,
        /// Vertical Blanking End
        VerticalBlankingEnd = 0x16,
        /// Mode Control
        ModeControl = 0x17,
        /// Line Compare
        LineCompare = 0x18,
    }
}

/// EGA Sequencer Registers
pub mod sequencer {
    /// Base address for sequencer registers
    pub const BASE: u16 = 0x3C4;
    /// Data register
    pub const DATA: u16 = 0x3C5;
    
    /// Sequencer Register Index
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Index {
        /// Reset
        Reset = 0x00,
        /// Clocking Mode
        ClockingMode = 0x01,
        /// Map Mask
        MapMask = 0x02,
        /// Character Map Select
        CharacterMapSelect = 0x03,
        /// Memory Mode
        MemoryMode = 0x04,
    }
}

/// EGA Graphics Controller Registers
pub mod graphics {
    /// Base address for graphics controller registers
    pub const BASE: u16 = 0x3CE;
    /// Data register
    pub const DATA: u16 = 0x3CF;
    
    /// Graphics Controller Register Index
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Index {
        /// Set/Reset
        SetReset = 0x00,
        /// Enable Set/Reset
        EnableSetReset = 0x01,
        /// Color Compare
        ColorCompare = 0x02,
        /// Data Rotate
        DataRotate = 0x03,
        /// Read Map Select
        ReadMapSelect = 0x04,
        /// Mode
        Mode = 0x05,
        /// Miscellaneous
        Miscellaneous = 0x06,
        /// Color Don't Care
        ColorDontCare = 0x07,
        /// Bit Mask
        BitMask = 0x08,
    }
}

/// EGA Attribute Controller Registers
pub mod attribute {
    /// Address register (also status register at 0x3DA)
    pub const ADDRESS: u16 = 0x3C0;
    /// Data register
    pub const DATA: u16 = 0x3C1;
    
    /// Attribute Controller Register Index
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Index {
        /// Palette 0-15
        Palette0 = 0x00,
        Palette1 = 0x01,
        Palette2 = 0x02,
        Palette3 = 0x03,
        Palette4 = 0x04,
        Palette5 = 0x05,
        Palette6 = 0x06,
        Palette7 = 0x07,
        Palette8 = 0x08,
        Palette9 = 0x09,
        Palette10 = 0x0A,
        Palette11 = 0x0B,
        Palette12 = 0x0C,
        Palette13 = 0x0D,
        Palette14 = 0x0E,
        Palette15 = 0x0F,
        /// Attribute Mode Control
        AttributeModeControl = 0x10,
        /// Overscan Color
        OverscanColor = 0x11,
        /// Color Plane Enable
        ColorPlaneEnable = 0x12,
        /// Horizontal Pixel Panning
        HorizontalPixelPanning = 0x13,
        /// Color Select
        ColorSelect = 0x14,
    }
}

/// EGA Video Memory Map
pub mod memory {
    /// EGA memory is organized as 4 planes of 64KB each
    /// Total video memory: 256KB
    
    /// Start of plane 0
    pub const PLANE_0_START: usize = 0xA0000;
    /// Start of plane 1
    pub const PLANE_1_START: usize = 0xA0000;
    /// Start of plane 2
    pub const PLANE_2_START: usize = 0xA0000;
    /// Start of plane 3
    pub const PLANE_3_START: usize = 0xA0000;
    
    /// Start of EGA character font (8x14)
    pub const FONT_8X14: usize = 0x1FF6A;
    
    /// Standard EGA text mode resolution
    pub const TEXT_WIDTH: usize = 80;
    pub const TEXT_HEIGHT: usize = 25;
    
    /// Standard EGA graphics resolution
    pub const GRAPHICS_WIDTH: usize = 640;
    pub const GRAPHICS_HEIGHT: usize = 350;
}

/// EGA Color Palette
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgaPalette {
    /// 16 palette entries, each with RGB values (0-63)
    entries: [EgaColor; 16],
}

impl EgaPalette {
    /// Default EGA palette (same as CGA)
    pub fn default() -> Self {
        Self {
            entries: [
                EgaColor { r: 0, g: 0, b: 0 },       // Black
                EgaColor { r: 0, g: 0, b: 42 },     // Blue
                EgaColor { r: 0, g: 42, b: 0 },     // Green
                EgaColor { r: 0, g: 42, b: 42 },   // Cyan
                EgaColor { r: 42, g: 0, b: 0 },     // Red
                EgaColor { r: 42, g: 0, b: 42 },    // Magenta
                EgaColor { r: 42, g: 21, b: 0 },    // Brown
                EgaColor { r: 42, g: 42, b: 42 },  // Light Gray
                EgaColor { r: 21, g: 21, b: 21 },  // Dark Gray
                EgaColor { r: 21, g: 21, b: 63 },  // Light Blue
                EgaColor { r: 21, g: 63, b: 21 },  // Light Green
                EgaColor { r: 21, g: 63, b: 63 },  // Light Cyan
                EgaColor { r: 63, g: 21, b: 21 },  // Light Red
                EgaColor { r: 63, g: 21, b: 63 },  // Light Magenta
                EgaColor { r: 63, g: 63, b: 21 },  // Yellow
                EgaColor { r: 63, g: 63, b: 63 },  // White
            ],
        }
    }
    
    /// Get palette entry
    pub fn get(&self, index: usize) -> Option<EgaColor> {
        self.entries.get(index).copied()
    }
    
    /// Set palette entry
    pub fn set(&mut self, index: usize, color: EgaColor) {
        if index < 16 {
            self.entries[index] = color;
        }
    }
}

/// EGA Color (6-bit RGB)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgaColor {
    /// Red (0-63)
    pub r: u8,
    /// Green (0-63)
    pub g: u8,
    /// Blue (0-63)
    pub b: u8,
}

impl EgaColor {
    /// Create a new EGA color
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self {
            r: r.min(63),
            g: g.min(63),
            b: b.min(63),
        }
    }
    
    /// Convert to 8-bit RGB (scale up)
    pub fn to_rgb888(&self) -> (u8, u8, u8) {
        (
            (self.r * 255) / 63,
            (self.g * 255) / 63,
            (self.b * 255) / 63,
        )
    }
}

/// EGA Graphics Mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgaMode {
    /// 80x25 text mode (color)
    Text80x25,
    /// 80x25 text mode (mono)
    Text80x25Mono,
    /// 40x25 text mode (color)
    Text40x25,
    /// 320x200 4-color graphics
    Graphics320x200x4,
    /// 640x200 2-color graphics
    Graphics640x200x2,
    /// 640x350 2-color graphics
    Graphics640x350x2,
    /// 640x350 16-color graphics
    Graphics640x350x16,
    /// 640x480 16-color graphics
    Graphics640x480x16,
}

/// EGA Driver State
pub struct EgaDriver {
    /// Current mode
    mode: Option<EgaMode>,
    /// Palette
    palette: EgaPalette,
    /// Is initialized
    initialized: bool,
}

impl EgaDriver {
    /// Create a new EGA driver
    pub fn new() -> Self {
        Self {
            mode: None,
            palette: EgaPalette::default(),
            initialized: false,
        }
    }
    
    /// Initialize the EGA driver
    pub fn init(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            // Reset the EGA
            self.reset();
            
            // Set default palette (clone to avoid borrow conflict)
            let palette_clone = self.palette.clone();
            self.set_palette(&palette_clone);
            
            self.initialized = true;
        }
        
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.initialized = true;
        }
    }
    
    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
    
    /// Reset EGA
    #[cfg(target_arch = "x86_64")]
    fn reset(&mut self) {
        unsafe {
            // Synchronous reset via sequencer
            core::arch::asm!(
                "mov dx, 0x3C4",
                "mov al, 0x00",
                "out dx, al",
                "inc dx",
                "mov al, 0x01",  // Synchronous reset
                "out dx, al",
            );
            
            // Short delay
            for _ in 0..100 {
                core::arch::asm!("nop");
            }
            
            // Take EGA out of reset
            core::arch::asm!(
                "mov dx, 0x3C4",
                "mov al, 0x00",
                "out dx, al",
                "inc dx",
                "mov al, 0x03",  // Reset synchronous reset
                "out dx, al",
            );
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn reset(&mut self) {
        // No-op on non-x86
    }
    
    /// Set video mode
    pub fn set_mode(&mut self, mode: EgaMode) {
        self.mode = Some(mode);
        
        #[cfg(target_arch = "x86_64")]
        {
            // BIOS function to set video mode
            let bios_mode = match mode {
                EgaMode::Text80x25 => 0x03,
                EgaMode::Text80x25Mono => 0x07,
                EgaMode::Text40x25 => 0x01,
                EgaMode::Graphics320x200x4 => 0x04,
                EgaMode::Graphics640x200x2 => 0x06,
                EgaMode::Graphics640x350x2 => 0x0F,
                EgaMode::Graphics640x350x16 => 0x10,
                EgaMode::Graphics640x480x16 => 0x12,
            };
            
            unsafe {
                core::arch::asm!(
                    "int 0x10",
                    in("ax") bios_mode as u16,
                );
            }
        }
    }
    
    /// Get current mode
    pub fn get_mode(&self) -> Option<EgaMode> {
        self.mode
    }
    
    /// Set palette
    pub fn set_palette(&mut self, palette: &EgaPalette) {
        self.palette = *palette;
        
        #[cfg(target_arch = "x86_64")]
        {
            for i in 0..16 {
                let color = palette.get(i).unwrap_or(EgaColor { r: 0, g: 0, b: 0 });
                
                unsafe {
                    // Set palette register
                    core::arch::asm!(
                        "mov dx, 0x3C0",
                        "mov al, [idx]",
                        "out dx, al",
                        in("al") i as u8,
                    );
                    
                    // Set color value
                    core::arch::asm!(
                        "mov dx, 0x3C1",
                        "mov al, [r]",
                        "out dx, al",
                        in("al") (color.r | ((color.b & 0x03) << 6)),
                    );
                }
            }
        }
    }
    
    /// Get palette
    pub fn get_palette(&self) -> EgaPalette {
        self.palette
    }
    
    /// Write to video memory plane
    #[cfg(target_arch = "x86_64")]
    pub fn write_plane(&mut self, plane: u8, offset: usize, data: u8) {
        if plane >= 4 {
            return;
        }
        
        unsafe {
            // Select map mask register
            core::arch::asm!(
                "mov dx, 0x3C4",
                "mov al, 0x02",  // Map mask
                "out dx, al",
                "inc dx",
                "mov al, [plane_mask]",
                "out dx, al",
                in("al") 1u8 << plane,
            );
            
            // Write data
            let ptr = (memory::PLANE_0_START + offset) as *mut u8;
            ptr.write_volatile(data);
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_plane(&mut self, _plane: u8, _offset: usize, _data: u8) {
        // No-op on non-x86
    }
    
    /// Read from video memory plane
    #[cfg(target_arch = "x86_64")]
    pub fn read_plane(&self, plane: u8, offset: usize) -> u8 {
        if plane >= 4 {
            return 0;
        }
        
        unsafe {
            // Select read map register
            core::arch::asm!(
                "mov dx, 0x3CE",
                "mov al, 0x04",  // Read map select
                "out dx, al",
                "inc dx",
                "mov al, [plane]",
                "out dx, al",
                in("al") plane,
            );
            
            // Read data
            let ptr = (memory::PLANE_0_START + offset) as *const u8;
            ptr.read_volatile()
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_plane(&self, _plane: u8, _offset: usize) -> u8 {
        0
    }
    
    /// Set CRT register
    #[cfg(target_arch = "x86_64")]
    pub fn set_crtc_register(&mut self, index: crtc::Index, value: u8) {
        // Use BIOS interrupt to set CRT register
        // This is a simplified implementation
        let _ = (index, value);
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_crtc_register(&mut self, _index: crtc::Index, _value: u8) {
        // No-op
    }

    /// Get CRT register
    #[cfg(target_arch = "x86_64")]
    pub fn get_crtc_register(&self, index: crtc::Index) -> u8 {
        // Simplified - return 0
        let _ = index;
        0
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn get_crtc_register(&self, _index: crtc::Index) -> u8 {
        0
    }

    /// Set sequencer register
    #[cfg(target_arch = "x86_64")]
    pub fn set_sequencer_register(&mut self, index: sequencer::Index, value: u8) {
        let _ = (index, value);
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_sequencer_register(&mut self, _index: sequencer::Index, _value: u8) {
        // No-op
    }

    /// Set graphics controller register
    #[cfg(target_arch = "x86_64")]
    pub fn set_graphics_register(&mut self, index: graphics::Index, value: u8) {
        let _ = (index, value);
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_graphics_register(&mut self, _index: graphics::Index, _value: u8) {
        // No-op
    }
    
    /// Clear video memory
    pub fn clear_memory(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            for _plane in 0..4 {
                unsafe {
                    // Select map mask (enable all planes)
                    core::arch::asm!(
                        "mov dx, 0x3C4",
                        "mov al, 0x02",
                        "out dx, al",
                        "inc dx",
                        "mov al, 0x0F",  // Enable all planes
                        "out dx, al",
                    );
                }
                
                // Write zeros to entire plane
                let ptr = (memory::PLANE_0_START) as *mut u8;
                for i in 0..(64 * 1024) {
                    unsafe {
                        ptr.add(i).write_volatile(0);
                    }
                }
            }
        }
        
        #[cfg(not(target_arch = "x86_64"))]
        {
            // No-op
        }
    }
}

impl Default for EgaDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EgaDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgaDriver")
            .field("initialized", &self.initialized)
            .field("mode", &self.mode)
            .finish()
    }
}

/// EGA Text Mode Functions
pub mod text {
//     use super::*;
    
    /// Character attribute byte
    #[derive(Debug, Clone, Copy)]
    pub struct TextAttribute {
        /// Foreground color (0-15)
        pub foreground: u8,
        /// Background color (0-7)
        pub background: u8,
        /// Blink enable
        pub blink: bool,
    }
    
    impl TextAttribute {
        /// Create a new attribute
        pub fn new(foreground: u8, background: u8, blink: bool) -> Self {
            Self {
                foreground: foreground.min(15),
                background: background.min(7),
                blink,
            }
        }
        
        /// Get the attribute byte
        pub fn byte(&self) -> u8 {
            (self.background << 4) | self.foreground | (if self.blink { 0x80 } else { 0 })
        }
        
        /// Default attribute (light gray on black)
        pub fn default() -> Self {
            Self::new(7, 0, false)
        }
    }
    
    /// Write text at cursor position
    #[cfg(target_arch = "x86_64")]
    pub fn write_char_at_cursor(ch: u8, attr: TextAttribute) {
        // Simplified - BIOS interrupt would be used in full implementation
        let _ = (ch, attr);
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_char_at_cursor(_ch: u8, _attr: TextAttribute) {
        // No-op
    }

    /// Set cursor position
    #[cfg(target_arch = "x86_64")]
    pub fn set_cursor_position(row: u8, col: u8, page: u8) {
        // Simplified - BIOS interrupt would be used in full implementation
        let _ = (row, col, page);
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_cursor_position(_row: u8, _col: u8, _page: u8) {
        // No-op
    }

    /// Get cursor position
    #[cfg(target_arch = "x86_64")]
    pub fn get_cursor_position(page: u8) -> (u8, u8) {
        // Simplified - return default position
        let _ = page;
        (0, 0)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn get_cursor_position(_page: u8) -> (u8, u8) {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ega_color() {
        let color = EgaColor::new(63, 63, 63);
        assert_eq!(color.r, 63);
        assert_eq!(color.g, 63);
        assert_eq!(color.b, 63);
    }

    #[test]
    fn test_text_attribute() {
        let attr = text::TextAttribute::new(15, 1, false);
        assert_eq!(attr.byte(), 0x1F);
        
        let attr_blink = text::TextAttribute::new(15, 1, true);
        assert_eq!(attr_blink.byte(), 0x9F);
    }

    #[test]
    fn test_ega_palette() {
        let palette = EgaPalette::default();
        assert!(palette.get(0).is_some());
        assert_eq!(palette.get(0).unwrap().r, 0);
    }
}

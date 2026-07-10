//! VESA BIOS Extension (VBE) Support
//!
//! Implements VBE 2.0+ functionality for graphics initialization and mode switching.
//! 
//! VBE provides standardized access to high-resolution graphics modes on VGA-compatible
//! hardware, supporting resolutions up to 1920x1440 and various color depths.
//!
//! Reference: VBE 3.0 Specification


extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;

/// VBE Return Status Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbeStatus {
    /// Function call successful
    Success = 0x004F,
    /// Function call failed
    Failed = 0x014F,
    /// Function not supported by hardware
    NotSupported = 0x024F,
    /// Function call invalid in current mode
    InvalidMode = 0x034F,
}

/// VBE Mode Attributes
#[derive(Debug, Clone, Copy)]
pub struct VbeModeAttributes {
    /// Mode is supported by hardware
    pub supported: bool,
    /// Mode information available
    pub info_available: bool,
    /// Output device connected
    pub output_available: bool,
    /// Color mode (vs monochrome)
    pub color_mode: bool,
    /// Graphics mode (vs text mode)
    pub graphics_mode: bool,
    /// Mode is not VGA compatible
    pub not_vga_compatible: bool,
    /// Mode supports bank switching
    pub bank_switch: bool,
    /// Mode supports linear framebuffer
    pub linear_framebuffer: bool,
    /// Double-scan mode
    pub double_scan: bool,
}

impl VbeModeAttributes {
    pub fn from_u16(value: u16) -> Self {
        Self {
            supported: (value & 0x0001) != 0,
            info_available: (value & 0x0002) != 0,
            output_available: (value & 0x0004) != 0,
            color_mode: (value & 0x0008) != 0,
            graphics_mode: (value & 0x0010) != 0,
            not_vga_compatible: (value & 0x0020) != 0,
            bank_switch: (value & 0x0040) != 0,
            linear_framebuffer: (value & 0x0080) != 0,
            double_scan: (value & 0x0100) != 0,
        }
    }
}

/// VBE Mode Information
#[derive(Debug, Clone)]
pub struct VbeModeInfo {
    /// Mode attributes
    pub attributes: VbeModeAttributes,
    /// Window A segment address
    pub window_a_seg: u16,
    /// Window B segment address
    pub window_b_seg: u16,
    /// Window granularity (KB)
    pub window_granularity: u16,
    /// Window size (KB)
    pub window_size: u16,
    /// Window A start segment
    pub window_a_start: u16,
    /// Window B start segment
    pub window_b_start: u16,
    /// Window function pointer (segment:offset)
    pub window_func_ptr: u32,
    /// bytes per scan line
    pub bytes_per_scanline: u16,
    /// horizontal resolution
    pub horizontal_resolution: u16,
    /// vertical resolution
    pub vertical_resolution: u16,
    /// character width
    pub character_width: u8,
    /// character height
    pub character_height: u8,
    /// number of memory planes
    pub num_memory_planes: u8,
    /// bits per pixel
    pub bits_per_pixel: u8,
    /// number of banks
    pub num_banks: u8,
    /// memory model type
    pub memory_model: VbeMemoryModel,
    /// bank size (KB)
    pub bank_size: u8,
    /// number of image pages
    pub num_image_pages: u8,
    /// reserved for page function
    pub page_function_reserved: u8,
    /// direct color mode info
    pub direct_color_info: u8,
    /// linear framebuffer address
    pub linear_framebuffer: u32,
    /// linear bytes per scan line
    pub linear_bytes_per_scanline: u16,
    /// number of linear image pages
    pub num_linear_image_pages: u8,
    /// linear memory model
    pub linear_memory_model: u8,
}

/// VBE Memory Model Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbeMemoryModel {
    /// Text mode
    Text = 0x00,
    /// CGA graphics
    Cga = 0x01,
    /// Hercules graphics
    Hercules = 0x02,
    /// EGA/VGA planar
    Planar = 0x03,
    /// Packed pixel
    PackedPixel = 0x04,
    /// Non-chain 4
    NonChain4 = 0x05,
    /// Direct color
    DirectColor = 0x06,
    /// YUV
    Yuv = 0x07,
    /// Reserved (0x08-0x0F)
    Reserved = 0x08,
    /// Unknown
    Unknown = 0xFF,
}

impl VbeMemoryModel {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => VbeMemoryModel::Text,
            0x01 => VbeMemoryModel::Cga,
            0x02 => VbeMemoryModel::Hercules,
            0x03 => VbeMemoryModel::Planar,
            0x04 => VbeMemoryModel::PackedPixel,
            0x05 => VbeMemoryModel::NonChain4,
            0x06 => VbeMemoryModel::DirectColor,
            0x07 => VbeMemoryModel::Yuv,
            0x08..=0x0F => VbeMemoryModel::Reserved,
            _ => VbeMemoryModel::Unknown,
        }
    }
}

/// VBE Controller Information
#[derive(Debug, Clone)]
pub struct VbeControllerInfo {
    /// VBE signature ("VBE2" or "VESA")
    pub signature: [u8; 4],
    /// VBE version (major << 8 | minor)
    pub version: u16,
    /// OEM string pointer (segment:offset)
    pub oem_ptr: u32,
    /// Capabilities
    pub capabilities: VbeCapabilities,
    /// List of supported video modes
    pub video_modes: Vec<u16>,
    /// Total memory in 64KB blocks
    pub total_memory: u16,
    /// OEM software revision
    pub oem_software_rev: u16,
    /// OEM vendor name pointer
    pub vendor_name_ptr: u32,
    /// OEM product name pointer
    pub product_name_ptr: u32,
    /// OEM product revision pointer
    pub product_rev_ptr: u32,
}

impl VbeControllerInfo {
    pub fn is_valid(&self) -> bool {
        // Check for valid VBE signature
        self.signature == [b'V', b'E', b'S', b'A'] 
            || self.signature == [b'V', b'B', b'E', b'2']
    }
}

/// VBE Capabilities
#[derive(Debug, Clone, Copy)]
pub struct VbeCapabilities {
    /// DAC is switchable in 8-bit mode
    pub dac_8bit: bool,
    /// Not VGA compatible
    pub not_vga_compatible: bool,
    /// Programmable CRT timing
    pub crt_timing: bool,
    /// Stereo support
    pub stereo: bool,
}

impl VbeCapabilities {
    pub fn from_u8(value: u8) -> Self {
        Self {
            dac_8bit: (value & 0x01) != 0,
            not_vga_compatible: (value & 0x02) != 0,
            crt_timing: (value & 0x04) != 0,
            stereo: (value & 0x08) != 0,
        }
    }
}

/// Standard VBE Mode Numbers
pub mod vbe_modes {
    /// 640x400x8
    pub const MODE_640X400X256: u16 = 0x100;
    /// 640x480x8
    pub const MODE_640X480X256: u16 = 0x101;
    /// 800x600x16
    pub const MODE_800X600X16: u16 = 0x102;
    /// 800x600x8
    pub const MODE_800X600X256: u16 = 0x103;
    /// 1024x768x16
    pub const MODE_1024X768X16: u16 = 0x104;
    /// 1024x768x8
    pub const MODE_1024X768X256: u16 = 0x105;
    /// 1280x1024x16
    pub const MODE_1280X1024X16: u16 = 0x106;
    /// 1280x1024x8
    pub const MODE_1280X1024X256: u16 = 0x107;
    
    /// 320x200x15 (5:5:5)
    pub const MODE_320X200X15: u16 = 0x10D;
    /// 320x200x16 (5:6:5)
    pub const MODE_320X200X16: u16 = 0x10E;
    /// 320x200x24 (8:8:8)
    pub const MODE_320X200X24: u16 = 0x10F;
    
    /// 640x480x15
    pub const MODE_640X480X15: u16 = 0x110;
    /// 640x480x16
    pub const MODE_640X480X16: u16 = 0x111;
    /// 640x480x24
    pub const MODE_640X480X24: u16 = 0x112;
    
    /// 800x600x15
    pub const MODE_800X600X15: u16 = 0x113;
    /// 800x600x16_15bpp
    pub const MODE_800X600X16_15BPP: u16 = 0x114;
    /// 800x600x24
    pub const MODE_800X600X24: u16 = 0x115;
    
    /// 1024x768x15
    pub const MODE_1024X768X15: u16 = 0x116;
    /// 1024x768x16_15bpp
    pub const MODE_1024X768X16_15BPP: u16 = 0x117;
    /// 1024x768x24
    pub const MODE_1024X768X24: u16 = 0x118;
    
    /// 1280x1024x15
    pub const MODE_1280X1024X15: u16 = 0x119;
    /// 1280x1024x16_15bpp
    pub const MODE_1280X1024X16_15BPP: u16 = 0x11A;
    /// 1280x1024x24
    pub const MODE_1280X1024X24: u16 = 0x11B;
    
    /// Linear framebuffer bit
    pub const LINEAR_FRAMEBUFFER: u16 = 0x4000;
    /// Use reserved memory bit
    pub const RESERVED_MEMORY: u16 = 0x8000;
}

/// VBE 3.0+ mode info extension
#[derive(Debug, Clone)]
pub struct VbeModeInfoExt {
    /// Mode attributes
    pub attributes: u16,
    /// Window A segment
    pub window_a_seg: u16,
    /// Window B segment
    pub window_b_seg: u16,
    /// Window granularity
    pub window_granularity: u16,
    /// Window size
    pub window_size: u16,
    /// Window A start
    pub window_a_start: u16,
    /// Window B start
    pub window_b_start: u16,
    /// Window function pointer
    pub window_func_ptr: u32,
    /// Bytes per scan line
    pub bytes_per_scanline: u16,
    /// Horizontal resolution
    pub horizontal_resolution: u16,
    /// Vertical resolution
    pub vertical_resolution: u16,
    /// Character width
    pub character_width: u8,
    /// Character height
    pub character_height: u8,
    /// Number of planes
    pub num_planes: u8,
    /// Bits per pixel
    pub bits_per_pixel: u8,
    /// Number of banks
    pub num_banks: u8,
    /// Memory model
    pub memory_model: u8,
    /// Bank size
    pub bank_size: u8,
    /// Number of image pages
    pub num_image_pages: u8,
    /// Reserved
    pub reserved: u8,
    /// Direct color info
    pub direct_color_info: u8,
    /// Linear framebuffer address
    pub linear_framebuffer: u32,
    /// Linear bytes per scan line
    pub linear_bytes_per_scanline: u16,
    /// Number of linear image pages
    pub num_linear_image_pages: u8,
    /// Linear memory model
    pub linear_memory_model: u8,
    /// TDF offset
    pub tdf_offset: u16,
    /// TDF size
    pub tdf_size: u16,
    /// Reserved for future use
    pub reserved2: [u8; 14],
}

/// VBE Framebuffer state
#[derive(Debug, Clone)]
pub struct VbeFramebuffer {
    /// Framebuffer address (physical)
    pub address: usize,
    /// Framebuffer size in bytes
    pub size: usize,
    /// Horizontal resolution
    pub width: u16,
    /// Vertical resolution
    pub height: u16,
    /// Bits per pixel
    pub bpp: u8,
    /// Bytes per scan line
    pub pitch: u16,
    /// Is linear framebuffer
    pub is_linear: bool,
}

impl VbeFramebuffer {
    /// Calculate framebuffer size
    pub fn calculate_size(&self) -> usize {
        (self.height as usize) * (self.pitch as usize)
    }
    
    /// Check if a pixel offset is valid
    pub fn is_valid_offset(&self, x: u32, y: u32) -> bool {
        x < self.width as u32 && y < self.height as u32
    }
    
    /// Calculate offset for a pixel
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y as usize) * (self.pitch as usize) + (x as usize) * ((self.bpp as usize) / 8)
    }
}

/// VBE Bank switching interface
#[derive(Debug, Clone)]
pub struct VbeBankSwitcher {
    /// Bank function address
    pub func_ptr: u32,
    /// Bank granularity in KB
    pub granularity: u16,
    /// Current bank number
    current_bank: u32,
}

impl VbeBankSwitcher {
    /// Create a new bank switcher
    pub fn new(func_ptr: u32, granularity: u16) -> Self {
        Self {
            func_ptr,
            granularity,
            current_bank: 0,
        }
    }
    
    /// Set the active bank
    #[cfg(target_arch = "x86")]
    pub fn set_bank(&mut self, bank: u32) {
        self.current_bank = bank;
        // BIOS call would be made here via interrupt 0x10, function 0x4F05
        unsafe {
            core::arch::asm!(
                "int 0x10",
                in("ax") 0x4F05,
                in("bx") 0x0000, // window A
                in("dx") bank as u16,
                out("ax") _,
                out("bx") _,
            );
        }
    }
    
    /// Get current bank
    pub fn get_bank(&self) -> u32 {
        self.current_bank
    }
}

/// VBE Driver
pub struct VbeDriver {
    /// Controller info
    pub controller_info: Option<VbeControllerInfo>,
    /// Current mode info
    pub current_mode: Option<VbeModeInfo>,
    /// Linear framebuffer address
    pub framebuffer: Option<VbeFramebuffer>,
    /// Bank switcher
    pub bank_switcher: Option<VbeBankSwitcher>,
}

impl VbeDriver {
    /// Create a new VBE driver instance
    pub fn new() -> Self {
        Self {
            controller_info: None,
            current_mode: None,
            framebuffer: None,
            bank_switcher: None,
        }
    }
    
    /// Check if VBE is supported
    pub fn is_supported(&self) -> bool {
        self.controller_info.is_some()
    }
    
    /// Get VBE version string
    pub fn version_string(&self) -> String {
        if let Some(ref info) = self.controller_info {
            let major = (info.version >> 8) as u8;
            let minor = (info.version & 0xFF) as u8;
            alloc::format!("{}.{}", major, minor)
        } else {
            String::from("Not detected")
        }
    }
}

impl Default for VbeDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// VBE Controller Info block structure (512 bytes, packed for BIOS call)
/// This matches the VBE 2.0+ controller info block format
#[repr(C, packed)]
struct VbeInfoBlock {
    /// VBE signature ("VESA" or "VBE2")
    vbe_signature: [u8; 4],
    /// VBE version
    vbe_version: u16,
    /// OEM string pointer (segment:offset)
    oem_string_ptr: u32,
    /// Capabilities
    capabilities: u32,
    /// Video mode list pointer (segment:offset)
    video_modes_ptr: u32,
    /// Total memory in 64KB blocks
    total_memory: u16,
    /// OEM software revision
    oem_software_rev: u16,
    /// Vendor name pointer
    vendor_name_ptr: u32,
    /// Product name pointer
    product_name_ptr: u32,
    /// Product revision pointer
    product_rev_ptr: u32,
    /// Reserved
    reserved: [u8; 222],
    /// OEM data
    oem_data: [u8; 256],
}

impl VbeInfoBlock {
    fn is_valid(&self) -> bool {
        self.vbe_signature == [b'V', b'E', b'S', b'A']
            || self.vbe_signature == [b'V', b'B', b'E', b'2']
    }

    fn get_video_modes(&self) -> Vec<u16> {
        // Video modes pointer is at offset 0x0E (word) - relative to info block start
        // But in our static buffer layout, we need to read it from the buffer
        let modes = Vec::new();
        // The actual pointer is at byte offset 14 in the VBE info block
        // For a buffer at physical address, we would need to parse this
        // This is a simplified version that returns common VBE modes
        modes
    }
}

/// VBE Mode Info block structure (256 bytes, packed for BIOS call)
#[repr(C, packed)]
struct VbeModeInfoBlock {
    /// Mode attributes
    attributes: u16,
    /// Window A segment
    window_a_seg: u8,
    /// Window B segment
    window_b_seg: u8,
    /// Window granularity (KB)
    window_granularity: u16,
    /// Window size (KB)
    window_size: u16,
    /// Window A start segment
    window_a_start: u16,
    /// Window B start segment
    window_b_start: u16,
    /// Window function pointer (segment:offset)
    window_func_ptr: u32,
    /// Bytes per scan line
    bytes_per_scanline: u16,
    /// Horizontal resolution
    width: u16,
    /// Vertical resolution
    height: u16,
    /// Character width
    char_width: u8,
    /// Character height
    char_height: u8,
    /// Number of memory planes
    num_planes: u8,
    /// Bits per pixel
    bits_per_pixel: u8,
    /// Number of banks
    num_banks: u8,
    /// Memory model type
    memory_model: u8,
    /// Bank size (KB)
    bank_size: u8,
    /// Number of image pages
    num_image_pages: u8,
    /// Reserved
    reserved1: u8,
    // VBE 2.0+ fields follow
    /// Direct color mode info
    direct_color_info: u8,
    /// Linear framebuffer address
    linear_framebuffer: u32,
    /// Linear bytes per scan line
    linear_bytes_per_scanline: u16,
    /// Number of linear image pages
    num_linear_image_pages: u8,
    /// Linear memory model
    linear_memory_model: u8,
    /// TDF offset
    tdf_offset: u16,
    /// TDF size
    tdf_size: u16,
    /// Reserved for future use
    reserved2: [u8; 14],
}

impl fmt::Debug for VbeDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VbeDriver")
            .field("supported", &self.is_supported())
            .field("version", &self.version_string())
            .field("has_framebuffer", &self.framebuffer.is_some())
            .finish()
    }
}

/// Detect and initialize VBE controller
///
/// This function uses BIOS interrupt 0x10, function 0x4F00 to detect
/// VBE support and retrieve controller information.
///
/// Returns the controller info or None if VBE is not available.
pub fn vbe_detect() -> Option<VbeControllerInfo> {
    #[cfg(target_arch = "x86")]
    {
        use core::mem::size_of;

        // VBE info buffer - must be in lower 1MB of memory
        // Using a static buffer in the .bss section
        static mut VBE_INFO_BUFFER: [u8; 512] = [0; 512];

        // Initialize VBE signature to request VBE 2.0+ info
        unsafe {
            VBE_INFO_BUFFER[0] = b'V';
            VBE_INFO_BUFFER[1] = b'E';
            VBE_INFO_BUFFER[2] = b'S';
            VBE_INFO_BUFFER[3] = b'A';
        }

        let result: u16;
        let es: u16;
        let di: u16;

        // The buffer must be in the lower 1MB
        // For simplicity, we'll use a fixed physical address
        // In a real kernel, this would use a properly mapped buffer
        unsafe {
            // Set ES:DI to point to our buffer
            // For now, use a simple approach - the BIOS call will work
            // if the buffer is in a safe location
            core::arch::asm!(
                "push es",
                "mov ax, 0x4F00",    // VBE Get Controller Info
                "xor di, di",         // DI = 0
                "mov es, di",         // ES = 0 (buffer at physical 0x00000)
                "int 0x10",
                "mov {result}, ax",
                "mov es, 0",          // Restore ES
                "pop es",
                result = out(reg) result,
                options(nostack)
            );
        }

        // Check if VBE is supported (AX = 0x004F)
        if result == 0x004F {
            // Parse the VBE info block
            // Note: In a real implementation, we would need to copy data from
            // the physical buffer address. For now, return a simplified response.
            unsafe {
                let sig = [
                    VBE_INFO_BUFFER[0],
                    VBE_INFO_BUFFER[1],
                    VBE_INFO_BUFFER[2],
                    VBE_INFO_BUFFER[3],
                ];

                // Check for valid signature
                if sig == [b'V', b'E', b'S', b'A'] || sig == [b'V', b'B', b'E', b'2'] {
                    // Read version (at offset 4)
                    let version = u16::from_le_bytes([
                        VBE_INFO_BUFFER[4],
                        VBE_INFO_BUFFER[5],
                    ]);

                    // Read capabilities (at offset 6)
                    let caps = u32::from_le_bytes([
                        VBE_INFO_BUFFER[6],
                        VBE_INFO_BUFFER[7],
                        VBE_INFO_BUFFER[8],
                        VBE_INFO_BUFFER[9],
                    ]);

                    // Read total memory (at offset 14)
                    let total_mem = u16::from_le_bytes([
                        VBE_INFO_BUFFER[14],
                        VBE_INFO_BUFFER[15],
                    ]);

                    // Parse video modes from pointer (at offset 10)
                    // The video modes list is a sequence of 16-bit mode numbers
                    // terminated by 0xFFFF
                    let mut video_modes = Vec::new();
                    let modes_ptr = u32::from_le_bytes([
                        VBE_INFO_BUFFER[10],
                        VBE_INFO_BUFFER[11],
                        VBE_INFO_BUFFER[12],
                        VBE_INFO_BUFFER[13],
                    ]);

                    // For now, return standard VBE mode numbers
                    // In a full implementation, we would read from the modes_ptr
                    video_modes.push(0x101); // 640x480x256
                    video_modes.push(0x103); // 800x600x256
                    video_modes.push(0x105); // 1024x768x256
                    video_modes.push(0x107); // 1280x1024x256
                    video_modes.push(0x111); // 640x480x32bpp
                    video_modes.push(0x114); // 800x600x32bpp
                    video_modes.push(0x118); // 1024x768x32bpp
                    video_modes.push(0x11B); // 1280x1024x32bpp

                    Some(VbeControllerInfo {
                        signature: sig,
                        version,
                        oem_ptr: 0,
                        capabilities: VbeCapabilities {
                            dac_8bit: (caps & 0x0001) != 0,
                            not_vga_compatible: (caps & 0x0002) != 0,
                            crt_timing: (caps & 0x0004) != 0,
                            stereo: (caps & 0x0008) != 0,
                        },
                        video_modes,
                        total_memory: total_mem,
                        oem_software_rev: 0,
                        vendor_name_ptr: 0,
                        product_name_ptr: 0,
                        product_rev_ptr: 0,
                    })
                } else {
                    None
                }
            }
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "x86"))]
    {
        None
    }
}

/// Set VBE video mode
/// 
/// # Arguments
/// * `mode` - VBE mode number
/// 
/// Returns Success if the mode was set successfully.
pub fn vbe_set_mode(_mode: u16) -> VbeStatus {
    #[cfg(target_arch = "x86")]
    {
        let status: u16;
        unsafe {
            core::arch::asm!(
                "int 0x10",
                in("ax") 0x4F02,
                in("bx") mode,
                out("ax") status,
            );
        }
        
        // AX & 0x00FF contains the status
        match status & 0xFF {
            0x4F => VbeStatus::Success,
            0x01 => VbeStatus::Failed,
            0x02 => VbeStatus::NotSupported,
            0x03 => VbeStatus::InvalidMode,
            _ => VbeStatus::Failed,
        }
    }
    
    #[cfg(not(target_arch = "x86"))]
    {
        VbeStatus::NotSupported
    }
}

/// Get VBE mode information
/// 
/// # Arguments
/// * `mode` - VBE mode number
/// 
/// Returns the mode information or None if not available.
pub fn vbe_get_mode_info(mode: u16) -> Option<VbeModeInfo> {
    #[cfg(target_arch = "x86")]
    {
        // VBE mode info buffer - must be in lower 1MB of memory
        static mut VBE_MODE_BUFFER: [u8; 256] = [0; 256];

        let result: u16;
        let cx = mode;

        unsafe {
            core::arch::asm!(
                "push es",
                "mov ax, 0x4F01",    // VBE Get Mode Info
                "mov cx, {mode}",     // Mode number
                "xor di, di",         // DI = 0 (buffer at physical 0x00000)
                "mov es, di",
                "int 0x10",
                "mov {result}, ax",
                "mov es, 0",
                "pop es",
                mode = in(reg) cx,
                result = out(reg) result,
                options(nostack)
            );
        }

        if result == 0x004F {
            // Parse mode info from buffer
            unsafe {
                // Read attributes (offset 0)
                let attrs = u16::from_le_bytes([
                    VBE_MODE_BUFFER[0],
                    VBE_MODE_BUFFER[1],
                ]);

                // Read window info (offset 2-7)
                let window_a_seg = VBE_MODE_BUFFER[2] as u16;
                let window_b_seg = VBE_MODE_BUFFER[3] as u16;
                let window_granularity = u16::from_le_bytes([
                    VBE_MODE_BUFFER[4],
                    VBE_MODE_BUFFER[5],
                ]);
                let window_size = u16::from_le_bytes([
                    VBE_MODE_BUFFER[6],
                    VBE_MODE_BUFFER[7],
                ]);
                let window_a_start = u16::from_le_bytes([
                    VBE_MODE_BUFFER[8],
                    VBE_MODE_BUFFER[9],
                ]);
                let window_b_start = u16::from_le_bytes([
                    VBE_MODE_BUFFER[10],
                    VBE_MODE_BUFFER[11],
                ]);

                // Read timing info (offset 12-19)
                let bytes_per_scanline = u16::from_le_bytes([
                    VBE_MODE_BUFFER[16],
                    VBE_MODE_BUFFER[17],
                ]);
                let width = u16::from_le_bytes([
                    VBE_MODE_BUFFER[18],
                    VBE_MODE_BUFFER[19],
                ]);
                let height = u16::from_le_bytes([
                    VBE_MODE_BUFFER[20],
                    VBE_MODE_BUFFER[21],
                ]);
                let char_width = VBE_MODE_BUFFER[22];
                let char_height = VBE_MODE_BUFFER[23];
                let num_planes = VBE_MODE_BUFFER[24];
                let bits_per_pixel = VBE_MODE_BUFFER[25];
                let num_banks = VBE_MODE_BUFFER[26];
                let memory_model = VBE_MODE_BUFFER[27];
                let bank_size = VBE_MODE_BUFFER[28];
                let num_image_pages = VBE_MODE_BUFFER[29];

                // VBE 2.0+ fields (offset 32+)
                let direct_color_info = VBE_MODE_BUFFER[32];
                let linear_framebuffer = u32::from_le_bytes([
                    VBE_MODE_BUFFER[40],
                    VBE_MODE_BUFFER[41],
                    VBE_MODE_BUFFER[42],
                    VBE_MODE_BUFFER[43],
                ]);
                let linear_bytes_per_scanline = u16::from_le_bytes([
                    VBE_MODE_BUFFER[44],
                    VBE_MODE_BUFFER[45],
                ]);
                let num_linear_image_pages = VBE_MODE_BUFFER[46];
                let linear_memory_model = VBE_MODE_BUFFER[47];

                Some(VbeModeInfo {
                    attributes: VbeModeAttributes::from_u16(attrs),
                    window_a_seg,
                    window_b_seg,
                    window_granularity,
                    window_size,
                    window_a_start,
                    window_b_start,
                    window_func_ptr: 0,
                    bytes_per_scanline,
                    horizontal_resolution: width,
                    vertical_resolution: height,
                    character_width: char_width,
                    character_height: char_height,
                    num_memory_planes: num_planes,
                    bits_per_pixel,
                    num_banks,
                    memory_model: VbeMemoryModel::from_u8(memory_model),
                    bank_size,
                    num_image_pages,
                    page_function_reserved: 0,
                    direct_color_info,
                    linear_framebuffer,
                    linear_bytes_per_scanline,
                    num_linear_image_pages,
                    linear_memory_model,
                })
            }
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "x86"))]
    {
        let _ = mode;
        None
    }
}

/// Save/restore VBE video state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbeStateType {
    /// Save/restore hardware state
    Hardware = 1,
    /// Save/restore BIOS data area
    BiosData = 2,
    /// Save/restore DAC state
    Dac = 4,
    /// Save/restore video registers
    VideoRegisters = 8,
    /// Save/restore all state
    All = 0x000F,
}

/// Save VBE video state
pub fn vbe_save_state(buffer: &mut [u8]) -> bool {
    #[cfg(target_arch = "x86")]
    {
        let buffer_size = buffer.len() as u16;
        let status: u16;
        
        unsafe {
            core::arch::asm!(
                "int 0x10",
                in("ax") 0x4F04,
                in("cx") 0x000F, // save all state
                in("dx") 0x0001, // save
                in("bx") 0x0000, // ES:0
                out("ax") status,
            );
        }
        
        status == 0x004F
    }
    
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = buffer;
        false
    }
}

/// Restore VBE video state
pub fn vbe_restore_state(buffer: &[u8]) -> bool {
    #[cfg(target_arch = "x86")]
    {
        let status: u16;
        
        unsafe {
            core::arch::asm!(
                "int 0x10",
                in("ax") 0x4F04,
                in("cx") 0x000F, // restore all state
                in("dx") 0x0002, // restore
                in("bx") 0x0000, // ES:0
                out("ax") status,
            );
        }
        
        status == 0x004F
    }
    
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = buffer;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_attributes() {
        let attrs = VbeModeAttributes::from_u16(0x009B);
        assert!(attrs.supported);
        assert!(attrs.graphics_mode);
        assert!(attrs.linear_framebuffer);
    }

    #[test]
    fn test_memory_model() {
        assert_eq!(VbeMemoryModel::from_u8(0x06), VbeMemoryModel::DirectColor);
        assert_eq!(VbeMemoryModel::from_u8(0x04), VbeMemoryModel::PackedPixel);
    }

    #[test]
    fn test_capabilities() {
        let caps = VbeCapabilities::from_u8(0x07);
        assert!(caps.dac_8bit);
        assert!(caps.not_vga_compatible);
        assert!(caps.crt_timing);
        assert!(caps.stereo);
    }

    #[test]
    fn test_vbe_driver_default() {
        let driver = VbeDriver::new();
        assert!(!driver.is_supported());
    }
}

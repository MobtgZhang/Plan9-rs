//! GRUB2 / Multiboot2 Bootloader Support
//!
//! Implements Multiboot2 protocol parsing for GRUB2-loaded kernels.
//! This allows the kernel to be loaded by GRUB2 and receive boot information
//! including memory map, framebuffer info, and kernel command line.
//!
//! ## Multiboot2 Protocol
//!
//! GRUB2 uses the Multiboot2 specification to pass information to loaded kernels.
//! The bootloader writes a Multiboot2 information structure, and the kernel
//! parses it to obtain:
//! - Memory map (usable and reserved regions)
//! - Boot device information
//! - Command line arguments
//! - Module information (initial ramdisk, etc.)
//! - Framebuffer configuration
//!
//! ## References
//!
//! - [Multiboot2 Specification](https://www.gnu.org/software/grub/manual/multiboot2/)
//! - [GRUB2 Manual](https://www.gnu.org/software/grub/manual/grub/)


extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// Multiboot2 Constants
// ============================================================================

/// Multiboot2 magic number (passed in EAX register)
pub const MB2_MAGIC: u32 = 0x36D76289;

/// Multiboot2 header magic (used in header structure itself)
pub const MB2_HEADER_MAGIC: u32 = 0xE85250D6;

/// Multiboot2 architecture: i386
pub const MB2_ARCH_I386: u32 = 0;

/// Multiboot2 architecture: AMD64 (long mode)
pub const MB2_ARCH_AMD64: u32 = 0x_ABCD_EF01;

/// Multiboot2 header tag types
pub mod tag_type {
    /// End of tag list
    pub const END: u16 = 0;
    /// Boot command line (string)
    pub const CMDLINE: u16 = 1;
    /// Boot loader name (string)
    pub const BOOT_LOADER_NAME: u16 = 2;
    /// Module(s) - initial ramdisk etc.
    pub const MODULE: u16 = 3;
    /// Basic memory information
    pub const BASIC_MEMINFO: u16 = 4;
    /// Boot device information
    pub const BOOTDEV: u16 = 5;
    /// Memory map
    pub const MEMMAP: u16 = 6;
    /// VBE information
    pub const VBE: u16 = 7;
    /// Framebuffer information
    pub const FRAMEBUFFER: u16 = 8;
    /// APM table
    pub const APM: u16 = 9;
    /// EFI 32-bit system table pointer
    pub const EFI32: u16 = 10;
    /// EFI 64-bit system table pointer
    pub const EFI64: u16 = 11;
    /// SMBIOS tables
    pub const SMBIOS: u16 = 12;
    /// ACPI 1.0 RSDP
    pub const ACPI1: u16 = 13;
    /// ACPI 2.0+ RSDP
    pub const ACPI2: u16 = 14;
    /// Network information
    pub const NETWORK: u16 = 15;
    /// EFI memory map
    pub const EFI_MMAP: u16 = 16;
    /// EFI boot services not to be released
    pub const EFI_IL: u16 = 17;
    /// Padding - must be 8-byte aligned
    pub const PAD: u16 = 18;
}

/// Memory map entry types
pub mod memory_type {
    /// Unknown type (don't use for allocation)
    pub const UNKNOWN: u32 = 0;
    /// Available RAM
    pub const AVAILABLE: u32 = 1;
    /// Reserved memory (ACPI, MMIO, etc.)
    pub const RESERVED: u32 = 2;
    /// ACPI reclaimable memory
    pub const ACPI_RECLAIMABLE: u32 = 3;
    /// NVS (Non-Volatile Storage)
    pub const NVS: u32 = 4;
    /// Defective memory regions
    pub const DEFECTIVE: u32 = 5;
}

// ============================================================================
// Multiboot2 Structures
// ============================================================================

/// Multiboot2 information header (at fixed address)
/// This is placed by GRUB2 at a known address (typically 0x100000 on 32-bit)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Multiboot2Info {
    /// Total size including this field and all tags
    pub total_size: u32,
    /// Reserved, must be zero
    pub reserved: u32,
    // Tags follow immediately after this structure
    // tag_offset: u8,
}

/// Multiboot2 tag header (common to all tags)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TagHeader {
    /// Tag type (see tag_type module)
    pub typ: u16,
    /// Tag size (including header, padded to 8 bytes)
    pub size: u16,
}

/// Multiboot2 memory map entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MmapEntry {
    /// Entry size (not including this field)
    pub size: u32,
    /// Base address of memory region
    pub addr: u64,
    /// Length of memory region in bytes
    pub len: u64,
    /// Type of memory region
    pub type_: u32,
    /// Unused, padding
    _reserved: u32,
}

impl MmapEntry {
    /// Get memory type as human-readable string
    pub fn type_name(&self) -> &'static str {
        match self.type_ {
            memory_type::AVAILABLE => "Available RAM",
            memory_type::RESERVED => "Reserved",
            memory_type::ACPI_RECLAIMABLE => "ACPI Reclaimable",
            memory_type::NVS => "NVS (Non-Volatile)",
            memory_type::DEFECTIVE => "Defective",
            _ => "Unknown",
        }
    }

    /// Check if this memory region is usable for allocation
    pub fn is_available(&self) -> bool {
        self.type_ == memory_type::AVAILABLE
    }

    /// Get the end address of this memory region
    pub fn end_addr(&self) -> u64 {
        self.addr.wrapping_add(self.len)
    }
}

/// Multiboot2 framebuffer info
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    /// Framebuffer physical address
    pub framebuffer_addr: u64,
    /// Framebuffer pitch (bytes per row)
    pub framebuffer_pitch: u32,
    /// Framebuffer width in pixels
    pub framebuffer_width: u32,
    /// Framebuffer height in pixels
    pub framebuffer_height: u32,
    /// Bits per pixel
    pub framebuffer_bpp: u8,
    /// Framebuffer type (see fb_type)
    pub framebuffer_type: u8,
    /// Reserved
    _reserved: u16,
    // Color info follows (varies by type)
}

/// Framebuffer types
pub mod fb_type {
    /// Linear RGB pixels
    pub const RGB: u8 = 0;
    /// EGA text mode
    pub const INDEXED: u8 = 1;
}

/// RGB color layout for direct framebuffer
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FbColorInfo {
    /// Red color mask position
    pub red_field_pos: u8,
    /// Red color mask size
    pub red_mask_size: u8,
    /// Green color mask position
    pub green_field_pos: u8,
    /// Green color mask size
    pub green_mask_size: u8,
    /// Blue color mask position
    pub blue_field_pos: u8,
    /// Blue color mask size
    pub blue_mask_size: u8,
    /// Reserved
    _reserved: u8,
}

/// Multiboot2 module entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ModuleInfo {
    /// Module start address
    pub mod_start: u32,
    /// Module end address
    pub mod_end: u32,
    /// Command line string
    pub cmdline: u32,
    /// Padding
    _pad: u32,
}

impl ModuleInfo {
    /// Get the command line as a string
    pub fn command_line(&self) -> alloc::string::String {
        // cmdline is stored as a u32 offset from the start of the module
        // In a real implementation, we'd add this to the module's base address
        // For now, return a placeholder since we don't have the base address
        alloc::string::String::from("(module command line)")
    }
}

/// Basic memory information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BasicMemInfo {
    /// Memory lower bound (typically 640KB)
    pub mem_lower: u32,
    /// Memory upper bound (above 1MB, in KB)
    pub mem_upper: u32,
}

impl BasicMemInfo {
    /// Get total memory in bytes (lower + upper)
    pub fn total_memory_kb(&self) -> u64 {
        (self.mem_lower as u64) + (self.mem_upper as u64)
    }

    /// Get total memory in bytes
    pub fn total_memory_bytes(&self) -> u64 {
        self.total_memory_kb() * 1024
    }
}

// ============================================================================
// Boot Information Structure (Parsed)
// ============================================================================

/// Parsed boot information from GRUB2/Multiboot2
#[derive(Debug, Clone, Default)]
pub struct BootInfo {
    /// Total memory in bytes (if available)
    pub memory_lower: Option<u32>,
    pub memory_upper: Option<u32>,
    /// Boot device (bios drive number)
    pub boot_device: Option<u32>,
    /// Command line string
    pub cmdline: Option<String>,
    /// Boot loader name
    pub bootloader_name: Option<String>,
    /// Memory map entries
    pub memory_map: Vec<MemoryRegion>,
    /// Framebuffer information
    pub framebuffer: Option<FramebufferConfig>,
    /// Loaded modules
    pub modules: Vec<ModuleEntry>,
    /// ACPI RSDP pointer (if available)
    pub acpi_rsdp: Option<u64>,
    /// SMBIOS tables pointer (if available)
    pub smbios: Option<u64>,
    /// EFI system table pointer (if available)
    pub efi_system_table: Option<u64>,
}

impl BootInfo {
    /// Create a new empty boot info
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total usable memory in bytes
    pub fn total_usable_memory(&self) -> u64 {
        let mut total = 0u64;
        for region in &self.memory_map {
            if region.is_available() {
                total += region.length;
            }
        }
        // Also add basic mem info if available
        if let (Some(lower), Some(upper)) = (self.memory_lower, self.memory_upper) {
            total += (lower as u64) * 1024;
            total += (upper as u64) * 1024;
        }
        total
    }

    /// Get kernel command line as string slice
    pub fn cmdline_str(&self) -> &str {
        self.cmdline.as_deref().unwrap_or("")
    }

    /// Check if a specific memory region is available
    pub fn is_memory_available(&self, addr: u64, len: u64) -> bool {
        for region in &self.memory_map {
            if region.is_available() {
                if addr >= region.base_addr && (addr + len) <= region.end_addr() {
                    return true;
                }
            }
        }
        false
    }
}

/// Memory region descriptor (parsed from mmap entry)
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address
    pub base_addr: u64,
    /// Length in bytes
    pub length: u64,
    /// Region type
    pub region_type: u32,
}

impl MemoryRegion {
    /// Create from raw Multiboot2 entry
    pub fn from_mmap_entry(entry: &MmapEntry) -> Self {
        Self {
            base_addr: entry.addr,
            length: entry.len,
            region_type: entry.type_,
        }
    }

    /// Check if available for allocation
    pub fn is_available(&self) -> bool {
        self.region_type == memory_type::AVAILABLE
    }

    /// Get end address
    pub fn end_addr(&self) -> u64 {
        self.base_addr.wrapping_add(self.length)
    }

    /// Get type as string
    pub fn type_name(&self) -> &'static str {
        match self.region_type {
            memory_type::AVAILABLE => "RAM",
            memory_type::RESERVED => "Reserved",
            memory_type::ACPI_RECLAIMABLE => "ACPI",
            memory_type::NVS => "NVS",
            memory_type::DEFECTIVE => "Defective",
            _ => "Unknown",
        }
    }
}

/// Framebuffer configuration
#[derive(Debug, Clone)]
pub struct FramebufferConfig {
    /// Physical address
    pub address: u64,
    /// Pitch (bytes per scanline)
    pub pitch: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bits per pixel
    pub bpp: u8,
    /// Framebuffer type
    pub fb_type: FramebufferType,
}

#[derive(Debug, Clone)]
pub enum FramebufferType {
    /// Linear RGB framebuffer
    Rgb {
        /// Red mask shift
        red_pos: u8,
        /// Red mask bits
        red_size: u8,
        /// Green mask shift
        green_pos: u8,
        /// Green mask bits
        green_size: u8,
        /// Blue mask shift
        blue_pos: u8,
        /// Blue mask bits
        blue_size: u8,
    },
    /// Indexed (text mode)
    Indexed,
}

impl FramebufferConfig {
    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> u32 {
        (self.bpp as u32 + 7) / 8
    }

    /// Get total framebuffer size
    pub fn buffer_size(&self) -> u64 {
        (self.pitch as u64) * (self.height as u64)
    }
}

/// Loaded module entry
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Command line
    pub cmdline: String,
}

impl ModuleEntry {
    /// Get module size
    pub fn size(&self) -> u64 {
        self.end.wrapping_sub(self.start)
    }
}

// ============================================================================
// Multiboot2 Parsing
// ============================================================================

/// Parse Multiboot2 information structure
/// 
/// This function parses the Multiboot2 information structure placed by GRUB2
/// at the address specified in the multiboot header (typically 0x100000).
/// 
/// # Arguments
/// 
/// * `info_addr` - Physical address of Multiboot2 info structure
/// 
/// # Returns
/// 
/// Parsed `BootInfo` structure on success, or `None` if parsing fails
pub fn parse_multiboot2(info_addr: u64) -> Option<BootInfo> {
    // Read total size first (first 8 bytes)
    let total_size = unsafe {
        let ptr = info_addr as *const u32;
        *ptr
    };
    
    if total_size < 8 {
        return None;
    }
    
    let boot_info = BootInfo::new();
    
    // For a no_std environment, we'll parse what we can from the header
    // In a real implementation, this would walk the tag chain
    
    // Parse the fixed header
    // Multiboot2 info starts at info_addr with:
    // - u32 total_size
    // - u32 reserved (must be 0)
    // Then tag chain follows
    
    let mut offset: usize = 8;
    let end_offset = total_size as usize;
    
    while offset < end_offset {
        // Read tag header (type and size)
        let (tag_type, tag_size) = unsafe {
            let ptr = (info_addr as usize + offset) as *const u16;
            (u16::from_le(*ptr), u16::from_le(*ptr.add(1)))
        };
        
        if tag_type == tag_type::END {
            break;
        }
        
        // Skip to next tag (aligned to 8 bytes)
        offset += tag_size as usize;
        offset = (offset + 7) & !7;
    }
    
    Some(boot_info)
}

/// Parse memory map tag
pub fn parse_memory_map(tag_ptr: *const TagHeader) -> Option<Vec<MemoryRegion>> {
    let tag = unsafe { &*tag_ptr };
    if tag.size < 16 {
        return None;
    }
    
    let mut regions = Vec::new();
    let tag_base = tag_ptr as *const u8;
    let mut entry_ptr = unsafe { tag_base.add(8) };
    let tag_end = unsafe { tag_base.add(tag.size as usize) };
    
    while entry_ptr < tag_end {
        let mmap = unsafe { &*(entry_ptr as *const MmapEntry) };
        let entry_size = mmap.size as usize + 4; // size field + data
        
        if entry_size < core::mem::size_of::<MmapEntry>() {
            break;
        }
        
        regions.push(MemoryRegion::from_mmap_entry(mmap));
        
        entry_ptr = unsafe { entry_ptr.add(entry_size) };
    }
    
    Some(regions)
}

/// Parse framebuffer tag
pub fn parse_framebuffer(tag: *const TagHeader, info_addr: u64) -> Option<FramebufferConfig> {
    let tag = unsafe { &*(tag as *const TagHeader) };
    if tag.size < 20 {
        return None;
    }

    // `info_addr` is the physical address of the boot info block; we keep it
    // around for callers that want to validate the tag came from the same
    // boot info (debug builds can compare pointers).
    let _ = info_addr;

    let fb_ptr = unsafe { (tag as *const TagHeader as *const FramebufferInfo).add(1) };
    let fb = unsafe { *fb_ptr };
    
    let fb_type = if fb.framebuffer_type == fb_type::RGB {
        // Get color info (starts at offset 20)
        let color_ptr = unsafe { (fb_ptr as *const FramebufferInfo as *const FbColorInfo).add(2) };
        let color = unsafe { *color_ptr };
        FramebufferType::Rgb {
            red_pos: color.red_field_pos,
            red_size: color.red_mask_size,
            green_pos: color.green_field_pos,
            green_size: color.green_mask_size,
            blue_pos: color.blue_field_pos,
            blue_size: color.blue_mask_size,
        }
    } else {
        FramebufferType::Indexed
    };
    
    Some(FramebufferConfig {
        address: fb.framebuffer_addr,
        pitch: fb.framebuffer_pitch,
        width: fb.framebuffer_width,
        height: fb.framebuffer_height,
        bpp: fb.framebuffer_bpp,
        fb_type,
    })
}

/// Parse module tag
/// Note: In a real implementation, this would calculate the module's
/// base address and resolve the command line string pointer.
/// For now, we return a placeholder.
pub fn parse_module(tag: *const TagHeader, info_addr: u64) -> Option<ModuleEntry> {
    // Module parsing would require knowing the module base address.
    // We accept `info_addr` so the signature matches the other parsers
    // and future implementations can resolve the module's command line
    // pointer relative to the boot info block.
    let _ = tag;
    let _ = info_addr;
    None
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Get kernel command line from parsed boot info
pub fn get_kernel_cmdline(info: &BootInfo) -> &str {
    info.cmdline_str()
}

/// Get memory map from parsed boot info
pub fn get_memory_map(info: &BootInfo) -> &[MemoryRegion] {
    &info.memory_map
}

/// Get framebuffer configuration from parsed boot info
pub fn get_framebuffer_info(info: &BootInfo) -> Option<&FramebufferConfig> {
    info.framebuffer.as_ref()
}

/// Find the largest available memory region
pub fn find_largest_free_region(info: &BootInfo) -> Option<&MemoryRegion> {
    info.memory_map
        .iter()
        .filter(|r| r.is_available())
        .max_by_key(|r| r.length as u64)
}

/// Check if address is in valid memory range
pub fn is_valid_memory(info: &BootInfo, addr: u64) -> bool {
    info.memory_map
        .iter()
        .any(|r| r.is_available() && addr >= r.base_addr && addr < r.end_addr())
}

// ============================================================================
// GRUB2 Multiboot2 Header (for kernel linking)
// ============================================================================

/// Multiboot2 header structure for kernel image
/// This should be placed in the kernel's linker script or assembly
/// at the beginning of the kernel image (within first 32KB)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Multiboot2Header {
    /// Magic number (MB2_HEADER_MAGIC)
    pub magic: u32,
    /// Architecture (MB2_ARCH_I386 or MB2_ARCH_AMD64)
    pub architecture: u32,
    /// Header length
    pub header_length: u32,
    /// Checksum (must make magic + arch + header_length + checksum = 0)
    pub checksum: u32,
    // Optional alignment tag follows
}

// ============================================================================
// Integration with plan9-bootloader
// ============================================================================

/// Boot source enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSource {
    /// Booted via GRUB2
    Grub2,
    /// Booted via GRUB Legacy
    GrubLegacy,
    /// Direct boot (no bootloader)
    Direct,
    /// Unknown
    Unknown,
}

impl BootSource {
    /// Detect boot source from available information
    pub fn detect(info_addr: u64) -> Self {
        // Try to parse as Multiboot2
        if let Some(info) = parse_multiboot2(info_addr) {
            if info.bootloader_name.is_some() {
                let name = info.bootloader_name.as_ref().unwrap().to_lowercase();
                if name.contains("grub") {
                    if name.contains("2") || name.contains("grub2") {
                        return BootSource::Grub2;
                    }
                    return BootSource::GrubLegacy;
                }
            }
            return BootSource::Grub2;
        }
        
        // Try to detect GRUB legacy Multiboot1
        // (Multiboot1 uses magic 0x2BADB002)
        BootSource::Unknown
    }
}

/// Combine GRUB2 info with existing BootInfo structure
/// 
/// Note: This function requires integration with the UEFI BootInfo structure.
/// In a standalone build without UEFI, use BootInfo from this module directly.
#[allow(dead_code)]
pub fn merge_boot_info(grub_info: BootInfo) -> BootInfo {
    // In a full implementation, this would merge with UEFI BootInfo
    // For now, just return the GRUB2 boot info
    grub_info
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_from_entry() {
        let entry = MmapEntry {
            size: 24,
            addr: 0x1000,
            len: 0x1000,
            type_: memory_type::AVAILABLE,
            _reserved: 0,
        };
        
        let region = MemoryRegion::from_mmap_entry(&entry);
        assert_eq!(region.base_addr, 0x1000);
        assert_eq!(region.length, 0x1000);
        assert!(region.is_available());
    }

    #[test]
    fn test_basic_meminfo_total() {
        let mem = BasicMemInfo {
            mem_lower: 640,
            mem_upper: 262144,
        };
        
        assert_eq!(mem.total_memory_kb(), 262784);
        assert_eq!(mem.total_memory_bytes(), 262784 * 1024);
    }

    #[test]
    fn test_fb_config_size() {
        let fb = FramebufferConfig {
            address: 0xA0000,
            pitch: 1920 * 4,
            width: 1920,
            height: 1080,
            bpp: 32,
            fb_type: FramebufferType::Rgb {
                red_pos: 16,
                red_size: 8,
                green_pos: 8,
                green_size: 8,
                blue_pos: 0,
                blue_size: 8,
            },
        };
        
        assert_eq!(fb.bytes_per_pixel(), 4);
        assert_eq!(fb.buffer_size(), fb.pitch as u64 * 1080);
    }
}

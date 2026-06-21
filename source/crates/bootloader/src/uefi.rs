//! UEFI Bootloader Support
//!
//! Implements UEFI boot environment detection and setup for the kernel.

#![no_std]

extern crate alloc;

// ============================================================================
// UEFI Constants
// ============================================================================

/// UEFI GUIDs
pub mod guid {
    use super::*;

    /// Global unique identifier
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

    impl Guid {
        /// EFI System Table
        pub const SYSTEM_TABLE: Guid = Guid(0x4B5C6F70, 0x7232, 0x204B, [0x65, 0x72, 0x6E, 0x65, 0x6C, 0x00, 0x00, 0x00]);

        /// EFI Loaded Image Protocol
        pub const LOADED_IMAGE: Guid = Guid(0x5B1B31A1, 0x9562, 0x11D2, [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

        /// EFI Device Path Protocol
        pub const DEVICE_PATH: Guid = Guid(0x09576E91, 0x6D3F, 0x11D2, [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

        /// EFI Block IO Protocol
        pub const BLOCK_IO: Guid = Guid(0x016A31B5, 0x6F42, 0x11D2, [0x86, 0x5C, 0x00, 0x00, 0x10, 0xE3, 0x32, 0x0B]);

        /// EFI File System Info
        pub const FILE_SYSTEM_INFO: Guid = Guid(0x09576E92, 0x6D3F, 0x11D2, [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

        /// EFI File System Volume Label ID
        pub const FILE_SYSTEM_VOLUME_LABEL: Guid = Guid(0xDB47D7D3, 0xFE81, 0x11D3, [0x9A, 0x35, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D]);

        /// EFI Simple Text Output Protocol
        pub const TEXT_OUTPUT: Guid = Guid(0x387477C2, 0x69C7, 0x11D2, [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

        /// EFI Simple Text Input Protocol
        pub const TEXT_INPUT: Guid = Guid(0x387477C1, 0x69C7, 0x11D2, 0x8E, 0x39, [0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);

        /// EFI Graphics Output Protocol
        pub const GRAPHICS_OUTPUT: Guid = Guid(0x9042A9DE, 0x23DC, 0x4A38, [0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A]);

        /// EFI Memory Type Information
        pub const MEMORY_TYPE_INFO: Guid = Guid(0x4C19049F, 0x4137, 0x4DD3, [0x9E, 0xC2, 0x53, 0xEB, 0x68, 0xFD, 0xFC, 0x94]);

        /// Empty GUID (all zeros)
        pub const EMPTY: Guid = Guid(0, 0, 0, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    impl Default for Guid {
        fn default() -> Self {
            Guid::EMPTY
        }
    }
}

use guid::Guid;

// ============================================================================
// UEFI Types
// ============================================================================

/// UEFI handle
pub type Handle = usize;

/// UEFI status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success = 0,
    LoadError = 1,
    InvalidParameter = 2,
    Unsupported = 3,
    BadBufferSize = 4,
    BufferTooSmall = 5,
    NotReady = 6,
    DeviceError = 7,
    WriteProtected = 8,
    OutOfResources = 9,
    VolumeCorrupted = 10,
    VolumeFull = 11,
    NoMedia = 12,
    MediaChanged = 13,
    NotFound = 14,
    AccessDenied = 15,
    NoResponse = 16,
    NoMapping = 17,
    Timeout = 18,
    NotStarted = 19,
    AlreadyStarted = 20,
    Aborted = 21,
    IcmpError = 22,
    TftpError = 23,
    ProtocolError = 24,
    IncompatibleVersion = 25,
    SecurityViolation = 26,
    CrcError = 27,
    EndOfMedia = 28,
}

/// UEFI memory types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Reserved,
    LoaderCode,
    LoaderData,
    BootServicesCode,
    BootServicesData,
    RuntimeServicesCode,
    RuntimeServicesData,
    Conventional,
    Unusable,
    ACPIReclaim,
    ACPINVS,
    MemoryMappedIO,
    MemoryMappedIOPortSpace,
    PalCode,
    Persistent,
    MoreReliable,
    Max,
}

impl MemoryType {
    pub fn from_uefi(t: u32) -> Self {
        match t {
            0 => Self::Reserved,
            1 => Self::LoaderCode,
            2 => Self::LoaderData,
            3 => Self::BootServicesCode,
            4 => Self::BootServicesData,
            5 => Self::RuntimeServicesCode,
            6 => Self::RuntimeServicesData,
            7 => Self::Conventional,
            8 => Self::Unusable,
            9 => Self::ACPIReclaim,
            10 => Self::ACPINVS,
            11 => Self::MemoryMappedIO,
            12 => Self::MemoryMappedIOPortSpace,
            13 => Self::PalCode,
            14 => Self::Persistent,
            15 => Self::MoreReliable,
            _ => Self::Max,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Conventional | Self::Persistent)
    }
}

/// Memory descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryDescriptor {
    pub type_: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub num_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub fn memory_type(&self) -> MemoryType {
        MemoryType::from_uefi(self.type_)
    }

    pub fn size(&self) -> usize {
        (self.num_pages * 4096) as usize
    }
}

// ============================================================================
// UEFI Boot Services
// ============================================================================

/// Boot services table
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BootServices {
    _hdr: [u64; 4],
    // In practice, would have function pointers
}

impl BootServices {
    /// Exit boot services
    pub fn exit_boot_services(&mut self, _image_handle: Handle, _map_key: usize) -> Status {
        // In real implementation, would call ExitBootServices
        Status::Success
    }
}

/// UEFI System Table
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SystemTable {
    _hdr: [u64; 4],
    pub fw_vendor: usize,           // *const u16
    pub fw_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: usize,             // SIMPLE_TEXT_INPUT_PROTOCOL
    pub console_out_handle: Handle,
    pub con_out: usize,            // SIMPLE_TEXT_OUTPUT_PROTOCOL
    pub standard_error_handle: Handle,
    pub std_err: usize,            // SIMPLE_TEXT_OUTPUT_PROTOCOL
    pub runtime_services: usize,     // RUNTIME_SERVICES
    pub boot_services: usize,       // BOOT_SERVICES
    pub num_table_entries: u64,
    pub configuration_tables: usize, // EFI_CONFIGURATION_TABLE
}

impl SystemTable {
    /// Check if running in UEFI
    pub fn is_uefi(&self) -> bool {
        // Check for valid signature
        // In practice, would verify the header
        self.con_out != 0
    }

    /// Get boot services
    pub fn boot_services(&self) -> Option<&BootServices> {
        if self.boot_services != 0 {
            Some(unsafe { &*(self.boot_services as *const BootServices) })
        } else {
            None
        }
    }
}

// ============================================================================
// UEFI Boot Info
// ============================================================================

/// Boot information passed to kernel
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Memory map
    pub memory_map: Vec<MemoryDescriptor>,
    /// Kernel command line
    pub cmdline: String,
    /// Framebuffer info
    pub framebuffer: FramebufferInfo,
    /// RSDP pointer
    pub rsdp: u64,
    /// SMBIOS table
    pub smbios: u64,
    /// Boot drive
    pub boot_drive: u32,
}

impl BootInfo {
    /// Create new boot info
    pub fn new() -> Self {
        Self {
            memory_map: Vec::new(),
            cmdline: String::new(),
            framebuffer: FramebufferInfo::default(),
            rsdp: 0,
            smbios: 0,
            boot_drive: 0x80, // Default to first HDD
        }
    }

    /// Add memory region
    pub fn add_memory(&mut self, desc: MemoryDescriptor) {
        self.memory_map.push(desc);
    }

    /// Get total usable memory
    pub fn total_memory(&self) -> u64 {
        self.memory_map.iter()
            .filter(|m| m.memory_type().is_available())
            .map(|m| m.size() as u64)
            .sum()
    }

    /// Get kernel command line
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// Set kernel command line
    pub fn set_cmdline(&mut self, cmdline: &str) {
        self.cmdline = String::from(cmdline);
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Framebuffer information
#[derive(Debug, Clone, Default)]
pub struct FramebufferInfo {
    /// Framebuffer address
    pub addr: u64,
    /// Framebuffer size
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Pixels per scan line
    pub stride: u32,
    /// Pixel format
    pub format: PixelFormat,
}

/// Pixel formats
#[derive(Debug, Clone, Copy, Default)]
pub enum PixelFormat {
    #[default]
    Rgb,
    Bgr,
    Bitmask,
    BltOnly,
}

/// Pixel bitmask
#[derive(Debug, Clone, Copy, Default)]
pub struct PixelBitmask {
    pub red: u32,
    pub green: u32,
    pub blue: u32,
    pub reserved: u32,
}

// ============================================================================
// Bootloader Entry Point
// ============================================================================

/// Bootloader context
pub struct Bootloader {
    /// System table
    system_table: Option<SystemTable>,
    /// Boot info
    boot_info: BootInfo,
    /// Exit boot services called
    exited: bool,
}

impl Bootloader {
    /// Create new bootloader context
    pub fn new(system_table: SystemTable) -> Self {
        Self {
            system_table: Some(system_table),
            boot_info: BootInfo::new(),
            exited: false,
        }
    }

    /// Get boot info
    pub fn boot_info(&self) -> &BootInfo {
        &self.boot_info
    }

    /// Get mutable boot info
    pub fn boot_info_mut(&mut self) -> &mut BootInfo {
        &mut self.boot_info
    }

    /// Get system table
    pub fn system_table(&self) -> Option<&SystemTable> {
        self.system_table.as_ref()
    }

    /// Exit boot services and prepare for kernel
    pub fn exit_boot_services(&mut self, image_handle: Handle, map_key: usize) -> Status {
        if self.exited {
            return Status::AlreadyStarted;
        }

        if let Some(st) = &self.system_table {
            if let Some(bs) = st.boot_services() {
                let mut bs_mut = *bs; // Copy
                let status = bs_mut.exit_boot_services(image_handle, map_key);

                if status == Status::Success {
                    self.exited = true;
                    self.system_table = None;
                }

                return status;
            }
        }

        Status::Unsupported
    }

    /// Check if boot services are still available
    pub fn is_boot_services_available(&self) -> bool {
        !self.exited && self.system_table.is_some()
    }
}

// ============================================================================
// Kernel Loading
// ============================================================================

/// Loaded kernel image
#[derive(Debug, Clone)]
pub struct LoadedKernel {
    /// Physical address
    pub physical_addr: u64,
    /// Virtual address
    pub virtual_addr: u64,
    /// Size
    pub size: u64,
    /// Entry point
    pub entry: u64,
}

impl LoadedKernel {
    /// Create new loaded kernel
    pub fn new(physical: u64, virtual_addr: u64, size: u64, entry: u64) -> Self {
        Self {
            physical_addr: physical,
            virtual_addr,
            size,
            entry,
        }
    }
}

/// Load kernel from file
pub fn load_kernel(_path: &str) -> Result<LoadedKernel, ()> {
    // In real implementation, would:
    // 1. Open the kernel file
    // 2. Read the ELF header
    // 3. Allocate memory for each segment
    // 4. Copy segments to memory
    // 5. Relocate if necessary
    // 6. Return entry point and addresses

    Err(())
}

// ============================================================================
// Memory Map
// ============================================================================

/// Memory map iterator
pub struct MemoryMapIter {
    map: Vec<MemoryDescriptor>,
    index: usize,
}

impl MemoryMapIter {
    pub fn new(map: Vec<MemoryDescriptor>) -> Self {
        Self { map, index: 0 }
    }
}

impl Iterator for MemoryMapIter {
    type Item = MemoryDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.map.len() {
            let item = self.map[self.index];
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

impl MemoryMapIter {
    /// Filter by memory type
    pub fn available_only(self) -> impl Iterator<Item = MemoryDescriptor> {
        self.map.into_iter()
            .filter(|m| m.memory_type().is_available())
    }

    /// Filter by type
    pub fn by_type(self, mem_type: MemoryType) -> impl Iterator<Item = MemoryDescriptor> {
        self.map.into_iter()
            .filter(move |m| m.memory_type() == mem_type)
    }
}

// ============================================================================
// ACPI Detection
// ============================================================================

/// Find RSDP in memory
pub fn find_rsdp() -> Option<u64> {
    // Search EBDA
    // Search BIOS area
    None
}

/// Parse RSDP
pub fn parse_rsdp(_ptr: u64) -> Option<AcpiInfo> {
    // Parse ACPI tables
    None
}

/// ACPI information
#[derive(Debug, Clone, Default)]
pub struct AcpiInfo {
    pub rsdp: u64,
    pub xsdt: u64,
    pub rsdt: u64,
    pub version: u8,
}

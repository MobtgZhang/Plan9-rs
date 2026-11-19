//! Flash Memory Device Driver
//!
//! Implements support for NOR and NAND flash memory devices.
//! Flash memory is commonly used for boot ROM, BIOS, embedded storage, and SSDs.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Flash error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    /// Operation timeout
    Timeout,
    /// Write error
    WriteError,
    /// Erase error
    EraseError,
    /// Programming error
    ProgramError,
    /// Protection error
    ProtectionError,
    /// Device not found
    NotFound,
    /// Invalid operation
    InvalidOp,
    /// Unknown error
    Unknown,
}

/// Flash operation result
pub type FlashResult<T> = Result<T, FlashError>;

/// Flash device types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashType {
    /// NOR flash - random access read/write, block erase
    Nor,
    /// NAND flash - page-based access, block erase
    Nand,
    /// OneNAND - hybrid NOR+NAND
    OneNand,
    /// Parallel NOR
    ParallelNor,
    /// Serial NOR (SPI flash)
    SerialNor,
}

impl FlashType {
    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            FlashType::Nor => "NOR",
            FlashType::Nand => "NAND",
            FlashType::OneNand => "OneNAND",
            FlashType::ParallelNor => "Parallel NOR",
            FlashType::SerialNor => "Serial NOR",
        }
    }
}

/// Flash geometry information
#[derive(Debug, Clone, Copy)]
pub struct FlashGeometry {
    /// Total flash size in bytes
    pub size: usize,
    /// Size of each erase block in bytes
    pub erase_block_size: usize,
    /// Size of each page (NAND) or sector (NOR) in bytes
    pub page_size: usize,
    /// Number of erase blocks
    pub num_blocks: usize,
    /// Number of planes (for multi-plane operations)
    pub num_planes: usize,
}

impl FlashGeometry {
    /// Calculate number of pages per block
    pub fn pages_per_block(&self) -> usize {
        self.erase_block_size / self.page_size
    }
    
    /// Calculate number of blocks
    pub fn blocks(&self) -> usize {
        self.size / self.erase_block_size
    }
}

/// Flash device status
#[derive(Debug, Clone, Copy)]
pub struct FlashStatus {
    /// Write in progress
    pub write_busy: bool,
    /// Erase in progress
    pub erase_busy: bool,
    /// Device is in suspend state
    pub suspended: bool,
    /// Device is locked
    pub locked: bool,
}

/// Flash protection types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionType {
    /// No protection
    None,
    /// Top block protected
    TopBlock,
    /// Bottom block protected
    BottomBlock,
    /// Password protected
    Password,
    /// OTP (One-Time Programmable)
    Otp,
}

/// Flash partition information
#[derive(Debug, Clone)]
pub struct FlashPartition {
    /// Partition name
    pub name: &'static str,
    /// Start offset in bytes
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
    /// Is readable
    pub readable: bool,
    /// Is writable
    pub writable: bool,
    /// Is erasable
    pub erasable: bool,
}

impl FlashPartition {
    /// Check if offset is within partition
    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.offset && offset < self.offset + self.size
    }
    
    /// Get relative offset within partition
    pub fn relative_offset(&self, offset: usize) -> Option<usize> {
        if self.contains(offset) {
            Some(offset - self.offset)
        } else {
            None
        }
    }
}

/// Flash device command codes (JEDEC standard)
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum FlashCommand {
    // Common commands
    Read = 0xFF,
    ReadId = 0x90,
    ReadStatus = 0x70,
    ClearStatus = 0x50,
    WriteDisable = 0x04,
    WriteEnable = 0x06,

    // NOR flash commands
    BlockErase = 0xD8,
    ChipErase = 0xC7,
    PageProgram = 0x02,
    ReadQuery = 0xEB,

    // NAND flash commands
    PageRead = 0x00,
    PageReadConfirm = 0x30,
    BlockEraseStart = 0x60,
    BlockEraseConfirm = 0xD0,
    PageProgramStart = 0x80,
    PageProgramConfirm = 0x10,
    CopyBackRead = 0x35, // was 0x00 (collides with PageRead); use 0x35
    CopyBackProgram = 0x85,
}

/// Flash status-register bit positions. Kept separate from
/// [`FlashCommand`] because the numeric values are bit positions,
/// not opcode values, and reusing the same `repr(u8)` enum would
/// cause discriminant collisions.
pub mod flash_status {
    /// Operation in progress
    pub const OIP: u8 = 0x01;
    /// Write enable latch
    pub const WEL: u8 = 0x02;
    /// Block protect bits mask
    pub const WELBP: u8 = 0x3C;
    /// Erase/program error
    pub const EPE: u8 = 0x20;
    /// Erase suspend
    pub const ESO: u8 = 0x40;
    /// Program suspend
    pub const PSO: u8 = 0x80;
}

/// Flash device ID
#[derive(Debug, Clone, Copy)]
pub struct FlashId {
    /// Manufacturer ID
    pub manufacturer: u8,
    /// Device ID
    pub device_id: u8,
    /// Extended ID
    pub extended_id: u16,
    /// Flash type
    pub flash_type: FlashType,
}

impl FlashId {
    /// Check if ID is valid
    pub fn is_valid(&self) -> bool {
        self.manufacturer != 0xFF && self.manufacturer != 0x00
    }
    
    /// Get manufacturer name
    pub fn manufacturer_name(&self) -> &'static str {
        match self.manufacturer {
            0x01 => "AMD/Spansion",
            0x1C => "eMemory",
            0x1F => "Atmel",
            0x20 => "Micron",
            0x37 => "AMIC",
            0x40 => "Micron/Numonyx",
            0x68 => "Bohai",
            0x8C => "ESMT",
            0xA1 => "Fudan",
            0xC2 => "Macronix",
            0xC8 => "GigaDevice",
            0xD5 => "Nantronics",
            0xE0 => "Paragon",
            0xEF => "Winbond",
            0xF8 => "Fudan",
            0xFF => "Unknown",
            _ => "Unknown",
        }
    }
}

/// Flash device state
pub struct FlashDevice {
    /// Device name
    name: &'static str,
    /// Flash type
    flash_type: FlashType,
    /// Base address
    base_addr: usize,
    /// Geometry
    geometry: FlashGeometry,
    /// Partitions
    partitions: Vec<FlashPartition>,
    /// Is initialized
    initialized: AtomicBool,
    /// Is write protected
    write_protected: AtomicBool,
    /// Current status
    status: UnsafeCell<FlashStatus>,
}

unsafe impl Send for FlashDevice {}
unsafe impl Sync for FlashDevice {}

impl FlashDevice {
    /// Create a new flash device
    pub fn new(
        name: &'static str,
        flash_type: FlashType,
        base_addr: usize,
        geometry: FlashGeometry,
    ) -> Self {
        Self {
            name,
            flash_type,
            base_addr,
            geometry,
            partitions: Vec::new(),
            initialized: AtomicBool::new(false),
            write_protected: AtomicBool::new(false),
            status: UnsafeCell::new(FlashStatus {
                write_busy: false,
                erase_busy: false,
                suspended: false,
                locked: false,
            }),
        }
    }
    
    /// Create a new NOR flash device with common parameters
    pub fn new_nor(
        name: &'static str,
        base_addr: usize,
        size: usize,
        block_size: usize,
        page_size: usize,
    ) -> Self {
        let geometry = FlashGeometry {
            size,
            erase_block_size: block_size,
            page_size,
            num_blocks: size / block_size,
            num_planes: 1,
        };
        
        Self::new(name, FlashType::Nor, base_addr, geometry)
    }
    
    /// Create a new NAND flash device with common parameters
    pub fn new_nand(
        name: &'static str,
        base_addr: usize,
        size: usize,
        block_size: usize,
        page_size: usize,
    ) -> Self {
        let geometry = FlashGeometry {
            size,
            erase_block_size: block_size,
            page_size,
            num_blocks: size / block_size,
            num_planes: 1,
        };
        
        Self::new(name, FlashType::Nand, base_addr, geometry)
    }
    
    /// Create a new SPI NOR flash device
    pub fn new_spi_nor(
        name: &'static str,
        base_addr: usize,
        size: usize,
    ) -> Self {
        let geometry = FlashGeometry {
            size,
            erase_block_size: 4096, // Common SPI erase size
            page_size: 256,          // Common SPI page size
            num_blocks: size / 4096,
            num_planes: 1,
        };
        
        Self::new(name, FlashType::SerialNor, base_addr, geometry)
    }
    
    /// Get device name
    pub fn name(&self) -> &'static str {
        self.name
    }
    
    /// Get flash type
    pub fn flash_type(&self) -> FlashType {
        self.flash_type
    }
    
    /// Get geometry
    pub fn geometry(&self) -> &FlashGeometry {
        &self.geometry
    }
    
    /// Get base address
    pub fn base_addr(&self) -> usize {
        self.base_addr
    }
    
    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
    
    /// Check if write protected
    pub fn is_write_protected(&self) -> bool {
        self.write_protected.load(Ordering::SeqCst)
    }
    
    /// Set write protection
    pub fn set_write_protected(&self, protected: bool) {
        self.write_protected.store(protected, Ordering::SeqCst);
    }
    
    /// Add a partition
    pub fn add_partition(&mut self, partition: FlashPartition) {
        self.partitions.push(partition);
    }
    
    /// Get partitions
    pub fn partitions(&self) -> &[FlashPartition] {
        &self.partitions
    }
    
    /// Initialize the flash device
    pub fn init(&self) -> FlashResult<()> {
        if self.is_initialized() {
            return Ok(());
        }
        
        // TODO: Read ID and verify device
        // For now, just mark as initialized
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// Read data from flash
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> FlashResult<usize> {
        if !self.is_initialized() {
            return Err(FlashError::Unknown);
        }
        
        if offset >= self.geometry.size {
            return Err(FlashError::InvalidOp);
        }
        
        let max_read = (self.geometry.size - offset).min(buf.len());
        
        // For NOR flash, direct memory access
        if matches!(self.flash_type, FlashType::Nor | FlashType::ParallelNor) {
            let src = (self.base_addr + offset) as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), max_read);
            }
        } else {
            // For NAND/SPI, use indirect access
            // TODO: Implement indirect read
            for i in 0..max_read {
                buf[i] = self.read_byte(offset + i)?;
            }
        }
        
        Ok(max_read)
    }
    
    /// Read a single byte (for indirect access)
    fn read_byte(&self, offset: usize) -> FlashResult<u8> {
        let addr = self.base_addr + offset;
        Ok(unsafe { core::ptr::read_volatile(addr as *const u8) })
    }
    
    /// Write a single byte (for indirect access)
    fn write_byte(&self, offset: usize, value: u8) -> FlashResult<()> {
        if self.is_write_protected() {
            return Err(FlashError::ProtectionError);
        }
        
        let addr = self.base_addr + offset;
        unsafe {
            core::ptr::write_volatile(addr as *mut u8, value);
        }
        
        // Wait for operation to complete
        self.wait_ready(1000)?;
        
        Ok(())
    }
    
    /// Program a page (NAND) or write data (NOR)
    pub fn program(&self, offset: usize, data: &[u8]) -> FlashResult<()> {
        if !self.is_initialized() {
            return Err(FlashError::Unknown);
        }
        
        if self.is_write_protected() {
            return Err(FlashError::ProtectionError);
        }
        
        if offset >= self.geometry.size {
            return Err(FlashError::InvalidOp);
        }
        
        // Check alignment
        let page_mask = self.geometry.page_size - 1;
        if offset & page_mask != 0 {
            return Err(FlashError::InvalidOp); // Must be page-aligned
        }
        
        match self.flash_type {
            FlashType::Nor | FlashType::ParallelNor => {
                // NOR flash: direct write
                for (i, &byte) in data.iter().enumerate() {
                    self.write_byte(offset + i, byte)?;
                }
            }
            FlashType::Nand => {
                // NAND flash: page program
                self.nand_page_program(offset, data)?;
            }
            FlashType::SerialNor => {
                // SPI NOR flash
                self.spi_page_program(offset, data)?;
            }
            _ => return Err(FlashError::InvalidOp),
        }
        
        Ok(())
    }
    
    /// NAND page program
    fn nand_page_program(&self, offset: usize, data: &[u8]) -> FlashResult<()> {
        // TODO: Send page program commands
        let _ = offset;
        let _ = data;
        Ok(())
    }
    
    /// SPI NOR page program
    fn spi_page_program(&self, offset: usize, data: &[u8]) -> FlashResult<()> {
        // TODO: Use SPI interface to program
        let _ = offset;
        let _ = data;
        Ok(())
    }
    
    /// Erase a block
    pub fn erase_block(&self, block_num: usize) -> FlashResult<()> {
        if !self.is_initialized() {
            return Err(FlashError::Unknown);
        }
        
        if self.is_write_protected() {
            return Err(FlashError::ProtectionError);
        }
        
        if block_num >= self.geometry.blocks() {
            return Err(FlashError::InvalidOp);
        }
        
        let offset = block_num * self.geometry.erase_block_size;
        
        match self.flash_type {
            FlashType::Nor | FlashType::ParallelNor => {
                self.nor_block_erase(offset)?;
            }
            FlashType::Nand => {
                self.nand_block_erase(offset)?;
            }
            FlashType::SerialNor => {
                self.spi_block_erase(offset)?;
            }
            _ => return Err(FlashError::InvalidOp),
        }
        
        Ok(())
    }
    
    /// NOR block erase
    fn nor_block_erase(&self, offset: usize) -> FlashResult<()> {
        // TODO: Send erase commands
        let _ = offset;
        Ok(())
    }
    
    /// NAND block erase
    fn nand_block_erase(&self, offset: usize) -> FlashResult<()> {
        // TODO: Send block erase commands
        let _ = offset;
        Ok(())
    }
    
    /// SPI NOR block erase (typically 4KB, 32KB, or 64KB)
    fn spi_block_erase(&self, offset: usize) -> FlashResult<()> {
        // TODO: Send SPI erase command
        let _ = offset;
        Ok(())
    }
    
    /// Erase the entire chip
    pub fn chip_erase(&self) -> FlashResult<()> {
        if !self.is_initialized() {
            return Err(FlashError::Unknown);
        }
        
        if self.is_write_protected() {
            return Err(FlashError::ProtectionError);
        }
        
        match self.flash_type {
            FlashType::SerialNor => {
                // Send chip erase command
                self.write_byte(0, FlashCommand::WriteEnable as u8)?;
                self.write_byte(0, FlashCommand::ChipErase as u8)?;
                self.wait_ready(300000)?; // Chip erase can take minutes
            }
            _ => {
                // For other flash types, erase block by block
                for block in 0..self.geometry.blocks() {
                    self.erase_block(block)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Read flash ID
    pub fn read_id(&self) -> FlashResult<FlashId> {
        if !self.is_initialized() {
            return Err(FlashError::Unknown);
        }
        
        let mfr = self.read_byte(0x00)?;
        let dev = self.read_byte(0x01)?;
        let ext = ((self.read_byte(0x02)? as u16) << 8) | (self.read_byte(0x03)? as u16);
        
        Ok(FlashId {
            manufacturer: mfr,
            device_id: dev,
            extended_id: ext,
            flash_type: self.flash_type,
        })
    }
    
    /// Read status register
    pub fn read_status(&self) -> FlashResult<u8> {
        self.read_byte(0)
    }
    
    /// Wait for operation to complete
    fn wait_ready(&self, timeout_ms: usize) -> FlashResult<()> {
        for _ in 0..timeout_ms {
            let status = self.read_status()?;
            if status & flash_status::OIP == 0 {
                // Check for errors
                if status & flash_status::EPE != 0 {
                    return Err(FlashError::ProgramError);
                }
                return Ok(());
            }
        }
        
        Err(FlashError::Timeout)
    }
    
    /// Enable write operations
    pub fn write_enable(&self) -> FlashResult<()> {
        self.write_byte(0, FlashCommand::WriteEnable as u8)
    }
    
    /// Disable write operations
    pub fn write_disable(&self) -> FlashResult<()> {
        self.write_byte(0, FlashCommand::WriteDisable as u8)
    }
    
    /// Erase a region of flash
    pub fn erase(&self, offset: usize, length: usize) -> FlashResult<()> {
        let mut current = offset;
        let end = offset + length;
        
        while current < end {
            let block_num = current / self.geometry.erase_block_size;
            self.erase_block(block_num)?;
            current = (block_num + 1) * self.geometry.erase_block_size;
        }
        
        Ok(())
    }
    
    /// Write data to flash (with automatic erase)
    pub fn write(&self, offset: usize, data: &[u8]) -> FlashResult<()> {
        // TODO: Implement erase-before-write for NOR flash
        // For now, assume already erased
        self.program(offset, data)
    }
    
    /// Get status
    pub fn status(&self) -> FlashStatus {
        // Safe because we're just reading atomic values
        let status_ptr = self.status.get() as *const FlashStatus;
        unsafe { *status_ptr }
    }
}

// ============================================================================
// Common Flash Device Tables
// ============================================================================

/// Common SPI NOR flash devices
pub mod spi_nor_devices {
    use super::*;
    
    /// Winbond W25Qxx series
    pub const WINBOND_W25Q16: FlashId = FlashId {
        manufacturer: 0xEF,
        device_id: 0x40,
        extended_id: 0x15,
        flash_type: FlashType::SerialNor,
    };
    
    pub const WINBOND_W25Q32: FlashId = FlashId {
        manufacturer: 0xEF,
        device_id: 0x40,
        extended_id: 0x16,
        flash_type: FlashType::SerialNor,
    };
    
    pub const WINBOND_W25Q64: FlashId = FlashId {
        manufacturer: 0xEF,
        device_id: 0x40,
        extended_id: 0x17,
        flash_type: FlashType::SerialNor,
    };
    
    pub const WINBOND_W25Q128: FlashId = FlashId {
        manufacturer: 0xEF,
        device_id: 0x40,
        extended_id: 0x18,
        flash_type: FlashType::SerialNor,
    };
    
    /// Macronix MX25L series
    pub const MACRONIX_MX25L256: FlashId = FlashId {
        manufacturer: 0xC2,
        device_id: 0x20,
        extended_id: 0x19,
        flash_type: FlashType::SerialNor,
    };
    
    /// Create a W25Q64 device (8MB SPI flash)
    pub fn create_w25q64(base: usize) -> FlashDevice {
        FlashDevice::new_spi_nor("W25Q64", base, 8 * 1024 * 1024)
    }
    
    /// Create a W25Q128 device (16MB SPI flash)
    pub fn create_w25q128(base: usize) -> FlashDevice {
        FlashDevice::new_spi_nor("W25Q128", base, 16 * 1024 * 1024)
    }
}

// ============================================================================
// Flash Manager
// ============================================================================

use core::sync::atomic::AtomicPtr;

static FLASH_MANAGER: AtomicPtr<FlashManager> = AtomicPtr::new(core::ptr::null_mut());

/// Flash memory manager
pub struct FlashManager {
    /// Registered flash devices
    devices: Vec<Option<FlashDevice>>,
    /// Next device index
    next_index: usize,
}

impl FlashManager {
    /// Create a new flash manager
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            next_index: 0,
        }
    }
    
    /// Register a flash device
    pub fn register(&mut self, device: FlashDevice) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        
        while self.devices.len() <= index {
            self.devices.push(None);
        }
        
        self.devices[index] = Some(device);
        index
    }
    
    /// Get a flash device by index
    pub fn get(&self, index: usize) -> Option<&FlashDevice> {
        self.devices.get(index).and_then(|d| d.as_ref())
    }
    
    /// Get a mutable flash device by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut FlashDevice> {
        self.devices.get_mut(index).and_then(|d| d.as_mut())
    }
    
    /// Initialize all registered devices
    pub fn init_all(&self) {
        for device in &self.devices {
            if let Some(ref dev) = device {
                let _ = dev.init();
            }
        }
    }
}

impl Default for FlashManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize flash manager
pub fn init_flash() {
    let manager = Box::new(FlashManager::new());
    let ptr = Box::into_raw(manager);
    FLASH_MANAGER.store(ptr, Ordering::SeqCst);
}

/// Get flash manager
pub fn flash_manager() -> &'static mut FlashManager {
    unsafe { &mut *FLASH_MANAGER.load(Ordering::SeqCst) }
}

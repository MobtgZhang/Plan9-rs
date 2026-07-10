//! Storage Device Drivers
//!
//! Implements storage device abstraction and ATA/IDE driver.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use plan9_common::error::{Error, Result};
use plan9_common::types::PhysAddr;

// ============================================================================
// Storage Error Types
// ============================================================================

/// Storage operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdError {
    /// Device not found
    NotFound,
    /// No device present
    NoDevice,
    /// Invalid sector number
    InvalidSector,
    /// Invalid parameter
    Invalid,
    /// Read failure
    ReadError,
    /// Write failure
    WriteError,
    /// Device timeout
    Timeout,
    /// Device busy
    Busy,
    /// I/O error
    IoError,
    /// General error
    General,
}

impl core::fmt::Display for SdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SdError::NotFound => write!(f, "device not found"),
            SdError::NoDevice => write!(f, "no device present"),
            SdError::InvalidSector => write!(f, "invalid sector"),
            SdError::Invalid => write!(f, "invalid parameter"),
            SdError::ReadError => write!(f, "read error"),
            SdError::WriteError => write!(f, "write error"),
            SdError::Timeout => write!(f, "device timeout"),
            SdError::Busy => write!(f, "device busy"),
            SdError::IoError => write!(f, "I/O error"),
            SdError::General => write!(f, "general error"),
        }
    }
}

/// Storage operation result
pub type SdResult<T> = core::result::Result<T, SdError>;

/// Storage backend trait for block devices
pub trait StorageBackend: Send + Sync {
    /// Read sectors
    fn read_sectors(&mut self, lba: u64, count: u16, buffer: &mut [u8]) -> SdResult<()>;
    /// Write sectors
    fn write_sectors(&mut self, lba: u64, count: u16, buffer: &[u8]) -> SdResult<()>;
    /// Flush caches
    fn flush(&mut self) -> SdResult<()>;
    /// Get device capacity in bytes
    fn capacity(&self) -> u64;
    /// Get block size
    fn block_size(&self) -> usize;
    /// Check if device is online
    fn is_online(&self) -> bool;
    /// Get device model name
    fn model(&self) -> [u8; 40];
    /// Get device serial number
    fn serial(&self) -> [u8; 20];
}

// ============================================================================
// Block Device Interface
// ============================================================================

/// Block device operations
pub trait BlockDevice {
    /// Read blocks from device
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize>;
    /// Write blocks to device
    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize>;
    /// Get device block size
    fn block_size(&self) -> usize;
    /// Get total device size in bytes
    fn size(&self) -> usize;
    /// Flush any pending writes
    fn flush(&mut self) -> Result<()>;
}

// ============================================================================
// ATA/IDE Driver
// ============================================================================

/// ATA registers
pub mod ata_reg {
    pub const ATA_DATA: u16 = 0x1F0;
    pub const ATA_ERROR: u16 = 0x1F1;
    pub const ATA_FEATURE: u16 = 0x1F1;
    pub const ATA_SECCOUNT0: u16 = 0x1F2;
    pub const ATA_LBA0: u16 = 0x1F3;
    pub const ATA_LBA1: u16 = 0x1F4;
    pub const ATA_LBA2: u16 = 0x1F5;
    pub const ATA_HDDEVSEL: u16 = 0x1F6;
    pub const ATA_STATUS: u16 = 0x1F7;
    pub const ATA_COMMAND: u16 = 0x1F7;
    pub const ATA_CTRL: u16 = 0x3F6;
    pub const ATA_ALTSTATUS: u16 = 0x3F6;

    // ATA commands
    pub const ATA_CMD_READ: u8 = 0x20;
    pub const ATA_CMD_READ_EXT: u8 = 0x24;
    pub const ATA_CMD_WRITE: u8 = 0x30;
    pub const ATA_CMD_WRITE_EXT: u8 = 0x34;
    pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
    pub const ATA_CMD_FLUSH: u8 = 0xE7;
    pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;

    // ATA status bits
    pub const ATA_SR_BSY: u8 = 0x80;
    pub const ATA_SR_DRDY: u8 = 0x40;
    pub const ATA_SR_DF: u8 = 0x20;
    pub const ATA_SR_DSC: u8 = 0x10;
    pub const ATA_SR_DRQ: u8 = 0x08;
    pub const ATA_SR_CORR: u8 = 0x04;
    pub const ATA_SR_IDX: u8 = 0x02;
    pub const ATA_SR_ERR: u8 = 0x01;

    // ATA error bits
    pub const ATA_ER_AMNF: u8 = 0x01;
    pub const ATA_ER_TK0NF: u8 = 0x02;
    pub const ATA_ER_ABRT: u8 = 0x04;
    pub const ATA_ER_MCR: u8 = 0x08;
    pub const ATA_ER_IDNF: u8 = 0x10;
    pub const ATA_ER_MC: u8 = 0x20;
    pub const ATA_ER_UNC: u8 = 0x40;
    pub const ATA_ER_BBK: u8 = 0x80;
}

/// ATA device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaDeviceType {
    None,
    Pata,
    Satap,
    Unknown,
}

/// ATA device information
#[derive(Debug, Clone, Copy)]
pub struct AtaDevice {
    pub channel: usize,
    pub device_num: usize,
    pub device_type: AtaDeviceType,
    pub present: bool,
    pub slave: bool,
    pub block_size: usize,
    pub sectors: u64,
    pub model: [u8; 40],
    pub serial: [u8; 20],
    pub revision: [u8; 8],
}

impl Default for AtaDevice {
    fn default() -> Self {
        Self {
            channel: 0,
            device_num: 0,
            device_type: AtaDeviceType::None,
            present: false,
            slave: false,
            block_size: 512,
            sectors: 0,
            model: [0; 40],
            serial: [0; 20],
            revision: [0; 8],
        }
    }
}

/// ATA channel with state
pub struct AtaChannel {
    pub base: u16,
    pub ctrl: u16,
    pub bmide: u16,
    pub n_ien: bool,
    pub devices: [AtaDevice; 2],
    /// Bus lock for channel access serialization
    bus_locked: bool,
    /// Currently selected device (true = slave, false = master)
    selected_slave: bool,
}

impl AtaChannel {
    /// Create primary channel (bus 0)
    pub fn primary() -> Self {
        Self {
            base: ata_reg::ATA_DATA,
            ctrl: ata_reg::ATA_CTRL,
            bmide: 0,
            n_ien: false,
            devices: [AtaDevice::default(), AtaDevice::default()],
            bus_locked: false,
            selected_slave: false,
        }
    }

    /// Get shared instance of primary channel
    pub fn get_primary() -> &'static mut Self {
        use core::sync::atomic::{AtomicPtr, Ordering};
        // AtomicPtr is the safe primitive for a global mutable pointer;
        // wrap it in an `unsafe impl Sync` container so that `static` (not
        // `static mut`) can hold it and we avoid the
        // `static_mut_refs` lint entirely.
        struct SyncPtr<T>(AtomicPtr<T>);
        unsafe impl<T> Sync for SyncPtr<T> {}
        static PRIMARY_CHANNEL: SyncPtr<AtaChannel> = SyncPtr(AtomicPtr::new(core::ptr::null_mut()));

        unsafe {
            let ptr = PRIMARY_CHANNEL.0.load(Ordering::SeqCst);
            if ptr.is_null() {
                let channel = Box::new(Self::primary());
                let raw = Box::into_raw(channel);
                PRIMARY_CHANNEL.0.store(raw, Ordering::SeqCst);
                &mut *raw
            } else {
                &mut *ptr
            }
        }
    }

    /// Select device and cache the selection
    fn ensure_selected(&mut self, slave: bool) {
        if self.selected_slave != slave {
            self.select(slave);
            self.selected_slave = slave;
        }
    }

    /// Read ATA status register
    pub fn status(&self) -> u8 {
        plan9_arch::x86_64::inb(self.base + 7)
    }

    /// Read ATA status with alternate register
    pub fn alt_status(&self) -> u8 {
        plan9_arch::x86_64::inb(self.ctrl)
    }

    /// Wait for ATA device to be ready
    pub fn wait_ready(&self, timeout_ms: usize) -> Result<()> {
        // Use the kernel's timer if available, otherwise just loop
        // The actual timing would use clock_gettime or similar
        for _ in 0..timeout_ms {
            let status = self.alt_status();
            if status & ata_reg::ATA_SR_BSY == 0 && status & ata_reg::ATA_SR_DRQ != 0 {
                return Ok(());
            }
        }
        Err(Error::Eio)
    }

    /// Poll status register until not busy
    pub fn poll_not_busy(&self, timeout_ms: usize) -> Result<u8> {
        for _ in 0..timeout_ms {
            let status = self.status();
            if status & ata_reg::ATA_SR_BSY == 0 {
                return Ok(status);
            }
        }
        Err(Error::Eio)
    }

    /// Select device (master/slave)
    pub fn select(&mut self, slave: bool) {
        let devsel: u8 = if slave { 0xB0 } else { 0xA0 };
        plan9_arch::x86_64::outb(ata_reg::ATA_HDDEVSEL, devsel);
        plan9_arch::x86_64::wait();
    }

    /// Identify device
    pub fn identify(&mut self, slave: bool) -> Result<AtaDevice> {
        self.select(slave);

        // Send IDENTIFY command
        plan9_arch::x86_64::outb(ata_reg::ATA_SECCOUNT0, 0);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA0, 0);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA1, 0);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA2, 0);
        plan9_arch::x86_64::outb(ata_reg::ATA_COMMAND, ata_reg::ATA_CMD_IDENTIFY);

        // Check if device exists
        let status = self.status();
        if status == 0xFF || status == 0x00 {
            return Err(Error::Enodev);
        }

        // Wait for completion
        self.wait_ready(5000)?;

        // Read identify data
        let mut device = AtaDevice {
            present: true,
            slave,
            ..Default::default()
        };

        let identify_data = self.read_buffer(256);
        device.block_size = 512;
        device.sectors = u64::from(identify_data[60]) | (u64::from(identify_data[61]) << 16);

        // Parse model string (word-swapped 16-bit chars)
        for i in 0..20 {
            let w = identify_data[27 + i];
            device.model[i * 2] = (w >> 8) as u8;
            device.model[i * 2 + 1] = (w & 0xFF) as u8;
        }

        // Parse serial number
        for i in 0..10 {
            let w = identify_data[10 + i];
            device.serial[i * 2] = (w >> 8) as u8;
            device.serial[i * 2 + 1] = (w & 0xFF) as u8;
        }

        // Parse revision
        for i in 0..4 {
            let w = identify_data[23 + i];
            device.revision[i * 2] = (w >> 8) as u8;
            device.revision[i * 2 + 1] = (w & 0xFF) as u8;
        }

        // Determine device type
        if identify_data[0] & (1 << 15) == 0 {
            device.device_type = AtaDeviceType::Pata;
        } else {
            device.device_type = AtaDeviceType::Satap;
        }

        Ok(device)
    }

    /// Read data buffer from ATA
    fn read_buffer(&self, count: usize) -> Vec<u16> {
        let mut buf = vec![0u16; count];
        let ptr = buf.as_mut_ptr();
        for i in 0..count {
            unsafe {
                core::ptr::write(ptr.add(i), plan9_arch::x86_64::inw(self.base));
            }
        }
        buf
    }

    /// Read sectors using PIO
    pub fn read_sectors(
        &mut self,
        slave: bool,
        lba: u64,
        count: u8,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if count == 0 || count > 128 {
            return Err(Error::Einval);
        }

        let sectors = usize::from(count);
        let bytes = sectors * 512;
        if buffer.len() < bytes {
            return Err(Error::Einval);
        }

        self.select(slave);

        // Set LBA mode
        plan9_arch::x86_64::outb(ata_reg::ATA_SECCOUNT0, count);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA0, lba as u8);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA1, (lba >> 8) as u8);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA2, (lba >> 16) as u8);
        // Set LBA48 bit and device select
        let device_reg = 0x40 | if slave { 0x10 } else { 0x00 } | ((lba >> 24) & 0x0F) as u8;
        plan9_arch::x86_64::outb(ata_reg::ATA_HDDEVSEL, device_reg);

        // Send read command
        plan9_arch::x86_64::outb(ata_reg::ATA_COMMAND, ata_reg::ATA_CMD_READ_EXT);

        // Read data
        let mut total = 0;
        for _ in 0..sectors {
            // Wait for data ready
            self.wait_ready(5000)?;

            // Read 256 words (512 bytes)
            for _i in 0..256 {
                let word = plan9_arch::x86_64::inw(self.base);
                if total + 2 <= buffer.len() {
                    buffer[total] = (word & 0xFF) as u8;
                    buffer[total + 1] = ((word >> 8) & 0xFF) as u8;
                }
                total += 2;
            }
        }

        Ok(total)
    }

    /// Write sectors using PIO
    pub fn write_sectors(
        &mut self,
        slave: bool,
        lba: u64,
        count: u8,
        buffer: &[u8],
    ) -> Result<usize> {
        if count == 0 || count > 128 {
            return Err(Error::Einval);
        }

        let sectors = usize::from(count);
        let bytes = sectors * 512;
        if buffer.len() < bytes {
            return Err(Error::Einval);
        }

        self.select(slave);

        // Set LBA mode
        plan9_arch::x86_64::outb(ata_reg::ATA_SECCOUNT0, count);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA0, lba as u8);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA1, (lba >> 8) as u8);
        plan9_arch::x86_64::outb(ata_reg::ATA_LBA2, (lba >> 16) as u8);
        let device_reg = 0x40 | if slave { 0x10 } else { 0x00 } | ((lba >> 24) & 0x0F) as u8;
        plan9_arch::x86_64::outb(ata_reg::ATA_HDDEVSEL, device_reg);

        // Send write command
        plan9_arch::x86_64::outb(ata_reg::ATA_COMMAND, ata_reg::ATA_CMD_WRITE_EXT);

        // Write data
        let mut total = 0;
        for _ in 0..sectors {
            // Wait for device ready
            self.poll_not_busy(5000)?;

            // Write 256 words (512 bytes)
            for _i in 0..256 {
                let word = (buffer[total + 1] as u16) << 8 | buffer[total] as u16;
                plan9_arch::x86_64::outw(self.base, word);
                total += 2;
            }
        }

        // Send flush command
        plan9_arch::x86_64::outb(ata_reg::ATA_COMMAND, ata_reg::ATA_CMD_FLUSH_EXT);
        self.poll_not_busy(5000)?;

        Ok(total)
    }
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// VirtIO block device configuration
#[derive(Debug, Clone, Copy)]
pub struct VirtioBlockConfig {
    pub capacity: u64,        // Total size in 512-byte sectors
    pub size_max: u32,        // Maximum segment size
    pub seg_max: u32,         // Maximum number of segments
    pub geometry: VirtioGeometry,
    pub block_size: u32,      // Block size (usually 512)
}

#[derive(Debug, Clone, Copy)]
pub struct VirtioGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}

/// VirtIO block request
#[repr(C)]
pub struct VirtioBlockRequest {
    pub type_: u32,          // 0=read, 1=write, 2=flush
    pub reserved: u32,
    pub sector: u64,          // Starting sector
    pub status: u8,           // Result status
}

/// VirtIO block device
pub struct VirtioBlock {
    pub base_addr: PhysAddr,
    pub config: VirtioBlockConfig,
    pub queue_size: u16,
}

impl VirtioBlock {
    /// Create VirtIO block device
    pub fn new(base: PhysAddr) -> Self {
        Self {
            base_addr: base,
            config: VirtioBlockConfig {
                capacity: 0,
                size_max: 0,
                seg_max: 0,
                geometry: VirtioGeometry {
                    cylinders: 0,
                    heads: 0,
                    sectors: 0,
                },
                block_size: 512,
            },
            queue_size: 256,
        }
    }

    /// Get device capacity
    pub fn capacity(&self) -> u64 {
        self.config.capacity * 512
    }
}

// ============================================================================
// Device Manager
// ============================================================================

/// Storage device manager
pub struct StorageManager {
    pub ata_primary: AtaChannel,
    pub devices: [Option<Box<dyn BlockDevice>>; 4],
    pub device_count: usize,
}

impl StorageManager {
    /// Create new storage manager
    pub fn new() -> Self {
        Self {
            ata_primary: AtaChannel::primary(),
            devices: [None, None, None, None],
            device_count: 0,
        }
    }

    /// Probe for ATA devices
    pub fn probe_ata(&mut self) {
        // Try to identify master device
        if let Ok(device) = self.ata_primary.identify(false) {
            if device.present {
                self.devices[self.device_count] = Some(Box::new(device));
                self.device_count += 1;
            }
        }

        // Try to identify slave device
        if let Ok(device) = self.ata_primary.identify(true) {
            if device.present {
                self.devices[self.device_count] = Some(Box::new(device));
                self.device_count += 1;
            }
        }
    }

    /// Get device by index
    pub fn get_device(&self, index: usize) -> Option<&dyn BlockDevice> {
        self.devices.get(index).and_then(|d| d.as_ref().map(|b| b.as_ref()))
    }

    /// Get mutable device by index
    pub fn get_device_mut(&mut self, index: usize) -> Option<&mut Box<dyn BlockDevice>> {
        self.devices.get_mut(index).and_then(|d| d.as_mut())
    }
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}

// Implement BlockDevice for AtaDevice
impl BlockDevice for AtaDevice {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let sector = offset / 512;
        
        // Use the shared primary channel
        let channel = AtaChannel::get_primary();
        
        // Ensure correct device is selected
        channel.ensure_selected(self.slave);
        
        // Read sectors using the shared channel
        channel.read_sectors(self.slave, sector as u64, 1, buf)
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize> {
        let sector = offset / 512;
        
        // Use the shared primary channel
        let channel = AtaChannel::get_primary();
        
        // Ensure correct device is selected
        channel.ensure_selected(self.slave);
        
        channel.write_sectors(self.slave, sector as u64, 1, buf)
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn size(&self) -> usize {
        (self.sectors as usize) * 512
    }

    fn flush(&mut self) -> Result<()> {
        // Use the shared primary channel
        let channel = AtaChannel::get_primary();
        
        // Select the correct device
        channel.ensure_selected(self.slave);
        
        // Send flush command
        plan9_arch::x86_64::outb(ata_reg::ATA_COMMAND, ata_reg::ATA_CMD_FLUSH);
        channel.poll_not_busy(5000)?;
        
        Ok(())
    }
}

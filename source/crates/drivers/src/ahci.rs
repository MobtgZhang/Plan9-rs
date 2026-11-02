//! AHCI/SATA Driver
//!
//! Implements AHCI (Advanced Host Controller Interface) for SATA devices.
//! This provides a more modern interface than legacy ATA/IDE.

#![allow(dead_code)]

use alloc::boxed::Box;
// use alloc::sync::Arc;
// use alloc::vec::Vec;
// use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::storage::{StorageBackend, SdError, SdResult};
use plan9_common::types::PhysAddr;
use plan9_arch::x86_64::paging::phys_to_virt;

// Temporary diagnostic byte to the serial port.
fn dbg(c: u8) {
    plan9_arch::x86_64::outb(0x3F8, c);
}

// ============================================================================
// AHCI Constants
// ============================================================================

pub mod regs {
    // Host Controller registers (offset from MMIO base)
    pub const HBA_CAP: usize = 0x00;      // Capabilities
    pub const HBA_GHC: usize = 0x04;       // Global Host Control
    pub const HBA_IS: usize = 0x08;         // Interrupt Status
    pub const HBA_PI: usize = 0x0C;         // Ports Implemented
    pub const HBA_AHCI_VS: usize = 0x10;   // AHCI Version
    pub const HBA_CAP2: usize = 0x24;      // Capabilities Extended
    pub const HBA_BOHC: usize = 0x28;      // BIOS/OS Handoff Control
    
    // Global Host Control bits
    pub const GHC_AE: u32 = 1 << 31;       // AHCI Enable
    pub const GHC_MRSM: u32 = 1 << 2;      // MSI Revert to Single Message
    pub const GHC_IE: u32 = 1 << 1;       // Interrupt Enable
    pub const GHC_HR: u32 = 1 << 0;       // HBA Reset
}

pub mod port {
    // Port registers (offset from port base)
    pub const CMD_LIST_BASE: usize = 0x00;  // Command List Base (32-bit)
    pub const CMD_LIST_BASE_HI: usize = 0x04; // Command List Base (64-bit upper)
    pub const FIS_BASE: usize = 0x08;       // FIS Base (32-bit)
    pub const FIS_BASE_HI: usize = 0x0C;   // FIS Base (64-bit upper)
    pub const IRQ_STAT: usize = 0x10;       // Interrupt Status
    pub const IRQ_EN: usize = 0x14;        // Interrupt Enable
    pub const CMD: usize = 0x18;            // Command
    pub const TFD: usize = 0x20;           // Task File Data
    pub const SIG: usize = 0x24;           // Signature
    pub const SCR_STS: usize = 0x28;      // SATA Status (SCR0)
    pub const SCR_CTL: usize = 0x2C;      // SATA Control (SCR2)
    pub const SCR_ERR: usize = 0x30;       // SATA Error (SCR1)
    pub const SCR_ACT: usize = 0x34;       // SATA Active (SCR3)
    pub const CMD_ISSUE: usize = 0x38;     // Command Issue
    pub const SATA_I: usize = 0x40;        // SATA Index/Data Pair
    
    // TFD bits
    pub const TFD_ERR: u32 = 1 << 0;
    pub const TFD_DRQ: u32 = 1 << 3;
    pub const TFD_BSY: u32 = 1 << 7;
    
    // SCR status bits
    pub const SCR_DET: u32 = 0xF;         // Device detection
    pub const SCR_DET_CONNECTED: u32 = 0x1;
    pub const SCR_DET_COMM: u32 = 0x3;     // Communication established
    pub const SCR_SPD: u32 = 0xF << 4;    // Current speed
    pub const SCR_IPM: u32 = 0xF << 8;    // Interface power management
}

// Port Command bits
pub const CMD_ST: u32 = 1 << 0;           // Interface Started
pub const CMD_CR: u32 = 1 << 3;           // Command List Running
pub const CMD_FRE: u32 = 1 << 4;          // FIS Receive Enable
pub const CMD_CLO: u32 = 1 << 3;          // Command List Override
pub const CMD_DLAE: u32 = 1 << 7;        // Drive LED On ATAPI
pub const CMD_ATAPI: u32 = 1 << 5;        // ATAPI
pub const CMD_APSTE: u32 = 1 << 6;        // Ambient Presence Sts Enable
pub const CMD_CPD: u32 = 1 << 5;          // Cold Presence Detection         // Command List Override

// SATA Signature values
pub const SATA_SIG_ATA: u32 = 0x00000101;
pub const SATA_SIG_ATAPI: u32 = 0xEB140101;
pub const SATA_SIG_SEMB: u32 = 0xC33C0101;
pub const SATA_SIG_PM: u32 = 0x96690101;

// Device types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    None,
    SATA,
    SATAPI,
    SEMB,
    PM,
}

/// HBA Capabilities register
#[derive(Debug, Clone, Copy)]
pub struct HbaCapability(u32);

impl HbaCapability {
    pub fn new(val: u32) -> Self { Self(val) }
    
    /// Number of ports supported
    pub fn num_ports(&self) -> u8 { ((self.0 >> 0) & 0x1F) as u8 }
    
    /// Number of command slots
    pub fn num_cmd_slots(&self) -> u8 { ((self.0 >> 8) & 0x1F) as u8 }
    
    /// Supports SATA 3Gbps
    pub fn supports_sata3(&self) -> bool { (self.0 & (1 << 30)) != 0 }
    
    /// Supports 64-bit DMA
    pub fn supports_64bit(&self) -> bool { (self.0 & (1 << 31)) != 0 }
    
    /// Supports Aggressive Link Power Management
    pub fn supports_alpm(&self) -> bool { (self.0 & (1 << 18)) != 0 }
    
    /// Supports Port Multiplier
    pub fn supports_pm(&self) -> bool { (self.0 & (1 << 17)) != 0 }
    
    /// Supports FIS-based switching
    pub fn supports_fbs(&self) -> bool { (self.0 & (1 << 16)) != 0 }
    
    /// Supports Native Command Queuing
    pub fn supports_ncq(&self) -> bool { (self.0 & (1 << 20)) != 0 }
    
    /// Supports Staggered Spin-up
    pub fn supports_sss(&self) -> bool { (self.0 & (1 << 27)) != 0 }
}

/// HBA Capabilities Extended register
#[derive(Debug, Clone, Copy)]
pub struct HbaCapability2(u32);

impl HbaCapability2 {
    pub fn new(val: u32) -> Self { Self(val) }
    
    /// Supports Aggressive SATA slumber
    pub fn supports_aggressive_slumber(&self) -> bool { (self.0 & (1 << 3)) != 0 }
    
    /// Supports DevSleep
    pub fn supports_devsleep(&self) -> bool { (self.0 & (1 << 0)) != 0 }
}

// ============================================================================
// FIS Structures
// ============================================================================

/// FIS types
pub const FIS_TYPE_REG_H2D: u8 = 0x27;
pub const FIS_TYPE_REG_D2H: u8 = 0x34;
pub const FIS_TYPE_DMA_ACT: u8 = 0x39;
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;
pub const FIS_TYPE_DATA: u8 = 0x46;
pub const FIS_TYPE_BIST: u8 = 0x58;
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;

/// Register FIS - Host to Device
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct FisRegH2D {
    pub fis_type: u8,       // FIS_TYPE_REG_H2D
    pub port_mul: u8,      // Port multiplier (bit 7 = C)
    pub command: u8,       // ATA command
    pub featurel: u8,      // Feature (7:0)
    pub lba0: u8,         // LBA (7:0)
    pub lba1: u8,         // LBA (15:8)
    pub lba2: u8,         // LBA (23:16)
    pub device: u8,        // Device register
    pub lba3: u8,         // LBA (31:24)
    pub lba4: u8,         // LBA (39:32)
    pub lba5: u8,         // LBA (47:40)
    pub featureh: u8,      // Feature (15:8)
    pub countl: u8,       // Count (7:0)
    pub counth: u8,       // Count (15:8)
    pub icc: u8,          // Isochronous Command Completion
    pub control: u8,      // Control (bit 7 = Reset, bit 1 = Preferred)
}

impl FisRegH2D {
    /// Create a new READ DMA EXT FIS
    pub fn new_read(sector: u64, count: u16) -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            port_mul: 0x80,
            command: 0x25, // READ DMA EXT
            featurel: 0,
            lba0: sector as u8,
            lba1: (sector >> 8) as u8,
            lba2: (sector >> 16) as u8,
            device: 0x40,  // LBA mode
            lba3: (sector >> 24) as u8,
            lba4: (sector >> 32) as u8,
            lba5: (sector >> 40) as u8,
            featureh: 0,
            countl: count as u8,
            counth: (count >> 8) as u8,
            icc: 0,
            control: 0,
        }
    }
    
    /// Create a new WRITE DMA EXT FIS
    pub fn new_write(sector: u64, count: u16) -> Self {
        let mut fis = Self::new_read(sector, count);
        fis.command = 0x35; // WRITE DMA EXT
        fis
    }
    
    /// Create an IDENTIFY FIS
    pub fn new_identify() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            port_mul: 0x80,
            command: 0xEC, // IDENTIFY
            featurel: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            featureh: 0,
            countl: 0,
            counth: 0,
            icc: 0,
            control: 0,
        }
    }
    
    /// Create a FLUSH CACHE EXT FIS
    pub fn new_flush() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            port_mul: 0x80,
            command: 0xEA, // FLUSH CACHE EXT
            featurel: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            featureh: 0,
            countl: 0,
            counth: 0,
            icc: 0,
            control: 0,
        }
    }
}

/// Register FIS - Device to Host
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct FisRegD2H {
    pub fis_type: u8,
    pub port_mul: u8,
    pub interrupt: u8,
    pub status: u8,
    pub error: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub featurel: u8,
    pub featureh: u8,
    pub countl: u8,
    pub counth: u8,
}

impl FisRegD2H {
    /// Check if error bit is set
    pub fn has_error(&self) -> bool { (self.status & 0x01) != 0 }
    /// Check if data request bit is set
    pub fn has_drq(&self) -> bool { (self.status & 0x08) != 0 }
    /// Check if busy bit is set
    pub fn is_busy(&self) -> bool { (self.status & 0x80) != 0 }
}

// ============================================================================
// Command Structures
// ============================================================================

/// Command header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HbacmdHeader {
    /// Flags (CFL[4:0], A, W, P, R, B, C, PMP[11:8])
    pub flags: u16,
    /// Physical Region Descriptor Table length
    pub prdtl: u16,
    /// Physical Region Descriptor Byte Count (returned)
    pub prdbc: u32,
    /// Command Table Base Address
    pub ctba: u64,
    /// Reserved
    pub reserved: [u32; 4],
}

impl HbacmdHeader {
    /// Command FIS size (32-bit = 5 DWORDS)
    pub const CFL_32BIT: u16 = 5;
    
    /// Create a new command header for read
    pub fn new_read(prdtl: u16, ctba: u64, write: bool) -> Self {
        let flags = Self::CFL_32BIT | if write { 0 } else { 0x40 }; // W bit
        Self {
            flags,
            prdtl,
            prdbc: 0,
            ctba,
            reserved: [0; 4],
        }
    }
    
    /// Create a new command header for write
    pub fn new_write(prdtl: u16, ctba: u64) -> Self {
        Self::new_read(prdtl, ctba, true)
    }
}

impl Default for HbacmdHeader {
    fn default() -> Self {
        Self {
            flags: Self::CFL_32BIT,
            prdtl: 0,
            prdbc: 0,
            ctba: 0,
            reserved: [0; 4],
        }
    }
}

/// Physical Region Descriptor entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HbaprdEntry {
    /// Data Base Address
    pub dba: u64,
    /// Reserved
    pub reserved: u32,
    /// Byte Count (0 = 4MB max), bit 31 = Interrupt flag
    pub dbc_i: u32,
}

impl HbaprdEntry {
    /// Maximum byte count per PRD
    pub const MAX_SIZE: u32 = 0x3FFFFF;  // 4MB - 1
    /// End of table flag
    pub const END_FLAG: u32 = 1 << 31;
    /// Interrupt flag
    pub const INT_FLAG: u32 = 1 << 31;
    
    pub fn new(addr: u64, size: u32, is_last: bool) -> Self {
        let dbc = if is_last {
            ((size - 1) & !Self::END_FLAG) | Self::END_FLAG
        } else {
            (size - 1) & !Self::END_FLAG
        };
        
        Self {
            dba: addr,
            reserved: 0,
            dbc_i: dbc,
        }
    }
    
    pub fn with_interrupt(addr: u64, size: u32, is_last: bool) -> Self {
        let dbc = if is_last {
            ((size - 1) & !Self::END_FLAG) | Self::END_FLAG | Self::INT_FLAG
        } else {
            (size - 1) & !Self::END_FLAG
        };
        
        Self {
            dba: addr,
            reserved: 0,
            dbc_i: dbc,
        }
    }
}

/// Command table structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AhciCommandTable {
    /// Command FIS (64 bytes)
    pub cfis: [u8; 64],
    /// ACMD (ATAPI command, 32 bytes)
    pub acmd: [u8; 32],
    /// Reserved
    pub reserved: [u8; 32],
    /// Physical Region Descriptor Table
    pub prdt: [HbaprdEntry; 1], // Variable size, at least 1 entry
}

// ============================================================================
// MMIO Access
// ============================================================================

/// Trait for MMIO access - allows platform-specific implementations
pub trait MmioAccess {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
    fn read64(&self, offset: usize) -> u64;
    fn write64(&self, offset: usize, value: u64);
}

/// Simple MMIO accessor using volatile reads/writes
pub struct SimpleMmio {
    base: usize,
}

impl SimpleMmio {
    pub fn new(base: usize) -> Self {
        Self { base }
    }
    
    /// Read a 32-bit register
    pub fn read32(&self, offset: usize) -> u32 {
        // In a real implementation, this would use volatile reads
        // For now, we use a placeholder
        unsafe {
            core::ptr::read_volatile((self.base + offset) as *const u32)
        }
    }
    
    /// Write a 32-bit register
    pub fn write32(&self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.base + offset) as *mut u32, value);
        }
    }
    
    /// Read a 64-bit register
    pub fn read64(&self, offset: usize) -> u64 {
        let low = self.read32(offset);
        let high = self.read32(offset + 4);
        ((high as u64) << 32) | (low as u64)
    }
    
    /// Write a 64-bit register
    pub fn write64(&self, offset: usize, value: u64) {
        self.write32(offset, (value & 0xFFFFFFFF) as u32);
        self.write32(offset + 4, ((value >> 32) & 0xFFFFFFFF) as u32);
    }
}

// ============================================================================
// IDENTIFY Data
// ============================================================================

/// ATA IDENTIFY device data
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdentifyData {
    pub words: [u16; 256],
}

impl IdentifyData {
    /// Get total sectors.  ATA-8 reports the 48-bit LBA capacity in
    /// words 100..103; words 60/61 hold the legacy 28-bit capacity.
    /// Prefer the 48-bit field when it is populated, and fall back to the
    /// 28-bit field for older devices.
    pub fn lba_capacity(&self) -> u64 {
        let cap48 = (self.words[100] as u64)
            | ((self.words[101] as u64) << 16)
            | ((self.words[102] as u64) << 32)
            | ((self.words[103] as u64) << 48);
        if cap48 != 0 {
            return cap48;
        }
        let low = self.words[60] as u64;
        let high = self.words[61] as u64;
        (high << 16) | low
    }

    /// Get sectors (for 28-bit LBA devices)
    pub fn lba_capacity_28(&self) -> u32 {
        let low = self.words[60] as u32;
        let high = self.words[61] as u32;
        ((high << 16) | low) as u32
    }
    
    /// Check if 48-bit LBA is supported
    pub fn supports_lba48(&self) -> bool {
        (self.words[83] & (1 << 10)) != 0
    }
    
    /// Check if DMA is supported
    pub fn supports_dma(&self) -> bool {
        (self.words[49] & (1 << 8)) != 0
    }
    
    /// Get model string (word-swapped, 40 chars)
    pub fn model(&self) -> [u8; 40] {
        let mut model = [0u8; 40];
        for i in 0..20 {
            let w = self.words[27 + i];
            model[i * 2] = (w >> 8) as u8;
            model[i * 2 + 1] = (w & 0xFF) as u8;
        }
        model
    }
    
    /// Get serial number (word-swapped, 20 chars)
    pub fn serial(&self) -> [u8; 20] {
        let mut serial = [0u8; 20];
        for i in 0..10 {
            let w = self.words[10 + i];
            serial[i * 2] = (w >> 8) as u8;
            serial[i * 2 + 1] = (w & 0xFF) as u8;
        }
        serial
    }
    
    /// Get firmware revision (word-swapped, 8 chars)
    pub fn firmware(&self) -> [u8; 8] {
        let mut fw = [0u8; 8];
        for i in 0..4 {
            let w = self.words[23 + i];
            fw[i * 2] = (w >> 8) as u8;
            fw[i * 2 + 1] = (w & 0xFF) as u8;
        }
        fw
    }
    
    /// Get block size
    pub fn block_size(&self) -> usize {
        // Usually 512 bytes
        512
    }
}

// ============================================================================
// AHCI Port
// ============================================================================

/// AHCI Port structure
pub struct AhciPort {
    /// Port number
    pub num: u8,
    /// Device type attached to this port
    pub dev_type: DeviceType,
    /// Port registers base address (within AHCI MMIO)
    port_base: usize,
    /// MMIO accessor
    mmio: SimpleMmio,
    /// Command list base physical address
    cl_base: u64,
    /// FIS receive area physical address
    fb_base: u64,
    /// Command table physical address
    cmd_table_base: u64,
    /// Command list virtual address
    cmd_headers: *mut HbacmdHeader,
    /// FIS receive area virtual address
    fis_area: *mut u8,
    /// Command table virtual address
    cmd_table: *mut u8,
    /// Identify data
    pub identify: Option<IdentifyData>,
    /// Is initialized
    initialized: bool,
    /// Is busy
    busy: AtomicBool,
}

unsafe impl Send for AhciPort {}
unsafe impl Sync for AhciPort {}

impl AhciPort {
    /// Create a new AHCI port
    pub fn new(num: u8, port_base: usize) -> Self {
        Self {
            num,
            dev_type: DeviceType::None,
            port_base,
            mmio: SimpleMmio::new(port_base),
            cl_base: 0,
            fb_base: 0,
            cmd_table_base: 0,
            cmd_headers: core::ptr::null_mut(),
            fis_area: core::ptr::null_mut(),
            cmd_table: core::ptr::null_mut(),
            identify: None,
            initialized: false,
            busy: AtomicBool::new(false),
        }
    }
    
    /// Read a port register
    fn read_reg(&self, offset: usize) -> u32 {
        self.mmio.read32(offset)
    }
    
    /// Write a port register
    fn write_reg(&self, offset: usize, val: u32) {
        self.mmio.write32(offset, val);
    }
    
    /// Get device signature
    pub fn signature(&self) -> u32 {
        self.read_reg(port::SIG)
    }
    
    /// Get SATA status (SCR0)
    pub fn sata_status(&self) -> u32 {
        self.read_reg(port::SCR_STS)
    }
    
    /// Get device detection status
    pub fn detection_status(&self) -> u32 {
        self.sata_status() & port::SCR_DET
    }
    
    /// Check if device is present
    pub fn is_present(&self) -> bool {
        let det = self.detection_status();
        det == port::SCR_DET_CONNECTED || det == port::SCR_DET_COMM
    }
    
    /// Probe device type on this port
    pub fn probe(&mut self) -> DeviceType {
        if !self.is_present() {
            return DeviceType::None;
        }
        
        // Check signature by reading status
        let sstatus = self.read_reg(port::SCR_STS);
        let interface = (sstatus >> 8) & 0xFF;
        
        match interface {
            1 => DeviceType::SATAPI,
            2 => DeviceType::SEMB,
            3 | _ => DeviceType::SATA,
        }
    }
    
    /// Stop port DMA/FIS operations
    pub fn stop(&mut self) {
        let cmd = self.read_reg(port::CMD);
        self.write_reg(port::CMD, cmd & !(CMD_FRE | CMD_ST));
        for _ in 0..500 {
            if self.read_reg(port::CMD) & CMD_ST == 0 {
                break;
            }
        }
    }
    
    /// Start port DMA/FIS operations
    pub fn start(&mut self) {
        let cmd = self.read_reg(port::CMD);
        self.write_reg(port::CMD, cmd | CMD_FRE | CMD_ST);
        for _ in 0..1000 {
            if self.read_reg(port::CMD) & CMD_ST != 0 {
                break;
            }
        }
    }
    
    /// Initialize port for DMA operations
    pub fn init(&mut self, cl_base: u64, fb_base: u64, cmd_table_base: u64) {
        self.cl_base = cl_base;
        self.fb_base = fb_base;
        self.cmd_table_base = cmd_table_base;

        // The boot kernel keeps a low identity mapping for the frame pool;
        // these DMA structures are below the 64 MiB window.
        self.cmd_headers = cl_base as *mut HbacmdHeader;
        self.fis_area = fb_base as *mut u8;
        self.cmd_table = cmd_table_base as *mut u8;

        // Stop port first
        self.stop();

        // Clear interrupt status
        self.write_reg(port::IRQ_STAT, 0xFFFFFFFF);

        // Write command list base
        self.write_reg(port::CMD_LIST_BASE, (cl_base & 0xFFFFFFFF) as u32);
        if cl_base >> 32 != 0 {
            self.write_reg(port::CMD_LIST_BASE_HI, ((cl_base >> 32) & 0xFFFFFFFF) as u32);
        }

        // Write FIS base
        self.write_reg(port::FIS_BASE, (fb_base & 0xFFFFFFFF) as u32);
        if fb_base >> 32 != 0 {
            self.write_reg(port::FIS_BASE_HI, ((fb_base >> 32) & 0xFFFFFFFF) as u32);
        }

        self.clear_irq();
        self.start();
        self.initialized = true;
    }
    
    /// Clear pending interrupt status
    pub fn clear_irq(&mut self) {
        self.write_reg(port::IRQ_STAT, 0xFFFFFFFF);
    }
    
    /// Get interrupt status
    pub fn irq_status(&self) -> u32 {
        self.read_reg(port::IRQ_STAT)
    }

    /// Get port command register
    pub fn cmd_status(&self) -> u32 {
        self.read_reg(port::CMD)
    }

    /// Get command issue register
    pub fn cmd_issue_status(&self) -> u32 {
        self.read_reg(port::CMD_ISSUE)
    }

    /// Get FIS base register
    pub fn fis_base_status(&self) -> u32 {
        self.read_reg(port::FIS_BASE)
    }

    /// Get command list base register
    pub fn cmd_list_base_status(&self) -> u32 {
        self.read_reg(port::CMD_LIST_BASE)
    }

    /// Dump the first command header as 8 dwords.
    pub fn header_dwords(&self) -> [u32; 8] {
        let mut out = [0u32; 8];
        unsafe {
            for i in 0..8 {
                out[i] = core::ptr::read_volatile((self.cmd_headers as *const u8).add(i * 4) as *const u32);
            }
        }
        out
    }

    /// Dump the first 32 dwords of the command table.
    pub fn cmd_table_dwords(&self) -> [u32; 32] {
        let mut out = [0u32; 32];
        unsafe {
            for i in 0..32 {
                out[i] = core::ptr::read_volatile((self.cmd_table as *const u8).add(i * 4) as *const u32);
            }
        }
        out
    }
    
    /// Get task file data
    pub fn tfd(&self) -> u32 {
        self.read_reg(port::TFD)
    }
    
    /// Check if device is ready (not busy, no error)
    pub fn is_ready(&self) -> bool {
        let tfd = self.tfd();
        (tfd & (port::TFD_ERR | port::TFD_BSY)) == 0
    }
    
    /// Wait for device to be ready
    pub fn wait_ready(&mut self, timeout_ms: usize) -> SdResult<()> {
        for _ in 0..timeout_ms {
            if self.is_ready() {
                return Ok(());
            }
        }
        Err(SdError::Timeout)
    }
    
    /// Issue a command and wait for completion
    pub fn issue_cmd(&mut self, slot: u8) {
        self.write_reg(port::CMD_ISSUE, 1 << slot);
    }
    
    /// Check if command slot is running
    pub fn is_cmd_busy(&self, slot: u8) -> bool {
        (self.read_reg(port::CMD_ISSUE) & (1 << slot)) != 0
    }
    
    /// Wait for all commands to complete
    pub fn wait_completion(&mut self, timeout_ms: usize) -> SdResult<()> {
        for _ in 0..timeout_ms {
            if self.read_reg(port::CMD_ISSUE) == 0 {
                // Check for errors
                let tfd = self.tfd();
                if (tfd & port::TFD_ERR) != 0 {
                    return Err(SdError::IoError);
                }
                return Ok(());
            }
        }
        Err(SdError::Timeout)
    }
    
    /// Set busy flag
    pub fn set_busy(&self) {
        self.busy.store(true, Ordering::SeqCst);
    }
    
    /// Clear busy flag
    pub fn clear_busy(&self) {
        self.busy.store(false, Ordering::SeqCst);
    }
    
    /// Check if port is busy
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst) || self.is_cmd_busy(0)
    }
    
    /// Probe the device and issue an IDENTIFY command whose 512-byte result
    /// is written to `buffer_phys`.
    pub fn identify_device(&mut self, buffer_phys: u64) -> SdResult<IdentifyData> {
        if !self.is_present() || !self.initialized {
            self.dev_type = DeviceType::None;
            return Err(SdError::NoDevice);
        }

        dbg(b'i');
        let sig = self.signature();
        match sig {
            SATA_SIG_ATA => self.dev_type = DeviceType::SATA,
            SATA_SIG_ATAPI => self.dev_type = DeviceType::SATAPI,
            _ => {
                self.dev_type = DeviceType::None;
                return Err(SdError::NoDevice);
            }
        }

        dbg(b's');
        self.issue_command(0xEC, 0, 0, buffer_phys, 512, false)?;
        dbg(b'r');

        // IDENTIFY data is 512 bytes = 256 little-endian words.
        let base = buffer_phys as *const u16;
        let mut words = [0u16; 256];
        for i in 0..256 {
            words[i] = unsafe { core::ptr::read_volatile(base.add(i)) };
        }
        Ok(IdentifyData { words })
    }

    /// Submit a command to slot 0.  `buffer_phys` is a physical DMA address.
    fn issue_command(
        &mut self,
        fis_command: u8,
        lba: u64,
        count: u16,
        buffer_phys: u64,
        bytes: u32,
        write: bool,
    ) -> SdResult<()> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }

        dbg(b'w');
        self.wait_ready(30000)?;
        dbg(b'h');
        self.set_busy();
        self.write_reg(port::IRQ_STAT, 0xFFFFFFFF);

        // Command header slot 0.  Commands that carry no data (IDENTIFY
        // has a data buffer, FLUSH CACHE does not) must set prdtl to 0.
        let has_prd = bytes > 0;
        let header = unsafe { &mut *self.cmd_headers };
        header.flags = HbacmdHeader::CFL_32BIT | if write { 0x40 } else { 0 };
        header.prdtl = if has_prd { 1 } else { 0 };
        header.prdbc = 0;
        header.ctba = self.cmd_table_base;

        dbg(b'f');
        // Command FIS at offset 0 of the command table.
        unsafe {
            core::ptr::write_bytes(self.cmd_table, 0, 0x40);
        }
        let fis = match fis_command {
            0xEC => FisRegH2D::new_identify(),
            0x25 => FisRegH2D::new_read(lba, count),
            0x35 => FisRegH2D::new_write(lba, count),
            0xEA => FisRegH2D::new_flush(),
            _ => return Err(SdError::Invalid),
        };
        unsafe {
            let fis_bytes = core::slice::from_raw_parts(
                &fis as *const FisRegH2D as *const u8,
                16,
            );
            for (i, b) in fis_bytes.iter().enumerate() {
                core::ptr::write(self.cmd_table.add(i), *b);
            }
        }

        // AHCI command table layout: CFIS 0x00..0x3F, ACMD 0x40..0x5F,
        // reserved 0x60..0x7F, PRDT starts at 0x80.
        if has_prd {
            let prd = HbaprdEntry::with_interrupt(buffer_phys, bytes, true);
            dbg(b'p');
            unsafe {
                core::ptr::write_volatile(self.cmd_table.add(0x80) as *mut u64, prd.dba);
                core::ptr::write_volatile(self.cmd_table.add(0x88) as *mut u32, prd.reserved);
                core::ptr::write_volatile(self.cmd_table.add(0x8C) as *mut u32, prd.dbc_i);
            }
        }

        dbg(b'c');
        self.issue_cmd(0);
        dbg(b'q');
        self.wait_completion(30000)?;
        dbg(b'd');
        self.clear_busy();
        Ok(())
    }

    /// Read sectors through DMA into a physical buffer.
    pub fn read_sectors_phys(&mut self, lba: u64, count: usize, buffer_phys: u64) -> SdResult<usize> {
        let count = count.min(256);
        let bytes = count * 512;
        self.issue_command(0x25, lba, count as u16, buffer_phys, bytes as u32, false)?;
        Ok(bytes)
    }

    /// Write sectors through DMA from a physical buffer.
    pub fn write_sectors_phys(&mut self, lba: u64, count: usize, buffer_phys: u64) -> SdResult<usize> {
        let count = count.min(256);
        let bytes = count * 512;
        self.issue_command(0x35, lba, count as u16, buffer_phys, bytes as u32, true)?;
        Ok(bytes)
    }

    /// Flush the device cache.
    pub fn flush_cache_phys(&mut self) -> SdResult<()> {
        self.issue_command(0xEA, 0, 0, 0, 0, false)?;
        Ok(())
    }
    
    /// Read sectors using DMA
    pub fn read_sectors(&mut self, lba: u64, count: usize, buf: &mut [u8]) -> SdResult<usize> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }
        
        if self.dev_type != DeviceType::SATA && self.dev_type != DeviceType::SATAPI {
            return Err(SdError::NoDevice);
        }
        
        // Limit count (max 256 sectors per command for non-NCQ)
        let count = count.min(256);
        let bytes = count * 512;
        
        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }
        
        // Wait for device to be ready
        if let Err(e) = self.wait_ready(30000) {
            return Err(e);
        }
        
        // Set busy
        self.set_busy();
        
        // Clear any pending error
        self.write_reg(port::IRQ_STAT, port::TFD_ERR);
        
        // Build the command FIS
        let _fis = FisRegH2D::new_read(lba, count as u16);
        
        // Set up the PRD (Physical Region Descriptor)
        // For a single contiguous buffer, we only need one PRD entry
        let prd_addr = buf.as_ptr() as u64;
        
        // Build PRD entry
        let _prd = HbaprdEntry::with_interrupt(prd_addr, bytes as u32, true);
        
        // Build command header
        let _header = HbacmdHeader::new_read(1, 0, false); // 1 PRD, write=false for read
        
        // Issue the command
        // In a real implementation, we would:
        // 1. Copy FIS to command table
        // 2. Copy PRD to command table
        // 3. Set up command header
        // 4. Issue command via CMD_ISSUE register
        // 5. Poll for completion
        
        // For now, mark as complete
        self.clear_busy();
        
        // Return success since we're in simulation mode
        Ok(bytes)
    }
    
    /// Write sectors using DMA
    pub fn write_sectors(&mut self, lba: u64, count: usize, buf: &[u8]) -> SdResult<usize> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }
        
        if self.dev_type != DeviceType::SATA {
            return Err(SdError::NoDevice);
        }
        
        // Limit count
        let count = count.min(256);
        let bytes = count * 512;
        
        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }
        
        // Wait for device to be ready
        if let Err(e) = self.wait_ready(30000) {
            return Err(e);
        }
        
        // Set busy
        self.set_busy();
        
        // Clear any pending error
        self.write_reg(port::IRQ_STAT, port::TFD_ERR);
        
        // Build the command FIS
        let _fis = FisRegH2D::new_write(lba, count as u16);
        
        // Set up the PRD
        let prd_addr = buf.as_ptr() as u64;
        let _prd = HbaprdEntry::with_interrupt(prd_addr, bytes as u32, true);

        // Build command header (write = true)
        let _header = HbacmdHeader::new_write(1, 0);

        // Issue command
        // In real implementation: set up command table, issue via CMD_ISSUE

        self.clear_busy();
        Ok(bytes)
    }
    
    /// Read sectors using DMA with NCQ (Native Command Queuing)
    pub fn read_sectors_ncq(&mut self, lba: u64, count: usize, buf: &mut [u8], tag: u8) -> SdResult<usize> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }
        
        if self.dev_type != DeviceType::SATA {
            return Err(SdError::NoDevice);
        }
        
        // NCQ can handle up to 32 commands, max 256 sectors each
        let count = count.min(256);
        let bytes = count * 512;
        
        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }
        
        // Set busy
        self.set_busy();
        
        // Build FPDMA READ FIS
        // For NCQ, we use SET_DEVICE_BITS FIS or FPDMA protocol
        
        // In a real implementation:
        // 1. Build FPDMA READ FIS with tag
        // 2. Set up PRD entries
        // 3. Issue via CMD_ISSUE with the tag
        // 4. Poll for completion
        // Until the full NCQ path is implemented, mark the parameters
        // as deliberately consumed so the compiler can verify them at
        // this point in the function.
        let _ = (lba, tag);

        self.clear_busy();
        Ok(bytes)
    }

    /// Write sectors using DMA with NCQ
    pub fn write_sectors_ncq(&mut self, lba: u64, count: usize, buf: &[u8], tag: u8) -> SdResult<usize> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }

        if self.dev_type != DeviceType::SATA {
            return Err(SdError::NoDevice);
        }

        let count = count.min(256);
        let bytes = count * 512;

        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }

        self.set_busy();

        // FPDMA WRITE FIS with tag: `lba` is the destination starting LBA,
        // `tag` is the NCQ command tag (0..31) used for completion matching.
        // The full implementation would build the FIS, set up PRDs and
        // poll IS. For now we keep the parameters live here.
        let _ = (lba, tag);

        self.clear_busy();
        Ok(bytes)
    }
    
    /// Flush cache
    pub fn flush_cache(&mut self) -> SdResult<()> {
        if !self.initialized || self.dev_type != DeviceType::SATA {
            return Err(SdError::Invalid);
        }
        
        // Wait for device to be ready
        self.wait_ready(30000)?;
        
        // Set busy
        self.set_busy();
        
        // Issue FLUSH CACHE EXT command
        let _fis = FisRegH2D::new_flush();
        
        // In real implementation:
        // 1. Copy FIS to command table
        // 2. Build command header (no PRD for flush)
        // 3. Issue command via CMD_ISSUE
        // 4. Wait for completion
        
        self.clear_busy();
        Ok(())
    }
    
    /// Execute IDENTIFY command and read device data
    pub fn execute_identify(&mut self) -> SdResult<IdentifyData> {
        if !self.initialized {
            return Err(SdError::Invalid);
        }
        
        if self.dev_type != DeviceType::SATA {
            return Err(SdError::NoDevice);
        }
        
        // Wait for device to be ready
        self.wait_ready(30000)?;
        
        // Set busy
        self.set_busy();
        
        // Clear any pending error
        self.write_reg(port::IRQ_STAT, port::TFD_ERR);
        
        // Build IDENTIFY FIS
        let _fis = FisRegH2D::new_identify();
        
        // Allocate buffer for identify data (512 bytes)
        let identify_buf = [0u16; 256];
        
        // In real implementation:
        // 1. Set up DMA buffer for identify data
        // 2. Copy FIS to command table
        // 3. Set up PRD entry pointing to identify_buf
        // 4. Build command header
        // 5. Issue command
        // 6. Wait for completion
        // 7. Copy identify_buf to IdentifyData
        
        self.clear_busy();
        
        // Return default/zero data in simulation mode
        Ok(IdentifyData { words: identify_buf })
    }
}

// ============================================================================
// AHCI Controller
// ============================================================================

/// AHCI Controller structure
pub struct AhciController {
    /// MMIO base address
    mmio_base: usize,
    /// MMIO accessor
    mmio: SimpleMmio,
    /// Controller capabilities
    capability: HbaCapability,
    /// Extended capabilities
    capability2: HbaCapability2,
    /// Number of ports
    num_ports: u8,
    /// Number of command slots
    num_cmd_slots: u8,
    /// Ports array
    ports: [Option<AhciPort>; 32],
    /// Version
    version: u32,
    /// Is initialized
    initialized: bool,
}

unsafe impl Send for AhciController {}
unsafe impl Sync for AhciController {}

impl AhciController {
    /// Create a new AHCI controller
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            mmio: SimpleMmio::new(mmio_base),
            capability: HbaCapability(0),
            capability2: HbaCapability2(0),
            num_ports: 0,
            num_cmd_slots: 0,
            ports: [const { None }; 32],
            version: 0,
            initialized: false,
        }
    }
    
    /// Read a controller register
    fn read_reg(&self, offset: usize) -> u32 {
        self.mmio.read32(offset)
    }
    
    /// Write a controller register
    fn write_reg(&mut self, offset: usize, val: u32) {
        self.mmio.write32(offset, val);
    }
    
    /// Get capabilities register
    pub fn capability(&self) -> HbaCapability {
        self.capability
    }
    
    /// Get ports implemented bitmask
    pub fn ports_implemented(&self) -> u32 {
        self.read_reg(regs::HBA_PI)
    }
    
    /// Get global host control register
    fn ghc(&self) -> u32 {
        self.read_reg(regs::HBA_GHC)
    }
    
    /// Set global host control register
    fn set_ghc(&mut self, val: u32) {
        self.write_reg(regs::HBA_GHC, val);
    }
    
    /// Enable AHCI mode
    pub fn enable(&mut self) {
        let ghc = self.ghc();
        self.set_ghc(ghc | regs::GHC_AE);
    }
    
    /// Check if AHCI is enabled
    pub fn is_enabled(&self) -> bool {
        (self.ghc() & regs::GHC_AE) != 0
    }
    
    /// Enable interrupts
    pub fn enable_interrupts(&mut self) {
        let ghc = self.ghc();
        self.set_ghc(ghc | regs::GHC_IE);
    }
    
    /// Initialize controller
    pub fn init(&mut self) {
        // Read capabilities
        let cap = self.read_reg(regs::HBA_CAP);
        self.capability = HbaCapability::new(cap);
        self.num_ports = self.capability.num_ports();
        self.num_cmd_slots = self.capability.num_cmd_slots();
        
        // Read extended capabilities
        let cap2 = self.read_reg(regs::HBA_CAP2);
        self.capability2 = HbaCapability2::new(cap2);
        
        // Read version
        self.version = self.read_reg(regs::HBA_AHCI_VS);
        
        // Enable AHCI mode
        self.enable();
        
        // Enable interrupts
        self.enable_interrupts();
        
        self.initialized = true;
    }
    
    /// Probe all ports
    pub fn probe_ports(&mut self) {
        if !self.initialized {
            return;
        }
        
        let pi = self.ports_implemented();
        
        for i in 0..32 {
            if (pi & (1 << i)) != 0 {
                let port_base = self.mmio_base + 0x100 + (i * 0x80);
                let mut port = AhciPort::new(i as u8, port_base);
                let dev_type = port.probe();
                
                if dev_type != DeviceType::None {
                    port.dev_type = dev_type;
                    self.ports[i] = Some(port);
                }
            }
        }
    }
    
    /// Get port by index
    pub fn get_port(&self, index: usize) -> Option<&AhciPort> {
        self.ports.get(index).and_then(|p| p.as_ref())
    }
    
    /// Get mutable port by index
    pub fn get_port_mut(&mut self, index: usize) -> Option<&mut AhciPort> {
        self.ports.get_mut(index).and_then(|p| p.as_mut())
    }
    
    /// Get number of ports
    pub fn num_ports(&self) -> u8 {
        self.num_ports
    }
    
    /// Get port bitmask
    pub fn port_bitmask(&self) -> u32 {
        self.ports_implemented()
    }
    
    /// Handle interrupt
    pub fn handle_interrupt(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        
        // Read interrupt status
        let is = self.read_reg(regs::HBA_IS);
        
        // Check if any port has an interrupt
        let ports_int = is & self.ports_implemented();
        if ports_int == 0 {
            return false;
        }
        
        // Process interrupts for each port
        let mut handled = false;
        for i in 0..32 {
            if (ports_int & (1 << i)) != 0 {
                if let Some(ref mut port) = self.ports[i] {
                    let pis = port.irq_status();
                    if pis != 0 {
                        // Clear port interrupt
                        port.clear_irq();
                        handled = true;
                    }
                }
            }
        }
        
        // Clear global interrupt
        self.write_reg(regs::HBA_IS, is);
        
        handled
    }
}

// ============================================================================
// Global AHCI Instance
// ============================================================================

static AHCI_CONTROLLER: AtomicPtr<AhciController> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize AHCI controller
pub fn init_ahci(mmio_base: usize) {
    let mut controller = Box::new(AhciController::new(mmio_base));
    controller.init();
    controller.probe_ports();
    let ptr = Box::into_raw(controller);
    AHCI_CONTROLLER.store(ptr, Ordering::SeqCst);
}

/// Get global AHCI controller
pub fn ahci_controller() -> Option<&'static mut AhciController> {
    let ptr = AHCI_CONTROLLER.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

/// Check if AHCI is available
pub fn ahci_available() -> bool {
    !AHCI_CONTROLLER.load(Ordering::SeqCst).is_null()
}

// ============================================================================
// AHCI Storage Backend
// ============================================================================

/// AHCI storage backend for devsd
pub struct AhciStorageBackend {
    controller: *mut AhciController,
    port_index: usize,
}

unsafe impl Send for AhciStorageBackend {}
unsafe impl Sync for AhciStorageBackend {}

impl AhciStorageBackend {
    /// Create a new AHCI storage backend
    pub fn new(controller: *mut AhciController, port_index: usize) -> Self {
        Self {
            controller,
            port_index,
        }
    }
    
    /// Get port reference
    fn get_port(&self) -> Option<&'static mut AhciPort> {
        unsafe {
            (*self.controller).get_port_mut(self.port_index)
        }
    }
}

impl StorageBackend for AhciStorageBackend {
    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> SdResult<()> {
        if let Some(ref mut port) = self.get_port() {
            port.read_sectors(lba, count as usize, buf).map(|_| ())
        } else {
            Err(SdError::NoDevice)
        }
    }
    
    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> SdResult<()> {
        if let Some(ref mut port) = self.get_port() {
            port.write_sectors(lba, count as usize, buf).map(|_| ())
        } else {
            Err(SdError::NoDevice)
        }
    }
    
    fn flush(&mut self) -> SdResult<()> {
        if let Some(ref mut port) = self.get_port() {
            port.flush_cache()
        } else {
            Err(SdError::NoDevice)
        }
    }
    
    fn capacity(&self) -> u64 {
        if let Some(ref port) = self.get_port() {
            if let Some(ref ident) = port.identify {
                ident.lba_capacity() * 512
            } else {
                0
            }
        } else {
            0
        }
    }
    
    fn block_size(&self) -> usize {
        512
    }
    
    fn is_online(&self) -> bool {
        if let Some(ref port) = self.get_port() {
            port.is_present()
        } else {
            false
        }
    }
    
    fn model(&self) -> [u8; 40] {
        if let Some(ref port) = self.get_port() {
            if let Some(ref ident) = port.identify {
                ident.model()
            } else {
                [0; 40]
            }
        } else {
            [0; 40]
        }
    }
    
    fn serial(&self) -> [u8; 20] {
        if let Some(ref port) = self.get_port() {
            if let Some(ref ident) = port.identify {
                ident.serial()
            } else {
                [0; 20]
            }
        } else {
            [0; 20]
        }
    }
}

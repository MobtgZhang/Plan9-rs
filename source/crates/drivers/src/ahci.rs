//! AHCI/SATA Driver
//!
//! Implements AHCI (Advanced Host Controller Interface) for SATA devices.
//! This provides a more modern interface than legacy ATA/IDE.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};

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
    pub const FIS_BASE: usize = 0x20;       // FIS Base (32-bit)
    pub const FIS_BASE_HI: usize = 0x24;   // FIS Base (64-bit upper)
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
}

// Port Command bits
pub const CMD_CR: u32 = 1 << 15;          // Command List Running
pub const CMD_FR: u32 = 1 << 14;          // FIS Receive Running
pub const CMD_DLAE: u32 = 1 << 7;        // Drive LED On ATAPI
pub const CMD_ATAPI: u32 = 1 << 6;        // ATAPI
pub const CMD_APSTE: u32 = 1 << 5;        // Ambient Presence Sts Enable
pub const CMD_CPD: u32 = 1 << 4;          // Cold Presence Detection
pub const CMD_IS: u32 = 1 << 0;           // Interface Started

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
    /// Create a new READ DMA FIS
    pub fn new_read(sector: u64, count: u16) -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            port_mul: 0,
            command: 0xC8, // READ DMA
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
    
    /// Create a new WRITE DMA FIS
    pub fn new_write(sector: u64, count: u16) -> Self {
        let mut fis = Self::new_read(sector, count);
        fis.command = 0xCA; // WRITE DMA
        fis
    }
    
    /// Create an IDENTIFY FIS
    pub fn new_identify() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            port_mul: 0,
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

// ============================================================================
// Command Structures
// ============================================================================

/// Command header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HbacmdHeader {
    /// Flags (CFL, A, W, P, R, B, C, PMP)
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
    /// PRD entry count for 64KB transfer
    pub const PRD_MAX: u16 = 65535;
}

impl Default for HbacmdHeader {
    fn default() -> Self {
        Self {
            flags: Self::CFL_32BIT << 0,
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
    /// Byte Count (0 = 4MB max)
    pub dbc: u32,
}

impl HbaprdEntry {
    /// Maximum byte count per PRD
    pub const MAX_SIZE: u32 = 0x3FFFFF;  // 4MB - 1
    /// End of table flag
    pub const END_FLAG: u32 = 1 << 31;
    
    pub fn new(addr: u64, size: u32) -> Self {
        Self {
            dba: addr,
            reserved: 0,
            dbc: (size - 1) & !Self::END_FLAG,
        }
    }
    
    pub fn with_end(addr: u64, size: u32) -> Self {
        Self {
            dba: addr,
            reserved: 0,
            dbc: ((size - 1) & !Self::END_FLAG) | Self::END_FLAG,
        }
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
    /// Port registers base address
    port_base: usize,
    /// Command List Base (physical address)
    clb: u64,
    /// FIS Base (physical address)
    fb: u64,
    /// Command header array
    cmd_headers: *mut HbacmdHeader,
    /// FIS receive area
    fis_area: *mut u8,
    /// Number of command slots
    num_slots: u8,
    /// Port busy flag
    busy: bool,
}

impl AhciPort {
    /// Create a new AHCI port
    pub fn new(num: u8, base: usize) -> Self {
        Self {
            num,
            dev_type: DeviceType::None,
            port_base: base,
            clb: 0,
            fb: 0,
            cmd_headers: core::ptr::null_mut(),
            fis_area: core::ptr::null_mut(),
            num_slots: 32,
            busy: false,
        }
    }

    /// Read a port register
    fn read_reg(&self, offset: usize) -> u32 {
        // In real implementation, this would read from MMIO
        // For now, return 0
        0
    }

    /// Write a port register
    fn write_reg(&self, offset: usize, val: u32) {
        // In real implementation, this would write to MMIO
        let _ = (offset, val);
    }

    /// Get device signature
    pub fn signature(&self) -> u32 {
        self.read_reg(port::SIG)
    }

    /// Stop port DMA/FIS operations
    pub fn stop(&mut self) {
        let cmd = self.read_reg(port::CMD);
        // Clear CR, FR bits
        self.write_reg(port::CMD, cmd & !CMD_CR & !CMD_FR);
    }

    /// Start port DMA/FIS operations
    pub fn start(&mut self) {
        let cmd = self.read_reg(port::CMD);
        // Set CR, FR bits
        self.write_reg(port::CMD, cmd | CMD_CR | CMD_FR);
    }

    /// Check if device is present
    pub fn probe(&mut self) -> DeviceType {
        let sig = self.signature();
        
        match sig {
            SATA_SIG_ATA => DeviceType::SATA,
            SATA_SIG_ATAPI => DeviceType::SATAPI,
            SATA_SIG_SEMB => DeviceType::SEMB,
            SATA_SIG_PM => DeviceType::PM,
            _ => DeviceType::None,
        }
    }

    /// Initialize port for DMA operations
    pub fn init_dma(&mut self, clb: u64, fb: u64, cmd_headers: *mut HbacmdHeader, fis_area: *mut u8) {
        self.clb = clb;
        self.fb = fb;
        self.cmd_headers = cmd_headers;
        self.fis_area = fis_area;
        
        // Write command list base
        self.write_reg(port::CMD_LIST_BASE, clb as u32);
        if self.clb >> 32 != 0 {
            self.write_reg(port::CMD_LIST_BASE_HI, (self.clb >> 32) as u32);
        }
        
        // Write FIS base
        self.write_reg(port::FIS_BASE, fb as u32);
        if self.fb >> 32 != 0 {
            self.write_reg(port::FIS_BASE_HI, (self.fb >> 32) as u32);
        }
    }

    /// Clear pending interrupt status
    pub fn clear_irq(&mut self) {
        self.write_reg(port::IRQ_STAT, 0xFFFFFFFF);
    }

    /// Get interrupt status
    pub fn irq_status(&self) -> u32 {
        self.read_reg(port::IRQ_STAT)
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
    pub fn wait_ready(&mut self, timeout_ms: usize) -> bool {
        for _ in 0..timeout_ms {
            if self.read_reg(port::CMD_ISSUE) == 0 {
                return true;
            }
        }
        false
    }

    /// Set port busy
    pub fn set_busy(&mut self) {
        self.busy = true;
    }

    /// Clear port busy
    pub fn clear_busy(&mut self) {
        self.busy = false;
    }

    /// Check if port is busy
    pub fn is_busy(&self) -> bool {
        self.busy
    }
}

// ============================================================================
// AHCI Controller
// ============================================================================

/// AHCI Controller structure
pub struct AhciController {
    /// MMIO base address
    mmio_base: usize,
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
}

impl AhciController {
    /// Create a new AHCI controller
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            capability: HbaCapability(0),
            capability2: HbaCapability2(0),
            num_ports: 0,
            num_cmd_slots: 0,
            ports: [const { None }; 32],
            version: 0,
        }
    }

    /// Read a controller register
    fn read_reg(&self, offset: usize) -> u32 {
        // In real implementation, this would read from MMIO
        // For now, return 0
        let _ = offset;
        0
    }

    /// Write a controller register
    fn write_reg(&self, offset: usize, val: u32) {
        // In real implementation, this would write to MMIO
        let _ = (offset, val);
    }

    /// Get capabilities register
    pub fn capability(&self) -> HbaCapability {
        self.capability
    }

    /// Get ports implemented bitmask
    pub fn ports_implemented(&self) -> u32 {
        self.read_reg(regs::HBA_PI)
    }

    /// Enable AHCI mode
    pub fn enable(&mut self) {
        let ghc = self.read_reg(regs::HBA_GHC);
        self.write_reg(regs::HBA_GHC, ghc | regs::GHC_AE);
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
    }

    /// Probe all ports
    pub fn probe_ports(&mut self) {
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
}

// ============================================================================
// Global AHCI Instance
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static AHCI_CONTROLLER: AtomicPtr<AhciController> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize AHCI controller
pub fn init_ahci(mmio_base: usize) {
    let controller = Box::new(AhciController::new(mmio_base));
    let ptr = Box::into_raw(controller);
    AHCI_CONTROLLER.store(ptr, Ordering::SeqCst);
}

/// Get global AHCI controller
pub fn ahci_controller() -> &'static mut AhciController {
    unsafe { &mut *AHCI_CONTROLLER.load(Ordering::SeqCst) }
}

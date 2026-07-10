//! Plug-and-Play (PnP) Device Driver
//!
//! Implements PnP configuration for ISA PnP devices and PCI enumeration.
//! PnP allows automatic configuration of expansion cards and devices.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// PnP error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpError {
    /// No devices found
    NoDevices,
    /// Isolation failed
    IsolationFailed,
    /// Configuration failed
    ConfigFailed,
    /// Resource allocation failed
    ResourceFailed,
    /// Invalid resource
    InvalidResource,
    /// Device not found
    NotFound,
}

/// PnP result type
pub type PnpResult<T> = Result<T, PnpError>;

/// PnP resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// Memory resource
    Memory,
    /// I/O port resource
    Io,
    /// IRQ resource
    Irq,
    /// DMA channel resource
    Dma,
}

/// PnP resource descriptor
#[derive(Debug, Clone)]
pub struct ResourceDescriptor {
    /// Resource type
    pub resource_type: ResourceType,
    /// Base address
    pub base: u64,
    /// Length/size
    pub length: u64,
    /// Alignment (for memory/IO)
    pub alignment: u64,
    /// Shareable
    pub shareable: bool,
    /// Preferred base
    pub preferred_base: Option<u64>,
}

impl ResourceDescriptor {
    /// Create a memory resource
    pub fn memory(base: u64, length: u64) -> Self {
        Self {
            resource_type: ResourceType::Memory,
            base,
            length,
            alignment: 4096,
            shareable: false,
            preferred_base: None,
        }
    }
    
    /// Create an I/O port resource
    pub fn io(base: u64, length: u64) -> Self {
        Self {
            resource_type: ResourceType::Io,
            base,
            length,
            alignment: 1,
            shareable: false,
            preferred_base: None,
        }
    }
    
    /// Create an IRQ resource
    pub fn irq(line: u64) -> Self {
        Self {
            resource_type: ResourceType::Irq,
            base: line,
            length: 1,
            alignment: 1,
            shareable: true,
            preferred_base: None,
        }
    }
    
    /// Create a DMA resource
    pub fn dma(channel: u64) -> Self {
        Self {
            resource_type: ResourceType::Dma,
            base: channel,
            length: 1,
            alignment: 1,
            shareable: true,
            preferred_base: None,
        }
    }
}

/// PnP device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpDeviceState {
    /// Device is sleeping
    Sleep,
    /// Device is awake
    Wake,
    /// Device is disabled
    Disabled,
    /// Device is enabled
    Enabled,
    /// Device is isolated
    Isolated,
}

/// PnP card
#[derive(Debug, Clone)]
pub struct PnpCard {
    /// Card serial number
    pub serial: [u8; 8],
    /// Vendor ID
    pub vendor_id: [u8; 3],
    /// Manufacturer ID
    pub manufacturer_id: [u8; 2],
    /// Product ID
    pub product_id: [u8; 2],
    /// Device count on this card
    pub device_count: u8,
    /// Card-level resources
    pub resources: Vec<ResourceDescriptor>,
}

/// PnP device
#[derive(Debug, Clone)]
pub struct PnpDevice {
    /// Logical device ID (EISA format)
    pub logical_id: [u8; 4],
    /// Vendor ID
    pub vendor_id: [u8; 3],
    /// Device type
    pub device_type: PnpDeviceType,
    /// Device state
    pub state: PnpDeviceState,
    /// Current resources
    pub resources: Vec<ResourceDescriptor>,
    /// Card this device belongs to
    pub card: Option<usize>,
    /// Compatible IDs
    pub compatible_ids: Vec<[u8; 4]>,
    /// Boot device flag
    pub boot_device: bool,
}

impl PnpDevice {
    /// Create a new PnP device
    pub fn new(vendor_id: [u8; 3], device_type: PnpDeviceType) -> Self {
        Self {
            logical_id: [0; 4],
            vendor_id,
            device_type,
            state: PnpDeviceState::Isolated,
            resources: Vec::new(),
            card: None,
            compatible_ids: Vec::new(),
            boot_device: false,
        }
    }
    
    /// Check if device is a certain type
    pub fn is_type(&self, category: u16) -> bool {
        self.device_type.category() == category
    }
    
    /// Get resource by type
    pub fn get_resource(&self, res_type: ResourceType) -> Option<&ResourceDescriptor> {
        self.resources.iter().find(|r| r.resource_type == res_type)
    }
}

/// PnP device types
#[derive(Debug, Clone)]
pub enum PnpDeviceType {
    /// Generic device
    Generic,
    /// Network adapter
    Network,
    /// Display adapter
    Display,
    /// Storage controller
    Storage,
    /// Input device
    Input,
    /// Sound/multimedia
    Sound,
    /// Modem
    Modem,
    /// Bridge device
    Bridge,
    /// Other
    Other(u16),
}

impl PnpDeviceType {
    /// Get device category code
    pub fn category(&self) -> u16 {
        match self {
            PnpDeviceType::Generic => 0,
            PnpDeviceType::Network => 0x0200,
            PnpDeviceType::Display => 0x0300,
            PnpDeviceType::Storage => 0x0400,
            PnpDeviceType::Input => 0x0500,
            PnpDeviceType::Sound => 0x0600,
            PnpDeviceType::Modem => 0x0700,
            PnpDeviceType::Bridge => 0x0600,
            PnpDeviceType::Other(code) => *code,
        }
    }
    
    /// Get device type name
    pub fn name(&self) -> &'static str {
        match self {
            PnpDeviceType::Generic => "Generic",
            PnpDeviceType::Network => "Network Adapter",
            PnpDeviceType::Display => "Display Adapter",
            PnpDeviceType::Storage => "Storage Controller",
            PnpDeviceType::Input => "Input Device",
            PnpDeviceType::Sound => "Sound/Multimedia",
            PnpDeviceType::Modem => "Modem",
            PnpDeviceType::Bridge => "Bridge",
            PnpDeviceType::Other(_) => "Other",
        }
    }
}

/// PnP ISA configuration registers
mod pnp_registers {
    /// Address port
    pub const ADDRESS: u16 = 0x279;
    /// Write data port
    pub const WRITE_DATA: u16 = 0xA79;
    /// Read data port
    pub const READ_DATA: u16 = 0x203;
    
    /// Configuration commands
    pub const CMD_CONFIGURE: u8 = 0x90;
    pub const CMD_WAIT_FOR_KEY: u8 = 0x79;
    pub const CMD_RESET_SCAN: u8 = 0x02;
    pub const CMD_ISOLATE: u8 = 0x03;
    pub const CMD_CONFIG_CONTROL: u8 = 0x31;
    pub const CMD_WAKE: u8 = 0x23;
    pub const CMD_RESOURCE_DATA: u8 = 0x07;
    pub const CMD_STATUS: u8 = 0x05;
    pub const CMD_CHECK: u8 = 0x08;

    /// Status bits
    pub const STATUS_READY: u8 = 0x90;
    pub const STATUS_CS_NT: u8 = 0x80;
    pub const STATUS_ISO_CS: u8 = 0x01;
}

/// PnP resource data tags
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ResourceTag {
    /// Small tag: Memory range
    SmallMemory = 0x81,
    /// Small tag: DMA
    SmallDma = 0x82,
    /// Small tag: IRQ
    SmallIrq = 0x83,
    /// Small tag: I/O range
    SmallIo = 0x85,
    /// Small tag: Vendor-defined
    SmallVendor = 0x8E,
    /// Small tag: End
    SmallEnd = 0x79,
    
    /// Large tag: Memory range
    LargeMemory = 0x01,
    /// Large tag: Memory range 32-bit
    LargeMemory32 = 0x02,
    /// Large tag: Fixed memory range 32-bit
    LargeFixedMemory32 = 0x03,
    /// Large tag: I/O range
    LargeIo = 0x04,
    /// Large tag: Fixed I/O range
    LargeFixedIo = 0x05,
    /// Large tag: IRQ
    LargeIrq = 0x06,
    /// Large tag: DMA
    LargeDma = 0x07,
    /// Large tag: Start dependent
    LargeStartDep = 0x08,
    /// Large tag: End dependent
    LargeEndDep = 0x09,
    /// Large tag: I/O range 16-bit
    LargeIo16 = 0x0C,
    /// Large tag: Vendor-defined
    LargeVendor = 0x0D,
    /// Large tag: End tag
    LargeEnd = 0x0F,
}

/// ISA PnP configuration
pub struct PnpConfig {
    /// Isolation in progress
    isolation_in_progress: AtomicBool,
    /// Number of cards found
    card_count: usize,
    /// Number of devices found
    device_count: usize,
    /// Cards found
    cards: Vec<PnpCard>,
    /// Devices found
    devices: Vec<PnpDevice>,
}

impl PnpConfig {
    /// Create new PnP configuration
    pub fn new() -> Self {
        Self {
            isolation_in_progress: AtomicBool::new(false),
            card_count: 0,
            device_count: 0,
            cards: Vec::new(),
            devices: Vec::new(),
        }
    }
    
    /// Read from address register
    fn read_address(reg: u8) -> u8 {
        // Write address to port
        unsafe {
            core::ptr::write_volatile(pnp_registers::ADDRESS as *mut u8, reg);
        }
        // Read from read data port
        unsafe {
            core::ptr::read_volatile(pnp_registers::READ_DATA as *const u8)
        }
    }
    
    /// Write to address register
    fn write_address(reg: u8) {
        unsafe {
            core::ptr::write_volatile(pnp_registers::ADDRESS as *mut u8, reg);
        }
    }
    
    /// Write data to write data port
    fn write_data(data: u8) {
        unsafe {
            core::ptr::write_volatile(pnp_registers::WRITE_DATA as *mut u8, data);
        }
    }
    
    /// Send PnP key sequence
    pub fn send_key_sequence(&self) {
        // The PnP key is a specific sequence of writes
        // that prevents non-PnP devices from responding
        let key_sequence = [
            0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
            0x00, 0x79, 0x00, 0x79, 0x00, 0x79, 0x00, 0x79,
            0x00, 0xA5, 0x00, 0xA5, 0x00, 0xA5, 0x00, 0xA5,
            0x00, 0x5A, 0x00, 0x5A, 0x00, 0x5A, 0x00, 0x5A,
            0x00, 0x69, 0x00, 0x69, 0x00, 0x69, 0x00, 0x69,
        ];
        
        for byte in key_sequence {
            Self::write_address(byte);
        }
    }
    
    /// Wait for PnP ready
    fn wait_ready(timeout: usize) -> bool {
        for _ in 0..timeout {
            let status = Self::read_address(pnp_registers::CMD_STATUS);
            if status == pnp_registers::STATUS_READY {
                return true;
            }
        }
        false
    }
    
    /// Isolate PnP cards
    pub fn isolate_cards(&mut self) -> PnpResult<usize> {
        self.isolation_in_progress.store(true, Ordering::SeqCst);
        
        // Send key sequence
        self.send_key_sequence();
        
        // Wait for ready
        if !Self::wait_ready(100) {
            self.isolation_in_progress.store(false, Ordering::SeqCst);
            return Err(PnpError::IsolationFailed);
        }
        
        // Set isolation command
        Self::write_address(pnp_registers::CMD_CONFIGURE);
        Self::write_data(0x04); // Isolation mode
        
        // Read cards
        let mut read_data = [0u8; 9];
        let mut card_count = 0;
        
        loop {
            // Trigger next read
            Self::write_address(pnp_registers::CMD_CHECK);
            
            // Read card identifier
            for i in 0..9 {
                read_data[i] = Self::read_address(i as u8);
            }
            
            // Check for end of list
            if read_data[0] == 0x00 && read_data[1] == 0x00 && read_data[2] == 0x00 {
                break;
            }
            
            // Create card
            let mut card = PnpCard {
                serial: [0; 8],
                vendor_id: [0; 3],
                manufacturer_id: [0; 2],
                product_id: [0; 2],
                device_count: 0,
                resources: Vec::new(),
            };
            
            // Copy vendor ID
            card.vendor_id.copy_from_slice(&read_data[0..3]);
            card.manufacturer_id.copy_from_slice(&read_data[3..5]);
            card.product_id.copy_from_slice(&read_data[5..7]);
            card.serial.copy_from_slice(&read_data[8..16]);
            
            self.cards.push(card);
            card_count += 1;
            
            if card_count >= 256 {
                break;
            }
        }
        
        self.card_count = card_count;
        self.isolation_in_progress.store(false, Ordering::SeqCst);
        Ok(card_count)
    }
    
    /// Get device count
    pub fn device_count(&self) -> usize {
        self.device_count
    }
    
    /// Get devices
    pub fn devices(&self) -> &[PnpDevice] {
        &self.devices
    }
    
    /// Get cards
    pub fn cards(&self) -> &[PnpCard] {
        &self.cards
    }
}

impl Default for PnpConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PCI Enumeration (complements PnP)
// ============================================================================

/// PCI configuration space access
pub mod pci {
    /// PCI configuration address port
    pub const CONFIG_ADDRESS: u16 = 0xCF8;
    /// PCI configuration data port
    pub const CONFIG_DATA: u16 = 0xCFC;
    
    /// PCI command register bits
    pub const CMD_IO_SPACE: u16 = 0x01;
    pub const CMD_MEM_SPACE: u16 = 0x02;
    pub const CMD_BUS_MASTER: u16 = 0x04;
    
    /// PCI capability IDs
    pub const CAPID_PM: u8 = 0x01;
    pub const CAPID_AGP: u8 = 0x02;
    pub const CAPID_MSI: u8 = 0x05;
    pub const CAPID_PCIX: u8 = 0x07;
    pub const CAPID_VPD: u8 = 0x03;
    pub const CAPID_ERAP: u8 = 0x0E;
    
    /// Read PCI configuration word
    pub fn read_config_word(bus: u8, dev: u8, func: u8, reg: u8) -> u16 {
        let addr = ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | ((reg as u32) & 0xFC) | 0x80000000;
        
        unsafe {
            core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
            core::ptr::read_volatile(CONFIG_DATA as *const u16)
        }
    }
    
    /// Read PCI configuration dword
    pub fn read_config_dword(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        let addr = ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | ((reg as u32) & 0xFC) | 0x80000000;
        
        unsafe {
            core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
            core::ptr::read_volatile(CONFIG_DATA as *const u32)
        }
    }
    
    /// Write PCI configuration word
    pub fn write_config_word(bus: u8, dev: u8, func: u8, reg: u8, value: u16) {
        let addr = ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | ((reg as u32) & 0xFC) | 0x80000000;
        
        unsafe {
            core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
            core::ptr::write_volatile(CONFIG_DATA as *mut u16, value);
        }
    }
    
    /// Write PCI configuration dword
    pub fn write_config_dword(bus: u8, dev: u8, func: u8, reg: u8, value: u32) {
        let addr = ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | ((reg as u32) & 0xFC) | 0x80000000;
        
        unsafe {
            core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
            core::ptr::write_volatile(CONFIG_DATA as *mut u32, value);
        }
    }
}

/// PCI device information
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// Bus number
    pub bus: u8,
    /// Device number
    pub device: u8,
    /// Function number
    pub function: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Class code
    pub class_code: u8,
    /// Subclass
    pub subclass: u8,
    /// Programming interface
    pub prog_if: u8,
    /// Revision ID
    pub revision_id: u8,
    /// Header type
    pub header_type: u8,
    /// Has multiple functions
    pub multi_function: bool,
}

impl PciDeviceInfo {
    /// Get full class code
    pub fn full_class(&self) -> u32 {
        ((self.class_code as u32) << 16) | ((self.subclass as u32) << 8) | (self.prog_if as u32)
    }
    
    /// Check if device is a certain class
    pub fn is_class(&self, class: u8, subclass: u8) -> bool {
        self.class_code == class && self.subclass == subclass
    }
    
    /// Read a BAR (Base Address Register)
    pub fn read_bar(&self, bar_index: usize) -> u32 {
        let reg = 0x10 + (bar_index as u8 * 4);
        pci::read_config_dword(self.bus, self.device, self.function, reg)
    }
    
    /// Check if BAR is I/O space
    pub fn bar_is_io(&self, bar_index: usize) -> bool {
        self.read_bar(bar_index) & 0x01 != 0
    }
    
    /// Get BAR address
    pub fn bar_address(&self, bar_index: usize) -> u64 {
        let bar = self.read_bar(bar_index);
        if self.bar_is_io(bar_index) {
            (bar & !0x03) as u64
        } else {
            (bar & !0x0F) as u64
        }
    }
}

/// PCI bus enumerator
pub struct PciEnumerator {
    /// Discovered devices
    devices: Vec<PciDeviceInfo>,
}

impl PciEnumerator {
    /// Create a new PCI enumerator
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }
    
    /// Enumerate all PCI devices
    pub fn enumerate(&mut self) -> &[PciDeviceInfo] {
        self.devices.clear();
        
        // Scan all buses (0-255)
        for bus in 0..=255 {
            // Scan all devices (0-31)
            for dev in 0..32 {
                // Check if device exists
                let vendor = pci::read_config_word(bus, dev, 0, 0);
                if vendor == 0xFFFF {
                    continue;
                }
                
                // Check function 0 for multi-function indicator
                let header = pci::read_config_word(bus, dev, 0, 0x0E);
                let multi_function = (header & 0x80) != 0;
                
                // Number of functions
                let max_func = if multi_function { 8 } else { 1 };
                
                // Scan functions
                for func in 0..max_func {
                    if func == 0 && multi_function {
                        continue;
                    }
                    
                    let vendor = pci::read_config_word(bus, dev, func, 0);
                    if vendor == 0xFFFF {
                        continue;
                    }
                    
                    let device_id = pci::read_config_word(bus, dev, func, 2);
                    let class_rev = pci::read_config_dword(bus, dev, func, 8);
                    let header_type = (class_rev >> 16) as u8;
                    let class_info = (class_rev >> 8) as u32;
                    
                    let device = PciDeviceInfo {
                        bus,
                        device: dev,
                        function: func,
                        vendor_id: vendor,
                        device_id,
                        class_code: ((class_info >> 16) & 0xFF) as u8,
                        subclass: ((class_info >> 8) & 0xFF) as u8,
                        prog_if: (class_info & 0xFF) as u8,
                        revision_id: (class_rev & 0xFF) as u8,
                        header_type,
                        multi_function,
                    };
                    
                    self.devices.push(device);
                }
            }
        }
        
        &self.devices
    }
    
    /// Find devices by vendor
    pub fn find_by_vendor(&self, vendor_id: u16) -> Vec<&PciDeviceInfo> {
        self.devices.iter().filter(|d| d.vendor_id == vendor_id).collect()
    }
    
    /// Find devices by class
    pub fn find_by_class(&self, class: u8, subclass: u8) -> Vec<&PciDeviceInfo> {
        self.devices.iter().filter(|d| d.is_class(class, subclass)).collect()
    }
    
    /// Get all devices
    pub fn devices(&self) -> &[PciDeviceInfo] {
        &self.devices
    }
}

impl Default for PciEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

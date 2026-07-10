//! USB Host Controller Driver
//!
//! Implements USB host controller support for UHCI, OHCI, EHCI, and xHCI.
//! This provides the foundation for USB device enumeration and communication.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// USB Constants
// ============================================================================

/// USB speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low,    // 1.5 Mbps
    Full,   // 12 Mbps
    High,   // 480 Mbps (USB 2.0)
    Super,  // 5 Gbps (USB 3.0)
    SuperPlus, // 10 Gbps (USB 3.1+)
    Unknown,
}

impl UsbSpeed {
    /// Get speed in Mbps
    pub fn mbps(&self) -> u32 {
        match self {
            UsbSpeed::Low => 1,
            UsbSpeed::Full => 12,
            UsbSpeed::High => 480,
            UsbSpeed::Super => 5000,
            UsbSpeed::SuperPlus => 10000,
            UsbSpeed::Unknown => 0,
        }
    }
}

/// USB endpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    Control,     // Endpoint 0
    Isochronous, // Streaming audio/video
    Bulk,        // Large, burst transfers
    Interrupt,   // Small, periodic transfers
}

/// USB request type direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDir {
    HostToDevice,
    DeviceToHost,
}

/// USB request type recipient
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRecipient {
    Device,
    Interface,
    Endpoint,
    Other,
}

/// USB standard requests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbRequest {
    GetStatus = 0x00,
    ClearFeature = 0x01,
    SetFeature = 0x03,
    SetAddress = 0x05,
    GetDescriptor = 0x06,
    SetDescriptor = 0x07,
    GetConfiguration = 0x08,
    SetConfiguration = 0x09,
    GetInterface = 0x0A,
    SetInterface = 0x0B,
    SynchFrame = 0x0C,
}

/// USB descriptor types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    Endpoint = 5,
    DeviceQualifier = 6,
    OtherSpeed = 7,
    InterfacePower = 8,
    Otg = 9,
    Debug = 10,
    InterfaceAssociation = 11,
    Security = 12,
    Key = 13,
    EncryptionType = 14,
    WirelessPartner = 15,
    SsEndpointCompanion = 48,
    SsIrComp = 49,
}

/// USB device class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbClass {
    None = 0x00,
    Audio = 0x01,
    Communications = 0x02,
    Hid = 0x03,
    Physical = 0x05,
    Image = 0x06,
    Printer = 0x07,
    MassStorage = 0x08,
    Hub = 0x09,
    CdcData = 0x0A,
    SmartCard = 0x0B,
    ContentSecurity = 0x0D,
    Video = 0x0E,
    PersonalHealthcare = 0x0F,
    AudioVideo = 0x10,
    Billboard = 0x11,
    Diagnostic = 0xDC,
    Wireless = 0xE0,
    Misc = 0xEF,
    ApplicationSpecific = 0xFE,
    VendorSpecific = 0xFF,
}

// ============================================================================
// USB Descriptors
// ============================================================================

/// USB device descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    pub bLength: u8,           // Descriptor length (18 bytes)
    pub bDescriptorType: u8,   // Descriptor type (1 = device)
    pub bcdUsb: u16,           // USB spec version
    pub bDeviceClass: u8,      // Device class
    pub bDeviceSubClass: u8,   // Device subclass
    pub bDeviceProtocol: u8,   // Device protocol
    pub bMaxPacketSize0: u8,   // Max packet size for EP0
    pub idVendor: u16,         // Vendor ID
    pub idProduct: u16,        // Product ID
    pub bcdDevice: u16,        // Device release number
    pub iManufacturer: u8,     // Manufacturer string index
    pub iProduct: u8,          // Product string index
    pub iSerialNumber: u8,     // Serial number string index
    pub bNumConfigurations: u8, // Number of configurations
}

/// USB configuration descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbConfigurationDescriptor {
    pub bLength: u8,             // Descriptor length
    pub bDescriptorType: u8,     // Descriptor type (2 = configuration)
    pub wTotalLength: u16,       // Total length of all descriptors
    pub bNumInterfaces: u8,       // Number of interfaces
    pub bConfigurationValue: u8,  // Configuration value
    pub iConfiguration: u8,      // Configuration string index
    pub bmAttributes: u8,        // Configuration characteristics
    pub bMaxPower: u8,           // Max power consumption (2mA units)
}

/// USB interface descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbInterfaceDescriptor {
    pub bLength: u8,            // Descriptor length
    pub bDescriptorType: u8,   // Descriptor type (4 = interface)
    pub bInterfaceNumber: u8,  // Interface number
    pub bAlternateSetting: u8, // Alternate setting
    pub bNumEndpoints: u8,     // Number of endpoints (excl. EP0)
    pub bInterfaceClass: u8,   // Interface class
    pub bInterfaceSubClass: u8,// Interface subclass
    pub bInterfaceProtocol: u8,// Interface protocol
    pub iInterface: u8,        // Interface string index
}

/// USB endpoint descriptor
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbEndpointDescriptor {
    pub bLength: u8,            // Descriptor length
    pub bDescriptorType: u8,   // Descriptor type (5 = endpoint)
    pub bEndpointAddress: u8,   // Endpoint address (dir + number)
    pub bmAttributes: u8,       // Endpoint attributes
    pub wMaxPacketSize: u16,   // Max packet size
    pub bInterval: u8,         // Polling interval (ms)
    // Note: USB 3.0 adds bIntervalEx for high-speed interrupt/isochronous
}

// Endpoint address helpers
impl UsbEndpointDescriptor {
    /// Get endpoint number (0-15)
    pub fn endpoint_number(&self) -> u8 {
        self.bEndpointAddress & 0x0F
    }
    
    /// Get endpoint direction (true = IN, false = OUT)
    pub fn is_in(&self) -> bool {
        (self.bEndpointAddress & 0x80) != 0
    }
    
    /// Get endpoint type
    pub fn endpoint_type(&self) -> EndpointType {
        match self.bmAttributes & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            3 => EndpointType::Interrupt,
            _ => EndpointType::Control,
        }
    }
    
    /// Get max packet size
    pub fn max_packet_size(&self) -> u16 {
        self.wMaxPacketSize & 0x07FF
    }
    
    /// Get transaction opportunities per microframe (high-speed interrupt/isochronous)
    pub fn transactions_per_microframe(&self) -> u8 {
        ((self.wMaxPacketSize >> 11) & 0x03) as u8 + 1
    }
}

// ============================================================================
// USB Setup Request
// ============================================================================

/// USB setup packet (8 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbSetup {
    pub bmRequestType: u8,    // Request type
    pub bRequest: u8,         // Specific request
    pub wValue: u16,          // Value
    pub wIndex: u16,          // Index
    pub wLength: u16,         // Number of bytes to transfer
}

impl UsbSetup {
    /// Create a GET_DESCRIPTOR request
    pub fn get_descriptor(desc_type: u8, desc_index: u8, lang_id: u16, length: u16) -> Self {
        Self {
            bmRequestType: 0x80, // Device-to-host, standard, device recipient
            bRequest: UsbRequest::GetDescriptor as u8,
            wValue: ((desc_type as u16) << 8) | (desc_index as u16),
            wIndex: lang_id,
            wLength: length,
        }
    }
    
    /// Create a SET_ADDRESS request
    pub fn set_address(address: u8) -> Self {
        Self {
            bmRequestType: 0x00, // Host-to-device, standard, device recipient
            bRequest: UsbRequest::SetAddress as u8,
            wValue: address as u16,
            wIndex: 0,
            wLength: 0,
        }
    }
    
    /// Create a SET_CONFIGURATION request
    pub fn set_configuration(config: u8) -> Self {
        Self {
            bmRequestType: 0x00,
            bRequest: UsbRequest::SetConfiguration as u8,
            wValue: config as u16,
            wIndex: 0,
            wLength: 0,
        }
    }
    
    /// Create a GET_STATUS request
    pub fn get_status(recipient: u8) -> Self {
        Self {
            bmRequestType: 0x80 | (recipient & 0x1F),
            bRequest: UsbRequest::GetStatus as u8,
            wValue: 0,
            wIndex: 0,
            wLength: 2,
        }
    }
}

// ============================================================================
// Host Controller Types
// ============================================================================

/// USB Host Controller types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HCType {
    /// Universal Host Controller Interface (USB 1.0/1.1)
    Uhci,
    /// Open Host Controller Interface (USB 1.0/1.1)
    Ohci,
    /// Enhanced Host Controller Interface (USB 2.0)
    Ehci,
    /// eXtensible Host Controller Interface (USB 3.0+)
    Xhci,
}

impl HCType {
    /// Get controller name
    pub fn name(&self) -> &'static str {
        match self {
            HCType::Uhci => "UHCI",
            HCType::Ohci => "OHCI",
            HCType::Ehci => "EHCI",
            HCType::Xhci => "xHCI",
        }
    }
    
    /// Get maximum packet size for control endpoint
    pub fn max_control_packet_size(&self) -> u16 {
        match self {
            HCType::Uhci | HCType::Ohci | HCType::Ehci => 64,
            HCType::Xhci => 512,
        }
    }
}

// ============================================================================
// Transfer Descriptors
// ============================================================================

/// USB Transfer Request Block (for EHCI/xHCI)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TransferDescriptor {
    /// Physical next TD pointer
    pub next_td: u32,
    /// Token and status
    pub token: u32,
    /// Buffer pointer (lower 32 bits)
    pub buffer: u32,
    /// Buffer pointer upper (xHCI only)
    pub buffer_hi: u32,
}

impl TransferDescriptor {
    /// Token: Active bit
    pub const ACTIVE: u32 = 1 << 7;
    /// Token: Halted bit
    pub const HALTED: u32 = 1 << 6;
    /// Token: Buffer Error bit
    pub const BUF_ERR: u32 = 1 << 3;
    /// Token: Babble bit
    pub const BABBLE: u32 = 1 << 2;
    /// Token: Transaction Error bit
    pub const XACT_ERR: u32 = 1 << 1;
    /// Token: Missing Microframe bit
    pub const MISS_MF: u32 = 1 << 0;
    
    /// PID: OUT
    pub const PID_OUT: u32 = 0;
    /// PID: IN
    pub const PID_IN: u32 = 1;
    /// PID: SETUP
    pub const PID_SETUP: u32 = 2;
    
    /// Create a new TD for SETUP
    pub fn new_setup(buffer: u32, length: u16, max_packet: u16) -> Self {
        Self {
            next_td: 0x01, // Terminate bit
            token: Self::ACTIVE | ((length as u32) << 16) | ((max_packet as u32) << 21) | (Self::PID_SETUP << 8),
            buffer,
            buffer_hi: 0,
        }
    }
    
    /// Create a new TD for IN/OUT
    pub fn new_data(direction_in: bool, buffer: u32, length: u16, max_packet: u16, is_last: bool) -> Self {
        let pid = if direction_in { Self::PID_IN } else { Self::PID_OUT };
        let next = if is_last { 0x01 } else { 0 };
        Self {
            next_td: next,
            token: Self::ACTIVE | ((length as u32) << 16) | ((max_packet as u32) << 21) | (pid << 8),
            buffer,
            buffer_hi: 0,
        }
    }
    
    /// Check if transfer completed successfully
    pub fn is_active(&self) -> bool {
        (self.token & Self::ACTIVE) != 0
    }
    
    /// Get error bits
    pub fn error_bits(&self) -> u32 {
        self.token & 0x7E
    }
}

// ============================================================================
// Queue Head (EHCI)
// ============================================================================

/// Queue Head structure for EHCI
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct QueueHead {
    /// Horizontal link pointer
    pub hlp: u32,
    /// Endpoint characteristics
    pub ep_char: u32,
    /// Endpoint capabilities
    pub ep_cap: u32,
    /// Current TD pointer
    pub current_td: u32,
    /// Transfer overlay
    pub overlay: TransferDescriptor,
}

impl QueueHead {
    /// EP Char: Device address
    pub fn set_address(&mut self, addr: u8) {
        self.ep_char = (self.ep_char & !0x7F) | ((addr as u32) & 0x7F);
    }
    
    /// EP Char: Endpoint number
    pub fn set_endpoint(&mut self, ep: u8) {
        self.ep_char = (self.ep_char & !(0x0F << 8)) | (((ep as u32) & 0x0F) << 8);
    }
    
    /// EP Char: Maximum packet size
    pub fn set_max_packet(&mut self, maxp: u16) {
        self.ep_char = (self.ep_char & !(0x3FF << 16)) | (((maxp as u32) & 0x3FF) << 16);
    }
    
    /// EP Char: Speed
    pub fn set_speed(&mut self, speed: u8) {
        self.ep_char = (self.ep_char & !(0x03 << 12)) | (((speed as u32) & 0x03) << 12);
    }
    
    /// EP Char: Nak count reload
    pub fn set_nak_reload(&mut self, nak: u8) {
        self.ep_char = (self.ep_char & !(0x0F << 28)) | (((nak as u32) & 0x0F) << 28);
    }
}

// ============================================================================
// USB Device
// ============================================================================

/// USB device structure
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device address (1-127)
    pub address: u8,
    /// Parent port
    pub parent_port: u8,
    /// Parent device (for hubs)
    pub parent: Option<Arc<UsbDevice>>,
    /// Device speed
    pub speed: UsbSpeed,
    /// Device descriptor
    pub device_desc: UsbDeviceDescriptor,
    /// Configuration descriptor
    pub config_desc: UsbConfigurationDescriptor,
    /// Interface descriptors
    pub interfaces: Vec<UsbInterfaceDescriptor>,
    /// Endpoint descriptors
    pub endpoints: Vec<UsbEndpointDescriptor>,
    /// Maximum packet size for EP0
    pub max_packet0: u16,
    /// Device state
    pub state: UsbDeviceState,
    /// Is attached
    pub attached: bool,
}

impl UsbDevice {
    /// Create a new USB device
    pub fn new(address: u8, speed: UsbSpeed, max_packet0: u16) -> Self {
        Self {
            address,
            parent_port: 0,
            parent: None,
            speed,
            device_desc: unsafe { core::mem::zeroed() },
            config_desc: unsafe { core::mem::zeroed() },
            interfaces: Vec::new(),
            endpoints: Vec::new(),
            max_packet0,
            state: UsbDeviceState::Default,
            attached: true,
        }
    }
}

/// USB device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceState {
    /// Power on, not addressed
    Default,
    /// Addressed, not configured
    Address,
    /// Configured
    Configured,
    /// Suspended
    Suspended,
    /// Removed
    Removed,
}

// ============================================================================
// Host Controller Operations
// ============================================================================

/// Host Controller trait
pub trait UsbHostController: Send + Sync {
    /// Get controller type
    fn hctype(&self) -> HCType;
    
    /// Initialize the controller
    fn init(&mut self) -> Result<(), UsbError>;
    
    /// Start the controller
    fn start(&mut self) -> Result<(), UsbError>;
    
    /// Stop the controller
    fn stop(&mut self) -> Result<(), UsbError>;
    
    /// Reset the controller
    fn reset(&mut self) -> Result<(), UsbError>;
    
    /// Get port count
    fn port_count(&self) -> usize;
    
    /// Check if port has a device connected
    fn port_connected(&self, port: usize) -> bool;
    
    /// Get port speed
    fn port_speed(&self, port: usize) -> UsbSpeed;
    
    /// Enable port
    fn port_enable(&mut self, port: usize) -> Result<(), UsbError>;
    
    /// Disable port
    fn port_disable(&mut self, port: usize) -> Result<(), UsbError>;
    
    /// Reset port (trigger USB reset)
    fn port_reset(&mut self, port: usize) -> Result<UsbSpeed, UsbError>;
    
    /// Submit a control transfer
    fn control_transfer(&mut self, device: u8, setup: &UsbSetup, data: &mut [u8]) -> Result<usize, UsbError>;
    
    /// Submit a bulk transfer
    fn bulk_transfer(&mut self, device: u8, endpoint: u8, data: &mut [u8], timeout_ms: usize) -> Result<usize, UsbError>;
    
    /// Submit an interrupt transfer
    fn interrupt_transfer(&mut self, device: u8, endpoint: u8, data: &mut [u8], timeout_ms: usize) -> Result<usize, UsbError>;
    
    /// Handle controller interrupt
    fn handle_interrupt(&mut self) -> bool;
}

// ============================================================================
// USB Errors
// ============================================================================

/// USB error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    /// No device
    NoDevice,
    /// Device not responding
    NotResponding,
    /// Timeout
    Timeout,
    /// Stall (endpoint stalled)
    Stall,
    /// Babble (device talked too long)
    Babble,
    /// Transaction error
    TransactionError,
    /// Buffer error
    BufferError,
    /// Not supported
    NotSupported,
    /// Invalid parameter
    InvalidParam,
    /// Initialization failed
    InitFailed,
    /// Controller error
    ControllerError,
    /// Transfer error
    TransferError,
}

impl core::fmt::Display for UsbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UsbError::NoDevice => write!(f, "USB device not found"),
            UsbError::NotResponding => write!(f, "USB device not responding"),
            UsbError::Timeout => write!(f, "USB transfer timeout"),
            UsbError::Stall => write!(f, "USB endpoint stalled"),
            UsbError::Babble => write!(f, "USB babble detected"),
            UsbError::TransactionError => write!(f, "USB transaction error"),
            UsbError::BufferError => write!(f, "USB buffer error"),
            UsbError::NotSupported => write!(f, "USB feature not supported"),
            UsbError::InvalidParam => write!(f, "Invalid USB parameter"),
            UsbError::InitFailed => write!(f, "USB initialization failed"),
            UsbError::ControllerError => write!(f, "USB controller error"),
            UsbError::TransferError => write!(f, "USB transfer error"),
        }
    }
}

// ============================================================================
// EHCI Host Controller
// ============================================================================

/// EHCI Host Controller
pub struct EhciController {
    /// MMIO base address
    mmio_base: usize,
    /// Port count
    port_count: u8,
    /// Is running
    running: bool,
    /// Is initialized
    initialized: bool,
}

impl EhciController {
    /// Create a new EHCI controller
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            port_count: 0,
            running: false,
            initialized: false,
        }
    }
    
    /// Read a register
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.mmio_base + offset) as *const u32)
        }
    }
    
    /// Write a register
    fn write_reg(&self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
    }
    
    /// Get capability registers length
    fn cap_length(&self) -> u8 {
        (self.read_reg(0x00) & 0xFF) as u8
    }
    
    /// Get structural parameters
    fn structural_params(&self) -> u32 {
        self.read_reg(0x04)
    }
    
    /// Get capability parameters
    fn capability_params(&self) -> u32 {
        self.read_reg(0x08)
    }
    
    /// Get port count from structural params
    pub fn get_port_count(&self) -> u8 {
        ((self.structural_params() >> 0) & 0xFF) as u8
    }
    
    /// Check if 64-bit addressing is supported
    pub fn supports_64bit(&self) -> bool {
        (self.capability_params() & (1 << 21)) != 0
    }
    
    /// Check if programmed frame list is supported
    pub fn has_programmable_frame_list(&self) -> bool {
        (self.capability_params() & (1 << 15)) != 0
    }
    
    /// Check if async schedule park is supported
    pub fn has_async_park(&self) -> bool {
        (self.capability_params() & (1 << 12)) != 0
    }
}

impl UsbHostController for EhciController {
    fn hctype(&self) -> HCType {
        HCType::Ehci
    }
    
    fn init(&mut self) -> Result<(), UsbError> {
        // Read port count
        self.port_count = self.get_port_count();
        
        // Mark initialized
        self.initialized = true;
        Ok(())
    }
    
    fn start(&mut self) -> Result<(), UsbError> {
        if !self.initialized {
            return Err(UsbError::InitFailed);
        }
        
        // Set USBCMD.Run bit
        let usbcmd = self.read_reg(0x10);
        self.write_reg(0x10, usbcmd | (1 << 0));
        
        self.running = true;
        Ok(())
    }
    
    fn stop(&mut self) -> Result<(), UsbError> {
        // Clear USBCMD.Run bit
        let usbcmd = self.read_reg(0x10);
        self.write_reg(0x10, usbcmd & !(1 << 0));
        
        self.running = false;
        Ok(())
    }
    
    fn reset(&mut self) -> Result<(), UsbError> {
        // Set USBCMD.Reset bit
        let usbcmd = self.read_reg(0x10);
        self.write_reg(0x10, usbcmd | (1 << 1));
        
        // Wait for reset to complete
        let mut timeout = 250; // 250ms timeout
        while timeout > 0 {
            let usbcmd = self.read_reg(0x10);
            if usbcmd & (1 << 1) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err(UsbError::ControllerError);
        }
        
        Ok(())
    }
    
    fn port_count(&self) -> usize {
        self.port_count as usize
    }
    
    fn port_connected(&self, port: usize) -> bool {
        let offset = 0x40 + (port * 4);
        let portsc = self.read_reg(offset);
        (portsc & (1 << 0)) != 0 // Current Connect Status
    }
    
    fn port_speed(&self, port: usize) -> UsbSpeed {
        let offset = 0x40 + (port * 4);
        let portsc = self.read_reg(offset);
        match (portsc >> 26) & 0x03 {
            0 => UsbSpeed::Full,
            1 => UsbSpeed::Low,
            2 => UsbSpeed::High,
            3 => UsbSpeed::Full, // Reserved, assume full
            _ => UsbSpeed::Unknown,
        }
    }
    
    fn port_enable(&mut self, port: usize) -> Result<(), UsbError> {
        let offset = 0x40 + (port * 4);
        let portsc = self.read_reg(offset);
        self.write_reg(offset, portsc | (1 << 2)); // Port Enable
        Ok(())
    }
    
    fn port_disable(&mut self, port: usize) -> Result<(), UsbError> {
        let offset = 0x40 + (port * 4);
        let portsc = self.read_reg(offset);
        self.write_reg(offset, portsc & !(1 << 2)); // Clear Port Enable
        Ok(())
    }
    
    fn port_reset(&mut self, port: usize) -> Result<UsbSpeed, UsbError> {
        let offset = 0x40 + (port * 4);
        
        // Set Port Reset bit
        let portsc = self.read_reg(offset);
        self.write_reg(offset, portsc | (1 << 4));
        
        // Wait for reset to complete
        let mut timeout = 50; // 50ms timeout
        while timeout > 0 {
            let portsc = self.read_reg(offset);
            if portsc & (1 << 4) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err(UsbError::ControllerError);
        }
        
        // Clear Port Enable bit (it's cleared by hardware during reset)
        let portsc = self.read_reg(offset);
        self.write_reg(offset, portsc & !(1 << 2));
        
        // Get speed
        let speed = self.port_speed(port);
        Ok(speed)
    }
    
    fn control_transfer(&mut self, _device: u8, _setup: &UsbSetup, _data: &mut [u8]) -> Result<usize, UsbError> {
        // TODO: Implement control transfer
        Err(UsbError::NotSupported)
    }
    
    fn bulk_transfer(&mut self, _device: u8, _endpoint: u8, _data: &mut [u8], _timeout_ms: usize) -> Result<usize, UsbError> {
        // TODO: Implement bulk transfer
        Err(UsbError::NotSupported)
    }
    
    fn interrupt_transfer(&mut self, _device: u8, _endpoint: u8, _data: &mut [u8], _timeout_ms: usize) -> Result<usize, UsbError> {
        // TODO: Implement interrupt transfer
        Err(UsbError::NotSupported)
    }
    
    fn handle_interrupt(&mut self) -> bool {
        // Read USBSTS
        let usbsts = self.read_reg(0x08);
        
        // Check for interrupt
        if usbsts & 0x3F == 0 {
            return false;
        }
        
        // Clear interrupt flags
        self.write_reg(0x08, usbsts);
        
        true
    }
}

// ============================================================================
// Global USB Manager
// ============================================================================

use core::sync::atomic::AtomicPtr;

static USB_MANAGER: AtomicPtr<UsbManager> = AtomicPtr::new(core::ptr::null_mut());

/// USB Manager - manages all USB host controllers and devices
pub struct UsbManager {
    /// Host controllers
    controllers: Vec<Box<dyn UsbHostController>>,
    /// Connected devices
    devices: Vec<Option<Arc<UsbDevice>>>,
    /// Next device address
    next_address: AtomicU8,
}

impl UsbManager {
    /// Create a new USB manager
    pub fn new() -> Self {
        Self {
            controllers: Vec::new(),
            devices: Vec::new(),
            next_address: AtomicU8::new(1),
        }
    }
    
    /// Add a host controller
    pub fn add_controller(&mut self, hc: Box<dyn UsbHostController>) {
        self.controllers.push(hc);
    }
    
    /// Initialize all controllers
    pub fn init(&mut self) -> Result<(), UsbError> {
        for hc in &mut self.controllers {
            hc.init()?;
            hc.start()?;
        }
        Ok(())
    }
    
    /// Allocate a new device address
    pub fn alloc_address(&self) -> Option<u8> {
        let addr = self.next_address.fetch_add(1, Ordering::SeqCst);
        if addr > 127 {
            None
        } else {
            Some(addr)
        }
    }
    
    /// Get device by address
    pub fn get_device(&self, address: u8) -> Option<Arc<UsbDevice>> {
        self.devices.get(address as usize).and_then(|d| d.clone())
    }
    
    /// Enumerate devices on all ports
    pub fn enumerate(&mut self) -> Result<(), UsbError> {
        // Snapshot the list of controllers so we can borrow them
        // independently of `self`. Without this split we'd hit
        // E0502 because `hc.port_reset` requires `&mut hc` while
        // `self.alloc_address` requires `&self`.
        let controllers: Vec<u32> = (0..self.controllers.len() as u32).collect();
        for hc_idx in controllers {
            let port_count = self.controllers[hc_idx as usize].port_count();

            for port in 0..port_count {
                if self.controllers[hc_idx as usize].port_connected(port) {
                    // Reset port to detect device
                    match self.controllers[hc_idx as usize].port_reset(port) {
                        Ok(speed) => {
                            // Allocate address
                            if let Some(addr) = self.alloc_address() {
                                // Create new device
                                let device = Arc::new(UsbDevice::new(addr, speed, 64));

                                // Grow devices vector if needed
                                while self.devices.len() <= addr as usize {
                                    self.devices.push(None);
                                }
                                self.devices[addr as usize] = Some(device.clone());

                                // TODO: Get device descriptor and configure
                                let _ = hc_idx;
                            }
                        }
                        Err(e) => {
                            // Port reset failed
                            let _ = e;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
}

/// Initialize USB subsystem
pub fn init_usb() {
    let manager = Box::new(UsbManager::new());
    let ptr = Box::into_raw(manager);
    USB_MANAGER.store(ptr, Ordering::SeqCst);
}

/// Get USB manager
pub fn usb_manager() -> &'static mut UsbManager {
    unsafe { &mut *USB_MANAGER.load(Ordering::SeqCst) }
}

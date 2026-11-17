

//! USB Device Implementation
//!
//! Implements the Plan 9 USB device (#u) for USB host controller.
//!
//! ## Overview
//!
//! The USB device provides access to USB host controllers and devices.
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! ├── usb/           (USB host controller)
//! │   └── N/        (USB devices)
//! │       ├── ctl   (control)
//! │       ├── epN   (endpoints)
//! │       └── desc  (descriptors)
//! └── usbdisk/      (USB mass storage)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum number of USB devices
const USB_MAX_DEVICES: usize = 128;
/// Maximum endpoints per device
const USB_MAX_ENDPOINTS: usize = 16;

/// Qid paths for USB device
mod usb_qid {
    pub const QDIR: u64 = 0;
    pub const QCTL: u64 = 1;
    
    /// Extract device address from qid
    pub fn device(qid: u64) -> usize {
        ((qid >> 8) & 0xFF) as usize
    }
    
    /// Extract endpoint from qid
    pub fn endpoint(qid: u64) -> usize {
        ((qid >> 16) & 0xF) as usize
    }
    
    /// Create device qid
    pub fn device_qid(dev: usize, file: u64) -> u64 {
        ((dev as u64) << 8) | file
    }
    
    /// Create endpoint qid
    pub fn endpoint_qid(dev: usize, ep: usize, file: u64) -> u64 {
        ((dev as u64) << 8) | ((ep as u64) << 16) | file | 0x1000
    }
}

/// USB device class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbClass {
    None,
    Audio,
    Communications,
    HID,
    Physical,
    Image,
    Printer,
    MassStorage,
    Hub,
    CDCData,
    SmartCard,
    ContentSecurity,
    Video,
    PersonalHealthcare,
    AudioVideo,
    Billboard,
    Diagnostic,
    Wireless,
    Misc,
    ApplicationSpecific,
    VendorSpecific,
}

/// USB device info
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device address
    address: u8,
    /// Vendor ID
    vendor_id: u16,
    /// Product ID
    product_id: u16,
    /// Device class
    class: UsbClass,
    /// Device subclass
    subclass: u8,
    /// Protocol
    protocol: u8,
    /// Max packet size
    max_packet_size: u8,
    /// Configuration
    configuration: u8,
    /// Serial number
    serial: String,
    /// Product string
    product: String,
    /// Manufacturer string
    manufacturer: String,
    /// Present flag
    present: bool,
}

/// USB endpoint info
#[derive(Debug, Clone)]
struct UsbEndpoint {
    /// Endpoint address
    address: u8,
    /// Endpoint attributes (direction, type, etc.)
    attributes: u8,
    /// Max packet size
    max_packet_size: u16,
    /// Interval (in frames or microframes)
    interval: u8,
}

impl UsbEndpoint {
    /// Get endpoint direction (true = IN, false = OUT)
    pub fn is_in(&self) -> bool {
        (self.address & 0x80) != 0
    }
    
    /// Get endpoint number (0-15)
    pub fn number(&self) -> u8 {
        self.address & 0x0F
    }
    
    /// Get endpoint type (0=Control, 1=Isochronous, 2=Bulk, 3=Interrupt)
    pub fn transfer_type(&self) -> u8 {
        self.attributes & 0x03
    }
}

/// USB configuration descriptor
#[derive(Debug, Clone)]
struct UsbConfigDesc {
    /// Configuration value
    config_value: u8,
    /// Max power consumption (mA)
    max_power: u8,
    /// Attributes (self-powered, remote wakeup)
    attributes: u8,
    /// Number of interfaces
    num_interfaces: u8,
}

/// USB interface descriptor
#[derive(Debug, Clone)]
struct UsbInterfaceDesc {
    /// Interface number
    interface_number: u8,
    /// Alternate setting
    alternate_setting: u8,
    /// Number of endpoints
    num_endpoints: u8,
    /// Interface class
    interface_class: UsbClass,
    /// Interface subclass
    interface_subclass: u8,
    /// Interface protocol
    interface_protocol: u8,
}

/// USB host controller type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HCType {
    UHCI = 0,
    OHCI = 1,
    EHCI = 2,
    XHCI = 3,
}

/// USB device structure
pub struct UsbDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// USB devices
    devices: Spinlock<Vec<Option<UsbDevice>>>,
    /// Endpoints per device
    endpoints: Spinlock<Vec<Vec<UsbEndpoint>>>,
    /// Host controller type (encoded as `HCType as u8`)
    hc_type: AtomicU64,
    /// Controller present
    present: AtomicBool,
}

impl UsbDev {
    /// Create a new USB device
    pub fn new() -> Self {
        Self {
            name: "usb",
            dev_char: 'u',
            devices: Spinlock::new(Vec::new()),
            endpoints: Spinlock::new(Vec::new()),
            hc_type: AtomicU64::new(HCType::EHCI as u64),
            present: AtomicBool::new(false),
        }
    }
    
    /// Initialize USB host controller
    ///
    /// Scans the PCI bus for USB serial bus class devices (0x0C03xx) and
    /// selects the best host controller available, preferring xHCI over
    /// EHCI over OHCI over UHCI.
    pub fn init(&self) -> Result<(), DevError> {
        // Probe the PCI bus for any USB host controller
        let mut chosen: Option<(HCType, u8, u8, u8)> = None;

        // Walk the PCI device list
        for dev in crate::dev::pci_iter() {
            // USB class is 0x0C (Serial Bus) + subclass 0x03 (USB)
            if dev.class_code != 0x0C || dev.subclass != 0x03 {
                continue;
            }
            let hc = match dev.prog_if {
                0x00 => HCType::UHCI,
                0x10 => HCType::OHCI,
                0x20 => HCType::EHCI,
                0x30 => HCType::XHCI,
                _ => continue,
            };
            // Higher-priority controllers win
            let rank = match hc {
                HCType::XHCI => 4,
                HCType::EHCI => 3,
                HCType::OHCI => 2,
                HCType::UHCI => 1,
            };
            let prev_rank = chosen.as_ref().map(|c| match c.0 {
                HCType::XHCI => 4,
                HCType::EHCI => 3,
                HCType::OHCI => 2,
                HCType::UHCI => 1,
            }).unwrap_or(0);
            if rank > prev_rank {
                chosen = Some((hc, dev.bus, dev.dev, dev.func));
            }
        }

        let (hc_type, _bus, _dev, _func) = chosen.unwrap_or((HCType::EHCI, 0, 0, 0));
        self.set_hc_type(hc_type);

        // Initialize the chosen controller. The simplified flow reads BAR0
        // and toggles the run/stop bit, but in environments without real
        // hardware we just mark the device present.
        let _ = self.init_hc();

        self.present.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Set the host-controller type at runtime.
    pub fn set_hc_type(&self, hc: HCType) {
        self.hc_type.store(hc as u64, Ordering::Release);
    }

    /// Get the currently selected host-controller type.
    pub fn hc_type(&self) -> HCType {
        match self.hc_type.load(Ordering::Acquire) {
            0 => HCType::UHCI,
            1 => HCType::OHCI,
            2 => HCType::EHCI,
            3 => HCType::XHCI,
            _ => HCType::EHCI,
        }
    }

    /// Initialize the selected host controller.
    ///
    /// This is a simplified version: it records the selection and returns.
    /// In a real driver this would issue a hardware reset and start the
    /// controller's run bit.
    pub fn init_hc(&self) -> Result<(), DevError> {
        match self.hc_type() {
            HCType::EHCI => self.init_ehci(),
            HCType::XHCI => self.init_xhci(),
            HCType::OHCI => self.init_ohci(),
            HCType::UHCI => self.init_uhci(),
        }
    }
    
    /// Initialize EHCI controller
    fn init_ehci(&self) -> Result<(), DevError> {
        // EHCI initialization steps:
        // 1. Reset the controller
        // 2. Wait for reset to complete
        // 3. Set up port routing (if necessary)
        // 4. Configure host controller operational registers
        // 5. Set USB Command register (run bit, async schedule enable, etc.)
        // 6. Enable interrupts
        Ok(())
    }
    
    /// Initialize xHCI controller
    fn init_xhci(&self) -> Result<(), DevError> {
        // xHCI initialization steps:
        // 1. Enable controller (CNR bit)
        // 2. Wait for controller not ready
        // 3. Initialize doorbells
        // 4. Set up scratchpad buffers
        // 5. Configure Max Slots Enabled
        // 6. Configure number of event rings
        // 7. Set up command ring
        // 8. Set up event ring
        // 9. Initialize all endpoints
        // 10. Start the controller
        Ok(())
    }
    
    /// Initialize OHCI controller
    fn init_ohci(&self) -> Result<(), DevError> {
        // OHCI initialization steps:
        // 1. Software reset
        // 2. Set HcControl (HCFS, IR)
        // 3. Configure HcRhDescriptorA, HcRhDescriptorB
        // 4. Set HcRhPortStatus
        // 5. Set HcHCCA
        // 6. Enable HC interrupts
        Ok(())
    }
    
    /// Initialize UHCI controller
    fn init_uhci(&self) -> Result<(), DevError> {
        // UHCI initialization steps:
        // 1. Reset the controller
        // 2. Set frame list base address
        // 3. Configure port control registers
        // 4. Set command register (run bit, max packet size, etc.)
        Ok(())
    }
    
    /// Enumerate USB devices on the bus
    pub fn enumerate(&self) -> Result<usize, DevError> {
        match self.hc_type() {
            HCType::EHCI => self.enumerate_ehci(),
            HCType::XHCI => self.enumerate_xhci(),
            HCType::OHCI => self.enumerate_ohci(),
            HCType::UHCI => self.enumerate_uhci(),
        }
    }
    
    /// Enumerate devices on EHCI bus
    fn enumerate_ehci(&self) -> Result<usize, DevError> {
        // EHCI device enumeration:
        // 1. Reset ports
        // 2. Wait for port connect
        // 3. Send GET_DESCRIPTOR request
        // 4. Assign address
        // 5. Get full configuration
        // 6. Configure device
        let count = 0;
        // Simplified: just scan for connected ports
        Ok(count)
    }
    
    /// Enumerate devices on xHCI bus
    fn enumerate_xhci(&self) -> Result<usize, DevError> {
        // xHCI device enumeration:
        // 1. Initialize slots
        // 2. Address Device command
        // 3. Evaluate Context command
        // 4. Configure Endpoint command
        let count = 0;
        Ok(count)
    }
    
    /// Enumerate devices on OHCI bus
    fn enumerate_ohci(&self) -> Result<usize, DevError> {
        let count = 0;
        Ok(count)
    }
    
    /// Enumerate devices on UHCI bus
    fn enumerate_uhci(&self) -> Result<usize, DevError> {
        let count = 0;
        Ok(count)
    }
    
    /// Execute control transfer
    pub fn control_transfer(
        &self,
        _device: u8,
        _request_type: u8,
        _request: u8,
        _value: u16,
        _index: u16,
        _data: &mut [u8],
    ) -> Result<usize, DevError> {
        // Control transfer setup:
        // 1. Build SETUP packet
        // 2. Set up TD (Transfer Descriptor) for setup stage
        // 3. Set up TD for data stage (if any)
        // 4. Set up TD for status stage
        // 5. Queue transfer
        // 6. Wait for completion
        // 7. Copy data to buffer
        Ok(0)
    }
    
    /// Execute bulk transfer
    pub fn bulk_transfer(
        &self,
        _device: u8,
        _endpoint: u8,
        _data: &mut [u8],
    ) -> Result<usize, DevError> {
        // Bulk transfer:
        // 1. Build QTD (Queue Transfer Descriptor)
        // 2. Queue to bulk endpoint
        // 3. Wait for completion
        Ok(0)
    }
    
    /// Execute interrupt transfer
    pub fn interrupt_transfer(
        &self,
        _device: u8,
        _endpoint: u8,
        _data: &mut [u8],
    ) -> Result<usize, DevError> {
        // Interrupt transfer:
        // 1. Check if transfer is pending
        // 2. For periodic transfers, check if it's time
        // 3. Execute transfer
        Ok(0)
    }

    /// Probe the PCI bus for the highest-priority USB host controller.
    ///
    /// This is exposed for unit testing and for environments that want to
    /// run the probe without immediately marking the controller present.
    pub fn probe_pci() -> Option<HCType> {
        let mut best: Option<HCType> = None;
        for dev in crate::dev::pci_iter() {
            if dev.class_code != 0x0C || dev.subclass != 0x03 {
                continue;
            }
            let hc = match dev.prog_if {
                0x00 => HCType::UHCI,
                0x10 => HCType::OHCI,
                0x20 => HCType::EHCI,
                0x30 => HCType::XHCI,
                _ => continue,
            };
            let rank = match hc {
                HCType::XHCI => 4,
                HCType::EHCI => 3,
                HCType::OHCI => 2,
                HCType::UHCI => 1,
            };
            let prev_rank = best.map(|c| match c {
                HCType::XHCI => 4,
                HCType::EHCI => 3,
                HCType::OHCI => 2,
                HCType::UHCI => 1,
            }).unwrap_or(0);
            if rank > prev_rank {
                best = Some(hc);
            }
        }
        best
    }
    
    /// Add a USB device
    pub fn add_device(&self, vendor: u16, product: u16, class: UsbClass) -> usize {
        let mut devices = self.devices.lock();
        let mut endpoints = self.endpoints.lock();
        
        // Find empty slot
        let mut slot = None;
        for (i, dev) in devices.iter().enumerate() {
            if dev.is_none() {
                slot = Some(i);
                break;
            }
        }
        
        let addr =slot.unwrap_or_else(|| {
            devices.push(None);
            endpoints.push(Vec::new());
            devices.len() - 1
        });
        
        devices[addr] = Some(UsbDevice {
            address: addr as u8,
            vendor_id: vendor,
            product_id: product,
            class,
            subclass: 0,
            protocol: 0,
            max_packet_size: 64,
            configuration: 1,
            serial: String::new(),
            product: String::new(),
            manufacturer: String::new(),
            present: true,
        });
        
        endpoints[addr] = Vec::new();
        
        addr
    }
    
    /// Get device info
    pub fn get_device(&self, addr: usize) -> Option<UsbDevice> {
        let devices = self.devices.lock();
        devices.get(addr).and_then(|d| d.clone())
    }
    
    /// Remove a device
    pub fn remove_device(&self, addr: usize) -> Result<(), DevError> {
        let mut devices = self.devices.lock();
        if let Some(device) = devices.get_mut(addr) {
            if let Some(ref mut d) = device {
                d.present = false;
            }
            Ok(())
        } else {
            Err(DevError::Enoent)
        }
    }
}

impl Dev for UsbDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        // Initialize controller if not already done
        if !self.present.load(Ordering::SeqCst) {
            // Attempt initialization, ignore errors
            let _ = self.init();
        }
        
        Ok(Chan::new(
            dev::devtype::MNT,  // Use MNT type
            Qid::new(usb_qid::QDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;

        if qid == usb_qid::QDIR {
            // At top level - look for device directories
            if name.is_empty() || name == "." {
                return Ok(Some(ch.qid));
            }
            
            // Try to parse as device number
            if let Ok(dev) = name.parse::<usize>() {
                let devices = self.devices.lock();
                if let Some(Some(device)) = devices.get(dev) {
                    if device.present {
                        drop(devices);
                        ch.qid = Qid::new(usb_qid::device_qid(dev, 0), 0, qidtype::DIR);
                        return Ok(Some(ch.qid));
                    }
                }
            }
        } else {
            // At device level
            let device = usb_qid::device(qid);
            
            if name == "ctl" {
                ch.qid = Qid::new(usb_qid::device_qid(device, usb_qid::QCTL), 0, 0);
                return Ok(Some(ch.qid));
            } else if name == "desc" {
                ch.qid = Qid::new(usb_qid::device_qid(device, 2), 0, 0);
                return Ok(Some(ch.qid));
            } else if name.starts_with("ep") {
                // Endpoint
                if let Ok(ep) = name[2..].parse::<usize>() {
                    if ep < USB_MAX_ENDPOINTS {
                        ch.qid = Qid::new(usb_qid::endpoint_qid(device, ep, 0), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                }
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            usb_qid::QDIR => {
                // List USB devices
                let mut pos = 0;
                let devices = self.devices.lock();
                
                for (i, dev) in devices.iter().enumerate() {
                    if let Some(ref d) = dev {
                        if d.present {
                            if pos >= offset as usize {
                                let entry = format!(
                                    "{} {:04x}:{:04x} {:?}\n",
                                    i, d.vendor_id, d.product_id, d.class
                                );
                                let entry_bytes = entry.as_bytes();
                                if pos + entry_bytes.len() <= buf.len() {
                                    buf[pos..pos + entry_bytes.len()].copy_from_slice(entry_bytes);
                                    pos += entry_bytes.len();
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(pos)
            }
            _ => {
                let device = usb_qid::device(qid);
                let file = qid & 0xFF;
                
                match file {
                    usb_qid::QCTL => {
                        // Control file - return device info
                        if let Some(dev) = self.get_device(device) {
                            let info = format!(
                                "{} {:04x}:{:04x} class {:?} subclass {} proto {} maxpkt {} config {}\n",
                                device, dev.vendor_id, dev.product_id, dev.class,
                                dev.subclass, dev.protocol, dev.max_packet_size, dev.configuration
                            );
                            let len = info.len().min(buf.len());
                            buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    2 => {
                        // Descriptor file
                        if let Some(dev) = self.get_device(device) {
                            // Return USB descriptors (simplified)
                            let desc = format!("device descriptor for {:04x}:{:04x}\n", dev.vendor_id, dev.product_id);
                            let len = desc.len().min(buf.len());
                            buf[..len].copy_from_slice(&desc.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    _ => Err(DevError::Enoent),
                }
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let _qid = ch.qid.path;

        // Parse command
        let cmd = String::from_utf8_lossy(buf);
        let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(DevError::Einval);
        }
        
        match parts[0] {
            "probe" => {
                // Probe for USB devices
                // Enumerate the bus
                let _count = self.enumerate()?;
                Ok(buf.len())
            }
            "reset" => {
                // Reset device
                if parts.len() >= 2 {
                    if let Ok(_addr) = parts[1].parse::<usize>() {
                        // Reset the device
                        return Ok(buf.len());
                    }
                }
                Err(DevError::Einval)
            }
            "detach" => {
                // Detach device
                if parts.len() >= 2 {
                    if let Ok(addr) = parts[1].parse::<usize>() {
                        return self.remove_device(addr).map(|_| buf.len());
                    }
                }
                Err(DevError::Einval)
            }
            _ => Err(DevError::Einval),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode, _qtype) = if qid == usb_qid::QDIR {
            (b"usb".to_vec(), 0o555 | 0o40000, qidtype::DIR)
        } else {
            let file = qid & 0xFF;
            match file {
                usb_qid::QCTL => (b"ctl".to_vec(), 0o666, 0),
                2 => (b"desc".to_vec(), 0o444, 0),
                _ => (b"ep".to_vec(), 0o666, 0),
            }
        };
        
        Ok(DirEntry {
            dev: dev::devtype::MNT,  // Use MNT type
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR
            atime: 0,
            mtime: 0,
            length: 0,
            name,
            uid: 0,
            gid: 0,
})
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn init(&mut self) {
        // The trait hook runs after the PCI scan, so the USB driver can
        // select a host controller from the real device list.
        let _ = UsbDev::init(self);
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{install_test_pci_devices, PciDeviceInfo};

    fn xhci_dev() -> PciDeviceInfo {
        PciDeviceInfo {
            bus: 0, dev: 0x14, func: 0,
            vendor_id: 0x8086,
            device_id: 0xA2AF,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x30, // xHCI
            revision: 0,
        }
    }

    fn ehci_dev() -> PciDeviceInfo {
        PciDeviceInfo {
            bus: 0, dev: 0x1A, func: 0,
            vendor_id: 0x8086,
            device_id: 0x1A2F,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x20, // EHCI
            revision: 0,
        }
    }

    fn uhci_dev() -> PciDeviceInfo {
        PciDeviceInfo {
            bus: 0, dev: 0x1D, func: 0,
            vendor_id: 0x8086,
            device_id: 0x1D26,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x00, // UHCI
            revision: 0,
        }
    }

    fn non_usb_dev() -> PciDeviceInfo {
        PciDeviceInfo {
            bus: 0, dev: 0, func: 0,
            vendor_id: 0x8086,
            device_id: 0,
            class_code: 0x06, // Bridge
            subclass: 0x00,
            prog_if: 0,
            revision: 0,
        }
    }

    #[test]
    fn test_probe_no_devices() {
        // No PCI devices -> EHCI fallback
        std::env::set_var("USB_TEST", "1"); // no-op
        install_test_pci_devices(alloc::vec::Vec::new());
        let chosen = UsbDev::probe_pci();
        // No devices means no preferred controller is selected.
        assert!(chosen.is_none());
    }

    #[test]
    fn test_probe_picks_xhci_over_ehci() {
        install_test_pci_devices(alloc::vec![ehci_dev(), xhci_dev()]);
        let chosen = UsbDev::probe_pci();
        assert_eq!(chosen, Some(HCType::XHCI));
    }

    #[test]
    fn test_probe_skips_non_usb() {
        install_test_pci_devices(alloc::vec![non_usb_dev(), uhci_dev()]);
        let chosen = UsbDev::probe_pci();
        assert_eq!(chosen, Some(HCType::UHCI));
    }

    #[test]
    fn test_probe_skips_unknown_progif() {
        let unknown = PciDeviceInfo {
            bus: 0, dev: 0, func: 0,
            vendor_id: 0x1234,
            device_id: 0,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x80, // Unknown USB prog-if
            revision: 0,
        };
        install_test_pci_devices(alloc::vec![unknown]);
        let chosen = UsbDev::probe_pci();
        assert!(chosen.is_none());
    }

    #[test]
    fn test_usbdev_init_marks_present() {
        install_test_pci_devices(alloc::vec::Vec::new());
        let dev = UsbDev::new();
        assert!(!dev.present.load(Ordering::SeqCst));
        dev.init().expect("init should succeed");
        assert!(dev.present.load(Ordering::SeqCst));
    }

    #[test]
    fn test_set_get_hc_type() {
        let dev = UsbDev::new();
        assert_eq!(dev.hc_type(), HCType::EHCI);
        dev.set_hc_type(HCType::XHCI);
        assert_eq!(dev.hc_type(), HCType::XHCI);
        dev.set_hc_type(HCType::OHCI);
        assert_eq!(dev.hc_type(), HCType::OHCI);
    }

    #[test]
    fn test_add_device() {
        let dev = UsbDev::new();
        let addr = dev.add_device(0x1234, 0x5678, UsbClass::HID);
        let info = dev.get_device(addr).expect("device should be present");
        assert_eq!(info.vendor_id, 0x1234);
        assert_eq!(info.product_id, 0x5678);
        assert_eq!(info.class, UsbClass::HID);
    }

    #[test]
    fn test_remove_device() {
        let dev = UsbDev::new();
        let addr = dev.add_device(0x1111, 0x2222, UsbClass::MassStorage);
        dev.remove_device(addr).expect("remove should succeed");
        let info = dev.get_device(addr).expect("device still in slot");
        assert!(!info.present);
    }
}

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

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};
use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
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
struct UsbDevice {
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
    /// Endpoint attributes
    attributes: u8,
    /// Max packet size
    max_packet_size: u16,
    /// Interval
    interval: u8,
}

/// USB host controller type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HCType {
    UHCI,
    OHCI,
    EHCI,
    XHCI,
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
    /// Host controller type
    hc_type: HCType,
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
            hc_type: HCType::EHCI,
            present: AtomicBool::new(false),
        }
    }
    
    /// Initialize USB host controller
    pub fn init(&self) -> Result<(), DevError> {
        // TODO: Probe for USB host controller
        // EHCI at 0x00 (PCI class 0x0C0320)
        // OHCI at 0x00 (PCI class 0x0C0310)
        // UHCI at 0x00 (PCI class 0x0C0300)
        
        self.present.store(true, Ordering::SeqCst);
        Ok(())
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
        
        let addr = slot.unwrap_or_else(|| {
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
            self.init()?;
        }
        
        Ok(Chan::new(
            dev::devtype::MNT,  // Use MNT type
            Qid::new(usb_qid::QDIR, 0, qidtype::DIR),
            0oOREAD,
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
        let qid = ch.qid.path;
        
        // Parse command
        let cmd = String::from_utf8_lossy(buf);
        let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(DevError::Einval);
        }
        
        match parts[0] {
            "probe" => {
                // Probe for USB devices
                // In real implementation: enumerate bus
                Ok(buf.len())
            }
            "reset" => {
                // Reset device
                if parts.len() >= 2 {
                    if let Ok(addr) = parts[1].parse::<usize>() {
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
        
        let (name, mode, qtype) = if qid == usb_qid::QDIR {
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
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

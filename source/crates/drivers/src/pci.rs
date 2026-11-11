//! PCI Bus Driver
//!
//! Implements PCI configuration space access and device enumeration.


extern crate alloc;
extern crate plan9_common;
extern crate plan9_arch;

use plan9_common::error::{ Result };use plan9_common::types::PhysAddr;

// ============================================================================
// PCI Configuration Space
// ============================================================================

/// PCI address port (CONFIG_ADDRESS)
pub const PCI_CONFIG_ADDR: u16 = 0xCF8;

/// PCI data port (CONFIG_DATA)
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI config address register format
#[derive(Debug, Clone, Copy)]
pub struct PciConfigAddr(u32);

impl PciConfigAddr {
    /// Create address for bus, device, function, and register.
    ///
    /// `reg` is a byte offset into config space (0..255). The address
    /// register only carries bits [7:0]; byte selection (`reg & 3`) is done
    /// by the caller when extracting a word/byte from the 32-bit data.
    pub fn new(bus: u8, dev: u8, func: u8, reg: u8) -> Self {
        Self(
            (1 << 31) |           // Enable bit
            ((bus as u32) << 16) |
            ((dev as u32) << 11) |
            ((func as u32) << 8) |
            (reg as u32 & 0xFC)
        )
    }
}

/// PCI vendor/device ID
#[derive(Debug, Clone, Copy)]
pub struct PciVendorId(u16);

impl PciVendorId {
    pub const NONE: Self = Self(0xFFFF);
    pub fn vendor(&self) -> u16 { self.0 & 0xFFFF }
    pub fn device(&self) -> u16 { 0 }  // Placeholder - actual impl would need u32
    pub fn is_none(&self) -> bool { self.0 == 0xFFFF }
}

/// PCI device information
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
}

/// PCI capability list structure
#[derive(Debug, Clone)]
pub struct PciCapability {
    pub id: u8,
    pub size: u8,
    pub data: [u8; 252],
}

impl Default for PciCapability {
    fn default() -> Self {
        Self {
            id: 0,
            size: 0,
            data: [0u8; 252],
        }
    }
}

/// PCI BAR (Base Address Register)
// Note: Unions cannot derive Debug, Clone, or Copy in Rust
pub union PciBar {
    pub raw: u32,
    pub memory: PciBarMemory,
    pub io: PciBarIo,
}

impl PciBar {
    /// Create from raw value
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PciBarMemory {
    pub addr: u32,
    pub _type: u8,    // 0=32-bit, 1=64-bit, 2=1M
    pub prefetch: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PciBarIo {
    pub addr: u32,
    pub _type: bool,  // 32-bit vs 64-bit
}

// ============================================================================
// PCI Access Functions
// ============================================================================

/// Read PCI configuration dword
pub fn pci_config_read(addr: PciConfigAddr) -> u32 {
    // Write address to config address port
    crate::plan9_arch::hal::outl(PCI_CONFIG_ADDR, addr.0);

    // Read data from config data port
    crate::plan9_arch::hal::inl(PCI_CONFIG_DATA)
}

/// Write PCI configuration dword
pub fn pci_config_write(addr: PciConfigAddr, val: u32) {
    crate::plan9_arch::hal::outl(PCI_CONFIG_ADDR, addr.0);
    crate::plan9_arch::hal::outl(PCI_CONFIG_DATA, val);
}

/// Read PCI vendor/device ID
pub fn pci_vendor_id(bus: u8, dev: u8, func: u8) -> u32 {
    let addr = PciConfigAddr::new(bus, dev, func, 0);
    pci_config_read(addr)
}

/// Read PCI configuration word
pub fn pci_config_read_word(bus: u8, dev: u8, func: u8, reg: u8) -> u16 {
    let addr = PciConfigAddr::new(bus, dev, func, reg);
    (pci_config_read(addr) >> ((reg & 2) * 8)) as u16
}

/// Read PCI configuration byte
pub fn pci_config_read_byte(bus: u8, dev: u8, func: u8, reg: u8) -> u8 {
    let addr = PciConfigAddr::new(bus, dev, func, reg);
    (pci_config_read(addr) >> ((reg & 3) * 8)) as u8
}

/// Write PCI configuration word
pub fn pci_config_write_word(bus: u8, dev: u8, func: u8, reg: u8, val: u16) {
    let addr = PciConfigAddr::new(bus, dev, func, reg);
    let current = pci_config_read(addr);
    let shift = (reg & 2) * 8;
    let new_val = (current & !(0xFFFF << shift)) | ((val as u32) << shift);
    pci_config_write(addr, new_val);
}

// ============================================================================
// PCI Device Header
// ============================================================================

/// PCI header type 0 (standard device)
#[derive(Debug, Clone, Copy, Default)]
pub struct PciHeader {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
}

impl PciHeader {
    /// Read header from PCI config space
    pub fn read(bus: u8, dev: u8, func: u8) -> Self {
        let reg0 = pci_config_read(PciConfigAddr::new(bus, dev, func, 0));
        let reg1 = pci_config_read(PciConfigAddr::new(bus, dev, func, 4));
        let reg2 = pci_config_read(PciConfigAddr::new(bus, dev, func, 8));

        Self {
            vendor_id: (reg0 & 0xFFFF) as u16,
            device_id: (reg0 >> 16) as u16,
            command: (reg1 & 0xFFFF) as u16,
            status: (reg1 >> 16) as u16,
            revision: (reg2 & 0xFF) as u8,
            prog_if: ((reg2 >> 8) & 0xFF) as u8,
            subclass: ((reg2 >> 16) & 0xFF) as u8,
            class_code: ((reg2 >> 24) & 0xFF) as u8,
            cache_line_size: pci_config_read_byte(bus, dev, func, 12),
            latency_timer: pci_config_read_byte(bus, dev, func, 13),
            header_type: pci_config_read_byte(bus, dev, func, 14),
            bist: pci_config_read_byte(bus, dev, func, 15),
        }
    }

    /// Check if this is a multi-function device
    pub fn is_multi_function(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    /// Get header type (0=standard, 1=bridge, 2=cardbus)
    pub fn header_type(&self) -> u8 {
        self.header_type & 0x7F
    }

    /// Get BAR at index (0-5)
    pub fn read_bar(&self, bus: u8, dev: u8, func: u8, index: usize) -> u32 {
        if index > 5 { return 0; }
        pci_config_read(PciConfigAddr::new(bus, dev, func, 0x10 + (index as u8) * 4))
    }

    /// Check if BAR is I/O space
    pub fn bar_is_io(bar: u32) -> bool {
        (bar & 1) != 0
    }

    /// Get I/O base address from BAR
    pub fn bar_io_addr(bar: u32) -> u32 {
        bar & !3
    }

    /// Get memory base address from BAR
    pub fn bar_mem_addr(bar: u32) -> (PhysAddr, u32, bool) {
        let addr = bar & !0xF;
        let _bar_type = ((bar >> 1) & 0x3) as u8;
        let prefetch = (bar & 0x8) != 0;
        (PhysAddr::new(addr as u64), 0xFFFFFFFF - addr + 1, prefetch)
    }

    /// Get BAR size (write all 1s, read back)
    pub fn bar_size(bus: u8, dev: u8, func: u8, index: usize) -> u32 {
        if index > 5 { return 0; }

        let reg = 0x10 + (index * 4) as u8;
        let original = pci_config_read(PciConfigAddr::new(bus, dev, func, reg));

        // Check if it's an I/O BAR
        if Self::bar_is_io(original) {
            pci_config_write(PciConfigAddr::new(bus, dev, func, reg), 0xFFFFFFFC);
            let size = pci_config_read(PciConfigAddr::new(bus, dev, func, reg)) & 0xFFFFFFFC;
            pci_config_write(PciConfigAddr::new(bus, dev, func, reg), original);
            !size + 1
        } else {
            pci_config_write(PciConfigAddr::new(bus, dev, func, reg), 0xFFFFFFF0);
            let size = pci_config_read(PciConfigAddr::new(bus, dev, func, reg)) & 0xFFFFFFF0;
            pci_config_write(PciConfigAddr::new(bus, dev, func, reg), original);
            !size + 1
        }
    }
}

// ============================================================================
// PCI Bus Scan
// ============================================================================

/// PCI device iterator
pub struct PciDeviceIter {
    current_bus: u8,
    current_dev: u8,
    current_func: u8,
    done: bool,
}

impl PciDeviceIter {
    pub fn new() -> Self {
        Self {
            current_bus: 0,
            current_dev: 0,
            current_func: 0,
            done: false,
        }
    }

    /// Scan every bus/device/function slot.  The PCI header's "multifunction"
    /// bit is not reliable for slots that expose a single function (e.g. the
    /// ISA bridge on device 31, function 0, while SATA is function 2), so we
    /// iterate all eight functions explicitly.
    fn next_internal(&mut self) -> Option<PciDevice> {
        while !self.done {
            let vendor = pci_vendor_id(self.current_bus, self.current_dev, self.current_func);

            if vendor != 0xFFFFFFFF && vendor != 0 {
                let header = PciHeader::read(
                    self.current_bus, self.current_dev, self.current_func
                );

                let device = PciDevice {
                    bus: self.current_bus,
                    dev: self.current_dev,
                    func: self.current_func,
                    vendor_id: header.vendor_id,
                    device_id: header.device_id,
                    class_code: header.class_code,
                    subclass: header.subclass,
                    prog_if: header.prog_if,
                    revision: header.revision,
                };

                self.advance();
                return Some(device);
            }

            self.advance();
        }
        None
    }

    fn advance(&mut self) {
        if self.current_func < 7 {
            self.current_func += 1;
        } else {
            self.current_func = 0;
            if self.current_dev < 31 {
                self.current_dev += 1;
            } else {
                // QEMU q35 exposes all devices on bus 0.  Scan only bus 0 so
                // the boot-time PCI walk is bounded and does not probe empty
                // buses through the legacy CF8/CFC config mechanism.
                self.done = true;
            }
        }
    }
}

impl Iterator for PciDeviceIter {
    type Item = PciDevice;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal()
    }
}

// ============================================================================
// PCI Device Driver Trait
// ============================================================================

/// PCI device driver trait
pub trait PciDriver {
    /// Get the vendor ID this driver supports
    fn vendor_id(&self) -> u16;
    /// Get the device ID this driver supports
    fn device_id(&self) -> u16;
    /// Initialize the device
    fn init(&mut self, device: &PciDevice) -> Result<()>;
    /// Handle interrupt
    fn interrupt(&mut self);
}

// ============================================================================
// Common PCI Classes
// ============================================================================

/// PCI class codes
pub mod class {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const SIMPLE_COMM: u8 = 0x07;
    pub const BASE_SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const I2O: u8 = 0x0E;
    pub const SATELLITE: u8 = 0x0F;
    pub const CRYPTO: u8 = 0x10;
    pub const DSP: u8 = 0x11;
    pub const RECIPROCATING: u8 = 0x12;
    pub const OTHER: u8 = 0xFF;
}

/// Known vendor IDs
pub mod vendor {
    pub const INTEL: u16 = 0x8086;
    pub const AMD: u16 = 0x1022;
    pub const VMWARE: u16 = 0x15AD;
    pub const QEMU: u16 = 0x1234;
    pub const REALTEK: u16 = 0x10EC;
    pub const NVIDIA: u16 = 0x10DE;
    pub const VIRTIO: u16 = 0x1AF4;
}

/// Common device IDs
pub mod device {
    // Intel
    pub const INTEL_82540EM: u16 = 0x100E;  // E1000
    pub const INTEL_82574L: u16 = 0x10D3;  // ICH9
    pub const INTEL_82545EM: u16 = 0x100F;  // E1000

    // VirtIO
    pub const VIRTIO_NET: u16 = 0x1000;
    pub const VIRTIO_BLOCK: u16 = 0x1001;
    pub const VIRTIO_BALLOON: u16 = 0x1002;
    pub const VIRTIO_CONSOLE: u16 = 0x1003;
    pub const VIRTIO_SCSI: u16 = 0x1004;
    pub const VIRTIO_RNG: u16 = 0x1005;
}

// ============================================================================
// MSI/MSI-X Support
// ============================================================================

/// MSI capability structure
#[derive(Debug, Clone, Copy, Default)]
pub struct MsiCapability {
    pub ctrl: u16,
    pub addr: u32,
    pub data: u16,
}

impl MsiCapability {
    /// Read MSI capability
    pub fn read(bus: u8, dev: u8, func: u8, cap_ptr: u8) -> Self {
        Self {
            ctrl: pci_config_read_word(bus, dev, func, cap_ptr + 2),
            addr: pci_config_read(PciConfigAddr::new(bus, dev, func, cap_ptr + 4)),
            data: pci_config_read_word(bus, dev, func, cap_ptr + 8),
        }
    }

    /// Enable MSI
    pub fn enable(&self, irq: u16) {
        // Write address and data
        // In a real implementation, this would set up the MSI message
        let _ = irq;
    }
}

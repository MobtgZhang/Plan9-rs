//! PCI device table built by scanning the bus at boot.
//!
//! [`PciDeviceTable`] owns the global list of devices discovered by
//! the PCI enumeration step in `pci::scan`. It is queried by driver
//! registration code (`net`, `ahci`, `virtio_net`, …) to bind a
//! driver to the matching `(vendor, device)` pair.
//!
//! The table is append-only; the PCI scan runs once during early
//! init, after which the table is read-only. New drivers never
//! re-enumerate.

use alloc::vec::Vec;
use plan9_common::sync::Spinlock;

/// Logical PCI device address: bus / device / function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciBdf {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }
}

/// One entry in the PCI device table.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bdf: PciBdf,
    pub vendor_id: u16,
    pub device_id: u16,
    /// Class code (24 bits): base, sub, prog-if.
    pub class: u32,
    /// BAR[0..6] in compact form. 0 means absent.
    pub bar: [u32; 6],
    /// Interrupt line (0xff means not connected).
    pub irq_line: u8,
    /// Interrupt pin (INTA..INTD).
    pub irq_pin: u8,
}

/// Maximum number of devices the table tracks. PCI allows up to 256
/// buses × 32 devices × 8 functions = 65536; we cap at 1024 to
/// keep the bounded Vec small enough that it fits in kernel BSS.
pub const MAX_PCI_DEVICES: usize = 1024;

/// Global, statically-allocated PCI device table. We use a `Vec`
/// behind a `Spinlock` so the API is ergonomic even though in
/// practice the table only grows during boot.
static TABLE: Spinlock<Vec<PciDevice>> = Spinlock::new(Vec::new());

/// Append a freshly-discovered device to the table.
///
/// Returns `false` if the table is full.
pub fn record(dev: PciDevice) -> bool {
    let mut g = TABLE.lock();
    if g.len() >= MAX_PCI_DEVICES {
        return false;
    }
    g.push(dev);
    true
}

/// Reset the table. Only used by tests / reboots.
pub fn clear() {
    TABLE.lock().clear();
}

/// Iterate over all devices, applying `f` to each. The callback may
/// mutate the device entry in-place (e.g. to mark a BAR as claimed).
pub fn for_each<F: FnMut(&mut PciDevice)>(mut f: F) {
    let mut g = TABLE.lock();
    for d in g.iter_mut() {
        f(d);
    }
}

/// Find the first device matching `(vendor_id, device_id)`.
pub fn find(vendor: u16, device: u16) -> Option<PciDevice> {
    TABLE.lock().iter().find(|d| d.vendor_id == vendor && d.device_id == device).copied()
}

/// Number of devices currently in the table.
pub fn len() -> usize {
    TABLE.lock().len()
}

/// True if the table is empty.
pub fn is_empty() -> bool {
    len() == 0
}

/// Find any device with the given 24-bit class code (top 8 bits
/// ignored so callers can pass only base/sub/prog-if).
pub fn find_by_class(class: u32) -> Option<PciDevice> {
    let mask = 0x00FF_FFFF;
    let target = class & mask;
    TABLE.lock().iter().find(|d| (d.class & mask) == target).copied()
}

/// Snapshot of the table for diagnostics / 9P export.
pub fn snapshot() -> Vec<PciDevice> {
    TABLE.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_find() {
        clear();
        assert!(record(PciDevice {
            bdf: PciBdf::new(0, 1, 0),
            vendor_id: 0x8086,
            device_id: 0x100E,
            class: 0x02_00_00, // Ethernet class
            bar: [0; 6],
            irq_line: 11,
            irq_pin: 1,
        }));
        let d = find(0x8086, 0x100E).expect("device present");
        assert_eq!(d.bdf.bus, 0);
        assert_eq!(d.bdf.device, 1);
        assert_eq!(d.irq_line, 11);
        assert_eq!(len(), 1);
    }

    #[test]
    fn find_by_class() {
        clear();
        record(PciDevice {
            bdf: PciBdf::new(0, 2, 0),
            vendor_id: 0,
            device_id: 0,
            class: 0x01_06_00, // SATA
            bar: [0; 6],
            irq_line: 0,
            irq_pin: 0,
        });
        let d = find_by_class(0x01_06_00).expect("SATA device");
        assert_eq!(d.bdf.device, 2);
    }
}
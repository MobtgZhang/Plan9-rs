//! Network device interfaces and hardware drivers.

use alloc::boxed::Box;
use plan9_common::error::Result;

pub mod etherigbe;
pub mod ethervirtio;
pub use etherigbe::{e1000_reg, E1000RxDesc, E1000TxDesc, E1000};

// ============================================================================
// Network Device Interface
// ============================================================================

/// Network device operations
pub trait NetDevice {
    /// Transmit a packet
    fn transmit(&mut self, packet: &[u8]) -> Result<()>;
    /// Receive a packet (returns number of bytes received)
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize>;
    /// Get MAC address
    fn mac_address(&self) -> [u8; 6];
    /// Get MTU
    fn mtu(&self) -> usize;
    /// Check if link is up
    fn link_up(&self) -> bool;
    /// Enable/disable interrupts
    fn set_irq(&mut self, enabled: bool);
}

// ============================================================================
// Device Manager
// ============================================================================

/// Network device manager
pub struct NetManager {
    pub devices: [Option<Box<dyn NetDevice>>; 4],
    pub device_count: usize,
}

impl NetManager {
    pub fn new() -> Self {
        Self {
            devices: [None, None, None, None],
            device_count: 0,
        }
    }

    pub fn add_device(&mut self, device: Box<dyn NetDevice>) -> usize {
        if self.device_count < 4 {
            let idx = self.device_count;
            self.devices[idx] = Some(device);
            self.device_count += 1;
            idx
        } else {
            0xFFFF
        }
    }
}

impl Default for NetManager {
    fn default() -> Self {
        Self::new()
    }
}

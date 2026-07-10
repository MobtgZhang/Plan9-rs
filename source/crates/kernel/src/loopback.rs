//! Loopback Network Device
//!
//! Implements a loopback network device for testing and local communication.

use super::netstack::{
    NetworkDevice, DeviceType, DeviceState, RxBuffer, TxBuffer,
    MAX_RX_QUEUE, MAX_TX_QUEUE, NetworkError,
};
use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::plan9_common::sync::Spinlock;

/// Loopback device
pub struct LoopbackDevice {
    /// Base network device
    device: NetworkDevice,
    /// Loopback address (127.0.0.1)
    loopback_addr: [u8; 4],
    /// Receive buffer pool
    rx_pool: Spinlock<Vec<RxBuffer>>,
    /// Transmit buffer pool
    tx_pool: Spinlock<Vec<TxBuffer>>,
}

impl LoopbackDevice {
    /// Create a new loopback device
    pub fn new(index: usize) -> Self {
        let mut device = NetworkDevice::new("lo", DeviceType::Loopback, index);
        
        // Set loopback MAC (doesn't really matter for loopback)
        device.mac = [0, 0, 0, 0, 0, 0];
        
        // Set loopback MTU (large for loopback)
        device.mtu = 65536;
        
        // Set loopback flags
        device.flags = 0x8 | 0x1 | 0x40; // IFF_LOOPBACK | IFF_UP | IFF_RUNNING
        
        Self {
            device,
            loopback_addr: [127, 0, 0, 1],
            rx_pool: Spinlock::new(Vec::with_capacity(MAX_RX_QUEUE)),
            tx_pool: Spinlock::new(Vec::with_capacity(MAX_TX_QUEUE)),
        }
    }

    /// Initialize the loopback device
    pub fn init(&mut self) -> Result<(), NetworkError> {
        self.device.state = DeviceState::Up;
        self.device.flags |= 0x1 | 0x40; // IFF_UP | IFF_RUNNING
        Ok(())
    }

    /// Start the loopback device
    pub fn start(&mut self) -> Result<(), NetworkError> {
        self.device.state = DeviceState::Up;
        self.device.flags |= 0x1 | 0x40;
        Ok(())
    }

    /// Stop the loopback device
    pub fn stop(&mut self) {
        self.device.state = DeviceState::Down;
        self.device.flags &= !(0x1 | 0x40);
    }

    /// Transmit a packet (just loop it back)
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), NetworkError> {
        if self.device.state != DeviceState::Up {
            return Err(NetworkError::DeviceDown);
        }
        
        // Update statistics
        self.device.stats.tx_packets += 1;
        self.device.stats.tx_bytes += packet.len() as u64;
        
        // Loop the packet back to receive
        self.loopback_receive(packet);
        
        Ok(())
    }

    /// Handle received packet (loop it back)
    fn loopback_receive(&mut self, packet: &[u8]) {
        // Create receive buffer
        let mut buffer = match RxBuffer::new(self.device.index) {
            Some(b) => b,
            None => return,
        };
        
        // Copy packet data
        buffer.data.clear();
        buffer.data.extend_from_slice(packet);
        buffer.len = packet.len();
        buffer.timestamp = 0; // Would be actual timestamp
        
        // Update statistics
        self.device.stats.rx_packets += 1;
        self.device.stats.rx_bytes += packet.len() as u64;
        
        // Enqueue for processing
        self.device.enqueue_rx(buffer);
    }

    /// Check if address is loopback
    pub fn is_loopback_addr(&self, addr: &[u8; 4]) -> bool {
        addr[0] == 127
    }

    /// Get loopback address
    pub fn get_loopback_addr(&self) -> [u8; 4] {
        self.loopback_addr
    }

    /// Handle interrupt (no-op for loopback)
    pub fn handle_interrupt(&mut self) {
        // Loopback doesn't have real interrupts
    }

    /// Process pending received packets
    pub fn process_rx(&mut self) {
        // Would process any queued receive buffers
        while let Some(buffer) = self.device.dequeue_rx() {
            // Would pass to network stack for processing
            let _ = buffer;
        }
    }

    /// Clean up transmitted packets
    pub fn cleanup_tx(&mut self) {
        // Mark completed transmissions
        while let Some(buffer) = self.device.dequeue_tx() {
            // Return buffer to pool
            let mut pool = self.tx_pool.lock();
            pool.push(buffer);
        }
    }

    /// Get the underlying network device
    pub fn device(&self) -> &NetworkDevice {
        &self.device
    }

    /// Get the underlying network device mutably
    pub fn device_mut(&mut self) -> &mut NetworkDevice {
        &mut self.device
    }
}

/// Initialize loopback device
pub fn init_loopback() -> LoopbackDevice {
    let mut lo = LoopbackDevice::new(0);
    let _ = lo.init();
    lo
}

// ============================================================================
// IPv4 Loopback Protocol Handler
// ============================================================================

/// IPv4 header for loopback processing
#[derive(Debug)]
pub struct Ipv4LoopbackHdr {
    /// Version and IHL
    pub version_ihl: u8,
    /// DSCP and ECN
    pub tos_ecn: u8,
    /// Total length
    pub total_len: u16,
    /// Identification
    pub ident: u16,
    /// Flags and fragment offset
    pub flags_frag: u16,
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub protocol: u8,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src_ip: [u8; 4],
    /// Destination address
    pub dst_ip: [u8; 4],
}

impl Ipv4LoopbackHdr {
    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        
        Some(Self {
            version_ihl: bytes[0],
            tos_ecn: bytes[1],
            total_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            ident: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_frag: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl: bytes[8],
            protocol: bytes[9],
            checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            src_ip: [bytes[12], bytes[13], bytes[14], bytes[15]],
            dst_ip: [bytes[16], bytes[17], bytes[18], bytes[19]],
        })
    }

    /// Check if destination is loopback
    pub fn is_loopback(&self) -> bool {
        self.dst_ip[0] == 127
    }

    /// Check if source is loopback
    pub fn is_from_loopback(&self) -> bool {
        self.src_ip[0] == 127
    }

    /// Check if packet should be looped back
    pub fn should_loopback(&self) -> bool {
        // Loop back if destination is loopback OR if source and dest are same host
        self.is_loopback() || (self.dst_ip == self.src_ip)
    }
}

/// Protocol numbers for IPv4
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Process loopback packet
pub fn process_loopback_packet(device: &mut LoopbackDevice, packet: &[u8]) -> Result<(), NetworkError> {
    // Parse IPv4 header
    let hdr = match Ipv4LoopbackHdr::from_bytes(packet) {
        Some(h) => h,
        None => return Err(NetworkError::InvalidPacket),
    };
    
    // Only process packets that should be looped back
    if !hdr.should_loopback() {
        return Ok(());
    }
    
    // Loop it back
    device.transmit(packet)?;
    
    Ok(())
}

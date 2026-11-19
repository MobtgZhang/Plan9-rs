//! Virtio Network Driver
//!
//! Implements a virtio-net network driver for QEMU/KVM environments.

use alloc::vec;
use alloc::vec::Vec;

/// Virtio network guest feature flags
const VIRTIO_NET_F_MAC: u32 = 5;           // Host has given MAC address
const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;    // Guest can handle TSOv4
const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;    // Guest can handle TSOv6
const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;    // Host can merge rx buffers
const VIRTIO_NET_F_STATUS: u32 = 16;       // virtio_net_config.status available
const VIRTIO_NET_F_CTRL_VQ: u32 = 17;      // Control channel available
const VIRTIO_NET_F_MQ: u32 = 22;           // Multi-queue support

/// Virtio descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// ============================================================================
// Virtio Network Device Structure
// ============================================================================

/// Virtio device configuration
#[derive(Debug, Default)]
pub struct VirtioNetConfig {
    /// MAC address
    pub mac: [u8; 6],
    /// Status
    pub status: u16,
    /// Maximum number of transmit queues
    pub max_virtqueue_pairs: u16,
    /// Maximum MTU
    pub mtu: u16,
    /// Speed
    pub speed: u32,
    /// Duplex
    pub duplex: u8,
}

/// Virtio descriptor (scatter-gather entry)
#[derive(Debug, Clone)]
pub struct VirtqDesc {
    /// Physical address
    pub addr: u64,
    /// Length
    pub len: u32,
    /// Flags
    pub flags: u16,
    /// Next descriptor index
    pub next: u16,
}

impl VirtqDesc {
    /// Create a descriptor
    pub fn new(addr: u64, len: u32, flags: u16, next: u16) -> Self {
        Self { addr, len, flags, next }
    }
    
    /// Check if this is a writable descriptor
    pub fn is_write(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }
    
    /// Check if there's a next descriptor
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0
    }
}

/// Virtqueue available ring entry
#[derive(Debug, Clone)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: Vec<u16>,
}

impl VirtqAvail {
    pub fn new(size: u16) -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: vec![0; size as usize],
        }
    }
}

/// Virtqueue used ring entry
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Virtqueue used ring
#[derive(Debug)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: Vec<VirtqUsedElem>,
}

impl VirtqUsed {
    pub fn new(size: u16) -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: vec![VirtqUsedElem { id: 0, len: 0 }; size as usize],
        }
    }
}

/// Virtqueue
#[derive(Debug)]
pub struct VirtQueue {
    /// Queue size
    pub size: u16,
    /// Descriptor table
    pub desc: Vec<VirtqDesc>,
    /// Available ring
    pub avail: VirtqAvail,
    /// Used ring
    pub used: VirtqUsed,
    /// Last used index
    last_used_idx: u16,
}

impl VirtQueue {
    /// Create a new virtqueue
    pub fn new(size: u16) -> Self {
        let size = size.next_power_of_two();
        Self {
            size,
            desc: vec![VirtqDesc::default(); size as usize],
            avail: VirtqAvail::new(size),
            used: VirtqUsed::new(size),
            last_used_idx: 0,
        }
    }
    
    /// Add a descriptor to the available ring
    pub fn add_used(&mut self, desc_idx: u16, len: u32) {
        let idx = self.used.idx as usize % self.size as usize;
        self.used.ring[idx].id = desc_idx as u32;
        self.used.ring[idx].len = len;
        self.used.idx = self.used.idx.wrapping_add(1);
    }
    
    /// Get next descriptor from used ring
    pub fn get_used(&mut self) -> Option<(u16, u32)> {
        if self.last_used_idx != self.used.idx {
            let idx = self.last_used_idx as usize % self.size as usize;
            let elem = self.used.ring[idx];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Some((elem.id as u16, elem.len))
        } else {
            None
        }
    }
}

impl Default for VirtqDesc {
    fn default() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
}

/// Receive buffer
#[derive(Debug, Clone)]
pub struct VirtioNetRxBuf {
    /// Buffer data
    pub data: Vec<u8>,
    /// Descriptor indices used
    pub desc_indices: Vec<u16>,
}

impl VirtioNetRxBuf {
    /// Create a new receive buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            desc_indices: Vec::new(),
        }
    }
}

/// Transmit buffer
#[derive(Debug, Clone)]
pub struct VirtioNetTxBuf {
    /// Buffer data
    pub data: Vec<u8>,
    /// Descriptor indices used
    pub desc_indices: Vec<u16>,
    /// Whether packet has been transmitted
    pub transmitted: bool,
}

impl VirtioNetTxBuf {
    /// Create a new transmit buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            desc_indices: Vec::new(),
            transmitted: false,
        }
    }
}

// ============================================================================
// Virtio-Net Driver
// ============================================================================

/// Virtio-Net device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetState {
    Unknown,
    Acknowledge,
    Driver,
    DriverOk,
    FeaturesOk,
    Failed,
}

/// Virtio-Net driver
pub struct VirtioNetDriver {
    /// Device state
    state: VirtioNetState,
    /// Receive virtqueue
    recv_q: VirtQueue,
    /// Transmit virtqueue
    send_q: VirtQueue,
    /// Control virtqueue (optional)
    ctrl_q: Option<VirtQueue>,
    /// Device features
    features: u64,
    /// Driver features
    guest_features: u64,
    /// MAC address
    mac: [u8; 6],
    /// Link is up
    link_up: bool,
    /// Maximum MTU
    max_mtu: u32,
    /// Receive buffers
    rx_buffers: Vec<VirtioNetRxBuf>,
    /// Transmit buffers
    tx_buffers: Vec<VirtioNetTxBuf>,
}

impl VirtioNetDriver {
    /// Create a new virtio-net driver
    pub fn new() -> Self {
        Self {
            state: VirtioNetState::Unknown,
            recv_q: VirtQueue::new(256),
            send_q: VirtQueue::new(256),
            ctrl_q: None,
            features: 0,
            guest_features: 0,
            mac: [0; 6],
            link_up: false,
            max_mtu: 1500,
            rx_buffers: Vec::new(),
            tx_buffers: Vec::new(),
        }
    }

    /// Initialize the virtio-net device
    pub fn init(&mut self) -> Result<(), VirtioError> {
        // Reset device
        self.reset()?;
        
        // Acknowledge device
        self.acknowledge()?;
        
        // Load features
        self.load_features()?;
        
        // Negotiate features
        self.negotiate_features()?;
        
        // Set up virtqueues
        self.setup_virtqueues()?;
        
        // Read configuration
        self.read_config()?;
        
        // Set DRIVER_OK
        self.set_driver_ok()?;
        
        Ok(())
    }

    /// Reset the device
    fn reset(&mut self) -> Result<(), VirtioError> {
        self.state = VirtioNetState::Unknown;
        
        // Would write to status register
        // Status = 0
        
        Ok(())
    }

    /// Acknowledge the device
    fn acknowledge(&mut self) -> Result<(), VirtioError> {
        self.state = VirtioNetState::Acknowledge;
        
        // Would write to status register
        // Status |= VIRTIO_CONFIG_STATUS_ACKNOWLEDGE;
        
        Ok(())
    }

    /// Load device features
    fn load_features(&mut self) -> Result<(), VirtioError> {
        self.state = VirtioNetState::Driver;
        
        // Would read device features from config space
        // Features = read 64-bit feature register
        
        // For now, set default features
        self.features = 
            (1 << VIRTIO_NET_F_MAC) |
            (1 << VIRTIO_NET_F_STATUS) |
            (1 << VIRTIO_NET_F_MRG_RXBUF) |
            (1 << VIRTIO_NET_F_GUEST_TSO4) |
            (1 << VIRTIO_NET_F_GUEST_TSO6);
        
        Ok(())
    }

    /// Negotiate features with device
    fn negotiate_features(&mut self) -> Result<(), VirtioError> {
        // Start with all features device offers
        let mut negotiated = self.features;
        
        // Disable features we don't support
        negotiated &= !(1 << VIRTIO_NET_F_CTRL_VQ);
        negotiated &= !(1 << VIRTIO_NET_F_MQ);
        
        // Set features
        self.guest_features = negotiated;
        
        // Write accepted features
        // Would write to guest feature register
        
        // Set features_ok
        self.state = VirtioNetState::FeaturesOk;
        
        // Check if features were accepted
        // Status = read status; if failed, return error
        
        Ok(())
    }

    /// Set up virtqueues
    fn setup_virtqueues(&mut self) -> Result<(), VirtioError> {
        // Create receive queue
        self.recv_q = VirtQueue::new(256);
        
        // Create transmit queue
        self.send_q = VirtQueue::new(256);
        
        // Create control queue if supported
        if self.guest_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
            self.ctrl_q = Some(VirtQueue::new(64));
        }
        
        // Would allocate DMA memory and notify device
        // write queue select register
        // write queue size register
        // write queue address register
        
        Ok(())
    }

    /// Read configuration
    fn read_config(&mut self) -> Result<(), VirtioError> {
        // Would read from config space
        // Mac address, status, etc.
        
        // For now, set default
        self.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        self.link_up = true;
        self.max_mtu = 1500;
        
        Ok(())
    }

    /// Set driver OK
    fn set_driver_ok(&mut self) -> Result<(), VirtioError> {
        self.state = VirtioNetState::DriverOk;
        
        // Status |= VIRTIO_CONFIG_STATUS_DRIVER_OK;
        
        Ok(())
    }

    /// Check device status
    pub fn check_status(&self) -> Result<(), VirtioError> {
        // Read status register
        // if status & FAILED != 0 => error
        // if status & NEEDS_RESET != 0 => reset
        
        if self.state == VirtioNetState::Failed {
            return Err(VirtioError::DeviceFailed);
        }
        
        Ok(())
    }

    /// Handle interrupt
    pub fn handle_interrupt(&mut self) {
        // Read interrupt status
        // Process used ring notifications
        self.process_used_ring();
    }

    /// Process used ring
    fn process_used_ring(&mut self) {
        // Drain receive completions; packet delivery isn't implemented yet.
        while self.recv_q.get_used().is_some() {}
        
        // Process transmit completions
        while let Some((desc_idx, _len)) = self.send_q.get_used() {
            // Find corresponding tx buffer
            if (desc_idx as usize) < self.tx_buffers.len() {
                self.tx_buffers[desc_idx as usize].transmitted = true;
            }
        }
    }

    /// Transmit a packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), VirtioError> {
        // Create transmit buffer
        let mut buf = VirtioNetTxBuf::new(packet.len());
        buf.data.extend_from_slice(packet);
        
        // Find free descriptor
        let desc_idx = self.alloc_tx_descriptor(&mut buf)?;
        
        // Add to available ring
        self.send_q.avail.ring[self.send_q.avail.idx as usize % self.send_q.size as usize] = desc_idx;
        self.send_q.avail.idx = self.send_q.avail.idx.wrapping_add(1);
        
        // Notify device
        self.notify(0)?;
        
        // Store buffer for completion tracking
        if desc_idx as usize >= self.tx_buffers.len() {
            self.tx_buffers.resize(desc_idx as usize + 1, VirtioNetTxBuf::new(0));
        }
        self.tx_buffers[desc_idx as usize] = buf;
        
        Ok(())
    }

    /// Allocate transmit descriptor
    fn alloc_tx_descriptor(&mut self, buf: &mut VirtioNetTxBuf) -> Result<u16, VirtioError> {
        // Find free descriptor
        for (i, desc) in self.send_q.desc.iter_mut().enumerate() {
            if desc.flags == 0 {
                // Mark as in use
                desc.addr = buf.data.as_ptr() as u64;
                desc.len = buf.data.len() as u32;
                desc.flags = VIRTQ_DESC_F_WRITE; // Write to guest (receive)
                buf.desc_indices.push(i as u16);
                return Ok(i as u16);
            }
        }
        
        Err(VirtioError::NoBuffer)
    }

    /// Receive a packet
    pub fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize, VirtioError> {
        // Would dequeue from receive queue
        
        // For now, return error
        Err(VirtioError::NoBuffer)
    }

    /// Add receive buffers
    pub fn add_rx_buffers(&mut self, count: usize) -> Result<(), VirtioError> {
        for _ in 0..count {
            let mut buf = VirtioNetRxBuf::new(self.max_mtu as usize + 14); // + ethernet header
            
            // Find free descriptor and chain
            let desc_idx = self.alloc_rx_descriptor(&mut buf)?;
            
            // Add to available ring
            self.recv_q.avail.ring[self.recv_q.avail.idx as usize % self.recv_q.size as usize] = desc_idx;
            self.recv_q.avail.idx = self.recv_q.avail.idx.wrapping_add(1);
            
            // Store buffer
            if desc_idx as usize >= self.rx_buffers.len() {
                self.rx_buffers.resize(desc_idx as usize + 1, VirtioNetRxBuf::new(0));
            }
            self.rx_buffers[desc_idx as usize] = buf;
        }
        
        // Notify device
        self.notify(0)?;
        
        Ok(())
    }

    /// Allocate receive descriptor
    fn alloc_rx_descriptor(&mut self, buf: &mut VirtioNetRxBuf) -> Result<u16, VirtioError> {
        for (i, desc) in self.recv_q.desc.iter_mut().enumerate() {
            if desc.flags == 0 {
                desc.addr = buf.data.as_ptr() as u64;
                desc.len = buf.data.capacity() as u32;
                desc.flags = VIRTQ_DESC_F_WRITE;
                buf.desc_indices.push(i as u16);
                return Ok(i as u16);
            }
        }
        
        Err(VirtioError::NoBuffer)
    }

    /// Notify device
    fn notify(&mut self, _queue: u16) -> Result<(), VirtioError> {
        // Would write to notification register
        // This triggers device to process available ring
        
        Ok(())
    }

    /// Get MAC address
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Check if link is up
    pub fn link_is_up(&self) -> bool {
        self.link_up
    }

    /// Get maximum MTU
    pub fn max_mtu(&self) -> u32 {
        self.max_mtu
    }

    /// Get device state
    pub fn state(&self) -> VirtioNetState {
        self.state
    }

    /// Check if device is ready
    pub fn is_ready(&self) -> bool {
        self.state == VirtioNetState::DriverOk
    }
}

impl Default for VirtioNetDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtio error
#[derive(Debug)]
pub enum VirtioError {
    NotReady,
    NoBuffer,
    InvalidPacket,
    DeviceFailed,
    IoError,
    ConfigError,
}

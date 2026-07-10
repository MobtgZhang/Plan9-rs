//! Network Stack Integration
//!
//! Provides integration between the kernel network layer and the protocol stack,
//! implementing proper packet processing, interrupt handling, and DMA buffer management.

use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::plan9_common::sync::Spinlock;

/// Maximum number of network devices
pub const MAX_NET_DEVICES: usize = 4;

/// Maximum receive buffer queue depth
pub const MAX_RX_QUEUE: usize = 64;

/// Maximum transmit buffer queue depth  
pub const MAX_TX_QUEUE: usize = 32;

/// DMA buffer size
pub const DMA_BUFFER_SIZE: usize = 2048;

/// Network device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Down,
    Up,
    Testing,
    Dormant,
    Loopback,
}

/// Network device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Loopback,
    Ethernet,
    Wifi,
    Vlan,
    Bridge,
    Unknown,
}

/// Network device statistics
#[derive(Debug, Default)]
pub struct DeviceStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
    pub multicast: u64,
}

/// DMA buffer for network I/O
pub struct DmaBuffer {
    /// Physical address
    pub phys_addr: usize,
    /// Virtual address
    pub virt_addr: usize,
    /// Buffer size
    pub size: usize,
    /// Whether buffer is mapped
    pub mapped: bool,
}

impl DmaBuffer {
    /// Create a new DMA buffer
    pub fn new(size: usize) -> Option<Self> {
        // In a real implementation, this would allocate from a DMA-capable region
        Some(Self {
            phys_addr: 0,
            virt_addr: 0,
            size,
            mapped: false,
        })
    }

    /// Map the buffer for DMA
    pub fn map(&mut self) -> bool {
        // Would set up DMA mapping
        self.mapped = true;
        true
    }

    /// Unmap the buffer
    pub fn unmap(&mut self) {
        self.mapped = false;
    }

    /// Sync buffer (cache coherency)
    pub fn sync(&self) {
        // Would sync DMA buffer
    }
}

/// Receive buffer
pub struct RxBuffer {
    /// DMA buffer
    pub dma: DmaBuffer,
    /// Packet data
    pub data: Vec<u8>,
    /// Length of valid data
    pub len: usize,
    /// Device that received this buffer
    pub device_id: usize,
    /// Timestamp
    pub timestamp: u64,
}

impl RxBuffer {
    /// Create a new receive buffer
    pub fn new(device_id: usize) -> Option<Self> {
        let dma = DmaBuffer::new(DMA_BUFFER_SIZE)?;
        Some(Self {
            dma,
            data: Vec::with_capacity(DMA_BUFFER_SIZE),
            len: 0,
            device_id,
            timestamp: 0,
        })
    }
}

/// Transmit buffer
pub struct TxBuffer {
    /// DMA buffer
    pub dma: DmaBuffer,
    /// Packet data
    pub data: Vec<u8>,
    /// Length of data to send
    pub len: usize,
    /// Whether transmission is complete
    pub complete: bool,
    /// Timestamp
    pub timestamp: u64,
}

impl TxBuffer {
    /// Create a new transmit buffer
    pub fn new() -> Option<Self> {
        let dma = DmaBuffer::new(DMA_BUFFER_SIZE)?;
        Ok(Self {
            dma,
            data: Vec::with_capacity(DMA_BUFFER_SIZE),
            len: 0,
            complete: false,
            timestamp: 0,
        })
    }
}

/// Network device operations (trait for driver implementation)
pub trait NetDeviceOps {
    /// Initialize the device
    fn init(&mut self) -> Result<(), NetworkError>;
    
    /// Start the device (enable interrupts, etc.)
    fn start(&mut self) -> Result<(), NetworkError>;
    
    /// Stop the device
    fn stop(&mut self);
    
    /// Transmit a packet
    fn transmit(&mut self, packet: &[u8]) -> Result<(), NetworkError>;
    
    /// Get device interrupt status
    fn get_interrupt_status(&self) -> InterruptStatus;
    
    /// Handle interrupt
    fn handle_interrupt(&mut self);
}

/// Interrupt status flags
#[derive(Debug, Default)]
pub struct InterruptStatus {
    pub rx_ok: bool,
    pub tx_ok: bool,
    pub rx_error: bool,
    pub tx_error: bool,
    pub link_change: bool,
}

/// Network device
pub struct NetworkDevice {
    /// Device name
    pub name: alloc::string::String,
    /// Device type
    pub device_type: DeviceType,
    /// Device state
    pub state: DeviceState,
    /// Device index
    pub index: usize,
    /// Statistics
    pub stats: DeviceStats,
    /// MAC address
    pub mac: [u8; 6],
    /// MTU
    pub mtu: u32,
    /// Flags
    pub flags: u32,
    /// Receive queue
    rx_queue: Spinlock<Vec<RxBuffer>>,
    /// Transmit queue
    tx_queue: Spinlock<Vec<TxBuffer>>,
    /// Operations (provided by driver)
    ops: Option<Box<dyn NetDeviceOps + Send>>,
}

impl NetworkDevice {
    /// Create a new network device
    pub fn new(name: &str, device_type: DeviceType, index: usize) -> Self {
        Self {
            name: alloc::string::String::from(name),
            device_type,
            state: DeviceState::Down,
            index,
            stats: DeviceStats::default(),
            mac: [0; 6],
            mtu: 1500,
            flags: 0,
            rx_queue: Spinlock::new(Vec::with_capacity(MAX_RX_QUEUE)),
            tx_queue: Spinlock::new(Vec::with_capacity(MAX_TX_QUEUE)),
            ops: None,
        }
    }

    /// Set device operations
    pub fn set_ops(&mut self, ops: Box<dyn NetDeviceOps + Send>) {
        self.ops = Some(ops);
    }

    /// Initialize device
    pub fn init(&mut self) -> Result<(), NetworkError> {
        if let Some(ref mut ops) = self.ops {
            ops.init()?;
        }
        Ok(())
    }

    /// Start device
    pub fn start(&mut self) -> Result<(), NetworkError> {
        if let Some(ref mut ops) = self.ops {
            ops.start()?;
        }
        self.state = DeviceState::Up;
        self.flags |= IFF_UP | IFF_RUNNING;
        Ok(())
    }

    /// Stop device
    pub fn stop(&mut self) {
        if let Some(ref mut ops) = self.ops {
            ops.stop();
        }
        self.state = DeviceState::Down;
        self.flags &= !(IFF_UP | IFF_RUNNING);
    }

    /// Transmit packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), NetworkError> {
        if self.state != DeviceState::Up {
            return Err(NetworkError::DeviceDown);
        }
        
        if let Some(ref mut ops) = self.ops {
            ops.transmit(packet)?;
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += packet.len() as u64;
        }
        
        Ok(())
    }

    /// Handle device interrupt
    pub fn handle_interrupt(&mut self) {
        if let Some(ref mut ops) = self.ops {
            ops.handle_interrupt();
        }
    }

    /// Enqueue received packet
    pub fn enqueue_rx(&self, buffer: RxBuffer) {
        let mut queue = self.rx_queue.lock();
        if queue.len() < MAX_RX_QUEUE {
            queue.push(buffer);
        }
    }

    /// Dequeue received packet
    pub fn dequeue_rx(&self) -> Option<RxBuffer> {
        let mut queue = self.rx_queue.lock();
        queue.pop()
    }

    /// Enqueue packet for transmission
    pub fn enqueue_tx(&self, buffer: TxBuffer) {
        let mut queue = self.tx_queue.lock();
        if queue.len() < MAX_TX_QUEUE {
            queue.push(buffer);
        }
    }

    /// Dequeue transmitted packet
    pub fn dequeue_tx(&self) -> Option<TxBuffer> {
        let mut queue = self.tx_queue.lock();
        queue.pop()
    }

    /// Update statistics
    pub fn update_stats(&mut self, rx_ok: bool, tx_ok: bool, errors: bool) {
        if rx_ok {
            self.stats.rx_packets += 1;
        }
        if tx_ok {
            self.stats.tx_packets += 1;
        }
        if errors {
            if rx_ok {
                self.stats.rx_errors += 1;
            } else {
                self.stats.tx_errors += 1;
            }
        }
    }
}

// Device flags
pub const IFF_UP: u32 = 0x1;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_PROMISC: u32 = 0x100;

// Network error
#[derive(Debug)]
pub enum NetworkError {
    DeviceNotFound,
    DeviceDown,
    NoBuffer,
    InvalidPacket,
    DriverError(alloc::string::String),
}

impl NetworkError {
    pub fn new(msg: &str) -> Self {
        Self::DriverError(alloc::string::String::from(msg))
    }
}

// ============================================================================
// Network Stack Integration
// ============================================================================

/// Global network stack state
pub struct NetworkStack {
    /// Registered devices
    devices: Spinlock<Vec<NetworkDevice>>,
    /// Current device count
    device_count: Spinlock<usize>,
    /// Default device (for routing)
    default_device: Spinlock<Option<usize>>,
    /// Packet processing hook
    packet_hook: Spinlock<Option<Box<dyn Fn(&[u8], usize) + Send>>>,
}

impl NetworkStack {
    /// Create new network stack
    pub fn new() -> Self {
        Self {
            devices: Spinlock::new(Vec::with_capacity(MAX_NET_DEVICES)),
            device_count: Spinlock::new(0),
            default_device: Spinlock::new(None),
            packet_hook: Spinlock::new(None),
        }
    }

    /// Register a network device
    pub fn register_device(&mut self, device: NetworkDevice) -> Option<usize> {
        let mut devices = self.devices.lock();
        let mut count = self.device_count.lock();
        
        if *count >= MAX_NET_DEVICES {
            return None;
        }
        
        let index = *count;
        devices.push(device);
        *count += 1;
        
        // Set as default if first device
        if index == 0 {
            let mut default = self.default_device.lock();
            *default = Some(index);
        }
        
        Some(index)
    }

    /// Unregister a network device
    pub fn unregister_device(&mut self, index: usize) -> bool {
        let mut devices = self.devices.lock();
        if index < devices.len() {
            devices.remove(index);
            
            // Update default device
            let mut default = self.default_device.lock();
            if *default == Some(index) {
                *default = if devices.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
            
            true
        } else {
            false
        }
    }

    /// Get device by index
    pub fn get_device(&self, index: usize) -> Option<NetworkDevice> {
        let devices = self.devices.lock();
        devices.get(index).cloned()
    }

    /// Set default device
    pub fn set_default_device(&mut self, index: usize) -> bool {
        let devices = self.devices.lock();
        if index < devices.len() {
            drop(devices);
            let mut default = self.default_device.lock();
            *default = Some(index);
            true
        } else {
            false
        }
    }

    /// Get default device
    pub fn get_default_device(&self) -> Option<usize> {
        *self.default_device.lock()
    }

    /// Set packet processing hook
    pub fn set_packet_hook<F>(&mut self, hook: F)
    where
        F: Fn(&[u8], usize) + Send + 'static,
    {
        let mut ph = self.packet_hook.lock();
        *ph = Some(Box::new(hook));
    }

    /// Process received packet
    pub fn process_packet(&self, packet: &[u8], device_index: usize) {
        let ph = self.packet_hook.lock();
        if let Some(ref hook) = *ph {
            hook(packet, device_index);
        }
    }

    /// Get all devices
    pub fn get_all_devices(&self) -> Vec<NetworkDevice> {
        self.devices.lock().clone()
    }
}

impl Default for NetworkStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Global network stack instance
pub static NETWORK_STACK: Spinlock<NetworkStack> = Spinlock::new(NetworkStack::new());

/// Initialize network stack
pub fn init_network_stack() {
    let mut stack = NETWORK_STACK.lock();
    // Would initialize protocols here
    let _ = stack;
}

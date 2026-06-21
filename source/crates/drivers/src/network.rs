//! Network Device Drivers
//!
//! Implements network device abstraction and common NIC drivers.

#![no_std]

extern crate alloc;

use plan9_common::error::{Error, Result};
use plan9_common::types::PhysAddr;

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
// E1000 Network Driver
// ============================================================================

/// E1000 registers
pub mod e1000_reg {
    // BAR0 registers
    pub const E1000_CTRL: usize = 0x0000;
    pub const E1000_STATUS: usize = 0x0008;
    pub const E1000_EECD: usize = 0x0010;
    pub const E1000_EERD: usize = 0x0014;
    pub const E1000_MDIC: usize = 0x0020;
    pub const E1000_FCAL: usize = 0x0028;
    pub const E1000_FCAH: usize = 0x002C;
    pub const E1000_FCT: usize = 0x0030;
    pub const E1000_VET: usize = 0x0038;
    pub const E1000_LEDCTL: usize = 0x0E00;
    pub const E1000_EXTCNF_CTRL: usize = 0x0F00;
    pub const E1000_EXTCNF_SIZE: usize = 0x0F08;
    pub const E1000_PHY_CTRL: usize = 0x0000;

    // Interrupt registers
    pub const E1000_ICR: usize = 0x00C0;
    pub const E1000_ICS: usize = 0x00C8;
    pub const E1000_IMS: usize = 0x00D0;
    pub const E1000_IMC: usize = 0x00D8;
    pub const E1000_IAM: usize = 0x00E0;

    // Flow control
    pub const E1000_FCRTH: usize = 0x0248;
    pub const E1000_FCRTL: usize = 0x024C;
    pub const E1000_FCTTV: usize = 0x0250;
    pub const E1000_FCRTV: usize = 0x025C;

    // Transmit
    pub const E1000_TDBAL: usize = 0x3800;
    pub const E1000_TDBAH: usize = 0x3804;
    pub const E1000_TDLEN: usize = 0x3808;
    pub const E1000_TDH: usize = 0x3810;
    pub const E1000_TDT: usize = 0x3818;
    pub const E1000_TCTL: usize = 0x0400;
    pub const E1000_TIPG: usize = 0x0410;
    pub const E1000_TBT: usize = 0x0408;

    // Receive
    pub const E1000_RDBAL: usize = 0x2800;
    pub const E1000_RDBAH: usize = 0x2804;
    pub const E1000_RDLEN: usize = 0x2808;
    pub const E1000_RDH: usize = 0x2810;
    pub const E1000_RDT: usize = 0x2818;
    pub const E1000_RCTL: usize = 0x0100;
    pub const E1000_RSCR: usize = 0x280C;

    // Statistics
    pub const E1000_CRCERRS: usize = 0x4000;
    pub const E1000_ALGERR: usize = 0x4004;
    pub const E1000_SYMERRS: usize = 0x4008;
    pub const E1000_RXERRC: usize = 0x400C;
    pub const E1000_MPC: usize = 0x4010;
    pub const E1000_SCC: usize = 0x4014;
    pub const E1000_COLC: usize = 0x4028;
    pub const E1000_RERC: usize = 0x402C;
    pub const E1000_DC: usize = 0x4030;
    pub const E1000_SEC: usize = 0x4034;
    pub const E1000_RLEC: usize = 0x4048;
    pub const E1000_XONRXC: usize = 0x4050;
    pub const E1000_XONTXC: usize = 0x4054;
    pub const E1000_XOFFRXC: usize = 0x4058;
    pub const E1000_XOFFTXC: usize = 0x405C;
    pub const E1000_GPRC: usize = 0x4074;
    pub const E1000_BPRC: usize = 0x4078;
    pub const E1000_MPRC: usize = 0x407C;
    pub const E1000_GPTC: usize = 0x4080;
    pub const E1000_TORL: usize = 0x40C0;
    pub const E1000_TORH: usize = 0x40C8;
    pub const E1000_TOTL: usize = 0x40D0;
    pub const E1000_TOTH: usize = 0x40D8;
    pub const E1000_TPR: usize = 0x40D0;
    pub const E1000_TPT: usize = 0x40D4;

    // MAC addresses
    pub const E1000_RAL0: usize = 0x5400;
    pub const E1000_RAH0: usize = 0x5404;

    // Multicast table
    pub const E1000_MTA: usize = 0x5200;

    // Receive registers
    pub const E1000_RDTR: usize = 0x2820;
    pub const E1000_RADV: usize = 0x282C;
    pub const E1000_RSRPD: usize = 0x2C00;

    // Transmit registers
    pub const E1000_TIDV: usize = 0x3820;
    pub const E1000_TADV: usize = 0x382C;
    pub const E1000_TSPMT: usize = 0x3830;

    // Device control
    pub const E1000_CTRL_FD: u32 = 1 << 0;
    pub const E1000_CTRL_LRST: u32 = 1 << 3;
    pub const E1000_CTRL_ASDE: u32 = 1 << 5;
    pub const E1000_CTRL_SLU: u32 = 1 << 6;
    pub const E1000_CTRL_FRCSPD: u32 = 1 << 11;
    pub const E1000_CTRL_FRCDPX: u32 = 1 << 12;

    // Transmit control
    pub const E1000_TCTL_EN: u32 = 1 << 1;
    pub const E1000_TCTL_PSP: u32 = 1 << 3;
    pub const E1000_TCTL_CT: u32 = 0xF << 4;
    pub const E1000_TCTL_COLD: u32 = 0x3F << 12;

    // Receive control
    pub const E1000_RCTL_EN: u32 = 1 << 1;
    pub const E1000_RCTL_UPE: u32 = 1 << 3;
    pub const E1000_RCTL_MPE: u32 = 1 << 4;
    pub const E1000_RCTL_LPE: u32 = 1 << 5;
    pub const E1000_RCTL_LBM: u32 = 3 << 6;
    pub const E1000_RCTL_RDMTS: u32 = 3 << 8;
    pub const E1000_RCTL_MO: u32 = 3 << 12;
    pub const E1000_RCTL_BAM: u32 = 1 << 15;
    pub const E1000_RCTL_SZ: u32 = 3 << 16;
    pub const E1000_RCTL_SZ_2048: u32 = 0 << 16;
    pub const E1000_RCTL_SZ_4096: u32 = 1 << 16;
    pub const E1000_RCTL_SZ_8192: u32 = 2 << 16;
    pub const E1000_RCTL_SZ_16384: u32 = 3 << 16;
    pub const E1000_RCTL_SECRC: u32 = 1 << 26;
}

/// E1000 transmit descriptor
#[repr(C)]
pub struct E1000TxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

impl E1000TxDesc {
    pub const CMD_EOP: u8 = 1 << 0;
    pub const CMD_IFCS: u8 = 1 << 1;
    pub const CMD_RS: u8 = 1 << 3;

    pub const STATUS_DD: u8 = 1 << 0;
}

/// E1000 receive descriptor
#[repr(C)]
pub struct E1000RxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

impl E1000RxDesc {
    pub const STATUS_DD: u8 = 1 << 0;
    pub const STATUS_EOP: u8 = 1 << 1;
}

/// E1000 network device
pub struct E1000 {
    pub base_addr: PhysAddr,
    pub mac: [u8; 6],
    pub tx_descs: *mut E1000TxDesc,
    pub rx_descs: *mut E1000RxDesc,
    pub tx_buffer: *mut u8,
    pub rx_buffers: [*mut u8; 16],
    pub tx_head: usize,
    pub tx_tail: usize,
    pub rx_head: usize,
    pub tx_size: usize,
    pub rx_size: usize,
}

impl E1000 {
    /// Create new E1000 device
    pub fn new(base: PhysAddr) -> Self {
        Self {
            base_addr: base,
            mac: [0; 6],
            tx_descs: core::ptr::null_mut(),
            rx_descs: core::ptr::null_mut(),
            tx_buffer: core::ptr::null_mut(),
            rx_buffers: [core::ptr::null_mut(); 16],
            tx_head: 0,
            tx_tail: 0,
            rx_head: 0,
            tx_size: 64,
            rx_size: 16,
        }
    }

    /// Read a register from MMIO
    ///
    /// Reads a 32-bit value from the specified register offset.
    /// Uses volatile read to prevent optimization.
    fn read_reg(&self, offset: usize) -> u32 {
        let addr = self.base_addr.as_u64() as *const u32;
        unsafe { core::ptr::read_volatile(addr.add(offset / 4)) }
    }

    /// Write a register to MMIO
    ///
    /// Writes a 32-bit value to the specified register offset.
    /// Uses volatile write to prevent optimization.
    fn write_reg(&self, offset: usize, val: u32) {
        let addr = self.base_addr.as_u64() as *mut u32;
        unsafe { core::ptr::write_volatile(addr.add(offset / 4), val) }
    }

    /// Read a register using I/O port (for legacy mode)
    ///
    /// Some E1000 devices use I/O ports instead of MMIO.
    fn read_reg_io(&self, offset: u16) -> u32 {
        // In real implementation, would use inl/outl instructions
        // unsafe { llvm_asm!("inl $1, $0" : "=a"(val) : "d"(port)) }
        0
    }

    /// Write a register using I/O port
    fn write_reg_io(&self, offset: u16, val: u32) {
        // unsafe { llvm_asm!("outl $0, $1" : : "a"(val), "d"(port)) }
        let _ = offset;
        let _ = val;
    }

    /// Initialize the device
    pub fn init(&mut self) -> Result<()> {
        // Reset the device
        self.write_reg(e1000_reg::E1000_CTRL, e1000_reg::E1000_CTRL_LRST);

        // Wait for reset to complete
        for _ in 0..1000 {
            if self.read_reg(e1000_reg::E1000_CTRL) & e1000_reg::E1000_CTRL_LRST == 0 {
                break;
            }
        }

        // Read MAC address
        let mac_low = self.read_reg(e1000_reg::E1000_RAH0);
        let mac_high = self.read_reg(e1000_reg::E1000_RAL0);

        self.mac[0] = (mac_low & 0xFF) as u8;
        self.mac[1] = ((mac_low >> 8) & 0xFF) as u8;
        self.mac[2] = ((mac_low >> 16) & 0xFF) as u8;
        self.mac[3] = ((mac_low >> 24) & 0xFF) as u8;
        self.mac[4] = (mac_high & 0xFF) as u8;
        self.mac[5] = ((mac_high >> 8) & 0xFF) as u8;

        // Allocate transmit descriptors
        // In real implementation, would allocate from memory

        // Configure transmit
        self.write_reg(e1000_reg::E1000_TCTL, 0
            | e1000_reg::E1000_TCTL_EN
            | e1000_reg::E1000_TCTL_PSP
            | (0xF << 4)  // Collision threshold
            | (0x40 << 12)  // Collision distance
        );

        // Inter-packet gap (recommended for 1GbE)
        self.write_reg(e1000_reg::E1000_TIPG, 0x00601006);

        // Configure receive
        self.write_reg(e1000_reg::E1000_RCTL, 0
            | e1000_reg::E1000_RCTL_BAM
            | e1000_reg::E1000_RCTL_SZ_2048
            | e1000_reg::E1000_RCTL_SECRC
        );

        // Enable link
        let ctrl = self.read_reg(e1000_reg::E1000_CTRL);
        self.write_reg(e1000_reg::E1000_CTRL, ctrl | e1000_reg::E1000_CTRL_SLU);

        Ok(())
    }

    /// Transmit a packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > 1514 {
            return Err(Error::Einval);
        }

        // In real implementation, would:
        // 1. Wait for a free transmit descriptor
        // 2. Copy packet to transmit buffer
        // 3. Update descriptor with packet length and CMD_RS
        // 4. Update TDT register
        // 5. Wait for TX completion

        Ok(())
    }

    /// Receive a packet
    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // In real implementation, would:
        // 1. Check if received packet is ready (status DD bit)
        // 2. Copy packet from receive buffer
        // 3. Update descriptor status
        // 4. Update RDT register

        Ok(0)
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
}

impl NetDevice for E1000 {
    fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        self.transmit(packet)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.receive(buffer)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn link_up(&self) -> bool {
        (self.read_reg(e1000_reg::E1000_STATUS) & (1 << 1)) != 0
    }

    fn set_irq(&mut self, _enabled: bool) {
        // Configure MSI or legacy interrupt
    }
}

// ============================================================================
// VirtIO Network Driver
// ============================================================================

/// VirtIO net device
pub struct VirtioNet {
    pub base_addr: PhysAddr,
    pub mac: [u8; 6],
    pub status: u16,
    pub max_vq: u16,
    pub mtu: usize,
    pub tx_buffer: *mut u8,
    pub rx_buffer: *mut u8,
}

impl VirtioNet {
    /// Create new VirtIO net device
    pub fn new(base: PhysAddr) -> Self {
        Self {
            base_addr: base,
            mac: [0; 6],
            status: 0,
            max_vq: 0,
            mtu: 1500,
            tx_buffer: core::ptr::null_mut(),
            rx_buffer: core::ptr::null_mut(),
        }
    }

    /// Initialize the device
    pub fn init(&mut self) -> Result<()> {
        // VirtIO initialization sequence:
        // 1. Reset device
        // 2. Acknowledge device
        // 3. Set driver features
        // 4. Set up virtqueues
        // 5. Set DRIVER_OK

        // Read MAC address from config
        // In real implementation, would read from VirtIO config space

        self.mtu = 1500;
        Ok(())
    }

    /// Transmit a packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(Error::Einval);
        }

        // In real implementation, would use TX virtqueue
        Ok(())
    }

    /// Receive a packet
    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // In real implementation, would use RX virtqueue
        Ok(0)
    }
}

impl NetDevice for VirtioNet {
    fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        self.transmit(packet)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.receive(buffer)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn link_up(&self) -> bool {
        self.status & 1 != 0
    }

    fn set_irq(&mut self, _enabled: bool) {
        // Configure MSI or virtio interrupt
    }
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
    /// Create new network manager
    pub fn new() -> Self {
        Self {
            devices: [None, None, None, None],
            device_count: 0,
        }
    }

    /// Add a device
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

    /// Get device by index
    pub fn get_device(&self, index: usize) -> Option<&dyn NetDevice> {
        self.devices.get(index).and_then(|d| d.as_ref().map(|b| b.as_ref()))
    }

    /// Get mutable device by index
    pub fn get_device_mut(&mut self, index: usize) -> Option<&mut dyn NetDevice> {
        self.devices.get_mut(index).and_then(|d| d.as_mut().map(|b| b.as_mut()))
    }
}

impl Default for NetManager {
    fn default() -> Self {
        Self::new()
    }
}

//! Network Device Drivers
//!
//! Implements network device abstraction and the E1000 NIC driver.  The
//! E1000 path uses real MMIO registers and physical DMA descriptor rings;
//! the virtio-net path remains a scaffold for future work.

extern crate alloc;

use alloc::boxed::Box;
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

    // MAC addresses
    pub const E1000_RAL0: usize = 0x5400;
    pub const E1000_RAH0: usize = 0x5404;

    // Device control bits
    pub const E1000_CTRL_FD: u32 = 1 << 0;
    pub const E1000_CTRL_LRST: u32 = 1 << 3;
    pub const E1000_CTRL_ASDE: u32 = 1 << 5;
    pub const E1000_CTRL_SLU: u32 = 1 << 6;

    // Transmit control bits
    pub const E1000_TCTL_EN: u32 = 1 << 1;
    pub const E1000_TCTL_PSP: u32 = 1 << 3;
    pub const E1000_TCTL_CT: u32 = 0xF << 4;
    pub const E1000_TCTL_COLD: u32 = 0x40 << 12;

    // Receive control bits
    pub const E1000_RCTL_EN: u32 = 1 << 1;
    pub const E1000_RCTL_BAM: u32 = 1 << 15;
    pub const E1000_RCTL_SZ_2048: u32 = 0 << 16;
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

// Raw descriptor pointers are safe to share only through the kernel's
// spinlock-guarded NIC object.
unsafe impl Send for E1000 {}
unsafe impl Sync for E1000 {}

impl E1000 {
    /// Create a new E1000 device with no DMA rings configured yet.
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

    /// Read a 32-bit MMIO register.
    fn read_reg(&self, offset: usize) -> u32 {
        let addr = self.base_addr.as_u64() as *const u32;
        unsafe { core::ptr::read_volatile(addr.add(offset / 4)) }
    }

    /// Write a 32-bit MMIO register.
    fn write_reg(&self, offset: usize, val: u32) {
        let addr = self.base_addr.as_u64() as *mut u32;
        unsafe { core::ptr::write_volatile(addr.add(offset / 4), val) }
    }

    /// Write a 64-bit MMIO register represented by two consecutive 32-bit
    /// registers (the E1000 uses this for descriptor-ring base addresses).
    fn write64(&self, offset: usize, val: u64) {
        self.write_reg(offset, (val & 0xFFFF_FFFF) as u32);
        self.write_reg(offset + 4, ((val >> 32) & 0xFFFF_FFFF) as u32);
    }

    /// Reset the NIC and configure its basic operating mode.
    pub fn init(&mut self) -> Result<()> {
        // Ask for a link reset.  QEMU's e1000e clears the LRST bit after the
        // reset completes; if the hardware does not implement it, the bounded
        // wait below simply continues with a normal configuration.
        self.write_reg(e1000_reg::E1000_CTRL, e1000_reg::E1000_CTRL_LRST);
        for _ in 0..2000 {
            if self.read_reg(e1000_reg::E1000_CTRL) & e1000_reg::E1000_CTRL_LRST == 0 {
                break;
            }
        }

        // RAL0 holds the low four MAC bytes and RAH0 holds the high two.
        let mac_low = self.read_reg(e1000_reg::E1000_RAL0);
        let mac_high = self.read_reg(e1000_reg::E1000_RAH0);

        self.mac[0] = (mac_low & 0xFF) as u8;
        self.mac[1] = ((mac_low >> 8) & 0xFF) as u8;
        self.mac[2] = ((mac_low >> 16) & 0xFF) as u8;
        self.mac[3] = ((mac_low >> 24) & 0xFF) as u8;
        self.mac[4] = (mac_high & 0xFF) as u8;
        self.mac[5] = ((mac_high >> 8) & 0xFF) as u8;

        // Disable legacy/MSI interrupt delivery; the kernel polls the rings.
        self.write_reg(e1000_reg::E1000_IMC, 0xFFFF_FFFF);

        // Transmit control: enable transmitter, pad short packets, and set
        // the collision threshold/distance.
        self.write_reg(
            e1000_reg::E1000_TCTL,
            e1000_reg::E1000_TCTL_EN
                | e1000_reg::E1000_TCTL_PSP
                | e1000_reg::E1000_TCTL_CT
                | e1000_reg::E1000_TCTL_COLD,
        );
        self.write_reg(e1000_reg::E1000_TIPG, 0x0060_1006);

        // Receive control: enable receiver and broadcast acceptance, and
        // strip CRC on receive.
        self.write_reg(
            e1000_reg::E1000_RCTL,
            e1000_reg::E1000_RCTL_EN
                | e1000_reg::E1000_RCTL_BAM
                | e1000_reg::E1000_RCTL_SZ_2048
                | e1000_reg::E1000_RCTL_SECRC,
        );

        // Force link up (SLU) and auto-speed detect if supported.
        let ctrl = self.read_reg(e1000_reg::E1000_CTRL);
        self.write_reg(
            e1000_reg::E1000_CTRL,
            ctrl | e1000_reg::E1000_CTRL_SLU | e1000_reg::E1000_CTRL_ASDE,
        );

        Ok(())
    }

    /// Install physical DMA rings and buffers.  All addresses are physical
    /// addresses; the kernel identity-maps the low 1 GiB region, so these
    /// pointers are directly usable by the CPU.
    pub fn init_dma(
        &mut self,
        tx_desc: PhysAddr,
        rx_desc: PhysAddr,
        tx_buffer: PhysAddr,
        rx_buffers: [PhysAddr; 16],
    ) -> Result<()> {
        self.tx_descs = tx_desc.as_u64() as *mut E1000TxDesc;
        self.rx_descs = rx_desc.as_u64() as *mut E1000RxDesc;
        self.tx_buffer = tx_buffer.as_u64() as *mut u8;
        for i in 0..self.rx_size {
            self.rx_buffers[i] = rx_buffers[i].as_u64() as *mut u8;
        }

        unsafe {
            for i in 0..self.tx_size {
                let d = &mut *self.tx_descs.add(i);
                d.buffer_addr = tx_buffer.as_u64();
                d.length = 0;
                d.cso = 0;
                d.cmd = 0;
                d.status = 0;
                d.css = 0;
                d.special = 0;
            }
            for i in 0..self.rx_size {
                let d = &mut *self.rx_descs.add(i);
                d.buffer_addr = rx_buffers[i].as_u64();
                d.length = 0;
                d.checksum = 0;
                d.status = 0;
                d.errors = 0;
                d.special = 0;
            }
        }

        // Transmit ring
        self.write64(e1000_reg::E1000_TDBAL, tx_desc.as_u64());
        self.write_reg(e1000_reg::E1000_TDLEN, (self.tx_size * 16) as u32);
        self.write_reg(e1000_reg::E1000_TDH, 0);
        self.write_reg(e1000_reg::E1000_TDT, 0);

        // Receive ring
        self.write64(e1000_reg::E1000_RDBAL, rx_desc.as_u64());
        self.write_reg(e1000_reg::E1000_RDLEN, (self.rx_size * 16) as u32);
        self.write_reg(e1000_reg::E1000_RDH, 0);
        self.write_reg(e1000_reg::E1000_RDT, (self.rx_size - 1) as u32);

        self.tx_head = 0;
        self.tx_tail = 0;
        self.rx_head = 0;
        Ok(())
    }

    /// Transmit one Ethernet frame.  The descriptor ring is used
    /// synchronously: one frame is copied into the transmit buffer and the
    /// descriptor is handed to the NIC before we wait for DD completion.
    pub fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > 1514 {
            return Err(Error::Einval);
        }
        if self.tx_descs.is_null() || self.tx_buffer.is_null() {
            return Err(Error::Eio);
        }

        let idx = self.tx_tail;
        unsafe {
            core::ptr::copy_nonoverlapping(packet.as_ptr(), self.tx_buffer, packet.len());
            let d = &mut *self.tx_descs.add(idx);
            d.buffer_addr = self.tx_buffer as u64;
            d.length = packet.len() as u16;
            d.cso = 0;
            d.cmd = E1000TxDesc::CMD_EOP | E1000TxDesc::CMD_IFCS | E1000TxDesc::CMD_RS;
            d.status = 0;
            d.css = 0;
            d.special = 0;
        }

        // Advancing TDT makes the descriptor visible to the hardware.
        self.write_reg(e1000_reg::E1000_TDT, ((idx + 1) % self.tx_size) as u32);
        self.tx_tail = (idx + 1) % self.tx_size;

        // Wait (bounded) for the descriptor's DD status bit.  QEMU sets this
        // almost immediately, but polling avoids depending on interrupts.
        unsafe {
            for _ in 0..100_000 {
                let d = &*self.tx_descs.add(idx);
                if d.status & E1000TxDesc::STATUS_DD != 0 {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Poll the receive ring and copy one received frame into `buffer`.
    /// Returns 0 when no descriptor is ready.
    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.rx_descs.is_null() {
            return Ok(0);
        }

        for _ in 0..self.rx_size {
            let idx = self.rx_head;
            unsafe {
                let d = &mut *self.rx_descs.add(idx);
                if d.status & E1000RxDesc::STATUS_DD != 0 {
                    let len = d.length as usize;
                    if len == 0 {
                        d.status = 0;
                        self.write_reg(e1000_reg::E1000_RDT, idx as u32);
                        self.rx_head = (idx + 1) % self.rx_size;
                        return Ok(0);
                    }
                    let n = core::cmp::min(len, buffer.len());
                    core::ptr::copy_nonoverlapping(
                        d.buffer_addr as *const u8,
                        buffer.as_mut_ptr(),
                        n,
                    );
                    d.status = 0;
                    d.length = 0;
                    d.errors = 0;
                    self.write_reg(e1000_reg::E1000_RDT, idx as u32);
                    self.rx_head = (idx + 1) % self.rx_size;
                    return Ok(n);
                }
            }
        }

        Ok(0)
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        (self.read_reg(e1000_reg::E1000_STATUS) & (1 << 1)) != 0
    }

    pub fn status(&self) -> u32 {
        self.read_reg(e1000_reg::E1000_STATUS)
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
        self.link_up()
    }

    fn set_irq(&mut self, _enabled: bool) {
        // Polling mode; interrupt delivery is disabled.
    }
}

// ============================================================================
// VirtIO Network Driver (scaffold)
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

    pub fn init(&mut self) -> Result<()> {
        self.mtu = 1500;
        Ok(())
    }

    pub fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(Error::Einval);
        }
        Ok(())
    }

    pub fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize> {
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

    fn set_irq(&mut self, _enabled: bool) {}
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

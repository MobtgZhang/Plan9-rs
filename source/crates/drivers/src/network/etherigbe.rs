//! Intel 82540EM Gigabit Ethernet driver, corresponding to Plan 9 etherigbe.

use core::sync::atomic::{fence, Ordering};
use plan9_common::error::{Error, Result};
use plan9_common::types::PhysAddr;

use super::NetDevice;

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
    tx_pending: Option<usize>,
    rx_discard: bool,
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
            tx_pending: None,
            rx_discard: false,
        }
    }

    /// Read a 32-bit MMIO register.
    fn read_reg(&self, offset: usize) -> u32 {
        let addr = crate::pci::mmio_address(self.base_addr.as_u64()) as *const u32;
        unsafe { core::ptr::read_volatile(addr.add(offset / 4)) }
    }

    /// Write a 32-bit MMIO register.
    fn write_reg(&self, offset: usize, val: u32) {
        let addr = crate::pci::mmio_address(self.base_addr.as_u64()) as *mut u32;
        unsafe { core::ptr::write_volatile(addr.add(offset / 4), val) }
    }

    /// Write a 64-bit MMIO register represented by two consecutive 32-bit
    /// registers (the E1000 uses this for descriptor-ring base addresses).
    fn write64(&self, offset: usize, val: u64) {
        self.write_reg(offset, (val & 0xFFFF_FFFF) as u32);
        self.write_reg(offset + 4, ((val >> 32) & 0xFFFF_FFFF) as u32);
    }

    pub fn stop(&mut self) {
        self.write_reg(e1000_reg::E1000_IMC, u32::MAX);
        self.write_reg(e1000_reg::E1000_RCTL, 0);
        self.write_reg(e1000_reg::E1000_TCTL, 0);
        let _ = self.read_reg(e1000_reg::E1000_STATUS);
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
        if self.mac == [0; 6] || self.mac[0] & 1 != 0 {
            return Err(Error::Eio);
        }

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
                | (1 << 4)
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

    /// Install physical DMA rings and buffers before enabling RX and TX.
    ///
    /// # Safety
    /// All addresses must be identity mapped, coherent, distinct DMA pages
    /// reserved for this device while it can perform DMA.
    pub unsafe fn init_dma(
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
        self.tx_pending = None;
        self.rx_discard = false;
        Ok(())
    }

    pub fn tx_ready(&mut self) -> bool {
        if let Some(index) = self.tx_pending {
            let descriptor = unsafe { self.tx_descs.add(index) };
            let status = unsafe { core::ptr::addr_of!((*descriptor).status).read_volatile() };
            if status & E1000TxDesc::STATUS_DD == 0 {
                return false;
            }
            fence(Ordering::Acquire);
            self.tx_pending = None;
        }
        !self.tx_descs.is_null()
    }

    /// Transmit one Ethernet frame. The NIC owns the transmit buffer until DD.
    pub fn transmit(&mut self, packet: &[u8]) -> Result<()> {
        if !(14..=1514).contains(&packet.len()) {
            return Err(Error::Einval);
        }
        if self.tx_descs.is_null() || self.tx_buffer.is_null() {
            return Err(Error::Eio);
        }
        if !self.tx_ready() {
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

        fence(Ordering::Release);
        self.write_reg(e1000_reg::E1000_TDT, ((idx + 1) % self.tx_size) as u32);
        self.tx_tail = (idx + 1) % self.tx_size;
        self.tx_pending = Some(idx);

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
            let descriptor = unsafe { self.rx_descs.add(idx) };
            let status = unsafe { core::ptr::addr_of!((*descriptor).status).read_volatile() };
            if status & E1000RxDesc::STATUS_DD == 0 {
                break;
            }
            fence(Ordering::Acquire);
            let length =
                unsafe { core::ptr::addr_of!((*descriptor).length).read_volatile() } as usize;
            let errors = unsafe { core::ptr::addr_of!((*descriptor).errors).read_volatile() };
            let end = status & E1000RxDesc::STATUS_EOP != 0;
            let valid = !self.rx_discard
                && end
                && errors == 0
                && (14..=1514).contains(&length)
                && length <= buffer.len();
            self.rx_discard = !end;
            if valid {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.rx_buffers[idx],
                        buffer.as_mut_ptr(),
                        length,
                    );
                }
            }
            unsafe { core::ptr::addr_of_mut!((*descriptor).status).write_volatile(0) };
            fence(Ordering::Release);
            self.write_reg(e1000_reg::E1000_RDT, idx as u32);
            self.rx_head = (idx + 1) % self.rx_size;
            if valid {
                return Ok(length);
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

    pub fn set_promiscuous(&mut self, enabled: bool) {
        let control = self.read_reg(e1000_reg::E1000_RCTL);
        self.write_reg(e1000_reg::E1000_RCTL, (control & !(1 << 3)) | (u32::from(enabled) << 3));
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

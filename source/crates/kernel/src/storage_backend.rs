//! Kernel-side storage backends for the Plan 9 SD device.
//!
//! The driver crate provides PCI, ATA and AHCI primitives.  This module
//! adapts those primitives to the kernel's `StorageBackend` trait and
//! registers the resulting backends with `SdDev`.
//!
//! ATA is implemented through the legacy PIO channel.  AHCI is wired
//! through the driver's MMIO controller.  NVMe is a small, self-contained
//! controller implementation that submits commands through its admin and
//! I/O queues.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::devsd::{SdError, SdResult, StorageBackend};
use crate::dev::{PciDeviceInfo};
use crate::serial;

// ============================================================================
// ATA / IDE backend
// ============================================================================

pub struct AtaBackend {
    slave: bool,
    sectors: u64,
    block_size: usize,
    model: [u8; 40],
    serial: [u8; 20],
}

impl AtaBackend {
    fn new(slave: bool, device: &plan9_drivers::storage::AtaDevice) -> Self {
        Self {
            slave,
            sectors: device.sectors,
            block_size: device.block_size.max(512),
            model: device.model,
            serial: device.serial,
        }
    }
}

impl StorageBackend for AtaBackend {
    fn read_sectors(&self, lba: u64, count: usize, buf: &mut [u8]) -> SdResult<usize> {
        let block = self.block_size;
        let bytes = count * block;
        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }

        let channel = plan9_drivers::storage::AtaChannel::get_primary();
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let chunk = left.min(128);
            let offset = done * block;
            let chunk_bytes = chunk * block;
            match channel.read_sectors(
                self.slave,
                lba + done as u64,
                chunk as u8,
                &mut buf[offset..offset + chunk_bytes],
            ) {
                Ok(n) => done += n / block,
                Err(_) => return Err(SdError::IoError),
            }
            left -= chunk;
        }
        Ok(done * block)
    }

    fn write_sectors(&mut self, lba: u64, count: usize, buf: &[u8]) -> SdResult<usize> {
        let block = self.block_size;
        let bytes = count * block;
        if buf.len() < bytes {
            return Err(SdError::Invalid);
        }

        let channel = plan9_drivers::storage::AtaChannel::get_primary();
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let chunk = left.min(128);
            let offset = done * block;
            let chunk_bytes = chunk * block;
            match channel.write_sectors(
                self.slave,
                lba + done as u64,
                chunk as u8,
                &buf[offset..offset + chunk_bytes],
            ) {
                Ok(n) => done += n / block,
                Err(_) => return Err(SdError::IoError),
            }
            left -= chunk;
        }
        Ok(done * block)
    }

    fn flush(&mut self) -> SdResult<()> {
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.sectors
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn is_online(&self) -> bool {
        self.sectors > 0
    }

    fn model(&self) -> [u8; 40] {
        self.model
    }

    fn serial(&self) -> [u8; 20] {
        self.serial
    }
}

// ============================================================================
// AHCI backend
// ============================================================================

pub struct AhciBackend {
    controller: *mut plan9_drivers::ahci::AhciController,
    port_index: usize,
    sectors: u64,
    model: [u8; 40],
    serial: [u8; 20],
}

// The kernel runs these backends in a single-threaded boot/init context;
// the raw controller pointer is never used concurrently.
unsafe impl Send for AhciBackend {}
unsafe impl Sync for AhciBackend {}

impl AhciBackend {
    fn port(&self) -> Option<&'static mut plan9_drivers::ahci::AhciPort> {
        unsafe { (*self.controller).get_port_mut(self.port_index) }
    }
}

impl StorageBackend for AhciBackend {
    fn read_sectors(&self, lba: u64, count: usize, buf: &mut [u8]) -> SdResult<usize> {
        let block = 512usize;
        if buf.len() < count * block {
            return Err(SdError::Invalid);
        }
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let chunk = left.min(256);
            let offset = done * block;
            let bytes = chunk * block;
            let frame = crate::frame_alloc::frame_alloc_zeroed();
            if frame.is_none() {
                return Err(SdError::IoError);
            }
            let phys = frame.unwrap().as_u64();
            if let Some(port) = self.port() {
                match port.read_sectors_phys(lba + done as u64, chunk, phys) {
                    Ok(_) => {}
                    Err(_) => return Err(SdError::IoError),
                }
            } else {
                return Err(SdError::NoDevice);
            }
            // DMA frames are in the low identity-mapped boot window.
            let src = unsafe { core::slice::from_raw_parts(phys as *const u8, bytes) };
            buf[offset..offset + bytes].copy_from_slice(src);
            done += chunk;
            left -= chunk;
        }
        Ok(done * block)
    }

    fn write_sectors(&mut self, lba: u64, count: usize, buf: &[u8]) -> SdResult<usize> {
        let block = 512usize;
        if buf.len() < count * block {
            return Err(SdError::Invalid);
        }
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let chunk = left.min(256);
            let offset = done * block;
            let bytes = chunk * block;
            let frame = crate::frame_alloc::frame_alloc_zeroed();
            if frame.is_none() {
                return Err(SdError::IoError);
            }
            let phys = frame.unwrap().as_u64();
            let dst = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, bytes) };
            dst.copy_from_slice(&buf[offset..offset + bytes]);
            if let Some(port) = self.port() {
                match port.write_sectors_phys(lba + done as u64, chunk, phys) {
                    Ok(_) => {}
                    Err(_) => return Err(SdError::IoError),
                }
            } else {
                return Err(SdError::NoDevice);
            }
            done += chunk;
            left -= chunk;
        }
        Ok(done * block)
    }

    fn flush(&mut self) -> SdResult<()> {
        if let Some(port) = self.port() {
            match port.flush_cache_phys() {
                Ok(()) => Ok(()),
                Err(_) => Err(SdError::IoError),
            }
        } else {
            Err(SdError::NoDevice)
        }
    }

    fn capacity(&self) -> u64 {
        self.sectors
    }

    fn block_size(&self) -> usize {
        512
    }

    fn is_online(&self) -> bool {
        self.sectors > 0
    }

    fn model(&self) -> [u8; 40] {
        self.model
    }

    fn serial(&self) -> [u8; 20] {
        self.serial
    }
}

// ============================================================================
// NVMe backend
// ============================================================================

/// Minimal NVMe controller state.  Only one I/O queue is created, which is
/// sufficient for the SD device's synchronous block reads and writes.
struct NvmeController {
    base: usize,
    asq: u64,
    acq: u64,
    sq_tail: u32,
    cq_head: u32,
    io_sq: u64,
    io_cq: u64,
    io_sq_tail: u32,
    io_cq_head: u32,
    next_cid: u16,
    sectors: u64,
    block_size: usize,
}

impl NvmeController {
    fn read32(&self, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
    }
    fn read64(&self, off: usize) -> u64 {
        unsafe { core::ptr::read_volatile((self.base + off) as *const u64) }
    }
    fn write32(&self, off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
    }
    fn write64(&self, off: usize, val: u64) {
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u64, val) }
    }

    fn init(base: usize) -> Option<Self> {
        let mut c = Self {
            base,
            asq: 0,
            acq: 0,
            sq_tail: 0,
            cq_head: 0,
            io_sq: 0,
            io_cq: 0,
            io_sq_tail: 0,
            io_cq_head: 0,
            next_cid: 1,
            sectors: 0,
            block_size: 512,
        };

        let cap = c.read64(0x0);
        if cap == 0 {
            return None;
        }

        // Reset controller.
        c.write32(0x14, 0);
        for _ in 0..1000 {
            if c.read32(0x1C) & 1 == 0 {
                break;
            }
        }

        let asq = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
        let acq = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
        if asq.is_none() || acq.is_none() {
            return None;
        }
        c.asq = asq.unwrap();
        c.acq = acq.unwrap();

        // Admin queue size: 4 entries => AQA value 3.
        c.write32(0x24, 3);
        c.write64(0x28, c.asq);
        c.write64(0x30, c.acq);

        // Enable controller.
        c.write32(0x14, 1);
        for _ in 0..10000 {
            if c.read32(0x1C) & 1 != 0 {
                break;
            }
        }
        if c.read32(0x1C) & 1 == 0 {
            return None;
        }

        // Identify namespace 1.  Identify Controller is not required for
        // block I/O, but Identify Namespace gives the sector count and LBA
        // format.
        let ns_buf = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
        if ns_buf.is_none() {
            return None;
        }
        let ns_ptr = ns_buf.unwrap();
        let ns_data = unsafe {
            core::slice::from_raw_parts(ns_ptr as *const u8, 4096)
        };
        // Clear the buffer before issuing the command.
        unsafe {
            core::ptr::write_bytes(ns_ptr as *mut u8, 0, 4096);
        }

        if !c.submit_admin(0x06, 1, ns_ptr, 0, 0) {
            return None;
        }

        let nsze = u64::from_le_bytes([
            ns_data[0], ns_data[1], ns_data[2], ns_data[3],
            ns_data[4], ns_data[5], ns_data[6], ns_data[7],
        ]);
        c.sectors = nsze;
        if ns_data[25] != 0 {
            let flbas = ns_data[26] as usize;
            let lbaf_off = 128 + flbas * 8;
            if lbaf_off + 3 < 4096 {
                let ds = ns_data[lbaf_off + 2];
                c.block_size = 1usize << ds;
            }
        }
        if c.sectors == 0 {
            return None;
        }

        // Create one I/O completion and submission queue pair.
        let io_sq = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
        let io_cq = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
        if io_sq.is_none() || io_cq.is_none() {
            return None;
        }
        c.io_sq = io_sq.unwrap();
        c.io_cq = io_cq.unwrap();

        // QID 1, queue size 4.
        if !c.submit_admin(0x05, 0, c.io_cq, 1, 3) {
            return None;
        }
        if !c.submit_admin(0x01, 0, c.io_sq, 1, 3) {
            return None;
        }

        Some(c)
    }

    fn submit_admin(&mut self, opcode: u32, nsid: u32, prp1: u64, cdw10: u32, cdw11: u32) -> bool {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let cmd = self.asq + (self.sq_tail as u64) * 64;
        unsafe {
            core::ptr::write_bytes(cmd as *mut u8, 0, 64);
        }
        let words: [u32; 16] = [
            opcode | ((cid as u32) << 16),
            nsid,
            0,
            0,
            0,
            0,
            (prp1 & 0xFFFF_FFFF) as u32,
            (prp1 >> 32) as u32,
            0,
            0,
            cdw10,
            cdw11,
            0,
            0,
            0,
            0,
        ];
        for (i, w) in words.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile((cmd + (i as u64) * 4) as *mut u32, *w);
            }
        }

        self.sq_tail = (self.sq_tail + 1) & 3;
        self.write32(0x1000, self.sq_tail);

        for _ in 0..100000 {
            let cq = self.acq + (self.cq_head as u64) * 16;
            let status = unsafe { core::ptr::read_volatile((cq + 12) as *const u16) };
            if status & 0x000F != 0 {
                return false;
            }
            // Phase bit alternates as the completion queue wraps.
            let phase = unsafe { core::ptr::read_volatile((cq + 14) as *const u16) };
            if phase & 1 == 1 {
                self.cq_head = (self.cq_head + 1) & 3;
                self.write32(0x1004, self.cq_head);
                return true;
            }
            // Give the controller a moment to post a completion.
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }
        false
    }

    fn submit_io(&mut self, opcode: u32, lba: u64, count: usize, buf_ptr: u64) -> bool {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let cmd = self.io_sq + (self.io_sq_tail as u64) * 64;
        unsafe {
            core::ptr::write_bytes(cmd as *mut u8, 0, 64);
        }
        let nlb = (count as u32).saturating_sub(1);
        let words: [u32; 16] = [
            opcode | ((cid as u32) << 16),
            1,
            0,
            0,
            0,
            0,
            (buf_ptr & 0xFFFF_FFFF) as u32,
            (buf_ptr >> 32) as u32,
            0,
            0,
            (lba & 0xFFFF_FFFF) as u32,
            (lba >> 32) as u32,
            nlb,
            0,
            0,
            0,
        ];
        for (i, w) in words.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile((cmd + (i as u64) * 4) as *mut u32, *w);
            }
        }

        self.io_sq_tail = (self.io_sq_tail + 1) & 3;
        self.write32(0x1002, self.io_sq_tail);

        for _ in 0..100000 {
            let cq = self.io_cq + (self.io_cq_head as u64) * 16;
            let status = unsafe { core::ptr::read_volatile((cq + 12) as *const u16) };
            if status & 0x000F != 0 {
                return false;
            }
            let phase = unsafe { core::ptr::read_volatile((cq + 14) as *const u16) };
            if phase & 1 == 1 {
                self.io_cq_head = (self.io_cq_head + 1) & 3;
                self.write32(0x1003, self.io_cq_head);
                return true;
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }
        false
    }
}

pub struct NvmeBackend {
    ctrl: *mut NvmeController,
    model: [u8; 40],
    serial: [u8; 20],
}

unsafe impl Send for NvmeBackend {}
unsafe impl Sync for NvmeBackend {}

impl NvmeBackend {
    fn cap(&self) -> u64 {
        unsafe { (*self.ctrl).sectors }
    }
    fn block(&self) -> usize {
        unsafe { (*self.ctrl).block_size }
    }
}

impl StorageBackend for NvmeBackend {
    fn read_sectors(&self, lba: u64, count: usize, buf: &mut [u8]) -> SdResult<usize> {
        let block = self.block();
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let offset = done * block;
            let ptr = buf[offset..offset + block].as_ptr() as u64;
            if unsafe { (*self.ctrl).submit_io(0x01, lba + done as u64, 1, ptr) } {
                done += 1;
            } else {
                return Err(SdError::IoError);
            }
            left -= 1;
        }
        Ok(done * block)
    }

    fn write_sectors(&mut self, lba: u64, count: usize, buf: &[u8]) -> SdResult<usize> {
        let block = self.block();
        let mut done = 0usize;
        let mut left = count;
        while left > 0 {
            let offset = done * block;
            let ptr = buf[offset..offset + block].as_ptr() as u64;
            if unsafe { (*self.ctrl).submit_io(0x02, lba + done as u64, 1, ptr) } {
                done += 1;
            } else {
                return Err(SdError::IoError);
            }
            left -= 1;
        }
        Ok(done * block)
    }

    fn flush(&mut self) -> SdResult<()> {
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.cap()
    }

    fn block_size(&self) -> usize {
        self.block()
    }

    fn is_online(&self) -> bool {
        self.cap() > 0
    }

    fn model(&self) -> [u8; 40] {
        self.model
    }

    fn serial(&self) -> [u8; 20] {
        self.serial
    }
}

// ============================================================================
// Probing
// ============================================================================

fn read_bar(base: u8, dev: u8, func: u8) -> Option<u64> {
    let header = plan9_drivers::pci::PciHeader::read(base, dev, func);
    for i in 0..6 {
        let bar = header.read_bar(base, dev, func, i);
        crate::serial::put_bytes(b"[sd] bar ");
        crate::serial::put_hex_u32(i as u32);
        crate::serial::put_bytes(b"=");
        crate::serial::put_hex_u32(bar);
        crate::serial::put_bytes(b"\n");
        if bar == 0 || plan9_drivers::pci::PciHeader::bar_is_io(bar) {
            continue;
        }
        let addr = bar & !0xF;
        if addr != 0 && addr != 0xFFFFFFFFu32 {
            return Some(addr as u64);
        }
    }
    None
}

pub fn probe_ata() -> Option<Arc<dyn StorageBackend>> {
    let channel = plan9_drivers::storage::AtaChannel::get_primary();
    for slave in [false, true] {
        if let Ok(device) = channel.identify(slave) {
            if device.present && device.sectors > 0 {
                return Some(Arc::new(AtaBackend::new(slave, &device)));
            }
        }
    }
    None
}

pub fn probe_ahci(device: &PciDeviceInfo) -> Vec<Arc<dyn StorageBackend>> {
    let mut out = Vec::new();
    // AHCI is class 0x01 (mass storage), subclass 0x06 (SATA), prog_if 0x01.
    let base = match read_bar(device.bus, device.dev, device.func) {
        Some(b) => b,
        None => return out,
    };
    crate::serial::put_bytes(b"[sd] ahci base=");
    crate::serial::put_hex_u64(base);
    crate::serial::put_bytes(b"\n");
    plan9_drivers::ahci::init_ahci(base as usize);

    let controller = match plan9_drivers::ahci::ahci_controller() {
        Some(c) => c,
        None => return out,
    };
    let mut controller_ptr: *mut plan9_drivers::ahci::AhciController = controller;

    let mask = controller_ptr_ports(controller_ptr);
    crate::serial::put_bytes(b"[sd] ahci pi=");
    crate::serial::put_hex_u32(mask);
    crate::serial::put_bytes(b"\n");
    for port_index in 0..32 {
        if mask & (1 << port_index) == 0 {
            continue;
        }
        if let Some(port) = unsafe { (*controller_ptr).get_port_mut(port_index) } {
            crate::serial::put_bytes(b"[sd] port ");
            crate::serial::put_hex_u32(port_index as u32);
            crate::serial::put_bytes(b" present=");
            crate::serial::put_hex_u32(if port.is_present() { 1 } else { 0 });
            crate::serial::put_bytes(b"\n");
            if port.is_present() {
                let cl = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
                let fb = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
                let ct = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
                if let (Some(cl), Some(fb), Some(ct)) = (cl, fb, ct) {
                    crate::serial::put_bytes(b"[sd] init start\n");
                    port.init(cl, fb, ct);
                    crate::serial::put_bytes(b"[sd] init done\n");

                    let ident_buf = crate::frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64());
                    crate::serial::put_bytes(b"[sd] identify start\n");
                    crate::serial::put_bytes(b"[sd] port cmd=");
                    crate::serial::put_hex_u32(port.cmd_status());
                    crate::serial::put_bytes(b" issue=");
                    crate::serial::put_hex_u32(port.cmd_issue_status());
                    crate::serial::put_bytes(b" clb=");
                    crate::serial::put_hex_u32(port.cmd_list_base_status());
                    crate::serial::put_bytes(b" fb=");
                    crate::serial::put_hex_u32(port.fis_base_status());
                    crate::serial::put_bytes(b"\n");
                    if let Some(ident_phys) = ident_buf {
                        match port.identify_device(ident_phys) {
                            Ok(ident) => {
                                crate::serial::put_bytes(b"[sd] identify sectors=");
                                crate::serial::put_hex_u64(ident.lba_capacity());
                                crate::serial::put_bytes(b" lba28=");
                                crate::serial::put_hex_u64(ident.lba_capacity_28() as u64);
                                crate::serial::put_bytes(b" w60=");
                                crate::serial::put_hex_u32(ident.words[60] as u32);
                                crate::serial::put_bytes(b" w61=");
                                crate::serial::put_hex_u32(ident.words[61] as u32);
                                crate::serial::put_bytes(b" w100=");
                                crate::serial::put_hex_u32(ident.words[100] as u32);
                                crate::serial::put_bytes(b" w101=");
                                crate::serial::put_hex_u32(ident.words[101] as u32);
                                crate::serial::put_bytes(b"\n");
                                port.identify = Some(ident);
                            }
                            Err(e) => {
                                crate::serial::put_bytes(b"[sd] after cmd=");
                                crate::serial::put_hex_u32(port.cmd_status());
                                crate::serial::put_bytes(b" issue=");
                                crate::serial::put_hex_u32(port.cmd_issue_status());
                                crate::serial::put_bytes(b" tfd=");
                                crate::serial::put_hex_u32(port.tfd());
                                crate::serial::put_bytes(b" irq=");
                                crate::serial::put_hex_u32(port.irq_status());
                                crate::serial::put_bytes(b" sig=");
                                crate::serial::put_hex_u32(port.signature());
                                crate::serial::put_bytes(b" ssts=");
                                crate::serial::put_hex_u32(port.sata_status());
                                crate::serial::put_bytes(b"\n");
                                crate::serial::put_bytes(b"[sd] header:");
                                for w in port.header_dwords() {
                                    crate::serial::put_bytes(b" ");
                                    crate::serial::put_hex_u32(w);
                                }
                                crate::serial::put_bytes(b"\n[sd] table:");
                                for w in port.cmd_table_dwords().iter().take(16) {
                                    crate::serial::put_bytes(b" ");
                                    crate::serial::put_hex_u32(*w);
                                }
                                crate::serial::put_bytes(b"\n");
                                crate::serial::put_bytes(b"[sd] identify failed code=");
                                let code = match e {
                                    plan9_drivers::storage::SdError::NotFound => 0u32,
                                    plan9_drivers::storage::SdError::NoDevice => 1,
                                    plan9_drivers::storage::SdError::InvalidSector => 2,
                                    plan9_drivers::storage::SdError::Invalid => 3,
                                    plan9_drivers::storage::SdError::ReadError => 4,
                                    plan9_drivers::storage::SdError::WriteError => 5,
                                    plan9_drivers::storage::SdError::Timeout => 6,
                                    plan9_drivers::storage::SdError::Busy => 7,
                                    plan9_drivers::storage::SdError::IoError => 8,
                                    plan9_drivers::storage::SdError::General => 9,
                                };
                                crate::serial::put_hex_u32(code);
                                crate::serial::put_bytes(b"\n");
                            }
                        }
                    }
                }
                let sectors = port.identify.as_ref().map(|i| i.lba_capacity()).unwrap_or(0);
                let mut backend = AhciBackend {
                    controller: controller_ptr,
                    port_index,
                    sectors,
                    model: port.identify.as_ref().map(|i| i.model()).unwrap_or([0u8; 40]),
                    serial: port.identify.as_ref().map(|i| i.serial()).unwrap_or([0u8; 20]),
                };

                // Validate the physical-DMA path with a read-only probe.
                // Boot probing must not write to user disks; a failed test
                // may corrupt data if the pattern is left behind.
                let mut read_ok = false;
                if sectors > 0 {
                    let mut buf = [0u8; 512];
                    crate::serial::put_bytes(b"[sd] dma read test\n");
                    match backend.read_sectors(0, 1, &mut buf) {
                        Ok(n) => {
                            crate::serial::put_bytes(b"[sd] dma read ok n=");
                            crate::serial::put_hex_u32(n as u32);
                            crate::serial::put_bytes(b" first=");
                            crate::serial::put_hex_u32(buf[0] as u32);
                            crate::serial::put_bytes(b"\n");
                            read_ok = true;
                        }
                        Err(e) => {
                            crate::serial::put_bytes(b"[sd] dma read failed code=");
                            crate::serial::put_hex_u32(ahci_error_code(e) as u32);
                            crate::serial::put_bytes(b"\n");
                        }
                    }
                }

                // Only publish ports that identified as ATA disks and passed
                // the read-only DMA probe.  Plan 9 numbers `sdN` units only
                // for working devices; publishing a failed port would shift
                // later disks to the wrong index and break `#f/sd1` on
                // machines whose AHCI reports an unimplemented/ATAPI port in
                // between.
                if read_ok {
                    out.push(Arc::new(backend));
                } else {
                    crate::serial::put_bytes(b"[sd] skipping unusable port\n");
                }
            }
        }
    }
    out
}

fn ahci_error_code(e: SdError) -> u32 {
    match e {
        SdError::NoDevice => 1,
        SdError::NotOnline => 2,
        SdError::Invalid => 3,
        SdError::IoError => 4,
        SdError::Timeout => 5,
        SdError::MediaError => 6,
        SdError::WriteProtected => 7,
        SdError::NoMedia => 8,
    }
}

fn controller_ptr_ports(controller: *mut plan9_drivers::ahci::AhciController) -> u32 {
    unsafe { (*controller).ports_implemented() }
}

pub fn probe_nvme(device: &PciDeviceInfo) -> Option<Arc<dyn StorageBackend>> {
    // NVMe is class 0x01 (mass storage), subclass 0x08 (NVM), prog_if 0x02.
    let base = read_bar(device.bus, device.dev, device.func)?;
    let ctrl = Box::new(NvmeController::init(base as usize)?);
    let ptr = Box::into_raw(ctrl);
    let model = [0u8; 40];
    let serial = [0u8; 20];
    Some(Arc::new(NvmeBackend { ctrl: ptr, model, serial }))
}

/// Probe all storage devices on the PCI bus and return the backends.
pub fn probe_all() -> Vec<Arc<dyn StorageBackend>> {
    let mut out = Vec::new();
    if let Some(be) = probe_ata() {
        out.push(be);
    }
    for d in crate::dev::pci_iter() {
        if d.class_code == 0x01 {
            if d.subclass == 0x06 {
                for be in probe_ahci(&d) {
                    out.push(be);
                }
            } else if d.subclass == 0x08 {
                if let Some(be) = probe_nvme(&d) {
                    out.push(be);
                }
            }
        }
    }
    out
}

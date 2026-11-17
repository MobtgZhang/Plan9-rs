//! ACPI Support
//!
//! Implements ACPI (Advanced Configuration and Power Interface) support
//! for power management, hardware enumeration, and system control.
//!
//! ## Reference
//! - Plan 9: `/sys/src/9/pc/mpacpi.c`, `/sys/src/9/pc/acpi.c`

use core::sync::atomic::{ AtomicPtr, Ordering };use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::format;

use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

// ============================================================================
// ACPI Tables
// ============================================================================

/// ACPI table header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AcpiSdtHeader {
    /// Signature (4 bytes)
    pub signature: [u8; 4],
    /// Length of the table
    pub length: u32,
    /// ACPI revision
    pub revision: u8,
    /// Checksum
    pub checksum: u8,
    /// OEM identification
    pub oem_id: [u8; 6],
    /// OEM table identification
    pub oem_table_id: [u8; 8],
    /// OEM revision
    pub oem_revision: u32,
    /// Creator ID
    pub creator_id: u32,
    /// Creator revision
    pub creator_revision: u32,
}

impl AcpiSdtHeader {
    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let mut sum: u8 = 0;
        let data = unsafe {
            core::slice::from_raw_parts(
                self as *const AcpiSdtHeader as *const u8,
                self.length as usize
            )
        };
        for &b in data {
            sum = sum.wrapping_add(b);
        }
        sum == 0
    }

    /// Get signature as string
    pub fn signature_str(&self) -> [u8; 5] {
        let mut s = [0u8; 5];
        s[..4].copy_from_slice(&self.signature);
        s
    }
}

/// RSDP (Root System Description Pointer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    /// Signature "RSD PTR "
    pub signature: [u8; 8],
    /// Checksum
    pub checksum: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// Revision (0 = ACPI 1.0, 2 = ACPI 2.0+)
    pub revision: u8,
    /// RSDT address (physical)
    pub rsdt_address: u32,
    /// ACPI 2.0+ fields
    /// Length (if revision >= 2)
    pub length: u32,
    /// XSDT address (physical, 64-bit)
    pub xsdt_address: u64,
    /// Extended checksum
    pub ext_checksum: u8,
    /// Reserved
    pub reserved: [u8; 3],
}

impl Rsdp {
    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let sum: u8 = self.signature.iter()
            .chain(self.oem_id.iter())
            .chain([self.revision].iter())
            .chain(self.rsdt_address.to_le_bytes().iter())
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }

    /// Check if ACPI 2.0+
    pub fn is_acpi20(&self) -> bool {
        self.revision >= 2
    }

    /// Get RSDT/XSDT address
    pub fn sdt_address(&self) -> u64 {
        if self.is_acpi20() {
            self.xsdt_address
        } else {
            self.rsdt_address as u64
        }
    }
}

/// ACPI FADT (Fixed ACPI Description Table)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: AcpiSdtHeader,
    /// Physical address of the DSDT
    pub dsdt: u32,
    /// Reserved
    pub reserved: u8,
    /// Power management profile
    pub profile: u8,
    /// SCI interrupt
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command: u32,
    /// ACPI enable
    pub acpi_enable: u8,
    /// ACPI disable
    pub acpi_disable: u8,
    /// S4BIOS_REQ
    pub s4bios_req: u8,
    /// PSTATE cutoff
    pub pstate_cnt: u8,
    /// PM1a event block
    pub pm1a_evt_blk: u32,
    /// PM1b event block
    pub pm1b_evt_blk: u32,
    /// PM1a control block
    pub pm1a_cnt_blk: u32,
    /// PM1b control block
    pub pm1b_cnt_blk: u32,
    /// PM2 control block
    pub pm2_cnt_blk: u32,
    /// PM timer block
    pub pm_tmr_blk: u32,
    /// GPE0 block
    pub gpe0_blk: u32,
    /// GPE1 block
    pub gpe1_blk: u32,
    /// PM1 event length
    pub pm1_evt_len: u8,
    /// PM1 control length
    pub pm1_cnt_len: u8,
    /// PM2 control length
    pub pm2_cnt_len: u8,
    /// PM timer length
    pub pm_tmr_len: u8,
    /// GPE0 length
    pub gpe0_blk_len: u8,
    /// GPE1 length
    pub gpe1_blk_len: u8,
    /// GPE1 base
    pub gpe1_base: u8,
    /// C state control
    pub cst_cnt: u8,
    /// P_LVL2 latency
    pub p_lvl2_lat: u16,
    /// P_LVL3 latency
    pub p_lvl3_lat: u16,
    /// Flush size
    pub flush_size: u16,
    /// Flush stride
    pub flush_stride: u16,
    /// Duty offset
    pub duty_offset: u8,
    /// Duty width
    pub duty_width: u8,
    /// Day alarm
    pub day_alrm: u8,
    /// Month alarm
    pub mon_alrm: u8,
    /// Century
    pub century: u8,
    /// Boot architecture flags
    pub iapc_boot_arch: u16,
    /// Flags
    pub flags: u32,
}

// ============================================================================
// ACPI State
// ============================================================================

/// ACPI power state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiPowerState {
    /// S0: Working
    S0 = 0,
    /// S1: S1/POS - Power on Suspend
    S1 = 1,
    /// S2: S2/SWP - CPU stopped
    S2 = 2,
    /// S3: S3/STR - Suspend to RAM
    S3 = 3,
    /// S4: S4/STD - Suspend to Disk
    S4 = 4,
    /// S5: Soft off
    S5 = 5,
}

impl AcpiPowerState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::S0),
            1 => Some(Self::S1),
            2 => Some(Self::S2),
            3 => Some(Self::S3),
            4 => Some(Self::S4),
            5 => Some(Self::S5),
            _ => None,
        }
    }
}

/// ACPI information
pub struct AcpiInfo {
    /// Whether ACPI is available
    pub available: bool,
    /// RSDP address
    pub rsdp_address: u64,
    /// RSDT/XSDT address
    pub sdt_address: u64,
    /// ACPI version
    pub version: u8,
    /// FADT address
    pub fadt_address: u64,
    /// DSDT address
    pub dsdt_address: u64,
    /// SCI interrupt
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command: u32,
    /// PM1a control port
    pub pm1a_cnt: u32,
    /// PM1b control port
    pub pm1b_cnt: u32,
}

impl Default for AcpiInfo {
    fn default() -> Self {
        Self {
            available: false,
            rsdp_address: 0,
            sdt_address: 0,
            version: 0,
            fadt_address: 0,
            dsdt_address: 0,
            sci_interrupt: 0,
            smi_command: 0,
            pm1a_cnt: 0,
            pm1b_cnt: 0,
        }
    }
}

/// ACPI state
pub struct Acpi {
    /// Information
    info: AcpiInfo,
    /// Tables cache
    tables: core::cell::UnsafeCell<Vec<(*const AcpiSdtHeader, u64)>>,
}

impl Acpi {
    /// Create new ACPI state
    pub fn new() -> Self {
        Self {
            info: AcpiInfo::default(),
            tables: core::cell::UnsafeCell::new(Vec::new()),
        }
    }

    /// Get ACPI info
    pub fn info(&self) -> &AcpiInfo {
        &self.info
    }

    /// Check if ACPI is available
    pub fn is_available(&self) -> bool {
        self.info.available
    }

    /// Find a table by signature
    pub fn find_table(&self, signature: &[u8; 4]) -> Option<*const AcpiSdtHeader> {
        let tables = unsafe { &*self.tables.get() };
        for (header, _) in tables {
            if unsafe { (**header).signature == *signature } {
                return Some(*header);
            }
        }
        None
    }
}

// ============================================================================
// Global ACPI
// ============================================================================

static ACPI: AtomicPtr<Acpi> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize ACPI
pub fn init_acpi(rsdp_address: u64) -> Result<(), &'static str> {
    if rsdp_address == 0 {
        return Err("No RSDP address provided");
    }

    // Read RSDP
    let rsdp = unsafe { &*(rsdp_address as *const Rsdp) };

    if !rsdp.verify_checksum() {
        return Err("RSDP checksum failed");
    }

    let mut acpi = Box::new(Acpi::new());

    // Fill in basic info
    acpi.info.rsdp_address = rsdp_address;
    acpi.info.sdt_address = rsdp.sdt_address();
    acpi.info.version = rsdp.revision;

    // Parse RSDT/XSDT to find FADT
    if let Some(fadt) = find_table::<Fadt>(rsdp.sdt_address(), b"FACP") {
        acpi.info.fadt_address = fadt as *const Fadt as u64;
        acpi.info.dsdt_address = fadt.dsdt as u64;
        acpi.info.sci_interrupt = fadt.sci_interrupt;
        acpi.info.smi_command = fadt.smi_command;
        acpi.info.pm1a_cnt = fadt.pm1a_cnt_blk;
        acpi.info.pm1b_cnt = fadt.pm1b_cnt_blk;
    }

    acpi.info.available = true;

    // Parse all tables from RSDT/XSDT
    parse_sdt(rsdp.sdt_address(), &mut acpi);

    ACPI.store(Box::into_raw(acpi), Ordering::SeqCst);

    Ok(())
}

/// Parse SDT (RSDT/XSDT)
fn parse_sdt(sdt_address: u64, acpi: &mut Acpi) {
    let header = unsafe { &*(sdt_address as *const AcpiSdtHeader) };

    if !header.verify_checksum() {
        return;
    }

    // Calculate number of entries
    let entry_size = if acpi.info.version >= 2 { 8 } else { 4 };
    let num_entries = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / entry_size;

    // Parse each entry
    let entries_base = unsafe { (sdt_address as *const AcpiSdtHeader as *const u8).add(core::mem::size_of::<AcpiSdtHeader>()) };

    for i in 0..num_entries {
        let entry_addr = if entry_size == 8 {
            unsafe { *(entries_base.add(i * 8) as *const u64) }
        } else {
            unsafe { *(entries_base.add(i * 4) as *const u32) as u64 }
        };

        if entry_addr != 0 {
            let entry_header = unsafe { &*(entry_addr as *const AcpiSdtHeader) };
            if entry_header.verify_checksum() {
                unsafe { (*acpi.tables.get()).push((entry_header, entry_addr)); }
            }
        }
    }
}

/// Find a table by type
fn find_table<T>(sdt_address: u64, signature: &[u8; 4]) -> Option<&'static T> {
    let header = unsafe { &*(sdt_address as *const AcpiSdtHeader) };

    let entry_size = if header.length >= 8 { 8 } else { 4 };
    let num_entries = (header.length as usize - core::mem::size_of::<AcpiSdtHeader>()) / entry_size;

    let entries_base = unsafe { (sdt_address as *const AcpiSdtHeader as *const u8).add(core::mem::size_of::<AcpiSdtHeader>()) };

    for i in 0..num_entries {
        let entry_addr = if entry_size == 8 {
            unsafe { *(entries_base.add(i * 8) as *const u64) }
        } else {
            unsafe { *(entries_base.add(i * 4) as *const u32) as u64 }
        };

        if entry_addr != 0 {
            let entry_header = unsafe { &*(entry_addr as *const AcpiSdtHeader) };
            if &entry_header.signature == signature {
                return Some(unsafe { &*(entry_addr as *const T) });
            }
        }
    }

    None
}

/// Get global ACPI
pub fn acpi() -> &'static Acpi {
    unsafe { &*ACPI.load(Ordering::SeqCst) }
}

// ============================================================================
// ACPI Operations
// ============================================================================

/// Enter a sleep state (S1-S5)
pub fn acpi_enter_sstate(state: AcpiPowerState) {
    if state == AcpiPowerState::S0 {
        return;  // Can't enter S0
    }

    let info = acpi().info();
    if !info.available {
        return;
    }

    // Get the sleep type
    let sleep_type = state as u16;

    // Write to PM1a control register
    if info.pm1a_cnt != 0 {
        let slp_typ_a = (sleep_type as u16) << 10;
        let slp_en = 1u16 << 13;
        let value = slp_typ_a | slp_en;

        unsafe {
            // Port 0x608 for PM1a control
            // This is architecture specific
            core::arch::asm!(
                "mov dx, 0x608",
                "mov ax, [{val}]",
                "out dx, ax",
                val = in(reg) &value,
                options(nostack)
            );
        }
    }
}

/// Trigger system shutdown via ACPI
pub fn acpi_shutdown() {
    // Enter S5 (soft off)
    acpi_enter_sstate(AcpiPowerState::S5);
}

/// Trigger system reset via ACPI
pub fn acpi_reset() {
    // Write to reset register in FADT
    // For now, fallback to triple fault
    triple_fault();
}

/// Triple fault to trigger reset
fn triple_fault() -> ! {
    unsafe {
        core::arch::asm!(
            "mov ax, 0",
            "div ax",
            options(noreturn)
        );
    }
}

// ============================================================================
// ACPI Device
// ============================================================================

/// ACPI device
pub struct AcpiDev {
    name: &'static str,
    dev_char: char,
}

impl AcpiDev {
    /// Create new ACPI device
    pub fn new() -> Self {
        Self {
            name: "acpi",
            dev_char: 'A',  // 'A' for ACPI
        }
    }
}

impl Dev for AcpiDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Err(Error::Enoent)
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        let info = acpi().info();

        let s = format!(
            "ACPI available: {}\n\
             RSDP: {:#018x}\n\
             Version: {}\n\
             RSDT/XSDT: {:#018x}\n\
             FADT: {:#018x}\n\
             DSDT: {:#018x}\n\
             SCI IRQ: {}\n\
             PM1a CNT: {:#010x}\n\
             PM1b CNT: {:#010x}\n",
            info.available,
            info.rsdp_address,
            info.version,
            info.sdt_address,
            info.fadt_address,
            info.dsdt_address,
            info.sci_interrupt,
            info.pm1a_cnt,
            info.pm1b_cnt,
        );

        let n = s.len().min(buf.len());
        buf[..n].copy_from_slice(s.as_bytes());
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| Error::Einval)?
            .trim();

        if cmd == "shutdown" {
            acpi_shutdown();
            Ok(buf.len())
        } else if cmd == "reset" {
            acpi_reset();
            Ok(buf.len())
        } else if cmd.starts_with("sstate=") {
            if let Ok(state) = cmd[7..].parse::<u8>() {
                if let Some(s) = AcpiPowerState::from_u8(state) {
                    acpi_enter_sstate(s);
                    Ok(buf.len())
                } else {
                    Err(Error::Einval)
                }
            } else {
                Err(Error::Einval)
            }
        } else {
            Err(Error::Einval)
        }
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        let _info =acpi().info();
        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o444,  // Read-only
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"acpi".to_vec(),
            uid: 0,
            gid: 0,
})
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

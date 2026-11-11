//! SMP bring-up.
//!
//! Enumerates the CPUs from the ACPI MADT, then wakes the application
//! processors through the classic INIT + SIPI handshake.  Each AP runs the
//! 16-bit real-mode trampoline copied to the low-memory page at
//! `AP_TRAMPOLINE` (see `arch::x86_64::ap_trampoline.S`), which switches on
//! paging with a fresh AP page table and calls [`ap_main`] in long mode.
//!
//! APs currently park in a halt loop after announcing themselves: parallel
//! scheduling is a follow-up step.  Bringing the CPUs online is the core of
//! the milestone — after this, `online_cpus()` reports the real core count.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::frame_alloc;
use crate::plan9_arch::hal::paging::{phys_to_virt, PAGESIZE};
use plan9_common::types::PhysAddr;

/// Physical page the trampoline binary is linked at (SIPI vector 0x50).
const AP_TRAMPOLINE: u64 = 0x50000;
/// Mailbox offset inside the trampoline page.
const AP_MAILBOX: u64 = AP_TRAMPOLINE + 0x800;

/// Number of CPUs seen in the MADT (never 0; 1 when MADT is unavailable).
static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
/// APs that reached `ap_main` (BSP counted as 1).
static CPUS_ONLINE: AtomicUsize = AtomicUsize::new(1);

/// Number of CPUs configured (from the ACPI MADT).
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::SeqCst)
}

/// Number of CPUs that completed bring-up (BSP included).
pub fn online_cpus() -> usize {
    CPUS_ONLINE.load(Ordering::SeqCst)
}

// ============================================================================
// RSDP / MADT discovery
// ============================================================================

/// Copy of the RSDP structure taken from the Multiboot2 ACPI tag (14/15).
/// Under OVMF/UEFI the legacy BIOS scan regions (EBDA, 0xE0000..0x100000)
/// hold nothing, so the bootloader-supplied copy is the primary source.
static mut RSDP_COPY: [u8; 36] = [0u8; 36];
static mut RSDP_COPY_LEN: usize = 0;

/// Record the RSDP bytes handed over by the bootloader.  Called from
/// `parse_boot_info` when it sees the Multiboot2 ACPI tags.
#[cfg(target_arch = "x86_64")]
pub fn store_rsdp_copy(bytes: &[u8]) {
    let n = bytes.len().min(36);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), RSDP_COPY.as_mut_ptr(), n);
        RSDP_COPY_LEN = n;
    }
}

/// Validate the stored RSDP copy and return its address.  The copy lives in
/// the kernel image, which is identity-mapped, so the address can be used
/// directly as an RSDP pointer (the bytes are identical to the original).
#[cfg(target_arch = "x86_64")]
fn rsdp_from_copy() -> Option<u64> {
    unsafe {
        if RSDP_COPY_LEN < 20 {
            return None;
        }
        let buf = &raw const RSDP_COPY;
        let b = &*buf;
        if b[0..8] != *b"RSD PTR " {
            return None;
        }
        let sum20 = b[0..20].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        if sum20 != 0 {
            return None;
        }
        if RSDP_COPY_LEN >= 32 {
            // RSDPv2: the extended checksum covers all 36 bytes.
            let sum36 = b[0..36].iter().fold(0u8, |a, &x| a.wrapping_add(x));
            if sum36 != 0 {
                return None;
            }
        }
        Some(buf as *const u8 as u64)
    }
}

/// Scan the conventional BIOS memory areas for the RSDP signature and
/// return its physical address, or `None`.
///
/// The Multiboot2 ACPI tags are the primary source (see `rsdp_from_copy`);
/// the standard BIOS scan is the fallback for non-UEFI boots: the EBDA
/// region pointed to by BDA word 0x40E, the 0x60000..0xA0000 conventional
/// memory top, then the 0xE0000..0x100000 BIOS ROM shadow area.
#[cfg(target_arch = "x86_64")]
fn find_rsdp() -> Option<u64> {
    if let Some(a) = rsdp_from_copy() {
        return Some(a);
    }
    let ebda_seg = unsafe { *(0x40Eusize as *const u16) } as u64;
    let ebda_base = ebda_seg << 4;
    // The EBDA can be as small as 512 bytes; scan up to 1 KiB but never
    // leave the conventional-memory area.
    let ebda_end = (ebda_base + 1024).min(0xA0000);
    if ebda_base >= 0x50000 && ebda_base < ebda_end {
        if let Some(a) = scan_rsdp_range(ebda_base, ebda_end) {
            return Some(a);
        }
    }
    // QEMU sometimes places the RSDP anywhere in the 0x60000..0xA0000
    // conventional-memory top; scan that too before the BIOS ROM area.
    if let Some(a) = scan_rsdp_range(0x60000, 0xA0000) {
        return Some(a);
    }
    scan_rsdp_range(0xE0000, 0x100000)
}

/// Look for "RSD PTR " followed by a valid ACPI 1.0 checksum.
#[cfg(target_arch = "x86_64")]
fn scan_rsdp_range(start: u64, end: u64) -> Option<u64> {
    let mut addr = start;
    while addr + 8 <= end {
        let sig = unsafe { *(addr as *const u64) };
        if sig == u64::from_le_bytes(*b"RSD PTR ") {
            // Verify the 20-byte ACPI 1.0 checksum.
            let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 20) };
            let sum = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            if sum == 0 {
                return Some(addr);
            }
        }
        addr += 16; // RSDPs are 16-byte aligned
    }
    None
}

/// Extract the RSDT/XSDT address from the RSDP at `rsdp`.  Returns the
/// table address plus whether it is an XSDT (64-bit entry format).
#[cfg(target_arch = "x86_64")]
unsafe fn rsdt_address(rsdp: u64) -> Option<(u64, bool)> {
    let revision = core::ptr::read_unaligned((rsdp as *const u8).add(15));
    if revision >= 2 {
        let xsdt = core::ptr::read_unaligned((rsdp as *const u64).add(3)); // offset 24
        if xsdt != 0 {
            return Some((xsdt, true));
        }
    }
    // RSDT pointer is at offset 16 (four u32 slots past the signature).
    let rsdt = core::ptr::read_unaligned((rsdp as *const u32).add(4)) as u64;
    if rsdt != 0 {
        return Some((rsdt, false));
    }
    None
}

/// Walk the RSDT/XSDT (a table of pointers to other SDTs), find the MADT
/// ("APIC" table) and return the APIC IDs of every enabled CPU.
#[cfg(target_arch = "x86_64")]
fn madt_apic_ids(rsdt: u64, xsdt: bool) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        // ACPI SDT header: 32-bit length field at offset 4. Firmware tables
        // are not guaranteed to be aligned for the entry width, so every
        // multi-byte access uses `read_unaligned`.
        let table_len = core::ptr::read_unaligned((rsdt as *const u32).add(1)) as usize;
        // 36-byte SDT header, then the pointer entries (u32 for RSDT,
        // u64 for XSDT).
        let stride = if xsdt { 8usize } else { 4usize };
        let mut off = 36usize;
        while off + stride <= table_len {
            let ptr = if xsdt {
                core::ptr::read_unaligned((rsdt + off as u64) as *const u64)
            } else {
                core::ptr::read_unaligned((rsdt + off as u64) as *const u32) as u64
            };
            if ptr != 0 {
                let sig = core::ptr::read_unaligned(ptr as *const [u8; 4]);
                if sig == *b"APIC" {
                    return parse_madt(ptr);
                }
            }
            off += stride;
        }
        None
    }
}

/// Parse a MADT ("APIC") table: return the APIC IDs of every enabled CPU.
///
/// Entry layout for type 0 (Processor Local APIC, 8 bytes):
/// [0]=type [1]=len [2]=ACPI UID [3]=APIC ID [4..8]=flags (bit 0 = enabled).
#[cfg(target_arch = "x86_64")]
fn parse_madt(madt: u64) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        let table_len = core::ptr::read_unaligned((madt as *const u32).add(1)) as usize;
        if table_len <= 44 {
            return None;
        }
        let mut ids = alloc::vec::Vec::new();
        // 36-byte SDT header + u32 local APIC controller address + u32
        // flags; variable entries start right after.
        let mut off = 44usize;
        while off + 2 <= table_len {
            let entry = madt + off as u64;
            let etype = core::ptr::read_unaligned(entry as *const u8);
            let elen = core::ptr::read_unaligned((entry + 1) as *const u8) as usize;
            if elen < 2 || off + elen > table_len {
                break;
            }
            if etype == 0 && elen >= 8 {
                let apic_id = core::ptr::read_unaligned((entry + 3) as *const u8);
                let flags = core::ptr::read_unaligned((entry + 4) as *const u32);
                if flags & 1 != 0 {
                    ids.push(apic_id);
                }
            }
            off += elen;
        }
        if ids.is_empty() {
            None
        } else {
            Some(ids)
        }
    }
}

// ============================================================================
// AP start
// ============================================================================

/// Bring up the application processors.  Must run once, from the BSP,
/// after the frame allocator, heap and scheduler are initialised.
#[cfg(target_arch = "x86_64")]
pub fn init_aps() {
    let cpus = unsafe {
        let rsdp = match find_rsdp() {
            Some(a) => a,
            None => {
                crate::serial::put_bytes(b"[smp] no RSDP found, single CPU\n");
                return;
            }
        };
        let (rsdt, xsdt) = match rsdt_address(rsdp) {
            Some(a) => a,
            None => {
                crate::serial::put_bytes(b"[smp] no RSDT/XSDT, single CPU\n");
                return;
            }
        };
        madt_apic_ids(rsdt, xsdt)
    };
    let cpus = match cpus {
        Some(c) => c,
        None => {
            crate::serial::put_bytes(b"[smp] no MADT or no CPUs, single CPU\n");
            return;
        }
    };

    CPU_COUNT.store(cpus.len(), Ordering::SeqCst);
    crate::serial::put_bytes(b"[smp] MADT reports ");
    crate::serial::put_hex_u32(cpus.len() as u32);
    crate::serial::put_bytes(b" cpus: ");
    for id in &cpus {
        crate::serial::put_hex_u32(*id as u32);
        crate::serial::put_bytes(b" ");
    }
    crate::serial::put_bytes(b"\n");

    // Copy the trampoline into low memory.  The page is identity-mapped
    // in both the boot page tables (0..1 GiB) and every AP page table.
    let tramp = AP_TRAMPOLINE as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(
            crate::plan9_arch::hal::smp::AP_TRAMPOLINE.as_ptr(),
            tramp,
            crate::plan9_arch::hal::smp::AP_TRAMPOLINE.len(),
        );
    }

    // Reserve the trampoline page so the frame allocator never hands it out.
    frame_alloc::reserve_range_pub(AP_TRAMPOLINE, AP_TRAMPOLINE + PAGESIZE as u64);

    // BSP LAPIC id (MSR-free: read the LAPIC ID register directly).
    let bsp_id = bsp_lapic_id();

    let mut started = 0usize;
    for &id in &cpus {
        if id == bsp_id {
            continue;
        }
        if start_ap(id) {
            started += 1;
        }
    }

    crate::serial::put_bytes(b"[smp] ");
    crate::serial::put_hex_u32(started as u32);
    crate::serial::put_bytes(b" AP(s) started, online=");
    crate::serial::put_hex_u32(CPUS_ONLINE.load(Ordering::SeqCst) as u32);
    crate::serial::put_bytes(b"\n");
}

/// Read the BSP's APIC id from the LAPIC ID register (0xFEE00020).  The
/// MMIO window sits in the boot identity map, so a plain pointer read works.
#[cfg(target_arch = "x86_64")]
fn bsp_lapic_id() -> u8 {
    let id_reg = unsafe { *(0xFEE00020usize as *const u32) };
    (id_reg >> 24) as u8
}

/// Minimal GDT for the AP's real->long transition.  The far jump in the
/// trampoline selects index 1 (selector 0x08 = kernel code, long mode);
/// `ap_main` then loads the kernel's own GDT.
#[repr(C, align(16))]
struct ApGdt {
    null: u64,
    code64: u64,
    data64: u64,
    pad: u64,
}

static mut AP_GDT: ApGdt = ApGdt {
    null: 0,
    // Long-mode code segment: P=1, DPL=0, S=1, EX=1, DC=0, RW=0, A=1
    // (0x9A), G=1, L=1, D=0 (0xA0 in the flags byte) -> 0x00AF9A000000FFFF
    code64: 0x00AF_9A00_0000_FFFF,
    // Flat data segment: 0x00CF92000000FFFF
    data64: 0x00CF_9200_0000_FFFF,
    pad: 0,
};

/// Start one AP by APIC id.  Returns whether it reported online.
#[cfg(target_arch = "x86_64")]
fn start_ap(apic_id: u8) -> bool {
    // AP page tables: kernel-half mirror + the 0..1 GiB identity map.
    let ap_pml4 = match frame_alloc::frame_alloc_zeroed() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
        if crate::init_loader::copy_kernel_pml4_into(ap_pml4).is_none() {
            return false;
        }
    }

    // AP kernel stack (32 KiB).  Use the identity-mapped virtual address:
    // the AP page tables keep the 0..1 GiB identity map, while the
    // high-half mirror (phys_to_virt) is not guaranteed to cover this
    // freshly allocated frame in every page-table generation.
    const AP_STACK_PAGES: u64 = 8;
    let stack_phys = match crate::vm::alloc_frames(AP_STACK_PAGES as usize) {
        Some(p) => p,
        None => return false,
    };
    let stack_top_virt = stack_phys.as_u64() + AP_STACK_PAGES * PAGESIZE as u64;

    // Fill the mailbox.
    let mb = AP_MAILBOX as *mut u8;
    unsafe {
        // +0x08 u64 ap_stack_top
        (mb.add(0x08) as *mut u64).write_volatile(stack_top_virt);
        // +0x10 u64 ap_entry
        (mb.add(0x10) as *mut u64).write_volatile(ap_main as usize as u64);
        // +0x18 u32 ap_cr3
        (mb.add(0x18) as *mut u32).write_volatile(ap_pml4.as_u64() as u32);
        // +0x28 lgdt operand: limit16, base32 (linear == physical for the
        // low GDT in every page table).
        let gdt_addr = (&raw const AP_GDT) as *const u8 as u64;
        // The GDT lives in the kernel image above 1 MiB, whose *linear*
        // address equals its link address in the boot identity map, and the
        // AP page tables inherit that mapping.  (The kernel image is linked
        // identity at 2 MiB.)
        (mb.add(0x28) as *mut u16).write_volatile((core::mem::size_of::<ApGdt>() - 1) as u16);
        (mb.add(0x2A) as *mut u32).write_volatile(gdt_addr as u32);
        // +0x30 u32 ap_cpu_id
        (mb.add(0x30) as *mut u32).write_volatile(apic_id as u32);
    }

    // Mark the AP stack frames reserved so they are not handed out again.
    frame_alloc::reserve_range_pub(
        stack_phys.as_u64(),
        stack_phys.as_u64() + AP_STACK_PAGES * PAGESIZE as u64,
    );
    frame_alloc::reserve_range_pub(ap_pml4.as_u64(), ap_pml4.as_u64() + PAGESIZE as u64);

    let online_before = CPUS_ONLINE.load(Ordering::SeqCst);

    // INIT + SIPI sequence (Intel SDM vol.3 §11.6, "typical startup").
    unsafe {
        icr_write(apic_id, 0x0000_4500); // INIT with assert, physical dest
        delay();
        let vector = (AP_TRAMPOLINE >> 12) as u8;
        icr_write(apic_id, 0x0000_0600 | vector as u32); // SIPI #1
        delay();
        icr_write(apic_id, 0x0000_0600 | vector as u32); // SIPI #2
    }

    // Wait for the AP to report online (bounded).
    for _ in 0..2_000_000 {
        if CPUS_ONLINE.load(Ordering::SeqCst) != online_before {
            return true;
        }
        unsafe { core::arch::asm!("pause", options(nostack, preserves_flags)); }
    }
    crate::serial::put_bytes(b"[smp] ap ");
    crate::serial::put_hex_u32(apic_id as u32);
    crate::serial::put_bytes(b" did not come online\n");
    false
}

/// Write one ICR command (destination APIC id + command word).
///
/// # Safety
/// The LAPIC MMIO window must be mapped (it is: the boot identity map
/// covers 0x80000000..0xC0000000).
#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn icr_write(dest_apic_id: u8, command: u32) {
    // LAPIC MMIO base 0xFEE00000: ICR low at +0x300, ICR2 (destination) at
    // +0x310.  Beware the hex digit count: 0xFEE00300 (32-bit) is correct;
    // 0xFEE000300 is a 36-bit typo that lands on unassigned memory.
    let icr_low = 0xFEE00300usize as *mut u32;
    let icr_high = 0xFEE00310usize as *mut u32;
    // The high dword must be written first (it arms the destination).
    icr_high.write_volatile((dest_apic_id as u32) << 24);
    icr_low.write_volatile(command);
    // Wait for the send to complete.  The delivery-status bit (12) is only
    // meaningful on older APICs; QEMU stores the ICR verbatim so the bit
    // never self-clears.  Poll a bounded number of times, then move on.
    for _ in 0..1000 {
        if icr_low.read_volatile() & (1 << 12) == 0 {
            break;
        }
        core::arch::asm!("pause", options(nostack, preserves_flags));
    }
}

/// Bounded busy-wait between IPI phases.
#[cfg(target_arch = "x86_64")]
#[inline]
fn delay() {
    for _ in 0..200_000 {
        unsafe { core::arch::asm!("pause", options(nostack, preserves_flags)); }
    }
}

/// AP entry point, called in long mode with the CPU id in the first
/// argument register.  Never returns.
#[cfg(target_arch = "x86_64")]
pub extern "C" fn ap_main(cpu_id: u32) -> ! {
    unsafe {
        // Per-CPU id for current_cpu_id() (TSC_AUX based).
        crate::plan9_arch::hal::write_tsc_aux(cpu_id);

        // Load the kernel GDT and reload segment registers (the
        // trampoline's CS refers to the minimal AP GDT).
        crate::plan9_arch::hal::gdt::gdt_init();
        crate::plan9_arch::hal::gdt::reload_segments();

        // Shared IDT: every CPU handles the same vectors.  The arch crate
        // owns the IDT (the kernel's trap::init_idt is unreferenced).
        unsafe { crate::plan9_arch::hal::idt::idt_init() };
    }

    crate::serial::put_bytes(b"[smp] cpu ");
    crate::serial::put_hex_u32(cpu_id);
    crate::serial::put_bytes(b" online\n");

    CPUS_ONLINE.fetch_add(1, Ordering::SeqCst);

    // Park with interrupts off.  Parallel scheduling is a follow-up; the
    // AP must not run the (single-CPU) scheduler yet.
    unsafe {
        loop {
            core::arch::asm!("cli", "hlt", options(nostack));
        }
    }
}

//! LoongArch64 MMU control — page-table base CSRs (PGDL/PGDH), direct-map
//! windows (DMW0–3), TLB maintenance (INVTLB) and fault info, exposed
//! through the architecture-neutral names the kernel uses.
//!
//! Naming bridge:
//!   * x86 CR3            → CSR.PGDL (low-half page global directory)
//!   * x86 CR2 (fault VA)  → CSR.BADV
//!   * x86 INVLPG / FLUSH  → INVTLB (op 0 = clear all)
//!   * x86 PTE error code  → ESTAT.EXC (ADE / TLBR codes)

extern crate plan9_common;

use plan9_common::types::{PhysAddr, VirtAddr};

use super::cpu::{csr, csr_read, csr_write};
use super::paging::{MMIO_VIRT, PHYS_MEMORY_VIRT, PT_ENTRIES, PageTable};

// ============================================================================
// Direct-mapped windows (DMW)
// ============================================================================

/// DMW register fields: PLV0–3 enable in bits [3:0], MAT in bits [5:4],
/// VSEG in bits [63:60].  VSEG 0 is a valid window matching addresses in
/// the lowest 2^60-byte range (bits [63:60] == 0), not a disabled value.
pub const DMW_PLV0: u64 = 1 << 0;
pub const DMW_MAT_COHERENT: u64 = 1 << 4; // MAT = 1 (coherent cached)
pub const DMW_MAT_UNCACHED: u64 = 0;      // MAT = 0 (strongly uncached)
pub const DMW_VSEG0: u64 = 0x0 << 60;
pub const DMW_VSEG8: u64 = 0x8 << 60;
pub const DMW_VSEG9: u64 = 0x9 << 60;

/// Install the boot direct-map windows:
///   * DMW0 — VSEG 0 (0x0000_0000_0000_0000), coherent cached, PLV0.
///     Keeps the low physical link-space kernel image, boot stack and
///     low absolute pointers addressable after paged translation.
///   * DMW1 — VSEG 8 (0x8000_0000_0000_0000), coherent cached, PLV0.
///     Cached direct-map view of physical memory (kernel image).
///   * DMW2 — VSEG 9 (0x9000_0000_0000_0000), strongly uncached, PLV0.
///     MMIO (UART, interrupt controllers); DMW2 is load/store-only.
pub fn install_direct_windows() {
    csr_write::<{ csr::DMW0 }>(DMW_VSEG0 | DMW_MAT_COHERENT | DMW_PLV0);
    csr_write::<{ csr::DMW1 }>(DMW_VSEG8 | DMW_MAT_COHERENT | DMW_PLV0);
    csr_write::<{ csr::DMW2 }>(DMW_VSEG9 | DMW_MAT_UNCACHED | DMW_PLV0);
    super::cpu::dbar();
}

// ============================================================================
// Root-table switch (x86 CR3 equivalents)
// ============================================================================

/// Page-table base address mask (bits [47:12]; low bits reserved).
const PGD_BASE_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Read the current low-half page-table base (CSR.PGDL).
#[inline]
pub fn cr3_read() -> PhysAddr {
    PhysAddr::new(csr_read::<{ csr::PGDL }>() & PGD_BASE_MASK)
}

/// Read the high-half page-table base (CSR.PGDH) — unused for the
/// kernel's DMW-based bring-up but kept for completeness.
#[inline]
pub fn pgdh_read() -> PhysAddr {
    PhysAddr::new(csr_read::<{ csr::PGDH }>() & PGD_BASE_MASK)
}

/// Switch the low-half page-table base (`pml4_phys` = PGD physical
/// address) and flush the TLB.
#[inline]
pub fn cr3_write(pml4_phys: PhysAddr) {
    csr_write::<{ csr::PGDL }>(pml4_phys.as_u64() & PGD_BASE_MASK);
    flush_tlb();
}

/// Alias kept for `sched.rs` compatibility.
#[inline]
pub fn switch_page_table(pml4_phys: PhysAddr) {
    cr3_write(pml4_phys);
}

/// Switch with a full TLB flush first.
#[inline]
pub fn switch_page_table_safe(pml4_phys: PhysAddr) {
    flush_tlb();
    cr3_write(pml4_phys);
}

// ============================================================================
// Fault address (x86 CR2 equivalent)
// ============================================================================

/// Read the faulting virtual address (CSR.BADV).
#[inline]
pub fn cr2_read() -> u64 {
    csr_read::<{ csr::BADV }>()
}

#[inline]
pub fn read_cr2() -> u64 {
    cr2_read()
}

// ============================================================================
// TLB maintenance
// ============================================================================

/// Invalidate the translation for one virtual address. LoongArch's
/// INVTLB supports per-VA invalidation (op 5, ASID+VA); with ASID 0 the
/// portable choice for the bring-up model is a full flush.
#[inline]
pub fn invlpg(_addr: VirtAddr) {
    flush_tlb();
}

/// Flush all TLB entries (`invtlb 0, 0, 0` — clear all).
#[inline]
pub fn flush_tlb() {
    let zero: u64 = 0;
    unsafe {
        core::arch::asm!(
            "invtlb 0, {z1}, {z2}",
            z1 = in(reg) zero,
            z2 = in(reg) zero,
            options(nostack)
        );
    }
}

/// Flush a range of pages (no range instruction; flush all).
pub fn flush_tlb_range(_start: VirtAddr, _count: usize) {
    flush_tlb();
}

// ============================================================================
// Direct-map helpers
// ============================================================================

/// Physical → virtual through the cached DMW0 window (for paging.rs).
#[inline]
pub fn paging_phys_to_virt(phys: u64) -> u64 {
    PHYS_MEMORY_VIRT | phys
}

/// Physical → uncached DMW1 MMIO window.
#[inline]
pub fn mmio_phys_to_virt(phys: u64) -> u64 {
    MMIO_VIRT | phys
}

// ============================================================================
// Raw page-table entry access
// ============================================================================

pub fn read_pte(table_virt: VirtAddr, index: usize) -> Option<u64> {
    if index >= PT_ENTRIES {
        return None;
    }
    let table = unsafe { &*(table_virt.as_u64() as *const PageTable) };
    Some(table.entries[index].0)
}

pub fn write_pte(table_virt: VirtAddr, index: usize, entry: u64) {
    if index >= PT_ENTRIES {
        return;
    }
    let table = unsafe { &mut *(table_virt.as_u64() as *mut PageTable) };
    table.entries[index].0 = entry;
    super::cpu::dbar();
}

// ============================================================================
// Exception-entry programming
// ============================================================================

/// Install the exception entry base (CSR.EENTRY). The kernel trap code
/// calls this once its vector page is ready.
pub fn set_exception_entry(base: u64) {
    csr_write::<{ csr::EENTRY }>(base);
    super::cpu::ibar();
}

// ============================================================================
// Fault-syndrome mapping (x86 PageFaultError equivalent)
// ============================================================================

/// Page-fault cause decoded from ESTAT.EXC (bits [21:16]).
///
/// LoongArch exception codes used here:
///   * 0x8  ADEM — address error (instruction fetch)
///   * 0x9  ADES — address error (store)
///   * 0xA  ADEF — address error (fetch)? see note
///   * 0xF  TLBR — TLB refill exception
///   * 0x10 TLBRI — TLB read/invalid exception
///
/// `write` = store address error; `present` = address error (the TLB
/// entry existed but the access was not allowed).
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    raw: u64,
}

impl PageFaultError {
    /// Build from the raw `ESTAT` value captured by the trap handler
    /// (the EXC code must be extracted by the caller: `(estat >> 16) & 0x3F`).
    pub fn new(raw: u64) -> Self { Self { raw } }

    /// Permission/address error — the translation existed.
    pub fn present(&self) -> bool { matches!(self.raw, 0x8 | 0x9 | 0xA) }

    /// Store address error (ADES).
    pub fn write(&self) -> bool { self.raw == 0x9 }

    /// Fault from PLV3 — the caller ORs PRMD.PPLV into bit 63.
    pub fn user(&self) -> bool { (self.raw & (1 << 63)) != 0 }

    pub fn reserved(&self) -> bool { false }
    pub fn instruction_fetch(&self) -> bool { self.raw == 0xA }
    pub fn protection_key(&self) -> bool { false }
    pub fn shadow_stack(&self) -> bool { false }
    pub fn raw(&self) -> u64 { self.raw }
}

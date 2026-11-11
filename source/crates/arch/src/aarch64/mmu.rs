//! AArch64 MMU control — TTBR/TCR/SCTLR register access and TLB
//! maintenance, exposed through the architecture-neutral names the
//! kernel uses (`cr3_read`, `invlpg`, `switch_page_table`, …).
//!
//! Naming bridge:
//!   * x86 CR3           → TTBR0_EL1 (user address-space root)
//!   * x86 CR2 (fault VA) → FAR_EL1
//!   * x86 INVLPG        → TLBI VALE1IS / VMALLE1IS
//!   * x86 PTE error code → ESR_EL1 data-abort ISS

extern crate plan9_common;

use crate::{read_sysreg, write_sysreg};
use plan9_common::types::{PhysAddr, VirtAddr};

use super::paging::{PHYS_MEMORY_VIRT, PT_ENTRIES, PageTable};

// ============================================================================
// Root-table switch (x86 CR3 equivalents)
// ============================================================================

/// Read the current user address-space root (TTBR0_EL1), masked to the
/// physical base address.
#[inline]
pub fn cr3_read() -> PhysAddr {
    let ttbr = read_sysreg!("TTBR0_EL1");
    PhysAddr::new(ttbr & 0x0000_FFFF_FFFF_F000)
}

/// Read the kernel root table (TTBR1_EL1).
#[inline]
pub fn kernel_root_table() -> PhysAddr {
    let ttbr = read_sysreg!("TTBR1_EL1");
    PhysAddr::new(ttbr & 0x0000_FFFF_FFFF_F000)
}

/// Switch the user address-space root table. `pml4_phys` is the
/// physical address of the new L0 table.
#[inline]
pub fn cr3_write(pml4_phys: PhysAddr) {
    write_sysreg!("TTBR0_EL1", pml4_phys.as_u64());
    super::cpu::dsb_sy();
    super::cpu::isb();
}

/// Alias kept for `sched.rs` compatibility: switch to the address space
/// whose root table is at `pml4_phys`.
#[inline]
pub fn switch_page_table(pml4_phys: PhysAddr) {
    cr3_write(pml4_phys);
}

/// Switch with a full TLB flush (used when address spaces are torn down).
#[inline]
pub fn switch_page_table_safe(pml4_phys: PhysAddr) {
    flush_tlb();
    cr3_write(pml4_phys);
}

// ============================================================================
// Fault address (x86 CR2 equivalent)
// ============================================================================

/// Read the faulting virtual address (FAR_EL1).
#[inline]
pub fn cr2_read() -> u64 {
    read_sysreg!("FAR_EL1")
}

#[inline]
pub fn read_cr2() -> u64 {
    cr2_read()
}

// ============================================================================
// TLB maintenance (x86 INVLPG / FLUSH equivalents)
// ============================================================================

/// Invalidate the translation for one virtual address.
#[inline]
pub fn invlpg(addr: VirtAddr) {
    let va = addr.as_u64();
    unsafe {
        // TLBI VALE1IS: invalidate by VA, EL1&0, inner shareable.
        core::arch::asm!(
            "tlbi vale1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va,
            options(nostack)
        );
    }
}

/// Flush all TLB entries for the current address space.
#[inline]
pub fn flush_tlb() {
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// Flush a range of `count` pages starting at `start`.
pub fn flush_tlb_range(start: VirtAddr, count: usize) {
    // AArch64 has no range invalidation pre-ARMv8.4; flushing everything
    // is the portable and correct fallback.
    let _ = (start, count);
    flush_tlb();
}

// ============================================================================
// Direct-map helpers shared by the paging module
// ============================================================================

/// Physical → virtual translation through the TTBR1 direct-map window.
/// Identical to `paging::phys_to_virt`; kept here so `paging.rs` can
/// reach it via `super::`.
#[inline]
pub fn paging_phys_to_virt(phys: u64) -> u64 {
    PHYS_MEMORY_VIRT + phys
}

// ============================================================================
// Raw page-table entry access through the direct map
// ============================================================================

/// Read the raw descriptor at `table_virt[index]`.
pub fn read_pte(table_virt: VirtAddr, index: usize) -> Option<u64> {
    if index >= PT_ENTRIES {
        return None;
    }
    let table = unsafe { &*(table_virt.as_u64() as *const PageTable) };
    Some(table.entries[index].0)
}

/// Write the raw descriptor at `table_virt[index]`.
pub fn write_pte(table_virt: VirtAddr, index: usize, entry: u64) {
    if index >= PT_ENTRIES {
        return;
    }
    let table = unsafe { &mut *(table_virt.as_u64() as *mut PageTable) };
    table.entries[index].0 = entry;
    super::cpu::dsb_sy();
}

// ============================================================================
// Fault-syndrome mapping (x86 PageFaultError equivalent)
// ============================================================================

/// Data-abort syndrome (ESR_EL1.ISS for Data Abort, EC == 0b1001xx).
///
/// Field names mirror the x86 `PageFaultError` so `fault.rs` compiles
/// unchanged; the semantics are mapped from the ARM ESR encoding:
///   * `write`     — ESR bit 6 (WnR)
///   * `user`      — ESR bit 0 (FnT: fault from lower Exception level)
///   * `present`   — status code == permission fault (TLB entry existed)
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    raw: u64,
}

impl PageFaultError {
    /// Build from the raw ESR_EL1 value captured by the trap handler.
    pub fn new(raw: u64) -> Self { Self { raw } }

    /// Permission fault (page was present but access was not allowed).
    pub fn present(&self) -> bool { (self.raw & 0x3C) == 0x0C || (self.raw & 0x3C) == 0x10 }

    /// Write fault — ESR.WnR (bit 6).
    pub fn write(&self) -> bool { (self.raw & (1 << 6)) != 0 }

    /// Fault came from EL0 — ESR.FnT (bit 0) set for "from lower EL".
    pub fn user(&self) -> bool { (self.raw & 1) != 0 }

    /// Reserved/unsupported access — translation fault with a reserved
    /// level encoding.
    pub fn reserved(&self) -> bool { (self.raw & 0x3C) == 0x14 }

    /// Instruction fetch — ESR.EA? On ARM, i-cache aborts arrive as
    /// instruction aborts (EC 0b100001); report false for data aborts.
    pub fn instruction_fetch(&self) -> bool { false }

    /// Protection-key fault — no ARM equivalent.
    pub fn protection_key(&self) -> bool { false }

    /// Shadow-stack fault — no ARM equivalent.
    pub fn shadow_stack(&self) -> bool { false }

    /// Raw ESR value.
    pub fn raw(&self) -> u64 { self.raw }
}

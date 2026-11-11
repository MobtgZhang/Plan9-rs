//! RISC-V MMU control — `satp` access and `sfence.vma`, exposed through
//! the architecture-neutral names the kernel uses.
//!
//! Naming bridge:
//!   * x86 CR3           → satp.PPN (Sv39 root page table)
//!   * x86 CR2 (fault VA) → sbadaddr / stval CSR
//!   * x86 INVLPG        → sfence.vma (VMA, asid)
//!   * x86 PTE error code → scause / scause high bits

extern crate plan9_common;

use plan9_common::types::{PhysAddr, VirtAddr};

use super::paging::{PHYS_MEMORY_VIRT, PT_ENTRIES, PageTable};

// ============================================================================
// Root-table switch (x86 CR3 equivalents)
// ============================================================================

/// satp mode for Sv39.
const SATP_MODE_SV39: u64 = 8;

/// Build the raw `satp` value for a root table physical address.
#[inline]
pub fn satp_for(root_phys: u64) -> u64 {
    (SATP_MODE_SV39 << 60) | (root_phys >> 12)
}

/// Read the current user address-space root (satp PPN).
#[inline]
pub fn cr3_read() -> PhysAddr {
    let satp: u64;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options()) };
    PhysAddr::new((satp & 0x0000_FFFF_FFFF_FFF) << 12)
}

/// Read the active MMU mode (0 = bare, 8 = Sv39, 9 = Sv48).
#[inline]
pub fn mmu_mode() -> u64 {
    let satp: u64;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options()) };
    satp >> 60
}

/// Switch the address-space root table (satp + sfence.vma).
#[inline]
pub fn cr3_write(pml4_phys: PhysAddr) {
    let satp = satp_for(pml4_phys.as_u64());
    unsafe { core::arch::asm!("csrw satp, {}", in(reg) satp, options()) };
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

/// Read the faulting virtual address (`stval` CSR).
#[inline]
pub fn cr2_read() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, stval", out(reg) v, options()) };
    v
}

#[inline]
pub fn read_cr2() -> u64 {
    cr2_read()
}

// ============================================================================
// TLB maintenance
// ============================================================================

/// Invalidate the translation for one virtual address.
#[inline]
pub fn invlpg(addr: VirtAddr) {
    let va = addr.as_u64();
    unsafe {
        core::arch::asm!(
            "sfence.vma zero, {va}",
            va = in(reg) va,
            options(nostack)
        );
    }
}

/// Flush all TLB entries.
#[inline]
pub fn flush_tlb() {
    unsafe {
        core::arch::asm!("sfence.vma zero, zero", options(nostack));
    }
}

/// Flush a range of pages (RISC-V has no range instruction; flush all).
pub fn flush_tlb_range(_start: VirtAddr, _count: usize) {
    flush_tlb();
}

// ============================================================================
// Direct-map helpers
// ============================================================================

/// Physical → virtual through the direct map (identical to
/// `paging::phys_to_virt`; kept for `super::` access from paging.rs).
#[inline]
pub fn paging_phys_to_virt(phys: u64) -> u64 {
    PHYS_MEMORY_VIRT + phys
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
    super::cpu::fence_rw();
}

// ============================================================================
// Fault-syndrome mapping (x86 PageFaultError equivalent)
// ============================================================================

/// Page-fault cause (`scause` for load/store/instruction page faults).
///
/// RISC-V `scause` values:
///   13 = load page fault, 15 = store page fault, 12 = instruction page
///   fault; access faults (5/7/1) are permission faults.
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    raw: u64,
}

impl PageFaultError {
    /// Build from the raw `scause` captured by the trap handler.
    pub fn new(raw: u64) -> Self { Self { raw } }

    /// Permission fault (page mapped but access not allowed): access
    /// fault causes (instruction 1, load 5, store 7).
    pub fn present(&self) -> bool { matches!(self.raw, 1 | 5 | 7) }

    /// Store page fault (scause 15) — also store access fault (7).
    pub fn write(&self) -> bool { self.raw == 15 || self.raw == 7 }

    /// Fault from user mode — determined by the trap handler from
    /// `sstatus.SPP`; the raw value carries it in bit 63 as a flag.
    pub fn user(&self) -> bool { (self.raw & (1 << 63)) != 0 }

    pub fn reserved(&self) -> bool { false }
    pub fn instruction_fetch(&self) -> bool { self.raw == 12 || self.raw == 1 }
    pub fn protection_key(&self) -> bool { false }
    pub fn shadow_stack(&self) -> bool { false }
    pub fn raw(&self) -> u64 { self.raw }
}

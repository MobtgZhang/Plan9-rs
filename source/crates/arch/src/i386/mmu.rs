//! i386 MMU control stubs (2-level paging; CR3/CR2 based).
#![allow(dead_code)]

extern crate plan9_common;

use plan9_common::types::{PhysAddr, VirtAddr};

use super::cpu;

/// Read the page-table base (CR3).
#[inline]
pub fn cr3_read() -> PhysAddr {
    PhysAddr::new(cpu::cr3_read() as u64 & 0xFFFF_F000 as u64)
}

/// Switch the page-table base (CR3) — implicitly flushes the TLB.
#[inline]
pub unsafe fn cr3_write(pa: PhysAddr) {
    cpu::cr3_write((pa.as_u64() & 0xFFFF_F000) as u32);
}

/// Alias kept for `sched.rs` compatibility.
#[inline]
pub unsafe fn switch_page_table(pa: PhysAddr) {
    cr3_write(pa);
}

/// Invalidate one TLB entry (INVLPG).
#[inline]
pub unsafe fn invlpg(_addr: VirtAddr) {
    // i386 has INVLPG; a full flush via CR3 rewrite is the portable stub.
    let cur = cpu::cr3_read();
    cpu::cr3_write(cur);
}

/// Flush the whole TLB (CR3 rewrite).
#[inline]
pub unsafe fn flush_tlb() {
    let cur = cpu::cr3_read();
    cpu::cr3_write(cur);
}

/// Read the faulting virtual address (CR2).
#[inline]
pub fn cr2_read() -> u64 {
    let v: u32;
    unsafe { core::arch::asm!("mov {v}, cr2", v = out(reg) v, options()) };
    v as u64
}

#[inline]
pub fn read_cr2() -> u64 {
    cr2_read()
}

/// Physical → virtual (identity on i386).
#[inline]
pub fn paging_phys_to_virt(phys: u64) -> u64 {
    phys
}

/// Physical → MMIO virtual (identity on i386).
#[inline]
pub fn mmio_phys_to_virt(phys: u64) -> u64 {
    phys
}

/// Page-fault error decode (i386 error word).
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    raw: u64,
}

impl PageFaultError {
    pub fn new(raw: u64) -> Self { Self { raw } }
    pub fn present(&self) -> bool { (self.raw & 1) != 0 }
    pub fn write(&self) -> bool { (self.raw & 2) != 0 }
    pub fn user(&self) -> bool { (self.raw & 4) != 0 }
    pub fn reserved(&self) -> bool { (self.raw & 8) != 0 }
    pub fn instruction_fetch(&self) -> bool { (self.raw & 16) != 0 }
    pub fn protection_key(&self) -> bool { false }
    pub fn shadow_stack(&self) -> bool { false }
    pub fn raw(&self) -> u64 { self.raw }
}

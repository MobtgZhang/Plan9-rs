//! i386 (32-bit x86) module root.
//!
//! i386 is not one of the four supported targets (x86-64, aarch64,
//! riscv64, loongarch64); these modules exist so the `hal` facade's
//! `#[cfg(target_arch = "x86")]` arms resolve if a 32-bit x86 build is
//! ever attempted. They are compiled only under `target_arch = "x86"`.

#![allow(dead_code)]

pub mod context;
pub mod cpu;
pub mod mmu;
pub mod paging;
pub mod switch_to_user;
pub mod timer;
pub mod uart;

use crate::arch_trait::{Arch, ContextArch, InterruptControl, TimerArch};

pub struct I386Arch;

impl InterruptControl for I386Arch {
    unsafe fn disable_interrupts(&self) { cpu::cli() }
    unsafe fn enable_interrupts(&self) { cpu::sti() }
    fn are_enabled(&self) -> bool { cpu::interrupts_enabled() }
}

impl TimerArch for I386Arch {
    fn init_timer(&self) {}
    fn current_tick(&self) -> u64 { 0 }
}

impl ContextArch for I386Arch {
    unsafe fn switch_to_user(&self, _pml4_phys: u64) -> ! {
        switch_to_user::switch_to_user_trampoline(_pml4_phys, 0)
    }
}

impl Arch for I386Arch {
    fn name(&self) -> &'static str { "i386" }
    fn cpu_id(&self) -> usize { 0 }
}

/// Early init stub.
pub fn early_init() {}

/// Paging init stub (2-level tables brought up by boot code).
pub fn paging_init() {}

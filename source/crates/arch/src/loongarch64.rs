//! Minimal LoongArch64 stub for `Arch` trait.

use crate::arch_trait::{Arch, ContextArch, InterruptControl, TimerArch};

pub struct LoongArch64Arch;

impl InterruptControl for LoongArch64Arch {
    unsafe fn disable_interrupts(&self) { core::hint::unreachable_unchecked() }
    unsafe fn enable_interrupts(&self) { core::hint::unreachable_unchecked() }
    fn are_enabled(&self) -> bool { false }
}

impl TimerArch for LoongArch64Arch {
    fn init_timer(&self) {}
    fn current_tick(&self) -> u64 { 0 }
}

impl ContextArch for LoongArch64Arch {
    unsafe fn switch_to_user(&self, _pml4_phys: u64) -> ! {
        core::hint::unreachable_unchecked()
    }
}

impl Arch for LoongArch64Arch {
    fn name(&self) -> &'static str { "loongarch64" }
    fn cpu_id(&self) -> usize { 0 }
}
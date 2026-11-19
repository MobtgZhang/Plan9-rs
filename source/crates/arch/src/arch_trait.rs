//! `Arch` trait and per-architecture implementations.

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::boxed::Box;

pub trait InterruptControl {
    unsafe fn disable_interrupts(&self);
    unsafe fn enable_interrupts(&self);
    fn are_enabled(&self) -> bool;
}

pub trait TimerArch {
    fn init_timer(&self);
    fn current_tick(&self) -> u64;
}

pub trait ContextArch {
    unsafe fn switch_to_user(&self, pml4_phys: u64) -> !;
}

pub trait Arch: InterruptControl + TimerArch + ContextArch {
    fn name(&self) -> &'static str;
    fn cpu_id(&self) -> usize { 0 }
}

static ACTIVE_ARCH: AtomicUsize = AtomicUsize::new(0);

const ARCH_SLOTS: usize = 4;
static mut ARCH_TABLE: [Option<Box<dyn Arch>>; ARCH_SLOTS] = [None, None, None, None];

/// # Safety
/// Each slot may only be written once, during single-threaded boot.
pub unsafe fn set_arch(idx: usize, arch: Box<dyn Arch>) {
    if idx >= ARCH_SLOTS {
        panic!("Arch::set_arch: idx out of range");
    }
    ARCH_TABLE[idx] = Some(arch);
    ACTIVE_ARCH.store(idx, Ordering::Release);
}

pub fn active() -> &'static dyn Arch {
    let idx = ACTIVE_ARCH.load(Ordering::Acquire);
    let opt = unsafe { &ARCH_TABLE[idx] };
    match opt {
        Some(b) => b.as_ref(),
        None => panic!("Arch::active: no architecture installed"),
    }
}

pub mod other {
    use super::{Arch, ContextArch, InterruptControl, TimerArch};

    pub struct OtherArch;

    impl InterruptControl for OtherArch {
        unsafe fn disable_interrupts(&self) { core::hint::unreachable_unchecked() }
        unsafe fn enable_interrupts(&self) { core::hint::unreachable_unchecked() }
        fn are_enabled(&self) -> bool { false }
    }

    impl TimerArch for OtherArch {
        fn init_timer(&self) {}
        fn current_tick(&self) -> u64 { 0 }
    }

    impl ContextArch for OtherArch {
        unsafe fn switch_to_user(&self, _pml4_phys: u64) -> ! {
            core::hint::unreachable_unchecked()
        }
    }

    impl Arch for OtherArch {
        fn name(&self) -> &'static str { "other" }
    }
}

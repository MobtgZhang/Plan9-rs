//! RISC-V timer driver.
//!
//! The kernel runs in S-mode on top of SBI firmware. The `time` CSR
//! (`rdtime`) reads the ACLINT/CLINT mtime counter, and the legacy SBI
//! `set_timer` call programs the one-shot supervisor timer interrupt.

use core::sync::atomic::{AtomicU64, Ordering};

/// Tick frequency the kernel scheduler expects (see `sched::HZ`).
pub const HZ: u64 = 100;

/// Timer frequency (timebase), discovered from the device tree at boot
/// or defaulted to QEMU virt's 10 MHz.
static TIMEBASE: AtomicU64 = AtomicU64::new(0);

/// Default timebase used until the device tree is parsed.
const DEFAULT_TIMEBASE: u64 = 10_000_000;

/// Set the timer timebase (Hz) discovered from the device tree.
pub fn set_timebase(hz: u64) {
    if hz != 0 {
        TIMEBASE.store(hz, Ordering::Relaxed);
    }
}

/// Effective timebase frequency.
#[inline(always)]
pub fn frequency() -> u64 {
    let f = TIMEBASE.load(Ordering::Relaxed);
    if f != 0 { f } else { DEFAULT_TIMEBASE }
}

/// Initialise the timer: install the default timebase and enable the
/// supervisor timer interrupt source.
pub fn init_timer() {
    TIMEBASE.store(DEFAULT_TIMEBASE, Ordering::Relaxed);
    unsafe {
        super::cpu::enable_timer_interrupts();
    }
}

/// Read the raw `time` counter.
#[inline(always)]
pub fn counter() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options()) };
    t
}

/// Current kernel tick (monotonic, scaled to `HZ`).
#[inline(always)]
pub fn current_tick() -> u64 {
    let f = frequency();
    counter() / (f / HZ)
}

/// Milliseconds since boot.
#[inline(always)]
pub fn ms_since_boot() -> u64 {
    let f = frequency();
    counter() / (f / 1000)
}

/// Program a one-shot deadline `ticks` scheduler ticks from now.
pub fn set_oneshot(ticks: u64) {
    let f = frequency();
    let delta = (ticks * f / HZ).max(1);
    let err = super::cpu::sbi_set_timer(counter() + delta);
    if err != 0 {
        // Legacy SBI absent — fall back to polling (kernel's timer wheel
        // polls `current_tick` anyway).
    }
}

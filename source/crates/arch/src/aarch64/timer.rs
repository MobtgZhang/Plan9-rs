//! AArch64 generic timer driver.
//!
//! The ARMv8 generic timer is a single always-running counter
//! (`CNTFRQ_EL0` gives its frequency, `CNTPCT_EL0` the physical count)
//! with one per-CPU comparator (`CNTP_CTL_EL0` / `CNTP_TVAL_EL0`).
//!
//! Plan 9's timer wheel only needs a monotonically increasing tick, so
//! this driver simply exposes the physical count scaled to the tick
//! rate, plus one-shot deadline support for the scheduler.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{read_sysreg, write_sysreg};

/// Tick frequency the kernel scheduler expects (see `sched::HZ`).
pub const HZ: u64 = 100;

/// Cached counter frequency read once at init.
static FRQ: AtomicU64 = AtomicU64::new(0);

/// Read the timer counter frequency (Hz). Falls back to 24 MHz
/// (QEMU virt's default CNTFRQ) before init.
#[inline(always)]
pub fn frequency() -> u64 {
    let f = FRQ.load(Ordering::Relaxed);
    if f != 0 {
        f
    } else {
        read_sysreg!("CNTFRQ_EL0")
    }
}

/// Initialise the generic timer: read the frequency and make sure the
/// physical comparator is not firing (we poll the counter instead).
pub fn init_timer() {
    let f = read_sysreg!("CNTFRQ_EL0");
    FRQ.store(f, Ordering::Relaxed);
    if f == 0 {
        // QEMU always provides a nonzero CNTFRQ, but be defensive.
        FRQ.store(24_000_000, Ordering::Relaxed);
    }
    // Disable the comparator interrupt; the kernel polls `current_tick`.
    unsafe {
        // CNTP_CTL: bit0 Enable=0, bit1 IMask=1 (masked)
        write_sysreg!("CNTP_CTL_EL0", 0x2u64);
    }
    super::cpu::isb();
}

/// Read the raw 64-bit physical counter.
#[inline(always)]
pub fn counter() -> u64 {
    read_sysreg!("CNTPCT_EL0")
}

/// Current kernel tick (monotonic, scaled to `HZ`).
#[inline(always)]
pub fn current_tick() -> u64 {
    let f = frequency();
    if f == 0 {
        return 0;
    }
    counter() / (f / HZ)
}

/// Milliseconds since boot.
#[inline(always)]
pub fn ms_since_boot() -> u64 {
    let f = frequency();
    if f == 0 {
        return 0;
    }
    counter() / (f / 1000)
}

/// Program a one-shot deadline `ticks` scheduler ticks from now.
/// The comparator interrupt will fire when it expires (if unmasked).
pub fn set_oneshot(ticks: u64) {
    let f = frequency();
    let delta = (ticks * f / HZ).max(1);
    unsafe {
        // CNTP_TVAL: countdown ticks from now.
        write_sysreg!("CNTP_TVAL_EL0", delta);
        // Enable + unmask: bit0 Enable=1, bit1 IMask=0.
        write_sysreg!("CNTP_CTL_EL0", 0x1u64);
    }
    super::cpu::isb();
}

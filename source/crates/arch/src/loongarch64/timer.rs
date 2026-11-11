//! LoongArch64 constant-rate timer driver.
//!
//! The LoongArch "constant timer" is a 64-bit always-running counter
//! read with `rdtime.d`; its frequency comes from CPUCFG 0x4/0x5
//! (100 MHz on QEMU's virt machine). One-shot deadlines are programmed
//! through the CSR.TCFG comparator (EN=bit 0, PERIODIC=bit 1, count
//! value in bits [47:2]), whose interrupt is enabled in ECFG.LIE bit 11
//! and cleared via CSR.TICLR bit 0.

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::{csr_read, csr_write, csr, timer_frequency};

/// Tick frequency the kernel scheduler expects (see `sched::HZ`).
pub const HZ: u64 = 100;

/// Cached timer frequency read once at init.
static FREQ: AtomicU64 = AtomicU64::new(0);

/// Effective timer frequency (Hz); defaults to QEMU's 100 MHz.
#[inline(always)]
pub fn frequency() -> u64 {
    let f = FREQ.load(Ordering::Relaxed);
    if f != 0 {
        f
    } else {
        100_000_000
    }
}

/// Read the raw 64-bit constant counter (`rdtime.d`).
#[inline(always)]
pub fn counter() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "rdtime.d {v}, $r0",
            v = out(reg) v,
            options()
        );
    }
    v
}

/// Initialise the timer: discover the frequency, enable the timer
/// interrupt source in ECFG.LIE (bit 11), and leave the comparator
/// stopped (the kernel polls `current_tick` unless a deadline is set).
pub fn init_timer() {
    let f = timer_frequency();
    if f == 0 {
        FREQ.store(100_000_000, Ordering::Relaxed);
    } else {
        FREQ.store(f, Ordering::Relaxed);
    }

    // ECFG.LIE: enable the timer local interrupt line (bit 11).
    let ecfg = csr_read::<{ csr::ECFG }>();
    let ecfg = (ecfg & !(0x7FFFu64)) | (1 << 11);
    csr_write::<{ csr::ECFG }>(ecfg);

    // Comparator stopped (TCFG.EN = 0).
    csr_write::<{ csr::TCFG }>(0u64);
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
/// The comparator interrupt will fire when it expires (if unmasked).
pub fn set_oneshot(ticks: u64) {
    let f = frequency();
    let delta = (ticks * f / HZ).max(1);
    // TCFG: EN (bit 0) | one-shot (PERIODIC=0) | count in bits [47:2].
    let cfg = (delta & 0x3FFF_FFFF_FFFF) << 2 | 1;
    csr_write::<{ csr::TCFG }>(cfg);
    super::cpu::dbar();
}

/// Clear a pending timer interrupt (write TICLR.TI = 1).
pub fn clear_interrupt() {
    csr_write::<{ csr::TICLR }>(1);
}

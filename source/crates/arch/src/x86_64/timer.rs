//! x86_64 timer driver stub.
//!
//! The x86_64 kernel reads wall-clock time from the CMOS RTC directly
//! (see `kernel/src/rtc.rs`), so this module only exists to satisfy the
//! `plan9_arch::hal::timer` facade.  `ms_since_boot()` returns 0 until a
//! real timer source is wired up.

use core::sync::atomic::{AtomicU64, Ordering};

/// Tick frequency the kernel scheduler expects (see `sched::HZ`).
pub const HZ: u64 = 100;

static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init_timer() {}

pub fn frequency() -> u64 { 1_000_000 }

pub fn counter() -> u64 { TICKS.load(Ordering::Relaxed) }

pub fn current_tick() -> u64 { 0 }

pub fn ms_since_boot() -> u64 { 0 }

pub fn set_oneshot(_ticks: u64) {}

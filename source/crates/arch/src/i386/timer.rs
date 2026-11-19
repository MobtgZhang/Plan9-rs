//! i386 timer driver stub.
//!
//! i386 is not one of the four supported targets; this stub exists so the
//! `plan9_arch::hal::timer` facade compiles if a 32-bit x86 build is
//! ever attempted.

use core::sync::atomic::{AtomicU64, Ordering};

pub const HZ: u64 = 100;

static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init_timer() {}
pub fn frequency() -> u64 { 1_000_000 }
pub fn counter() -> u64 { TICKS.load(Ordering::Relaxed) }
pub fn current_tick() -> u64 { 0 }
pub fn ms_since_boot() -> u64 { 0 }
pub fn set_oneshot(_ticks: u64) {}

//! x86_64 monotonic clock using the TSC calibrated against PIT channel 2.

use core::sync::atomic::{AtomicU64, Ordering};

/// Tick frequency the kernel scheduler expects (see `sched::HZ`).
pub const HZ: u64 = 100;

static FREQUENCY: AtomicU64 = AtomicU64::new(0);
static START: AtomicU64 = AtomicU64::new(0);

pub fn init_timer() {
    use crate::hal::{inb, outb};
    const PIT_HZ: u64 = 1_193_182;
    const COUNT: u16 = 11_932;
    let port = inb(0x61);
    outb(0x61, port & !3);
    outb(0x43, 0xb0);
    outb(0x42, COUNT as u8);
    outb(0x42, (COUNT >> 8) as u8);
    let start = counter();
    outb(0x61, (port & !2) | 1);
    let mut measured = None;
    for _ in 0..2_000_000 {
        if inb(0x61) & 0x20 != 0 {
            measured = Some(counter().wrapping_sub(start));
            break;
        }
    }
    outb(0x61, port);
    START.store(start, Ordering::Relaxed);
    FREQUENCY.store(
        measured
            .map_or(1_000_000_000, |elapsed| {
                elapsed.saturating_mul(PIT_HZ) / u64::from(COUNT)
            })
            .max(1000),
        Ordering::Release,
    );
}

pub fn frequency() -> u64 {
    FREQUENCY.load(Ordering::Acquire)
}

pub fn counter() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn current_tick() -> u64 {
    ms_since_boot() / (1000 / HZ)
}

pub fn ms_since_boot() -> u64 {
    let frequency = frequency();
    if frequency == 0 {
        return 0;
    }
    counter().saturating_sub(START.load(Ordering::Relaxed)) / (frequency / 1000)
}

pub fn set_oneshot(_ticks: u64) {}

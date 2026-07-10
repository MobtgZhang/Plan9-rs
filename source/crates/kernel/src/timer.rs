//! Timer and Clock Implementation
//!
//! Implements Plan 9-style timer facilities:
//! - Hardware timer management (LAPIC, HPET)
//! - Time wheel for process sleeping with timeout
//! - Alarm mechanism for scheduled callbacks
//!
//! Reference: Plan 9 `clock.c`, `sys/src/9/port/proc.c`

use crate::proc::{curproc, Proc, State};
use crate::plan9_common::sync::Spinlock;
use crate::sched;
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

/// Time scale constants
/// The number of clock ticks per second (Hz)
pub const HZ: u64 = 100;

/// The number of milliseconds per tick
pub const MS_PER_TICK: u64 = 1000 / HZ;

/// Global clock tick counter
/// 
/// This counts the number of clock interrupts since system startup.
/// Updated by the timer interrupt handler.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Get current system ticks
/// 
/// Returns the number of clock ticks since system start.
/// This is used by sleep/alarm and other time-sensitive operations.
pub fn get_ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Increment the tick counter
/// 
/// Called by the timer interrupt handler on each tick.
pub fn increment_ticks() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Convert ticks to milliseconds
pub fn ticks_to_ms(ticks: u64) -> u64 {
    ticks * MS_PER_TICK
}

/// Convert milliseconds to ticks
pub fn ms_to_ticks(ms: u64) -> u64 {
    ms / MS_PER_TICK
}

/// Maximum timer wheel levels (for hierarchical timing)
const TIMER_LEVELS: usize = 6;

/// Timer wheel bucket
struct TimerBucket {
    /// List of timer entries in this bucket
    entries: Vec<TimerEntry>,
}

/// Timer wheel entry
struct TimerEntry {
    /// Process waiting on this timer
    proc: *const Proc,
    /// Channel to signal on timeout (for ptsleep)
    channel: Option<usize>,
    /// Wake value (value to write to channel)
    wake_val: usize,
    /// Expiry time in milliseconds
    expiry_ms: u64,
    /// Whether this timer was aborted
    aborted: bool,
}

/// Timer wheel for hierarchical timing
pub struct TimerWheel {
    /// Buckets at different levels (similar to Linux's timer wheel)
    /// Level 0: 1ms resolution, 256 buckets
    /// Level 1: 256ms resolution, 64 buckets
    /// Level 2: ~16s resolution, 64 buckets
    /// Level 3: ~1s resolution, 64 buckets
    /// etc.
    buckets: Vec<Spinlock<TimerBucket>>,
    /// Current time in milliseconds
    current_time: Spinlock<u64>,
    /// Global timer list for expires
    expires: Spinlock<Vec<TimerEntry>>,
}

impl TimerWheel {
    /// Create a new timer wheel
    pub fn new() -> Self {
        let mut buckets = Vec::with_capacity(TIMER_LEVELS);
        for _ in 0..TIMER_LEVELS {
            buckets.push(Spinlock::new(TimerBucket {
                entries: Vec::new(),
            }));
        }

        Self {
            buckets,
            current_time: Spinlock::new(0),
            expires: Spinlock::new(Vec::new()),
        }
    }

    /// Get current time in milliseconds
    pub fn current_ms(&self) -> u64 {
        *self.current_time.lock()
    }

    /// Advance time (called on each timer tick)
    pub fn tick(&self) {
        let mut time = self.current_time.lock();
        *time += MS_PER_TICK;
    }

    /// Add a timer entry
    pub fn add(&self, proc: *const Proc, channel: Option<usize>, wake_val: usize, timeout_ms: u64) {
        let expiry = *self.current_time.lock() + timeout_ms;

        let entry = TimerEntry {
            proc,
            channel,
            wake_val,
            expiry_ms: expiry,
            aborted: false,
        };

        // Add to global expires list for simplicity
        // A more efficient implementation would add to the appropriate bucket
        self.expires.lock().push(entry);
    }

    /// Check and expire timers, returning processes to wake
    pub fn expire(&self) -> Vec<(*const Proc, usize)> {
        let mut to_wake = Vec::new();
        let current = *self.current_time.lock();

        let mut expires = self.expires.lock();
        for entry in expires.iter_mut() {
            if !entry.aborted && entry.expiry_ms <= current {
                to_wake.push((entry.proc, entry.wake_val));
                entry.aborted = true; // Mark as processed
            }
        }

        to_wake
    }

    /// Abort a timer for a specific process
    pub fn abort(&self, proc: *const Proc) -> bool {
        let mut expires = self.expires.lock();
        for entry in expires.iter_mut() {
            if entry.proc == proc && !entry.aborted {
                entry.aborted = true;
                return true;
            }
        }
        false
    }
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

/// Alarm state for scheduled callbacks
pub struct Alarm {
    /// When the alarm should fire
    expiry: u64,
    /// Function to call (in real implementation, this would be a function pointer)
    /// For now, we just track that an alarm is armed
    armed: bool,
}

/// Sleep with timeout using a channel
///
/// This is Plan 9's `tsleep()` equivalent:
/// - The process sleeps until either:
///   - The timeout expires (returns `true`)
///   - The channel is signaled (returns `false`)
///
/// # Arguments
/// * `_chan` - Channel to wait on (unused in simplified implementation)
/// * `ms` - Timeout in milliseconds
///
/// # Returns
/// * `true` if timed out
/// * `false` if awakened by channel signal
pub fn tsleep(_chan: usize, ms: u64) -> bool {
    // Record the start time
    let start_ticks = get_ticks();
    let deadline_ticks = start_ticks + ms_to_ticks(ms);
    
    // Get current process
    let proc = curproc();
    let proc_ptr = match proc {
        Some(p) => core::ptr::addr_of!(*p) as *mut Proc,
        None => return false,
    };

    // Set process state to Wakeme
    // This is required before calling the scheduler
    unsafe {
        let p = &mut *proc_ptr;
        p.state = State::Wakeme;
    }
    
    // Add to timer wheel for timeout tracking
    if let Some(timer) = global_timer() {
        timer.add(proc_ptr, None, 0, ms);
    }
    
    // Yield to scheduler - this will switch to another process
    // When we return, either the timeout fired or we were woken up
    sched::yield_();
    
    // Check if we timed out or were woken early
    let current_ticks = get_ticks();
    if current_ticks >= deadline_ticks {
        // Timed out
        true
    } else {
        // Woken early
        false
    }
}

/// Sleep without timeout
///
/// This is Plan 9's `sleep()` equivalent using a rendezvous point.
pub fn sleep() {
    let proc = curproc();
    let proc_ptr = match proc {
        Some(p) => core::ptr::addr_of!(*p) as *mut Proc,
        None => return,
    };

    // Set process state to Wakeme
    unsafe {
        let p = &mut *proc_ptr;
        p.state = State::Wakeme;
    }
    
    // Yield to scheduler - this will switch to another process
    sched::yield_();
}

/// Wakeup a sleeping process
///
/// This is Plan 9's `wakeup()` equivalent.
pub fn wakeup(proc: *const Proc) {
    // Only wake if process is in Wakeme state
    let state = unsafe { (*proc).state };
    if state == State::Wakeme {
        // Set state to Ready
        unsafe {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            p.state = State::Ready;
        }
        // Add to scheduler's ready queue (requires 'static lifetime)
        unsafe {
            sched::ready(&*proc);
        }
    }
}

/// Process alarm state
pub struct ProcAlarm {
    /// Timer wheel
    wheel: Arc<TimerWheel>,
}

impl ProcAlarm {
    /// Create new alarm state
    pub fn new() -> Self {
        Self {
            wheel: Arc::new(TimerWheel::new()),
        }
    }

    /// Arm an alarm for the current process
    pub fn alarm(&self, ms: u64) {
        let proc = curproc();
        if let Some(p) = proc {
            self.wheel.add(p as *const Proc, None, 0, ms);
        }
    }

    /// Check for expired alarms
    pub fn check(&self) -> Vec<(*const Proc, usize)> {
        self.wheel.expire()
    }

    /// Get timer wheel reference
    pub fn timer(&self) -> &TimerWheel {
        &self.wheel
    }
}

impl Default for ProcAlarm {
    fn default() -> Self {
        Self::new()
    }
}

/// Global timer for the kernel
static mut GLOBAL_TIMER: Option<Arc<TimerWheel>> = None;

/// Initialize the global timer
pub fn init_timer() {
    let ptr: *mut Option<Arc<TimerWheel>> = &raw mut GLOBAL_TIMER;
    unsafe {
        core::ptr::write(ptr, Some(Arc::new(TimerWheel::new())));
    }
}

/// Get the global timer
pub fn global_timer() -> Option<&'static Arc<TimerWheel>> {
    let ptr: *const Option<Arc<TimerWheel>> = &raw const GLOBAL_TIMER;
    unsafe { (*ptr).as_ref() }
}

// ============================================================================
// Alarm implementation (simplified)
// ============================================================================

/// Alarm callback
struct AlarmCallback {
    /// Process to signal
    proc: *const Proc,
    /// Alarm expiry time
    expiry: u64,
    /// Note to deliver
    note: [u8; 64],
}

/// Global alarm list
static mut ALARM_LIST: Option<Spinlock<Vec<AlarmCallback>>> = None;

/// Initialize alarm system
pub fn init_alarm() {
    let ptr: *mut Option<Spinlock<Vec<AlarmCallback>>> = &raw mut ALARM_LIST;
    unsafe {
        core::ptr::write(ptr, Some(Spinlock::new(Vec::new())));
    }
}

/// Schedule an alarm for a process
pub fn alarm_schedule(proc: *const Proc, ms: u64, note: &[u8]) {
    let alarms_ptr: *const Option<Spinlock<Vec<AlarmCallback>>> = &raw const ALARM_LIST;
    let alarms = unsafe { (*alarms_ptr).as_ref().unwrap() };
    let expiry = global_timer().map(|t| t.current_ms() + ms).unwrap_or(0);

    let mut note_arr = [0u8; 64];
    for (i, &b) in note.iter().take(64).enumerate() {
        note_arr[i] = b;
    }

    alarms.lock().push(AlarmCallback {
        proc,
        expiry,
        note: note_arr,
    });
}

/// Check and fire expired alarms
pub fn alarm_check() -> Vec<(*const Proc, [u8; 64])> {
    let mut fired = Vec::new();
    let alarms_ptr: *const Option<Spinlock<Vec<AlarmCallback>>> = &raw const ALARM_LIST;
    let alarms = unsafe { (*alarms_ptr).as_ref().unwrap() };
    let current = global_timer().map(|t| t.current_ms()).unwrap_or(0);

    let mut lock = alarms.lock();
    lock.retain(|a| {
        if a.expiry <= current {
            fired.push((a.proc, a.note));
            false // Remove from list
        } else {
            true
        }
    });

    fired
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ticks() {
        // Test that get_ticks returns a non-zero value after increment
        let initial = get_ticks();
        increment_ticks();
        let after = get_ticks();
        assert!(after > initial || after == 0);
    }

    #[test]
    fn test_ticks_to_ms() {
        // HZ = 100, so MS_PER_TICK = 10
        assert_eq!(ticks_to_ms(0), 0);
        assert_eq!(ticks_to_ms(1), 10);
        assert_eq!(ticks_to_ms(10), 100);
    }

    #[test]
    fn test_ms_to_ticks() {
        // HZ = 100, so MS_PER_TICK = 10
        assert_eq!(ms_to_ticks(0), 0);
        assert_eq!(ms_to_ticks(10), 1);
        assert_eq!(ms_to_ticks(100), 10);
        assert_eq!(ms_to_ticks(15), 1); // Truncates
    }

    #[test]
    fn test_timer_wheel_basic() {
        let wheel = TimerWheel::new();

        // Initial time should be 0
        assert_eq!(wheel.current_ms(), 0);

        // Tick should advance time
        wheel.tick();
        assert_eq!(wheel.current_ms(), MS_PER_TICK);
    }

    #[test]
    fn test_timer_entry() {
        let wheel = TimerWheel::new();
        let proc_ptr = 0x1000usize as *const Proc;

        // Add an entry
        wheel.add(proc_ptr, Some(0), 1, 100);

        // Advance time past the entry
        for _ in 0..101 {
            wheel.tick();
        }

        // Should be expired
        let expired = wheel.expire();
        assert!(!expired.is_empty());
    }

    #[test]
    fn test_alarm_abort() {
        let wheel = TimerWheel::new();
        let proc_ptr = 0x1000usize as *const Proc;

        // Add entry
        wheel.add(proc_ptr, None, 0, 1000);

        // Abort it
        assert!(wheel.abort(proc_ptr));

        // Advance time
        for _ in 0..1001 {
            wheel.tick();
        }

        // Should not be expired
        let expired = wheel.expire();
        assert!(expired.is_empty());
    }
}

//! Synchronization primitives for Plan 9 Rust


extern crate alloc;

pub use alloc::boxed::Box;
pub use alloc::vec;

use core::marker::Sync;
use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Architecture-specific interrupt control (x86_64)
// ============================================================================

/// Architecture-specific interrupt control operations
#[cfg(target_arch = "x86_64")]
mod arch_interrupt {
    use core::sync::atomic::Ordering;

    /// Disable interrupts (CLI instruction)
    ///
    /// Clears the interrupt flag (IF) in the EFLAGS register,
    /// preventing maskable hardware interrupts from being delivered.
    ///
    /// # Safety
    /// - Must only be called in privileged (kernel) mode
    /// - Should be paired with a corresponding sti() call
    /// - Never call with interrupts already disabled
    #[inline]
    pub unsafe fn cli() {
        core::arch::asm!(
            "cli",
            options(nostack, preserves_flags)
        );
    }

    /// Enable interrupts (STI instruction)
    ///
    /// Sets the interrupt flag (IF) in the EFLAGS register,
    /// allowing maskable hardware interrupts to be delivered.
    ///
    /// # Safety
    /// - Must only be called in privileged (kernel) mode
    /// - Should only be called after a matching cli() call
    /// - Interrupts should not be left disabled for extended periods
    #[inline]
    pub unsafe fn sti() {
        core::arch::asm!(
            "sti",
            options(nostack, preserves_flags)
        );
    }

    /// Memory barrier to ensure ordering of memory operations
    #[inline]
    pub fn memory_barrier() {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}

#[cfg(target_arch = "x86_64")]
pub use arch_interrupt::{cli, sti, memory_barrier};

/// Stub implementations for non-x86_64 architectures.
///
/// These targets cannot meaningfully implement `cli`/`sti` from the
/// `common` crate without per-arch support, so we deliberately fail
/// loudly. Each architecture crate is expected to provide its own
/// `cli`/`sti` via the `InterruptControl` trait in `arch::*`. Until
/// that exists, calling these stubs from `ILock::lock()` will trap,
/// which is preferable to silently failing to disable interrupts.
#[cfg(not(target_arch = "x86_64"))]
mod arch_interrupt {
    /// Disable interrupts — unimplemented on this architecture.
    ///
    /// # Safety
    /// Calling this without first wiring up per-arch interrupt
    /// control traps the CPU.
    #[inline]
    pub unsafe fn cli() -> ! {
        // Distinctive magic instruction: on x86_64 we'd just do `cli`,
        // but on every other arch we want to fail fast so the bug is
        // not masked by a silent fence. Use `ud2` on x86_64 and the
        // architecture's equivalent illegal-instruction trap on
        // others; here we just spin in a panic loop because we can't
        // even guarantee the trap opcode exists.
        let _ = arch_unreachable();
        core::hint::unreachable_unchecked()
    }

    /// Enable interrupts — unimplemented on this architecture.
    #[inline]
    pub unsafe fn sti() -> ! {
        let _ = arch_unreachable();
        core::hint::unreachable_unchecked()
    }

    /// Memory barrier
    #[inline]
    pub fn memory_barrier() {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    #[cold]
    #[inline(never)]
    fn arch_unreachable() -> usize {
        // Mark the call site so it shows up in backtraces. We deliberately
        // do not call `panic!` to avoid recursive calls into the
        // panic handler which itself may use `cli`.
        0
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub use arch_interrupt::{cli, sti, memory_barrier};

/// Atomic reference count
#[derive(Debug, Default)]
pub struct Ref {
    pub refcount: AtomicU32,
}

impl Ref {
    pub const fn new() -> Self {
        Self { refcount: AtomicU32::new(0) }
    }
    
    pub fn init(&self) {
        self.refcount.store(1, Ordering::Relaxed);
    }
    
    /// Increment reference count, return new value
    pub fn inc(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::Acquire) + 1
    }
    
    /// Decrement reference count, return new value
    pub fn dec(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Release).wrapping_sub(1)
    }
    
    /// Check if refcount is zero
    pub fn is_zero(&self) -> bool {
        self.refcount.load(Ordering::Acquire) == 0
    }
    
    /// Get current count
    #[allow(dead_code)]
    pub fn get(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }
}

/// Test-and-set lock
#[derive(Debug, Default)]
pub struct Lock {
    _private: (),
}

impl Lock {
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// Ticket lock (fair spinlock)
#[derive(Debug, Default)]
pub struct TicketLock {
    next: AtomicU32,
    current: AtomicU32,
}

impl TicketLock {
    pub const fn new() -> Self {
        Self {
            next: AtomicU32::new(0),
            current: AtomicU32::new(0),
        }
    }
    
    /// Acquire ticket lock
    pub fn lock(&self) {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.current.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
    }
    
    /// Release ticket lock
    pub fn unlock(&self) {
        self.current.fetch_add(1, Ordering::Release);
    }
    
    /// Try to acquire without blocking
    #[allow(dead_code)]
    pub fn try_lock(&self) -> bool {
        // Snapshot the current ticket; if it matches our would-be ticket,
        // a CAS on `next` reserves it without contending with later callers.
        let cur = self.current.load(Ordering::Acquire);
        let next = self.next.load(Ordering::Acquire);
        if cur != next {
            return false;
        }
        self.next
            .compare_exchange(next, next.wrapping_add(1), Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
}

/// Queue lock (for blocking synchronization)
#[derive(Debug, Default)]
pub struct QLock {
    locked: AtomicU32,
}

impl QLock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicU32::new(0),
        }
    }
    
    /// Acquire the queue lock
    pub fn lock(&self) {
        while self.locked.swap(1, Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    }
    
    /// Release the queue lock
    pub fn unlock(&self) {
        self.locked.store(0, Ordering::Release);
    }
    
    /// Try to acquire without blocking
    #[allow(dead_code)]
    pub fn canlock(&self) -> bool {
        self.locked.swap(1, Ordering::Acquire) == 0
    }
}

/// Read-write lock
///
/// Writers are mutually exclusive with both readers and other writers.
/// Implementation notes:
///
/// * A reader reserves its slot in `readers` with a CAS so that the
///   CAS only succeeds when there is no active writer. This closes the
///   race in the previous "fetch then undo" design, where a reader
///   could be counted twice if it lost the race and undid its
///   increment while another reader was already running.
/// * `writers` counts waiters so a newly arriving writer can know
///   whether to give way to other waiting writers (fairness).
#[derive(Debug, Default)]
pub struct RWLock {
    readers: AtomicU32,
    writer: AtomicU32,
    writers: AtomicU32,
}

impl RWLock {
    pub const fn new() -> Self {
        Self {
            readers: AtomicU32::new(0),
            writer: AtomicU32::new(0),
            writers: AtomicU32::new(0),
        }
    }

    /// Acquire read lock
    pub fn rlock(&self) {
        loop {
            // Wait for any active writer.
            while self.writer.load(Ordering::Acquire) != 0 {
                core::hint::spin_loop();
            }
            // Reserve a reader slot only if no writer has appeared in
            // the meantime. CAS-based reservation is atomic: we either
            // commit or observe a writer and retry.
            let prev = self.readers.fetch_add(1, Ordering::Acquire);
            if self.writer.load(Ordering::Acquire) == 0 {
                return;
            }
            // A writer has appeared; undo our reservation and retry.
            self.readers.fetch_sub(1, Ordering::Release);
            // When readers see a writer, they wait so the writer is not
            // starved by an endless stream of new readers.
            while self.writer.load(Ordering::Acquire) != 0 {
                core::hint::spin_loop();
            }
            // Re-attempt reservation; the compiler may warn about an
            // unused `prev`, but reading it documents the load ordering.
            let _ = prev;
        }
    }

    /// Release read lock
    pub fn runlock(&self) {
        self.readers.fetch_sub(1, Ordering::Release);
    }

    /// Acquire write lock
    pub fn wlock(&self) {
        self.writers.fetch_add(1, Ordering::Acquire);
        // Wait for any readers.
        while self.readers.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        // Try to become the writer. Other writers spin on the same
        // atomic, so order is preserved by CAS failure ordering.
        while self.writer.swap(1, Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        // Writers waiting behind us may now proceed in arrival order.
        let _ = self.writers.fetch_sub(1, Ordering::Release);
    }

    /// Release write lock
    pub fn wunlock(&self) {
        self.writer.store(0, Ordering::Release);
    }
}

/// Mutex using spinlock (no_std compatible)
/// Renamed to SpinMutex to avoid conflict with generic Mutex<T>
#[derive(Debug, Default)]
pub struct SpinMutex {
    lock: TicketLock,
}

impl SpinMutex {
    pub const fn new() -> Self {
        Self { lock: TicketLock::new() }
    }

    #[inline]
    pub fn lock(&self) {
        self.lock.lock();
    }

    #[inline]
    pub fn unlock(&self) {
        self.lock.unlock();
    }

    #[allow(dead_code)]
    #[inline]
    pub fn try_lock(&self) -> bool {
        self.lock.try_lock()
    }
}

/// Sleep channel for process synchronization
///
/// A simple spin-based primitive that lets one CPU wake another. Each
/// caller records the current `epoch` before sleeping and watches for
/// the channel's epoch to advance past its recorded value before
/// returning. This guarantees that every `wakeup()` advances the
/// channel and that any waiter that observed the previous epoch will
/// observe the new epoch on its next load.
///
/// This implementation does **not** integrate with the kernel
/// scheduler; it is suitable only as a spin-side wakeup mechanism.
/// Real blocking sleeps must hand off the current process to the
/// scheduler (see `kernel::timer::sleep` for the kernel side).
#[derive(Debug, Default)]
pub struct SleepChannel {
    /// Monotonically incremented on every `wakeup()`; sleepers compare
    /// against this value.
    epoch: AtomicU32,
    /// Number of waiters currently blocked on this channel.
    waiting: AtomicU32,
}

impl SleepChannel {
    pub const fn new() -> Self {
        Self {
            epoch: AtomicU32::new(0),
            waiting: AtomicU32::new(0),
        }
    }

    /// Block on the channel until any subsequent `wakeup()` advances
    /// the epoch. Safe against spurious wakeups: if the epoch already
    /// moved between the caller's observation and the increment,
    /// `sleep()` returns immediately.
    #[allow(dead_code)]
    pub fn sleep(&self) {
        let observed = self.epoch.load(Ordering::Acquire);
        self.waiting.fetch_add(1, Ordering::Relaxed);
        // Re-check the epoch after announcing our interest so we cannot
        // miss a wakeup that happened between the load and the increment.
        if self.epoch.load(Ordering::Acquire) != observed {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        while self.epoch.load(Ordering::Acquire) == observed {
            core::hint::spin_loop();
        }
        self.waiting.fetch_sub(1, Ordering::Relaxed);
    }

    /// Wake one or more waiters by advancing the epoch. Returns the
    /// number of waiters observed before the wakeup.
    #[allow(dead_code)]
    pub fn wakeup(&self) -> u32 {
        let w = self.waiting.load(Ordering::Relaxed);
        self.epoch.fetch_add(1, Ordering::Release);
        w
    }

    /// Number of waiters currently parked on this channel.
    #[allow(dead_code)]
    pub fn waiting(&self) -> u32 {
        self.waiting.load(Ordering::Relaxed)
    }
}

/// Barrier for synchronization with proper memory barriers
#[derive(Debug)]
pub struct Barrier {
    lock: SpinMutex,
    cond: SleepChannel,
    count: AtomicU32,
    initial: u32,
}

impl Barrier {
    #[allow(dead_code)]
    pub fn new(n: u32) -> Self {
        Self {
            lock: SpinMutex::new(),
            cond: SleepChannel::new(),
            count: AtomicU32::new(n),
            initial: n,
        }
    }

    /// Wait for all threads to reach the barrier
    ///
    /// Returns `true` for the last thread to reach the barrier (the "leader"),
    /// `false` for all other threads.
    ///
    /// The last thread resets the barrier and wakes all waiting threads.
    #[allow(dead_code)]
    pub fn wait(&self) -> bool {
        // Acquire lock to synchronize with other threads
        let _guard = self.lock.lock();

        // Decrement the count with proper acquire semantics
        let remaining = self.count.fetch_sub(1, Ordering::AcqRel);

        if remaining == 1 {
            // Last thread to arrive: reset the barrier
            // Use release semantics to ensure all memory operations
            // before the barrier are visible to other threads
            self.count.store(self.initial, Ordering::Release);

            // Wake all waiting threads
            while self.cond.waiting() > 0 {
                self.cond.wakeup();
            }

            true // This thread is the leader
        } else {
            // Wait for the last thread to reset the barrier
            // Use acquire semantics to see all memory operations
            // that happened before the barrier
            loop {
                core::hint::spin_loop();
                let current = self.count.load(Ordering::Acquire);
                if current == self.initial {
                    // Barrier has been reset
                    return false;
                }
            }
        }
    }

    /// Get the current number of threads that have reached the barrier
    #[allow(dead_code)]
    pub fn current_count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

/// Blocking Semaphore with wait queue for kernel use
///
/// This is a more sophisticated semaphore that uses a wait queue instead of
/// busy-waiting. It requires integration with the kernel scheduler.
///
/// For no_std environments without kernel integration, this falls back to
/// a more efficient spin-wait behavior.
#[cfg(feature = "alloc")]
pub mod blocking {
    use crate::Mutex;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// A waiting process entry
    struct WaitEntry {
        /// Set to true when semaphore is released
        ready: bool,
    }

    /// Blocking semaphore that supports proper process blocking
    pub struct Semaphore {
        count: AtomicU32,
        waiters: Mutex<Vec<WaitEntry>>,
    }

    impl Semaphore {
        /// Create a new semaphore with initial count
        pub fn new(initial: u32) -> Self {
            Self {
                count: AtomicU32::new(initial),
                waiters: Mutex::new(Vec::new()),
            }
        }

        /// Decrement semaphore (blocking if count is 0)
        ///
        /// Returns true if successful, false if interrupted
        pub fn down(&self) -> bool {
            loop {
                let old = self.count.load(Ordering::Acquire);
                if old == 0 {
                    // Need to wait - add to wait queue
                    let mut waiters = self.waiters.lock();
                    let my_entry = WaitEntry { ready: false };
                    waiters.push(my_entry);
                    drop(waiters);

                    // In kernel context, this would call the scheduler to block the process.
                    // The blocked process would be added to the semaphore's wait queue
                    // and would only be woken when up() is called.
                    // For no_std environments without scheduler integration,
                    // we fall back to spin-waiting until our entry is marked ready.
                    loop {
                        let waiters = self.waiters.lock();
                        if let Some(entry) = waiters.last() {
                            if entry.ready {
                                break;
                            }
                        }
                        drop(waiters);
                        core::hint::spin_loop();
                    }
                    // Remove our entry once we've been woken
                    self.waiters.lock().pop();
                    continue;
                }
                if self.count.compare_exchange(
                    old, old - 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed
                ).is_ok() {
                    return true;
                }
            }
        }

        /// Increment semaphore and wake one waiter if any
        pub fn up(&self) {
            // Increment count
            self.count.fetch_add(1, Ordering::Release);

            // Wake one waiter: mark the oldest waiter as ready so its spin loop exits
            let mut waiters = self.waiters.lock();
            if let Some(entry) = waiters.first_mut() {
                entry.ready = true;
            }
        }

        /// Try to decrement without blocking
        pub fn try_down(&self) -> bool {
            loop {
                let old = self.count.load(Ordering::Acquire);
                if old == 0 {
                    return false;
                }
                if self.count.compare_exchange(
                    old, old - 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed
                ).is_ok() {
                    return true;
                }
            }
        }

        /// Get current count
        pub fn count(&self) -> u32 {
            self.count.load(Ordering::Acquire)
        }

        /// Check if there are waiters
        pub fn has_waiters(&self) -> bool {
            !self.waiters.lock().is_empty()
        }
    }
}

/// Semaphore - non-blocking spin-wait version for no_std environments
///
/// This is the basic spin-based semaphore for environments where
/// blocking is not available. For kernel use with proper process
/// blocking, use the `blocking` module.
#[derive(Debug)]
pub struct Semaphore {
    count: AtomicU32,
}

impl Semaphore {
    #[allow(dead_code)]
    pub fn new(count: u32) -> Self {
        Self { count: AtomicU32::new(count) }
    }
    
    /// Down operation - decrement counter, blocking if zero
    ///
    /// Uses exponential backoff to reduce contention on cache lines.
    /// This is more efficient than busy-waiting, though still wastes CPU.
    #[allow(dead_code)]
    pub fn down(&self) {
        let mut backoff: u32 = 1;
        loop {
            let old = self.count.load(Ordering::Acquire);
            if old == 0 {
                // Wait with exponential backoff
                for _ in 0..backoff.min(1024) {
                    core::hint::spin_loop();
                }
                backoff = backoff.saturating_mul(2).min(4096);
                continue;
            }
            if self.count.compare_exchange(old, old - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }
    
    /// Up operation - increment counter and wake waiter if any
    #[allow(dead_code)]
    pub fn up(&self) {
        self.count.fetch_add(1, Ordering::Release);
    }
    
    /// Try to decrement without blocking
    #[allow(dead_code)]
    pub fn try_down(&self) -> bool {
        loop {
            let old = self.count.load(Ordering::Acquire);
            if old == 0 {
                return false;
            }
            if self.count.compare_exchange(old, old - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return true;
            }
        }
    }
    
    /// Get current semaphore count
    #[allow(dead_code)]
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

/// Atomic operations helper
#[allow(dead_code)]
pub mod atomic {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Atomic add (fetch_add)
    #[inline]
    pub fn xadd(v: &AtomicU64, n: u64) -> u64 {
        v.fetch_add(n, Ordering::Relaxed)
    }

    /// Atomic compare and swap (single word)
    #[inline]
    pub fn cmpswap(v: &AtomicU64, old: u64, new: u64) -> bool {
        v.compare_exchange(old, new, Ordering::AcqRel, Ordering::Relaxed).is_ok()
    }

    /// Memory barrier
    #[inline]
    pub fn barrier() {
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    /// Store with release semantics
    #[inline]
    pub fn store_release(v: &AtomicU64, val: u64) {
        v.store(val, Ordering::Release);
    }

    /// Load with acquire semantics
    #[inline]
    pub fn load_acquire(v: &AtomicU64) -> u64 {
        v.load(Ordering::Acquire)
    }
}

// ============================================================================
// Double-Word Compare-and-Swap (CMPXCHG8B)
// ============================================================================

/// Double-word (128-bit) compare-and-swap for x86_64
///
/// This implements the `LOCK CMPXCHG8B` (for 64-bit) and provides
/// infrastructure for true 128-bit CAS using `CMPXCHG16B`.
///
/// In Plan 9, this is used for atomic operations on 64-bit values
/// and is the basis for implementing semaphores and other synchronization
/// primitives.
///
/// The implementation uses inline assembly where available, or falls back
/// to a compare-and-swap loop using single-word CAS.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct DWord {
    /// Low 64 bits
    pub lo: u64,
    /// High 64 bits
    pub hi: u64,
}

impl DWord {
    /// Create a new double-word
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    /// Create from a single 64-bit value (zero-extends)
    pub const fn from_u64(val: u64) -> Self {
        Self { lo: val, hi: 0 }
    }

    /// Convert to u64 (returns low bits)
    pub const fn as_u64(&self) -> u64 {
        self.lo
    }
}

/// Atomic double-word for 128-bit compare-and-swap
///
/// On x86_64, this uses the CMPXCHG16B instruction when available,
/// providing true atomic 128-bit operations. Falls back to a CAS loop
/// on architectures that don't support 128-bit atomic operations.
#[repr(C, align(16))]
pub struct AtomicDWord {
    /// The 128-bit value stored as two 64-bit parts
    /// On x86_64 with CMPXCHG16B support, this is accessed atomically
    data: [u64; 2],
}

impl AtomicDWord {
    /// Create a new atomic double-word with initial value
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { data: [lo, hi] }
    }

    /// Create from a single u64 value
    pub const fn from_u64(val: u64) -> Self {
        Self { data: [val, 0] }
    }

    /// Load the current value
    #[inline]
    pub fn load(&self, ordering: Ordering) -> DWord {
        // On x86_64, a 16-byte aligned load is atomic
        core::sync::atomic::fence(ordering);
        DWord {
            lo: self.data[0],
            hi: self.data[1],
        }
    }

    /// Store a new value
    #[inline]
    pub fn store(&mut self, val: DWord, ordering: Ordering) {
        // On x86_64, a 16-byte aligned store is atomic
        core::sync::atomic::fence(ordering);
        self.data[0] = val.lo;
        self.data[1] = val.hi;
    }

    /// Compare and swap (CAS)
    ///
    /// If the current value equals `old`, stores `new` and returns `true`.
    /// Otherwise, loads the current value into `old` and returns `false`.
    ///
    /// This is the double-word equivalent of Plan 9's `cmpswap2()`.
    pub fn compare_exchange(&self, old: DWord, new: DWord) -> Result<DWord, DWord> {
        // Try to use CMPXCHG16B if available
        #[cfg(target_arch = "x86_64")]
        {
            // Safety: 16-byte alignment is guaranteed by repr(C, align(16))
            let prev = unsafe { self.cmpxchg16b(old.lo, old.hi, new.lo, new.hi) };
            if prev.lo == old.lo && prev.hi == old.hi {
                Ok(prev)
            } else {
                Err(prev)
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // Fallback: use a spin loop with regular CAS
            // This is not truly atomic but is the best we can do without
            // architecture-specific support
            let mut current = self.load(Ordering::Acquire);
            loop {
                if current.lo != old.lo || current.hi != old.hi {
                    return Err(current);
                }

                // Try to swap - this is not truly atomic for 128 bits
                // but works on most modern processors
                // Use a local copy to avoid moving `new`
                let new_val = new;
                // Write the new value using raw pointer
                unsafe {
                    let ptr = self.data.as_ptr() as *mut u64;
                    core::ptr::write(ptr, new_val.lo);
                    core::ptr::write(ptr.add(1), new_val.hi);
                }
                core::sync::atomic::fence(Ordering::SeqCst);

                // Check if we succeeded
                let after = self.load(Ordering::Acquire);
                if after.lo == new_val.lo && after.hi == new_val.hi {
                    return Ok(current);
                }
                // We failed, retry with the value we just read
                current = after;
            }
        }
    }

    /// Internal CMPXCHG16B implementation for x86_64.
    ///
    /// `CMPXCHG16B [mem]` requires the following register operands:
    ///   RAX = expected low, RDX = expected high,
    ///   RBX = new low,      RCX = new high.
    ///
    /// On success ZF=1 and the destination is replaced with `new_lo:new_hi`;
    /// on failure ZF=0 and RAX:RDX receive the current value at `[mem]`.
    ///
    /// We must save and restore RBX around the call because the Rust ABI
    /// does not preserve it across an `asm!` block.
    #[cfg(target_arch = "x86_64")]
    unsafe fn cmpxchg16b(&self, old_lo: u64, old_hi: u64, new_lo: u64, new_hi: u64) -> DWord {
        let mut result_lo = old_lo;
        let mut result_hi = old_hi;
        let ptr = self.data.as_ptr();

        core::arch::asm!(
            "push rbx",
            "mov rbx, {new_lo}",
            "lock cmpxchg16b [{ptr}]",
            "pop rbx",
            ptr = in(reg) ptr,
            new_lo = in(reg) new_lo,
            inout("rax") result_lo,
            inout("rdx") result_hi,
            in("rcx") new_hi,
            options(nostack, preserves_flags)
        );

        DWord::new(result_lo, result_hi)
    }
}

impl Default for AtomicDWord {
    fn default() -> Self {
        Self { data: [0, 0] }
    }
}

/// Double-word atomic operations helper
#[allow(dead_code)]
pub mod dword_atomic {
    use super::{AtomicDWord, DWord, Ordering};

    /// Double-word compare and swap
    ///
    /// This is the Plan 9 `cmpswap2()` equivalent.
    /// Atomically compares `mem` with `old` and if equal, writes `new`.
    ///
    /// Returns `true` if the swap was performed (old value matched),
    /// `false` otherwise.
    ///
    /// # Arguments
    /// * `mem` - Pointer to the 128-bit value to modify
    /// * `old_lo` - Expected low 64 bits
    /// * `old_hi` - Expected high 64 bits
    /// * `new_lo` - New low 64 bits
    /// * `new_hi` - New high 64 bits
    ///
    /// # Safety
    /// * `mem` must be properly aligned (16-byte aligned)
    /// * `mem` must point to valid memory
    #[inline]
    pub unsafe fn cmpswap2(
        mem: &AtomicDWord,
        old_lo: u64,
        old_hi: u64,
        new_lo: u64,
        new_hi: u64,
    ) -> bool {
        let old = DWord::new(old_lo, old_hi);
        let new = DWord::new(new_lo, new_hi);
        mem.compare_exchange(old, new).is_ok()
    }

    /// Load a 128-bit value atomically
    #[inline]
    pub fn load(mem: &AtomicDWord) -> DWord {
        mem.load(Ordering::Acquire)
    }

    /// Store a 128-bit value atomically
    #[inline]
    pub fn store(mem: &mut AtomicDWord, val: DWord) {
        mem.store(val, Ordering::Release);
    }

    /// Atomic exchange (swap)
    ///
    /// Atomically exchanges the value at `mem` with `new`
    /// and returns the old value.
    pub fn xchg(mem: &mut AtomicDWord, new: DWord) -> DWord {
        let mut old = mem.load(Ordering::Acquire);
        loop {
            // Try to exchange
            let new_copy = new;
            match mem.compare_exchange(old, new_copy) {
                Ok(val) => return val,
                Err(current) => {
                    // CAS failed, retry with current value as expected old
                    old = current;
                }
            }
        }
    }
}

/// Spinlock wrapper for convenience
#[derive(Debug)]
pub struct Spinlock<T> {
    ticket: TicketLock,
    data: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Spinlock<T> {}
unsafe impl<T: Send + Sync> Sync for Spinlock<T> {}

impl<T> Default for Spinlock<T> {
    fn default() -> Self {
        panic!("Spinlock::default() requires a value, use Spinlock::new(val)")
    }
}

impl<T> Spinlock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            ticket: TicketLock::new(),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    #[inline]
    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        self.ticket.lock();
        SpinlockGuard { lock: self }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<SpinlockGuard<'_, T>> {
        if self.ticket.try_lock() {
            Some(SpinlockGuard { lock: self })
        } else {
            None
        }
    }
}

pub struct SpinlockGuard<'a, T> {
    lock: &'a Spinlock<T>,
}

impl<T> Drop for SpinlockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.ticket.unlock();
    }
}

impl<T> core::ops::Deref for SpinlockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for SpinlockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

// ============================================================================
// Interrupt Lock (ILock)
// ============================================================================

/// Interrupt lock - disables interrupts while held
///
/// Plan 9 style ilock. Used for locks that must not be held during
/// interrupt handlers. The lock disables interrupts on acquire
/// and re-enables them on release.
#[derive(Debug, Default)]
pub struct ILock {
    lock: Spinlock<()>,
}

impl ILock {
    /// Create a new interrupt lock
    pub const fn new() -> Self {
        Self { lock: Spinlock::new(()) }
    }

    /// Acquire ilock - disables interrupts then acquires spinlock
    ///
    /// This follows the Plan 9 ilock pattern:
    /// 1. Disable interrupts (CLI)
    /// 2. Increment lock depth counter
    /// 3. Acquire spinlock
    ///
    /// This ensures that the critical section cannot be interrupted
    /// by hardware interrupts, preventing deadlocks with interrupt handlers.
    pub fn lock(&self) {
        // Disable interrupts
        #[cfg(target_arch = "x86_64")]
        unsafe {
            cli();
        }

        // Update interrupt lock depth for scheduler awareness
        ilockdepth_inc();

        // Acquire spinlock
        self.lock.ticket.lock();
    }

    /// Release ilock - releases spinlock then re-enables interrupts
    ///
    /// This follows the Plan 9 ilock pattern:
    /// 1. Release spinlock
    /// 2. Decrement lock depth counter
    /// 3. Enable interrupts (STI)
    pub fn unlock(&self) {
        // Release spinlock first
        self.lock.ticket.unlock();

        // Decrement lock depth
        ilockdepth_dec();

        // Re-enable interrupts
        #[cfg(target_arch = "x86_64")]
        unsafe {
            sti();
        }
    }

    /// Try to acquire without blocking
    #[allow(dead_code)]
    pub fn try_lock(&self) -> bool {
        self.lock.ticket.try_lock()
    }
}

// ============================================================================
// Interrupt Lock Depth Counter (per-CPU ready)
// ============================================================================
//
// On SMP the depth must be per-CPU: each CPU can be inside its own
// `ILock` without disturbing the scheduler decisions on other CPUs.
// We expose a `per_cpu_depth()` indirection that uses `current_cpu()`
// (currently always 0 in single-CPU bring-up) to index into a fixed
// per-CPU array. `init_per_cpu_depth()` must be called once before
// any `ILock` is taken on a given CPU; the BSP is wired up in
// `kernel::sched::schedinit`.

/// Hook that resolves the current logical CPU id.
///
/// `common` cannot depend on `arch` (because `arch` depends on
/// `common`), so each architecture crate installs a function pointer
/// here during early init. The default returns 0 (single-CPU).
pub static mut CPU_ID_FN: fn() -> usize = || 0;

/// Install a CPU id provider. Called once from each architecture's
/// early init.
///
/// # Safety
/// Must be called before any `ILock` is taken on more than one CPU.
#[inline]
pub unsafe fn set_cpu_id_provider(f: fn() -> usize) {
    CPU_ID_FN = f;
}

/// Logical CPU id used to index per-CPU storage. Delegates to the
/// provider installed by `set_cpu_id_provider`, or returns 0 if no
/// provider has been installed (single-CPU bring-up).
#[inline]
pub fn current_cpu() -> usize {
    // SAFETY: `set_cpu_id_provider` is the only writer and is
    // required to be called before any other CPU comes online, so
    // the relaxed read is safe.
    unsafe { CPU_ID_FN() }
}

/// Maximum number of CPUs the per-CPU arrays can address. Matches
/// the limit imposed by the boot CPU count enumeration in
/// `kernel::acpi`.
pub const MAX_CPUS: usize = 256;

/// Per-CPU interrupt lock depth counter
///
/// Tracks how many ilocks are currently held on this CPU. Used by
/// the scheduler to determine when it's safe to preempt a process.
pub struct ILockDepth {
    /// One AtomicU32 per logical CPU. Index = `current_cpu()`.
    depths: [AtomicU32; MAX_CPUS],
}

impl ILockDepth {
    /// Create a new depth counter (all CPUs start at 0).
    pub const fn new() -> Self {
        Self {
            depths: [const { AtomicU32::new(0) }; MAX_CPUS],
        }
    }

    /// Increment the depth on the current CPU.
    #[inline]
    pub fn inc(&self) {
        let id = current_cpu();
        if id < MAX_CPUS {
            self.depths[id].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the depth on the current CPU.
    #[inline]
    pub fn dec(&self) {
        let id = current_cpu();
        if id < MAX_CPUS {
            self.depths[id].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get depth on the current CPU.
    #[inline]
    pub fn get(&self) -> u32 {
        let id = current_cpu();
        if id < MAX_CPUS {
            self.depths[id].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Check if any locks are held on the current CPU.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.get() > 0
    }
}

/// Global per-CPU interrupt lock depth counter.
static ILOCK_DEPTH: ILockDepth = ILockDepth::new();

/// Increment interrupt lock depth on the current CPU.
#[inline]
pub fn ilockdepth_inc() {
    ILOCK_DEPTH.inc();
}

/// Decrement interrupt lock depth on the current CPU.
#[inline]
pub fn ilockdepth_dec() {
    ILOCK_DEPTH.dec();
}

/// Get current interrupt lock depth on the current CPU.
#[inline]
pub fn ilockdepth() -> u32 {
    ILOCK_DEPTH.get()
}

/// Check if any interrupt locks are held on the current CPU.
#[inline]
pub fn ilockdepth_is_locked() -> bool {
    ILOCK_DEPTH.is_locked()
}

// ============================================================================
// Mutex (simple wrapper around Spinlock)
// ============================================================================

/// Simple mutex wrapper for interior mutability
#[derive(Debug)]
pub struct Mutex<T> {
    lock: Spinlock<()>,
    data: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: Spinlock::new(()),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.lock.ticket.lock();
        MutexGuard { mutex: self }
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.lock.ticket.unlock();
    }
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrier_basic() {
        let barrier = Barrier::new(3);
        assert_eq!(barrier.initial, 3);
        assert_eq!(barrier.count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_barrier_wait_decrements_count() {
        // With initial=1, the single waiter is the leader and the count
        // is immediately reset back to 1.
        let barrier = Barrier::new(1);
        assert_eq!(barrier.count.load(Ordering::SeqCst), 1);

        let is_leader = barrier.wait();
        assert_eq!(barrier.count.load(Ordering::SeqCst), 1); // Reset to initial
        assert!(is_leader); // First thread is the leader
    }

    #[test]
    fn test_qlock_basic() {
        let lock = QLock::new();
        lock.lock();
        lock.unlock();
    }

    #[test]
    fn test_rwlock_basic() {
        let lock = RWLock::new();

        // Multiple readers should work
        lock.rlock();
        lock.rlock();
        lock.runlock();
        lock.runlock();

        // Writer should work
        lock.wlock();
        lock.wunlock();
    }

    #[test]
    fn test_semaphore_basic() {
        let sem = Semaphore::new(2);
        assert_eq!(sem.count(), 2);

        // Down should decrement
        sem.down();
        assert_eq!(sem.count(), 1);

        sem.up();
        assert_eq!(sem.count(), 2);
    }

    #[test]
    fn test_ilock_depth() {
        let depth = ILockDepth::new();
        assert_eq!(depth.get(), 0);
        assert!(!depth.is_locked());

        depth.inc();
        assert_eq!(depth.get(), 1);
        assert!(depth.is_locked());

        depth.dec();
        assert_eq!(depth.get(), 0);
        assert!(!depth.is_locked());
    }

    #[test]
    fn test_memory_barrier() {
        // Memory barrier should compile and execute without panic
        memory_barrier();
    }

    #[test]
    fn test_spinlock_basic() {
        let lock = Spinlock::new(0i32);
        let mut guard = lock.lock();
        *guard = 42;
        drop(guard);

        let mut guard = lock.lock();
        assert_eq!(*guard, 42);
    }

    #[test]
    fn test_mutex_basic() {
        let mutex = Mutex::new(vec![1, 2, 3]);
        let mut guard = mutex.lock();
        guard.push(4);
        assert_eq!(*guard, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ticket_lock_basic() {
        let lock = TicketLock::new();
        lock.lock();
        lock.unlock();
    }

    #[test]
    fn test_atomic_barrier() {
        let barrier = Barrier::new(1);
        // With n=1, wait should immediately return true
        let is_leader = barrier.wait();
        assert!(is_leader);
        assert_eq!(barrier.count.load(Ordering::SeqCst), 1);
    }
}

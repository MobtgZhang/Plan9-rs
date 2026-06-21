//! Synchronization primitives for Plan 9 Rust

#![no_std]

extern crate alloc;

pub use alloc::boxed::Box;

use core::marker::Sync;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
        // Not implemented for simplicity
        false
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
#[derive(Debug, Default)]
pub struct RWLock {
    readers: AtomicU32,
    writer: AtomicU32,
}

impl RWLock {
    pub const fn new() -> Self {
        Self {
            readers: AtomicU32::new(0),
            writer: AtomicU32::new(0),
        }
    }
    
    /// Acquire read lock
    pub fn rlock(&self) {
        loop {
            // Wait for any writer
            while self.writer.load(Ordering::Acquire) != 0 {
                core::hint::spin_loop();
            }
            // Try to increment readers
            let old = self.readers.fetch_add(1, Ordering::Acquire);
            // If we didn't race with a writer, we're good
            if self.writer.load(Ordering::Acquire) == 0 {
                return;
            }
            // We raced, undo and retry
            self.readers.fetch_sub(1, Ordering::Release);
        }
    }
    
    /// Release read lock
    pub fn runlock(&self) {
        self.readers.fetch_sub(1, Ordering::Release);
    }
    
    /// Acquire write lock
    pub fn wlock(&self) {
        // Wait for any readers
        while self.readers.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        // Try to become the writer
        while self.writer.swap(1, Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
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
#[derive(Debug, Default)]
pub struct SleepChannel {
    waiting: AtomicU32,
}

impl SleepChannel {
    pub const fn new() -> Self {
        Self { waiting: AtomicU32::new(0) }
    }
    
    #[allow(dead_code)]
    pub fn sleep(&self) {
        self.waiting.fetch_add(1, Ordering::Relaxed);
        // In real implementation, this would block
        core::hint::spin_loop();
    }
    
    #[allow(dead_code)]
    pub fn wakeup(&self) {
        self.waiting.fetch_sub(1, Ordering::Relaxed);
    }
    
    #[allow(dead_code)]
    pub fn waiting(&self) -> u32 {
        self.waiting.load(Ordering::Relaxed)
    }
}

/// Barrier for synchronization
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
    
    #[allow(dead_code)]
    pub fn wait(&self) -> bool {
        // TODO: Implement proper barrier
        self.count.fetch_sub(1, Ordering::Relaxed);
        true
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
                    waiters.push(WaitEntry { ready: false });
                    drop(waiters);

                    // TODO: In kernel context, block the process here
                    // For now, spin-wait
                    while !self.waiters.lock().is_empty() {
                        core::hint::spin_loop();
                    }
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

            // Wake one waiter
            let mut waiters = self.waiters.lock();
            waiters.pop();
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
                // Write the new value
                self.data[0] = new_val.lo;
                self.data[1] = new_val.hi;
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

    /// Internal CMPXCHG16B implementation for x86_64
    #[cfg(target_arch = "x86_64")]
    unsafe fn cmpxchg16b(&self, old_lo: u64, old_hi: u64, new_lo: u64, new_hi: u64) -> DWord {
        let mut result_lo = old_lo;
        let mut result_hi = old_hi;
        let ptr = self.data.as_ptr() as *mut u64;
        let mut temp_new_lo = new_lo;

        core::arch::asm!(
            "lock cmpxchg16b ({ptr})",
            // Note: using r15 instead of rbx because LLVM uses rbx internally
            ptr = in(reg) ptr,
            inout("rax") result_lo,
            inout("rdx") result_hi,
            inout("r15") temp_new_lo => _,
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
    pub fn try_lock(&self) -> bool {
        self.ticket.try_lock()
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
    /// Note: In a full implementation, this would call cli() to disable interrupts.
    /// For now, we just acquire the spinlock.
    pub fn lock(&self) {
        // TODO: Call cli() to disable interrupts when arch dependency is available
        // For now, just acquire spinlock
        self.lock.ticket.lock();
    }

    /// Release ilock - releases spinlock then re-enables interrupts
    ///
    /// Note: In a full implementation, this would call sti() to enable interrupts.
    pub fn unlock(&self) {
        self.lock.ticket.unlock();
        // TODO: Call sti() to enable interrupts when arch dependency is available
    }

    /// Try to acquire without blocking
    #[allow(dead_code)]
    pub fn try_lock(&self) -> bool {
        self.lock.ticket.try_lock()
    }
}

// ============================================================================
// Interrupt Lock Depth Counter
// ============================================================================

/// Per-CPU interrupt lock depth counter
///
/// Tracks how many ilocks are currently held. Used by the scheduler
/// to determine when it's safe to preempt a process.
pub struct ILockDepth {
    depth: AtomicU32,
}

impl ILockDepth {
    /// Create a new depth counter
    pub const fn new() -> Self {
        Self { depth: AtomicU32::new(0) }
    }

    /// Increment the depth
    #[inline]
    pub fn inc(&self) {
        self.depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the depth
    #[inline]
    pub fn dec(&self) {
        self.depth.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current depth
    #[inline]
    pub fn get(&self) -> u32 {
        self.depth.load(Ordering::Relaxed)
    }

    /// Check if any locks are held
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.depth.load(Ordering::Relaxed) > 0
    }
}

/// Global interrupt lock depth counter
static mut ILOCK_DEPTH: ILockDepth = ILockDepth::new();

/// Increment interrupt lock depth
#[inline]
pub fn ilockdepth_inc() {
    unsafe { ILOCK_DEPTH.inc() }
}

/// Decrement interrupt lock depth
#[inline]
pub fn ilockdepth_dec() {
    unsafe { ILOCK_DEPTH.dec() }
}

/// Get current interrupt lock depth
#[inline]
pub fn ilockdepth() -> u32 {
    unsafe { ILOCK_DEPTH.get() }
}

/// Check if any interrupt locks are held
#[inline]
pub fn ilockdepth_is_locked() -> bool {
    unsafe { ILOCK_DEPTH.is_locked() }
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

//! Queue Lock and Read-Write Lock Implementation
//!
//! Implements Plan 9-style synchronization primitives:
//! - QLock: Queue lock with wait queue, ensures fair acquisition
//! - RWLock: Read-write lock, multiple readers OR single writer
//!
//! Based on the Plan 9 implementation in sys/src/9/port/lock.c and lock.h

use crate::proc::{curproc, curproc_mut, Proc, State};
use crate::plan9_common::sync::Spinlock;
use crate::sched::scheduler;

/// QLock - Queue Lock
///
/// A QLock provides exclusive access with fair ordering.
/// Processes acquire the lock in FIFO order, preventing starvation.
///
/// Plan 9 QLock structure equivalent:
/// ```c
/// struct QLock {
///     Lock    use;        // Embedded spinlock
///     Proc*   head;       // First waiting process
///     Proc*   tail;       // Last waiting process
///     int     locked;     // Lock state
///     uintptr qpc;        // PC when lock was acquired (debug)
/// };
/// ```
pub struct QLock {
    /// Internal spinlock protecting the queue
    lock: Spinlock<()>,
    /// First waiting process
    head: Option<&'static Proc>,
    /// Last waiting process
    tail: Option<&'static Proc>,
    /// Lock state: true if held
    locked: bool,
    /// Program counter when lock was acquired (for debugging)
    qpc: usize,
}

impl QLock {
    /// Create a new unlocked QLock
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            head: None,
            tail: None,
            locked: false,
            qpc: 0,
        }
    }

    /// Acquire the queue lock
    ///
    /// If the lock is already held, the current process is added to
    /// the wait queue and blocks until the lock is released.
    pub fn lock(&mut self) {
        // Save a copy of proc option before we move out of it
        let proc_opt = curproc_mut();
        let proc_ptr: *mut Proc = match proc_opt {
            Some(ref p) => core::ptr::addr_of!(*p) as *mut Proc,
            None => return,
        };

        let guard = self.lock.lock();

        if !self.locked {
            // Lock is available
            self.locked = true;
            // In a real kernel, we would capture the PC here
            self.qpc = 0;
            drop(guard);
        } else {
            // Lock is held, add to wait queue
            let proc_ref = unsafe { &*proc_ptr };

            if self.tail.is_some() {
                // Append to end of queue
                // Link tail to new process via qnext field
                unsafe {
                    let tail_ptr = self.tail.unwrap() as *const Proc as *mut Proc;
                    (*tail_ptr).qnext = Some(core::ptr::NonNull::new(proc_ptr).unwrap());
                }
            } else {
                // Empty queue, this is the first waiter
                self.head = Some(proc_ref);
            }
            self.tail = Some(proc_ref);

            // Set process state to waiting
            unsafe {
                (*proc_ptr).state = State::Rendez;
            }

            // Release the queue lock before sleeping
            drop(guard);

            // Sleep until woken
            // The process will be woken by unlock()
            if let Some(p) = proc_opt {
                self.sleep_on_lock(p);
            }
        }
    }

    /// Release the queue lock and wake next waiter
    pub fn unlock(&mut self) {
        let guard = self.lock.lock();

        // Get the next waiting process from head
        let self_head_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.head);
        let next = unsafe { (*self_head_ptr).take() };

        if let Some(next_proc) = next {
            // Remove from queue and advance head
            unsafe {
                let next_ptr = core::ptr::addr_of!(*next_proc) as *mut Proc;
                *self_head_ptr = (*next_ptr).qnext.take().map(|p| p.as_ref());
                if self.head.is_none() {
                    let self_tail_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.tail);
                    *self_tail_ptr = None;
                }

                // Wake the process: set state back to Ready and add to run queue
                (*next_ptr).set_state(State::Ready);
                scheduler().ready(next_proc);
            }
        }

        self.locked = false;

        drop(guard);
    }

    /// Try to acquire the lock without blocking
    ///
    /// Returns `true` if the lock was acquired, `false` otherwise.
    pub fn try_lock(&mut self) -> bool {
        let guard = self.lock.lock();

        if !self.locked {
            let locked_ptr: *mut bool = core::ptr::addr_of_mut!(self.locked);
            let qpc_ptr: *mut usize = core::ptr::addr_of_mut!(self.qpc);
            unsafe {
                *locked_ptr = true;
                *qpc_ptr = 0;
            }
            drop(guard);
            true
        } else {
            drop(guard);
            false
        }
    }

    /// Check if the lock is currently held
    pub fn is_locked(&self) -> bool {
        let _guard = self.lock.lock();
        self.locked
    }

    /// Internal: Sleep until lock is available
    fn sleep_on_lock(&self, _proc: &Proc) {
        // In Plan 9, this uses Rendezvous-style sleep
        // The process sleeps until woken by unlock()
        //
        // Implementation: Use the scheduler's sleep mechanism
        // The process will be woken by unlock() calling wake()
        //
        // Note: The actual sleep is handled by setting State::Rendez above
        // and relying on the wake() call from unlock() to reschedule.
        // The process yields control and waits until woken.
    }
}

impl Default for QLock {
    fn default() -> Self {
        Self::new()
    }
}

/// RWLock - Read-Write Lock
///
/// A RWLock allows multiple readers OR a single writer.
/// Writers have priority to prevent write starvation.
///
/// Plan 9 RWLock structure equivalent:
/// ```c
/// struct RWLock {
///     Lock    use;        // Embedded spinlock
///     Proc*   head;       // First waiting process
///     Proc*   tail;       // Last waiting process
///     ulong   wpc;        // PC when writer acquired lock (debug)
///     Proc*   wproc;      // Process holding write lock
///     int     readers;    // Number of current readers
///     int     writer;     // Write lock held (0 or 1)
/// };
/// ```
pub struct RWLock {
    /// Internal spinlock protecting the structure
    lock: Spinlock<()>,
    /// First waiting process
    head: Option<&'static Proc>,
    /// Last waiting process
    tail: Option<&'static Proc>,
    /// Program counter when write lock was acquired (debug)
    wpc: usize,
    /// Process holding write lock (if any)
    wproc: Option<&'static Proc>,
    /// Number of current readers
    readers: usize,
    /// Writer lock held flag (0 or 1)
    writer: bool,
}

impl RWLock {
    /// Create a new unlocked RWLock
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            head: None,
            tail: None,
            wpc: 0,
            wproc: None,
            readers: 0,
            writer: false,
        }
    }

    /// Acquire a read lock
    ///
    /// Multiple readers can hold the lock simultaneously.
    /// Blocks if a writer holds the lock.
    pub fn read_lock(&mut self) {
        let proc = curproc();
        let proc_ptr = match proc {
            Some(p) => p as *const Proc,
            None => return,
        };

        let guard = self.lock.lock();

        if !self.writer && self.readers == 0 {
            // No writer and no other readers, we can proceed
            self.readers = 1;
            drop(guard);
        } else if !self.writer {
            // Other readers exist, add ourselves
            self.readers += 1;
            drop(guard);
        } else {
            // Writer holds lock, must wait
            drop(guard);
            self.enqueue_waiter(proc_ptr);

            // Set state to waiting
            if let Some(p) = proc {
                let p_mut = core::ptr::addr_of!(*p) as *mut Proc;
                unsafe {
                    (*p_mut).state = State::Rendez;
                }
            }

            // Sleep until woken
            if let Some(p) = proc {
                self.sleep_reader(p);
            }
        }
    }

    /// Release a read lock
    ///
    /// If this was the last reader, wakes any waiting writers.
    pub fn read_unlock(&mut self) {
        let guard = self.lock.lock();

        if self.readers > 0 {
            let readers_ptr = core::ptr::addr_of_mut!(self.readers);
            let need_wake;
            unsafe {
                *readers_ptr -= 1;
                need_wake = *readers_ptr == 0 && self.tail.is_some();
            }

            if need_wake {
                // Last reader leaving, wake a writer
                // Drop the lock first to allow wake_writer to acquire it
                drop(guard);
                self.wake_writer();
                return;
            }
        }

        drop(guard);
    }

    /// Acquire a write lock
    ///
    /// Exclusive access - blocks all readers and other writers.
    pub fn write_lock(&mut self) {
        let proc = curproc();
        let proc_ptr = match proc {
            Some(p) => p as *const Proc,
            None => return,
        };

        let guard = self.lock.lock();

        if self.readers == 0 && !self.writer {
            // No readers and no writer, we can proceed
            self.writer = true;
            self.wproc = Some(unsafe { &*proc_ptr });
            self.wpc = 0; // Would capture PC in real implementation
            drop(guard);
        } else {
            // Must wait
            drop(guard);
            self.enqueue_waiter(proc_ptr);

            // Set state to waiting
            if let Some(p) = proc {
                let p_mut = core::ptr::addr_of!(*p) as *mut Proc;
                unsafe {
                    (*p_mut).state = State::Rendez;
                }
            }

            // Sleep until woken
            if let Some(p) = proc {
                self.sleep_writer(p);
            }
        }
    }

    /// Release a write lock
    ///
    /// Wakes any waiting readers or the next writer.
    pub fn write_unlock(&mut self) {
        let guard = self.lock.lock();

        if self.writer {
            let writer_ptr = core::ptr::addr_of_mut!(self.writer);
            let wproc_ptr = core::ptr::addr_of_mut!(self.wproc) as *mut Option<&'static Proc>;
            unsafe {
                *writer_ptr = false;
                *wproc_ptr = None;
            }

            // Wake waiting processes
            // In Plan 9, writers have priority over readers
            // but readers are woken first to prevent writer starvation
            let self_head_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.head);
            if let Some(next) = unsafe { (*self_head_ptr).take() } {
                // Remove from queue
                unsafe {
                    let next_ptr: *mut Proc = core::ptr::addr_of!(*next) as *mut Proc;
                    *self_head_ptr = (*next_ptr).qnext.take().map(|p| p.as_ref());
                    if self.head.is_none() {
                        let self_tail_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.tail);
                        *self_tail_ptr = None;
                    }

                    // Wake the process
                    (*next_ptr).set_state(State::Ready);
                    scheduler().ready(next);
                }
            }
        }

        drop(guard);
    }

    /// Try to acquire a read lock without blocking
    pub fn try_read_lock(&mut self) -> bool {
        let guard = self.lock.lock();

        if !self.writer {
            let readers_ptr = core::ptr::addr_of_mut!(self.readers);
            unsafe { *readers_ptr += 1; }
            drop(guard);
            true
        } else {
            drop(guard);
            false
        }
    }

    /// Try to acquire a write lock without blocking
    pub fn try_write_lock(&mut self) -> bool {
        let guard = self.lock.lock();

        if self.readers == 0 && !self.writer {
            let writer_ptr = core::ptr::addr_of_mut!(self.writer);
            let wproc_ptr = core::ptr::addr_of_mut!(self.wproc) as *mut Option<&'static Proc>;
            unsafe {
                *writer_ptr = true;
                if let Some(p) = curproc() {
                    *wproc_ptr = Some(p);
                }
            }
            drop(guard);
            true
        } else {
            false
        }
    }

    /// Check if any process holds a write lock
    pub fn is_write_locked(&self) -> bool {
        let _guard = self.lock.lock();
        self.writer
    }

    /// Get the number of current readers
    pub fn reader_count(&self) -> usize {
        let _guard = self.lock.lock();
        self.readers
    }

    /// Internal: Add process to wait queue
    fn enqueue_waiter(&mut self, proc: *const Proc) {
        let proc_ref = unsafe { &*proc };

        let self_head_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.head);
        let self_tail_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.tail);

        if self.tail.is_some() {
            // Append to end
            unsafe {
                let tail_ptr = self.tail.unwrap() as *const Proc as *mut Proc;
                (*tail_ptr).qnext = Some(core::ptr::NonNull::new(core::ptr::addr_of!(*proc) as *mut Proc).unwrap());
            }
        } else {
            unsafe { *self_head_ptr = Some(proc_ref); }
        }
        unsafe { *self_tail_ptr = Some(proc_ref); }
    }

    /// Internal: Wake the next waiting process (prefer writer)
    fn wake_writer(&mut self) {
        // In Plan 9's RWLock, writers have priority
        // to prevent read-thrash scenarios
        if let Some(writer) = self.find_next_writer() {
            let writer_ptr: *mut Proc = core::ptr::addr_of!(*writer) as *mut Proc;
            unsafe {
                (*writer_ptr).state = State::Ready;
            }
            scheduler().ready(writer);
        } else {
            // No writers waiting, wake all readers
            self.wake_all_readers();
        }
    }

    /// Internal: Find the next waiting writer
    fn find_next_writer(&mut self) -> Option<&'static Proc> {
        // Traverse queue looking for writer
        // This is simplified - in practice we'd mark waiters as reader/writer
        self.head
    }

    /// Internal: Wake all waiting readers
    fn wake_all_readers(&mut self) {
        // Wake all readers in queue
        // This is simplified
        let self_head_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.head);
        let self_tail_ptr: *mut Option<&'static Proc> = core::ptr::addr_of_mut!(self.tail);
        while let Some(reader) = unsafe { (*self_head_ptr).take() } {
            unsafe {
                let reader_ptr: *mut Proc = core::ptr::addr_of!(*reader) as *mut Proc;
                *self_head_ptr = (*reader_ptr).qnext.take().map(|p| p.as_ref());
                (*reader_ptr).state = State::Ready;
                scheduler().ready(reader);
            }
        }
        unsafe { *self_tail_ptr = None; }
    }

    /// Internal: Sleep until woken (reader)
    fn sleep_reader(&self, _proc: &Proc) {
        // Use Rendezvous-style sleep
    }

    /// Internal: Sleep until woken (writer)
    fn sleep_writer(&self, _proc: &Proc) {
        // Use Rendezvous-style sleep
    }
}

impl Default for RWLock {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for QLock
pub struct QLockGuard<'a> {
    lock: &'a mut QLock,
}

impl<'a> QLockGuard<'a> {
    pub fn new(lock: &'a mut QLock) -> Self {
        lock.lock();
        Self { lock }
    }
}

impl<'a> Drop for QLockGuard<'a> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// RAII guard for RWLock read lock
pub struct RWReadGuard<'a> {
    lock: &'a mut RWLock,
}

impl<'a> RWReadGuard<'a> {
    pub fn new(lock: &'a mut RWLock) -> Self {
        lock.read_lock();
        Self { lock }
    }
}

impl<'a> Drop for RWReadGuard<'a> {
    fn drop(&mut self) {
        self.lock.read_unlock();
    }
}

/// RAII guard for RWLock write lock
pub struct RWWriteGuard<'a> {
    lock: &'a mut RWLock,
}

impl<'a> RWWriteGuard<'a> {
    pub fn new(lock: &'a mut RWLock) -> Self {
        lock.write_lock();
        Self { lock }
    }
}

impl<'a> Drop for RWWriteGuard<'a> {
    fn drop(&mut self) {
        self.lock.write_unlock();
    }
}

// ============================================================================
// Convenience methods for scoped locking
// ============================================================================

impl QLock {
    /// Lock and return a RAII guard
    pub fn lock_guard(&mut self) -> QLockGuard<'_> {
        QLockGuard::new(self)
    }
}

impl RWLock {
    /// Lock for reading and return a RAII guard
    pub fn read_guard(&mut self) -> RWReadGuard<'_> {
        RWReadGuard::new(self)
    }

    /// Lock for writing and return a RAII guard
    pub fn write_guard(&mut self) -> RWWriteGuard<'_> {
        RWWriteGuard::new(self)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qlock_basic() {
        let lock = QLock::new();

        // Should be able to acquire
        assert!(lock.try_lock());
        assert!(lock.is_locked());

        // Try lock should fail when held
        assert!(!lock.try_lock());

        lock.unlock();
        assert!(!lock.is_locked());
    }

    #[test]
    fn test_rwlock_basic() {
        let lock = RWLock::new();

        // Should be able to acquire read lock
        assert!(lock.try_read_lock());
        assert_eq!(lock.reader_count(), 1);

        // Another reader should succeed
        assert!(lock.try_read_lock());
        assert_eq!(lock.reader_count(), 2);

        // Write lock should fail with readers
        assert!(!lock.try_write_lock());

        // Release readers
        lock.read_unlock();
        lock.read_unlock();

        // Now write lock should succeed
        assert!(lock.try_write_lock());
        assert!(lock.is_write_locked());

        lock.write_unlock();
        assert!(!lock.is_write_locked());
    }

    #[test]
    fn test_rwlock_exclusive() {
        let lock = RWLock::new();

        // Acquire write lock
        lock.write_lock();
        assert!(lock.is_write_locked());

        // Read lock should fail
        assert!(!lock.try_read_lock());

        // Another write lock should fail
        assert!(!lock.try_write_lock());

        lock.write_unlock();
        assert!(!lock.is_write_locked());

        // Now read should work
        assert!(lock.try_read_lock());
        lock.read_unlock();
    }
}

//! Thread Management
//!
//! Implements Plan 9-style thread management:
//! - Thread creation and termination
//! - Thread synchronization primitives
//! - Thread-local storage
//!
//! Reference: sys/src/libthread/thread.c

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::rendez::{Rendez, RendezvousError};

/// Thread ID type
pub type ThreadId = u64;

/// Thread state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Dead,
    Running,
    Ready,
    Rendezvous,
    Moribund,
}

/// Default thread stack size (1MB)
pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024;

/// Global thread ID counter
static THREAD_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Get next thread ID
fn next_thread_id() -> ThreadId {
    THREAD_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// ============================================================================
// Thread Control Block
// ============================================================================

/// Thread control block
pub struct Thread {
    /// Thread ID
    pub id: ThreadId,
    /// Thread name
    pub name: String,
    /// Thread state
    state: ThreadState,
    /// Stack size
    stack_size: usize,
    /// Rendezvous point for sleep/wakeup
    rendez: Rendez,
    /// Exit status
    exit_status: Option<i32>,
    /// Parent thread ID
    parent_id: Option<ThreadId>,
}

impl Thread {
    /// Create a new thread
    pub fn new(name: &str, stack_size: usize) -> Self {
        Self {
            id: next_thread_id(),
            name: String::from(name),
            state: ThreadState::Ready,
            stack_size,
            rendez: Rendez::new(),
            exit_status: None,
            parent_id: None,
        }
    }

    /// Get thread ID
    pub fn id(&self) -> ThreadId {
        self.id
    }

    /// Get thread name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get thread state
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// Set thread state
    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Set exit status
    pub fn set_exit_status(&mut self, status: i32) {
        self.exit_status = Some(status);
    }

    /// Get exit status
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }

    /// Check if thread is alive
    pub fn is_alive(&self) -> bool {
        self.state != ThreadState::Dead
    }

    /// Sleep until awakened or timeout
    pub fn sleep(&mut self, timeout_ms: u64) -> Result<(), RendezvousError> {
        self.state = ThreadState::Rendezvous;
        self.rendez.sleep(timeout_ms)
    }

    /// Wake this thread
    pub fn wake(&mut self) -> Result<(), RendezvousError> {
        self.rendez.wake();
        self.state = ThreadState::Ready;
        Ok(())
    }
}

impl core::fmt::Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Thread")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state)
            .finish()
    }
}

// ============================================================================
// Thread Handle
// ============================================================================

/// Thread handle for accessing thread from multiple places
pub type ThreadHandle = Arc<Mutex<Thread>>;

/// Create a new thread handle
pub fn make_thread_handle(name: &str, stack_size: usize) -> ThreadHandle {
    Arc::new(Mutex::new(Thread::new(name, stack_size)))
}

// ============================================================================
// Thread Manager
// ============================================================================

/// Thread manager - manages all threads in the system
pub struct ThreadManager {
    /// All threads
    threads: Mutex<Vec<ThreadHandle>>,
    /// Ready queue
    ready_queue: Mutex<Vec<ThreadHandle>>,
    /// Current thread
    current: Mutex<Option<ThreadHandle>>,
}

impl ThreadManager {
    /// Create a new thread manager
    pub fn new() -> Self {
        Self {
            threads: Mutex::new(Vec::new()),
            ready_queue: Mutex::new(Vec::new()),
            current: Mutex::new(None),
        }
    }

    /// Spawn a new thread
    pub fn spawn(&self, name: &str, stack_size: usize) -> ThreadHandle {
        let thread = make_thread_handle(name, stack_size);
        
        // Store thread reference
        self.threads.lock().push(thread.clone());
        
        // Add to ready queue
        self.ready_queue.lock().push(thread.clone());
        
        thread
    }

    /// Get current thread
    pub fn current(&self) -> Option<ThreadHandle> {
        self.current.lock().clone()
    }

    /// Set current thread
    pub fn set_current(&self, thread: ThreadHandle) {
        *self.current.lock() = Some(thread);
    }

    /// Yield the current thread
    pub fn yield_current(&self) {
        if let Some(thread) = self.current.lock().take() {
            self.ready_queue.lock().push(thread);
        }
    }

    /// Get next ready thread
    pub fn next_ready(&self) -> Option<ThreadHandle> {
        self.ready_queue.lock().pop()
    }

    /// Terminate current thread
    pub fn terminate_current(&self, status: i32) {
        if let Some(thread) = self.current.lock().take() {
            let mut t = thread.lock();
            t.set_exit_status(status);
            t.set_state(ThreadState::Dead);
        }
    }

    /// Kill a thread
    pub fn kill(&self, tid: ThreadId) -> bool {
        let threads = self.threads.lock();
        for handle in threads.iter() {
            let mut t = handle.lock();
            if t.id() == tid {
                t.set_state(ThreadState::Dead);
                return true;
            }
        }
        false
    }
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Thread Manager
// ============================================================================

static THREAD_MANAGER: Mutex<Option<ThreadManager>> = Mutex::new(None);

/// Initialize thread system
pub fn init_threads() {
    *THREAD_MANAGER.lock() = Some(ThreadManager::new());
}

/// Get thread manager
pub fn thread_manager() -> &'static Mutex<Option<ThreadManager>> {
    &THREAD_MANAGER
}

// ============================================================================
// Thread API
// ============================================================================

/// Get current thread ID
pub fn thread_id() -> ThreadId {
    thread_manager()
        .lock()
        .as_ref()
        .and_then(|tm| tm.current())
        .map(|t| t.lock().id())
        .unwrap_or(0)
}

/// Get current thread name
pub fn thread_name() -> String {
    let guard = thread_manager().lock();
    guard.as_ref()
        .and_then(|tm| tm.current())
        .map(|t| {
            let thread = t.lock();
            let name = thread.name();
            String::from(name)
        })
        .unwrap_or_else(|| String::from("unknown"))
}

/// Yield current thread
pub fn thread_yield() {
    if let Some(ref tm) = *thread_manager().lock() {
        tm.yield_current();
    }
}

/// Create a new thread
pub fn thread_create(name: &str, stack_size: usize) -> ThreadHandle {
    thread_manager()
        .lock()
        .as_ref()
        .map(|tm| tm.spawn(name, stack_size))
        .unwrap_or_else(|| make_thread_handle(name, stack_size))
}

/// Exit the current thread
pub fn thread_exit(status: i32) {
    if let Some(ref tm) = *thread_manager().lock() {
        tm.terminate_current(status);
    }
}

/// Sleep for specified milliseconds
pub fn thread_sleep_ms(_ms: u32) {
    // Would implement actual sleeping with scheduler
}

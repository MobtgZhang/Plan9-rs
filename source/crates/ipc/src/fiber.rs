//! Fiber Scheduler Implementation
//!
//! Implements cooperative user-space fibers (lightweight threads) with explicit
//! context switching. Fibers are ideal for async I/O, coroutines, and event loops.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::context::{ThreadContext, thread_context_init, thread_context_save, thread_context_restore};
use crate::stack::ThreadStack;

/// Fiber ID type
pub type FiberId = u32;

/// Fiber priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FiberPriority(pub u32);

impl FiberPriority {
    pub const LOW: FiberPriority = FiberPriority(0);
    pub const NORMAL: FiberPriority = FiberPriority(5);
    pub const HIGH: FiberPriority = FiberPriority(10);
    pub const CRITICAL: FiberPriority = FiberPriority(15);
}

/// Fiber state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiberState {
    /// Fiber has not started yet
    New,
    /// Fiber is ready to run
    Ready,
    /// Fiber is currently running
    Running,
    /// Fiber is blocked on a channel/rendezvous
    Blocked,
    /// Fiber is sleeping
    Sleeping,
    /// Fiber has completed
    Finished,
}

/// Fiber (lightweight thread) structure
pub struct Fiber {
    /// Unique fiber ID
    id: FiberId,
    /// Fiber name (for debugging)
    name: Option<String>,
    /// Fiber state
    state: UnsafeCell<FiberState>,
    /// Fiber priority
    priority: FiberPriority,
    /// Saved context for switching
    context: UnsafeCell<ThreadContext>,
    /// Fiber stack
    stack: Option<ThreadStack>,
    /// Entry function
    entry: Option<unsafe fn(usize)>,
    /// Argument to entry function
    arg: usize,
    /// Yield counter (for fairness)
    yield_counter: AtomicU32,
    /// Is main fiber
    is_main: bool,
    /// Join handle
    join_info: UnsafeCell<Option<Box<FiberJoin>>>,
}

unsafe impl Send for Fiber {}
unsafe impl Sync for Fiber {}

/// Fiber join information
pub struct FiberJoin {
    /// Result value
    pub result: usize,
    /// Is finished
    pub finished: AtomicBool,
}

/// Fiber state lock guard
pub struct FiberStateGuard<'a> {
    fiber: &'a Fiber,
}

impl Fiber {
    /// Create a new fiber
    pub fn new(name: Option<&str>, entry: unsafe fn(usize), arg: usize, stack_size: usize) -> Option<Self> {
        let stack = ThreadStack::alloc(stack_size)?;
        
        Some(Self {
            id: next_fiber_id(),
            name: name.map(|s| s.to_string()),
            state: UnsafeCell::new(FiberState::New),
            priority: FiberPriority::NORMAL,
            context: UnsafeCell::new(ThreadContext::empty()),
            stack: Some(stack),
            entry: Some(entry),
            arg,
            yield_counter: AtomicU32::new(0),
            is_main: false,
            join_info: UnsafeCell::new(None),
        })
    }
    
    /// Create the main fiber (for the current execution context)
    pub fn new_main(name: Option<&str>) -> Self {
        Self {
            id: next_fiber_id(),
            name: name.map(|s| s.to_string()),
            state: UnsafeCell::new(FiberState::Running),
            priority: FiberPriority::CRITICAL,
            context: UnsafeCell::new(ThreadContext::empty()),
            stack: None,
            entry: None,
            arg: 0,
            yield_counter: AtomicU32::new(0),
            is_main: true,
            join_info: UnsafeCell::new(None),
        }
    }
    
    /// Get fiber ID
    pub fn id(&self) -> FiberId {
        self.id
    }
    
    /// Get fiber name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    
    /// Get current state
    pub fn state(&self) -> FiberState {
        unsafe { *self.state.get() }
    }
    
    /// Set state
    pub fn set_state(&self, new_state: FiberState) {
        unsafe { *self.state.get() = new_state; }
    }
    
    /// Get priority
    pub fn priority(&self) -> FiberPriority {
        self.priority
    }
    
    /// Set priority
    pub fn set_priority(&self, priority: FiberPriority) {
        // Can't change main fiber priority
        if !self.is_main {
            // Priority change would need scheduler support
        }
    }
    
    /// Get yield count
    pub fn yield_count(&self) -> u32 {
        self.yield_counter.load(Ordering::SeqCst)
    }
    
    /// Increment yield counter
    fn inc_yield(&self) {
        self.yield_counter.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Check if this is the main fiber
    pub fn is_main(&self) -> bool {
        self.is_main
    }
    
    /// Get the saved context
    pub fn context(&self) -> &UnsafeCell<ThreadContext> {
        &self.context
    }
    
    /// Save current context into this fiber
    pub unsafe fn save_context(&self) {
        let ctx = &mut *self.context.get();
        thread_context_save(ctx);
    }
    
    /// Restore this fiber's context
    pub unsafe fn restore_context(&self) {
        let ctx = &mut *self.context.get();
        thread_context_restore(ctx);
    }
    
    /// Initialize fiber context for first run
    pub unsafe fn init_context(&self) {
        if let Some(ref stack) = self.stack {
            let ctx = &mut *self.context.get();
            if let Some(entry) = self.entry {
                thread_context_init(ctx, Self::fiber_entry_trampoline, stack);
            }
        }
    }
    
    /// Fiber entry trampoline
    unsafe extern "C" fn fiber_entry_trampoline() {
        // Get current fiber
        let fiber = FIBER_SCHEDULER.with(|sched| {
            unsafe { sched.current_fiber() }
        });
        
        if let Some(f) = fiber {
            // Set state to running
            f.set_state(FiberState::Running);
            
            // Call the actual entry point
            let entry = f.entry;
            let arg = f.arg;
            
            // Run user code
            if let Some(e) = entry {
                e(arg);
            }
            
            // Mark as finished
            f.set_state(FiberState::Finished);
            
            // Return control to scheduler
            FIBER_SCHEDULER.with(|sched| {
                unsafe { sched.fiber_finished(f) }
            });
        }
        
        // Never returns - scheduler takes over
        loop {}
    }
    
    /// Yield to another fiber
    pub fn yield_to(&self) {
        self.inc_yield();
        
        FIBER_SCHEDULER.with(|sched| {
            unsafe { sched.schedule_next(Some(self)) }
        });
    }
    
    /// Check if fiber is finished
    pub fn is_finished(&self) -> bool {
        self.state() == FiberState::Finished
    }
    
    /// Join (wait for) this fiber
    pub fn join(&self) -> usize {
        loop {
            if self.is_finished() {
                // Get join info
                let join = unsafe { &*self.join_info.get() };
                if let Some(ref j) = *join {
                    // Wait for finish
                    while !j.finished.load(Ordering::SeqCst) {
                        // Spin wait
                    }
                    return j.result;
                }
                return 0;
            }
            
            // Yield and try again
            self.yield_to();
        }
    }
}

// ============================================================================
// Fiber Scheduler
// ============================================================================

/// Fiber scheduler
pub struct FiberScheduler {
    /// Current running fiber
    current: UnsafeCell<Option<Arc<Fiber>>>,
    /// Ready queue (priority-sorted)
    ready: UnsafeCell<Vec<Arc<Fiber>>>,
    /// Blocked fibers
    blocked: UnsafeCell<Vec<Arc<Fiber>>>,
    /// Finished fibers
    finished: UnsafeCell<Vec<Arc<Fiber>>>,
    /// Total fibers created
    total_created: AtomicU32,
    /// Is running
    running: AtomicBool,
    /// Quantum for fair scheduling (yields after this many operations)
    quantum: usize,
    /// Operations since last yield
    ops_since_yield: AtomicUsize,
}

impl FiberScheduler {
    /// Create new scheduler
    pub fn new() -> Self {
        Self {
            current: UnsafeCell::new(None),
            ready: UnsafeCell::new(Vec::new()),
            blocked: UnsafeCell::new(Vec::new()),
            finished: UnsafeCell::new(Vec::new()),
            total_created: AtomicU32::new(0),
            running: AtomicBool::new(false),
            quantum: 100,
            ops_since_yield: AtomicUsize::new(0),
        }
    }
    
    /// Initialize with main fiber
    pub fn init(&self, main: Arc<Fiber>) {
        unsafe { *self.current.get() = Some(main); }
    }
    
    /// Spawn a new fiber
    pub fn spawn(&self, name: Option<&str>, entry: unsafe fn(usize), arg: usize) -> Arc<Fiber> {
        let fiber = Fiber::new(name, entry, arg, ThreadStack::DEFAULT_SIZE)
            .expect("Failed to allocate fiber");
        let fiber = Arc::new(fiber);
        
        // Add to ready queue
        self.add_ready(fiber.clone());
        
        self.total_created.fetch_add(1, Ordering::SeqCst);
        fiber
    }
    
    /// Add fiber to ready queue
    pub fn add_ready(&self, fiber: Arc<Fiber>) {
        fiber.set_state(FiberState::Ready);
        
        let ready = unsafe { &mut *self.ready.get() };
        
        // Insert in priority order
        let priority = fiber.priority();
        let pos = ready.iter().position(|f| f.priority() < priority);
        match pos {
            Some(p) => ready.insert(p, fiber),
            None => ready.push(fiber),
        }
    }
    
    /// Add fiber to blocked queue
    pub fn add_blocked(&self, fiber: Arc<Fiber>) {
        fiber.set_state(FiberState::Blocked);
        let blocked = unsafe { &mut *self.blocked.get() };
        blocked.push(fiber);
    }
    
    /// Get current fiber
    pub fn current_fiber(&self) -> Option<Arc<Fiber>> {
        unsafe { (*self.current.get()).clone() }
    }
    
    /// Set current fiber
    pub fn set_current(&self, fiber: Arc<Fiber>) {
        unsafe { *self.current.get() = Some(fiber); }
    }
    
    /// Schedule next fiber
    pub unsafe fn schedule_next(&self, current: Option<&Fiber>) -> Option<Arc<Fiber>> {
        // If current fiber is given and still ready, add it back to ready queue
        if let Some(cur) = current {
            if cur.state() == FiberState::Ready {
                // Re-add with same priority
                self.add_ready(Arc::from_raw(cur as *const Fiber));
            }
        }
        
        // Check quantum
        let ops = self.ops_since_yield.load(Ordering::SeqCst);
        if ops >= self.quantum {
            // Force yield
            let ready = unsafe { &mut *self.ready.get() };
            if let Some(mut next) = ready.pop() {
                self.ops_since_yield.store(0, Ordering::SeqCst);
                return Some(next);
            }
        }
        
        self.ops_since_yield.fetch_add(1, Ordering::SeqCst);
        
        // Get next from ready queue
        let ready = unsafe { &mut *self.ready.get() };
        ready.pop()
    }
    
    /// Called when a fiber finishes
    pub unsafe fn fiber_finished(&self, fiber: &Fiber) {
        fiber.set_state(FiberState::Finished);
        
        // Add to finished list
        let finished = unsafe { &mut *self.finished.get() };
        finished.push(Arc::from_raw(fiber));
        
        // Wake any joiners (would need join queue per fiber)
    }
    
    /// Run the scheduler
    pub fn run(&self) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        
        loop {
            let next = {
                let ready = unsafe { &mut *self.ready.get() };
                ready.pop()
            };
            
            match next {
                Some(fiber) => {
                    // Save current context
                    if let Some(current) = unsafe { (*self.current.get()).as_ref() } {
                        unsafe { current.save_context(); }
                    }
                    
                    // Switch to next fiber
                    self.set_current(fiber.clone());
                    fiber.set_state(FiberState::Running);
                    fiber.restore_context();
                    
                    // Never returns here - we come back via yield
                }
                None => {
                    // No more fibers
                    break;
                }
            }
        }
        
        self.running.store(false, Ordering::SeqCst);
    }
    
    /// Check if scheduler is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    
    /// Get number of ready fibers
    pub fn ready_count(&self) -> usize {
        unsafe { (*self.ready.get()).len() }
    }
    
    /// Get number of blocked fibers
    pub fn blocked_count(&self) -> usize {
        unsafe { (*self.blocked.get()).len() }
    }
    
    /// Get total fibers created
    pub fn total_created(&self) -> u32 {
        self.total_created.load(Ordering::SeqCst)
    }
}

impl Default for FiberScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TLS Storage for Scheduler
// ============================================================================

use core::cell::Cell;

thread_local! {
    static FIBER_SCHEDULER: FiberSchedulerState = FiberSchedulerState {
        scheduler: None,
        main_fiber: None,
    };
}

struct FiberSchedulerState {
    scheduler: Option<Arc<FiberScheduler>>,
    main_fiber: Option<Arc<Fiber>>,
}

impl FiberSchedulerState {
    fn with_scheduler<R, F: FnOnce(&FiberScheduler) -> R>(&self, f: F) -> R {
        if let Some(ref sched) = self.scheduler {
            f(sched)
        } else {
            panic!("No fiber scheduler initialized");
        }
    }
}

// ============================================================================
// Fiber API Functions
// ============================================================================

static mut GLOBAL_SCHEDULER: Option<Arc<FiberScheduler>> = None;

/// Initialize fiber subsystem
pub fn init_fibers() {
    unsafe {
        let sched = Arc::new(FiberScheduler::new());
        GLOBAL_SCHEDULER = Some(sched);
    }
}

/// Get global scheduler
pub fn fiber_scheduler() -> Option<&'static Arc<FiberScheduler>> {
    unsafe { GLOBAL_SCHEDULER.as_ref() }
}

/// Create and spawn a new fiber
pub fn fiber_spawn(name: Option<&str>, entry: unsafe fn(usize), arg: usize) -> Option<Arc<Fiber>> {
    fiber_scheduler().map(|s| s.spawn(name, entry, arg))
}

/// Yield current fiber
pub fn fiber_yield() {
    if let Some(sched) = fiber_scheduler() {
        if let Some(current) = sched.current_fiber() {
            current.yield_to();
        }
    }
}

/// Sleep current fiber for specified iterations
pub fn fiber_sleep() {
    if let Some(sched) = fiber_scheduler() {
        if let Some(current) = sched.current_fiber() {
            current.set_state(FiberState::Sleeping);
            current.yield_to();
        }
    }
}

/// Wake a blocked fiber
pub fn fiber_wake(fiber: &Fiber) {
    if let Some(sched) = fiber_scheduler() {
        if fiber.state() == FiberState::Blocked || fiber.state() == FiberState::Sleeping {
            sched.add_ready(Arc::from_raw(fiber as *const Fiber));
        }
    }
}

/// Get current fiber
pub fn current_fiber() -> Option<Arc<Fiber>> {
    fiber_scheduler().and_then(|s| s.current_fiber())
}

/// Run all ready fibers
pub fn fiber_run() {
    if let Some(sched) = fiber_scheduler() {
        sched.run();
    }
}

/// Check if in fiber context
pub fn in_fiber_context() -> bool {
    current_fiber().is_some()
}

// ============================================================================
// Channel for Fiber Communication
// ============================================================================

/// Fiber-safe channel
pub struct FiberChannel<T> {
    /// Internal buffer
    buffer: UnsafeCell<Option<T>>,
    /// Sender blocked
    sender_blocked: AtomicBool,
    /// Receiver blocked
    receiver_blocked: AtomicBool,
}

impl<T> FiberChannel<T> {
    /// Create new channel
    pub fn new() -> Self {
        Self {
            buffer: UnsafeCell::new(None),
            sender_blocked: AtomicBool::new(false),
            receiver_blocked: AtomicBool::new(false),
        }
    }
    
    /// Send value (blocking)
    pub fn send(&self, value: T) {
        // Check if buffer has value
        let empty = unsafe { (*self.buffer.get()).is_none() };
        
        if empty {
            // Put value in buffer
            unsafe { *self.buffer.get() = Some(value); }
        } else {
            // Block until receiver takes it
            self.sender_blocked.store(true, Ordering::SeqCst);
            fiber_yield();
            // Try again
            self.send(value);
        }
    }
    
    /// Receive value (blocking)
    pub fn recv(&self) -> T {
        loop {
            // Check if buffer has value
            let value = unsafe { (*self.buffer.get()).take() };
            
            match value {
                Some(v) => {
                    self.receiver_blocked.store(false, Ordering::SeqCst);
                    return v;
                }
                None => {
                    // Block until sender sends
                    self.receiver_blocked.store(true, Ordering::SeqCst);
                    fiber_yield();
                }
            }
        }
    }
    
    /// Try to receive without blocking
    pub fn try_recv(&self) -> Option<T> {
        unsafe { (*self.buffer.get()).take() }
    }
    
    /// Check if sender is blocked
    pub fn is_sender_blocked(&self) -> bool {
        self.sender_blocked.load(Ordering::SeqCst)
    }
    
    /// Check if receiver is blocked
    pub fn is_receiver_blocked(&self) -> bool {
        self.receiver_blocked.load(Ordering::SeqCst)
    }
}

impl<T> Default for FiberChannel<T> {
    fn default() -> Self {
        Self::new()
    }
}

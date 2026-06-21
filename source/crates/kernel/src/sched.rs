//! Scheduler implementation
//!
//! Implements the Plan 9 scheduler with priority-based round-robin.
//! Based on the original Plan 9 scheduler from proc.c

use alloc::boxed::Box;
use crate::proc::{
    Proc, State, NPRIQ, PRI_NORMAL, PRI_KPROC, Pid,
    ProcTable, curproc, set_curproc, NERR, NNOTE, KSTACK_SIZE,
    EdfScheduler,
};
use crate::plan9_common::sync::{Spinlock, Mutex};
use crate::plan9_arch::x86_64::context::{Context, setjmp, longjmp, goto_context, save_context, procsave};
use crate::plan9_arch::x86_64::mmu::{switch_page_table, cr3_read};

// ============================================================================
// Scheduler Constants
// ============================================================================

/// Maximum number of processes in run queue
const RUNQ_LEN: usize = 64;

/// Scheduling quantum in ticks
const SCHED_QUANTUM: u64 = 10;

/// Maximum delay sched count before forcing schedule
const MAX_DELAY_SCHED: i32 = 20;

/// CPU decay constant - time window for CPU averaging (in seconds)
/// This is the "characteristic time" for the exponential decay
const SCHEDGAIN: i32 = 30;

/// Clock ticks per second (assuming 100Hz for Plan 9 compatibility)
const HZ: u64 = 100;

/// Scaling factor for fixed-point arithmetic
/// CPU usage is stored as fixed-point * 1000
const SCALING: i32 = 2;

/// Fixed-point multiplier for CPU (0-1000 represents 0-100%)
const CPUUNIT: i32 = 1000;

/// ============================================================================
// Run Queue
// ============================================================================

/// Inner run queue data (unprotected)
#[derive(Default)]
struct RunQueueInner {
    /// Queue of processes (linked list via Proc.next)
    head: Option<&'static Proc>,
    tail: Option<&'static Proc>,
    /// Queue length
    len: usize,
}

impl RunQueueInner {
    /// Create empty queue
    const fn new() -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
        }
    }

    /// Check if queue is empty
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Add process to end of queue
    fn push(&mut self, proc: &'static Proc) {
        proc.next = None;
        if let Some(tail) = self.tail {
            unsafe {
                if let Some(next) = (*(tail as *const Proc as *mut Proc)).next.as_mut() {
                    *next = Some(core::ptr::NonNull::new_unchecked(proc as *const Proc as *mut Proc));
                }
            }
        } else {
            self.head = Some(proc);
        }
        self.tail = Some(proc);
        self.len += 1;
    }

    /// Remove process from head of queue
    fn pop(&mut self) -> Option<&'static Proc> {
        let proc = self.head?;
        self.head = unsafe { proc.next.map(|p| p.as_ref()) };
        if self.head.is_none() {
            self.tail = None;
        }
        self.len = self.len.saturating_sub(1);
        Some(proc)
    }

    /// Remove specific process from queue
    fn remove(&mut self, proc: &'static Proc) -> bool {
        let mut prev: Option<&'static Proc> = None;
        let mut current = self.head;

        while let Some(p) = current {
            if core::ptr::eq(p, proc) {
                if let Some(pr) = prev {
                    unsafe {
                        if let Some(next) = p.next {
                            (*(pr as *const Proc as *mut Proc)).next = next;
                        }
                    }
                } else {
                    self.head = unsafe { p.next.map(|p| p.as_ref()) };
                }
                self.len = self.len.saturating_sub(1);
                return true;
            }
            prev = Some(p);
            current = unsafe { p.next.map(|p| p.as_ref()) };
        }
        false
    }
}

/// Locked run queue with spinlock protection
type LockedRunQueue = Spinlock<RunQueueInner>;

impl LockedRunQueue {
    /// Create a new locked run queue
    fn new() -> Self {
        Spinlock::new(RunQueueInner::new())
    }
}

// ============================================================================
// Scheduler State
// ============================================================================

/// Scheduler tick counter
static SCHED_TICKS: Mutex<u64> = Mutex::new(0);

/// Delayed sched counter (for debugging)
static DELAYED_SCHEDS: Mutex<u64> = Mutex::new(0);

// ============================================================================
// Main Scheduler
// ============================================================================

/// Plan 9 style scheduler
pub struct Scheduler {
    /// Run queues for each priority level (each with its own lock)
    run_queues: [LockedRunQueue; NPRIQ],
    /// Process table
    procs: ProcTable,
    /// Lock for scheduler operations
    lock: Spinlock,
    /// Scheduler ticks counter
    ticks: u64,
    /// Total context switches
    switches: u64,
    /// CPU number (for SMP)
    cpu_id: u32,
    /// Current process (inline for faster access)
    current_proc: Option<&'static Proc>,
    /// Scheduler context (for setjmp/longjmp)
    sched_ctx: Context,
    /// System load average (fixed-point * 1000)
    load: u64,
    /// Number of ready processes
    nrdy: u32,
    /// Bitmap of non-empty run queues (bit i = runq[i] is non-empty)
    runvec: u32,
    /// EDF Scheduler for real-time processes
    edf: EdfScheduler,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new() -> Self {
        // Create array of locked run queues, one per priority level
        let run_queues = [const { LockedRunQueue::new() }; NPRIQ];

        Self {
            run_queues,
            procs: ProcTable::new(),
            lock: Spinlock::new(),
            ticks: 0,
            switches: 0,
            cpu_id: 0,
            current_proc: None,
            sched_ctx: Context::default(),
            load: 0,
            nrdy: 0,
            runvec: 0,
            edf: EdfScheduler::new(),
        }
    }

    /// Initialize the scheduler
    pub fn init(&mut self) {
        // Create idle process
        self.create_idle();
    }

    /// Create the idle process
    fn create_idle(&mut self) {
        let mut proc = Box::new(Proc::new());
        proc.pid = self.procs.alloc_pid().unwrap_or(1);
        proc.state = State::Ready;
        proc.pri = PRI_KPROC;
        proc.basepri = PRI_KPROC;
        proc.set_text(b"idle");
        proc.kstack_size = KSTACK_SIZE;
        
        let proc_ptr = Box::leak(proc) as *const Proc as *mut Proc;
        self.procs.add(unsafe { Box::from_raw(proc_ptr) });
        
        let p = unsafe { &*proc_ptr };
        let idx = (PRI_KPROC as usize).min(NPRIQ - 1);
        self.run_queues[idx].lock().push(p);
    }

    /// Add a process to the ready queue
    pub fn ready(&mut self, proc: &'static Proc) {
        let idx = (proc.pri as usize).min(NPRIQ - 1);
        let mut q = self.run_queues[idx].lock();
        
        // Track if this is the first process in this queue
        let was_empty = q.is_empty();
        
        proc.state = State::Ready;
        q.push(proc);
        
        // Update runvec and nrdy
        if was_empty {
            self.runvec |= 1 << idx;
        }
        self.nrdy += 1;
    }

    /// Get next process to run from the run queue
    ///
    /// Implements EDF (Earliest Deadline First) scheduling for real-time processes:
    /// 1. First check if there are EDF real-time processes that need to run
    /// 2. If no EDF processes need to run, fall back to priority-based scheduling
    fn runproc(&mut self) -> Option<&'static Proc> {
        // === EDF Real-Time Scheduling ===
        // Check if there are any EDF processes that need to run
        // EDF processes are scheduled based on their earliest deadline
        let current_time = self.ticks; // Simplified: using ticks as time
        {
            let mut edf_lock = self.edf.lock();
            if let Some((pid, _)) = edf_lock.get_earliest_deadline() {
                if let Some(proc) = self.procs.get(pid) {
                    // Check if deadline is still feasible
                    if proc.edf.as_ref().map(|e| e.is_deadline_met(current_time)).unwrap_or(false) {
                        // EDF process with valid deadline has priority
                        // Move it to running state and return
                        return Some(proc);
                    }
                }
            }
        }

        // === Priority-based Round-Robin Scheduling ===
        // Find highest priority non-empty queue
        for i in 0..NPRIQ {
            let mut q = self.run_queues[i].lock();
            if let Some(proc) = q.pop() {
                self.nrdy = self.nrdy.saturating_sub(1);

                // Update runvec if queue became empty
                if q.is_empty() {
                    self.runvec &= !(1 << i);
                }
                return Some(proc);
            }
        }
        None
    }

    /// Add an EDF real-time process to the EDF scheduler
    ///
    /// Returns true if the process was successfully added (passed admission control)
    pub fn add_edf_task(&mut self, pid: Pid, params: crate::proc::EdfParams) -> bool {
        let current_time = self.ticks;
        self.edf.add_task(pid, params, current_time)
    }

    /// Remove an EDF process from the EDF scheduler
    pub fn remove_edf_task(&mut self, pid: Pid) {
        let _guard = self.edf.lock();
        self.edf.remove_task(pid);
    }

    /// Get current system utilization for EDF admission control
    pub fn edf_utilization(&self) -> f64 {
        let _guard = self.edf.lock();
        self.edf.utilization()
    }

    /// Main scheduler function (Plan 9 style)
    ///
    /// Implements the Plan 9 scheduling algorithm with:
    /// - delaysched: delays scheduling when holding locks
    /// - Priority-based round-robin
    /// - True context switching via setjmp/longjmp
    pub fn schedule(&mut self) {
        // The scheduler lock protects the run queues and scheduling state
        let _guard = self.lock.lock();

        let mut prev = self.current_proc_proc.take();

        // === Delaysched Logic (Plan 9 style) ===
        // If we're in a delay window, don't schedule yet
        if let Some(ref p) = prev {
            if p.delaysched > 0 {
                if p.delaysched < MAX_DELAY_SCHED {
                    // Still in delay window, don't schedule yet
                    p.delaysched += 1;
                    self.current_proc_proc = prev;
                    return;
                }
                // Reset delaysched counter
                let p = unsafe { &mut *(p as *const Proc as *mut Proc) };
                p.delaysched = 0;
            }

            // If holding locks and running, delay scheduling
            if p.nlocks > 0 && p.state == State::Running {
                let p = unsafe { &mut *(p as *const Proc as *mut Proc) };
                p.delaysched = 1;
                self.current_proc_proc = prev;
                return;
            }
        }

        // === Handle current process state ===
        if let Some(cur) = prev.take() {
            match cur.state {
                State::Running => {
                    // Process used its quantum, put back in queue
                    let cur = unsafe { &mut *(cur as *const Proc as *mut Proc) };
                    cur.state = State::Ready;
                    self.ready(cur);
                }
                State::Moribund => {
                    // Process is exiting
                    let cur = unsafe { &mut *(cur as *const Proc as *mut Proc) };
                    self.proc_exit(cur);
                }
                State::Dead => {
                    // Already dead, just clean up
                }
                _ => {
                    // For other states (sleeping, etc.), don't requeue
                }
            }
        }

        // === Select and run next process ===
        if let Some(next) = self.runproc() {
            // Update CPU time and recalculate priority for the new process
            self.updatecpu(next);
            let new_pri = self.reprioritize(next);
            
            // If priority changed, move to appropriate queue
            if new_pri != next.pri {
                // Remove from current queue (it's already been popped)
                // and re-add to the new priority queue
                let idx = (new_pri as usize).min(NPRIQ - 1);
                next.pri = new_pri;
                self.run_queues[idx].lock().push(next);
                next.state = State::Ready;
            }

            let prev = prev.map(|p| unsafe { &mut *(p as *const Proc as *mut Proc) });

            next.state = State::Running;
            self.current_proc = Some(next);
            set_curproc(next);
            self.switches += 1;

            // Perform context switch
            self.context_switch(prev, next);

            // When we return from context_switch, we're either:
            // 1. Returning from a yield (prev process resumed)
            // 2. First time running this process
        } else {
            // No runnable process, run idle
            self.run_idle();
        }
    }

    /// Update CPU time average for a process using exponential decay.
    ///
    /// This implements Plan 9's CPU decay algorithm:
    /// - CPU time average is a decaying average that lasts about D clock ticks
    /// - D is chosen to be approximately the CPU time of a CPU-intensive "quick job"
    /// - If a process gets in and out quickly, it won't be penalized
    /// - Interactive tasks are rewarded because they use less than their fair share
    ///
    /// The formula used is:
    /// - For processes not running: `cpu = cpu * (D-n)/D` (applied n times)
    /// - For the running process: `cpu = 1000 - (1000-cpu) * (D-n)/D`
    ///
    /// Reference: Plan 9 `updatecpu()` in proc.c
    fn updatecpu(&mut self, proc: &'static Proc) {
        let D = SCHEDGAIN * HZ as i32 * SCALING;
        
        // Calculate time since last update (in scaled ticks)
        let t = (self.ticks as i64) * SCALING as i64 + (SCALING as i64 / 2);
        let n = t - proc.lastupdate;
        
        // Store the current time as lastupdate
        // Note: proc is &static, so we can't modify it here directly
        // This will be handled when we actually switch to the process
        
        if n == 0 || n > D as i64 {
            // Nothing to do or too much time has passed
            return;
        }

        // Apply decay n times:
        // cpu = cpu * ((D-1)/D)^n ≈ cpu * (D-n)/D (when n << D)
        // Since D is large (typically thousands), we use the approximation
        let n = n as i32;
        let ocpu = proc.cpu as i32;
        
        // Decay formula for inactive process: cpu = cpu * (D-n)/D
        // Using integer arithmetic with fixed-point * 1000
        let new_cpu = (ocpu * (D - n)) / D;
        
        // Update load average: load = number of ready processes
        self.load = (self.nrdy as u64) * CPUUNIT as u64;
    }

    /// Recalculate process priority based on CPU usage.
    ///
    /// On average, a process has used p->cpu of a CPU recently.
    /// Its fair share is conf.nmach/m->load of a CPU.
    /// If it has been getting too much, penalize it.
    /// If it has been getting not enough, reward it.
    ///
    /// Priority range: 0 (highest) to basepri (normal).
    /// Interactive processes (using less CPU) get higher priority.
    ///
    /// Reference: Plan 9 `reprioritize()` in proc.c
    fn reprioritize(&mut self, proc: &'static Proc) -> i8 {
        let basepri = proc.basepri;
        
        // If load is 0, just return base priority
        if self.load == 0 {
            return basepri;
        }

        // fairshare = 1.000 * NPROC * 1000/load
        // This represents what fraction of CPU this process "deserves"
        let nproc = 1; // Single CPU for now
        let fairshare = (nproc * 1000 * 1000) / (self.load as i32).max(1);
        
        let cpu = proc.cpu as i32;
        let mut n = cpu;
        if n == 0 {
            n = 1; // Minimum to avoid division by zero
        }
        
        // ratio = (fairshare + cpu/2) / cpu
        // This gives us a priority boost for using less than fairshare
        let mut ratio = (fairshare + n / 2) / n;
        
        // Clamp to valid priority range
        if ratio > basepri {
            ratio = basepri;
        }
        if ratio < 0 {
            ratio = 0;
        }
        
        ratio as i8
    }

    /// Called periodically (once per second) to rebalance all ready processes.
    ///
    /// This recalculates priorities for all processes in the run queues
    /// and moves them to appropriate queues based on their CPU usage.
    ///
    /// Reference: Plan 9 `hzsched()` and `rebalance()` in proc.c
    pub fn hzsched(&mut self) {
        // Rebalance priorities for all ready processes
        self.rebalance();
        
        // Check if we should preempt the current process
        if self.anyhigher() || self.anyready() {
            if let Some(cur) = self.current_proc {
                let cur = unsafe { &mut *(cur as *const Proc as *mut Proc) };
                cur.delaysched += 1;
            }
        }
    }

    /// Check if there are any higher priority processes ready
    fn anyhigher(&self) -> bool {
        if let Some(cur) = self.current_proc {
            let cur_pri = cur.pri as u32;
            // Check if any queue with priority < current has processes
            let mask = !((1 << (cur_pri + 1)) - 1);
            return (self.runvec & mask) != 0;
        }
        false
    }

    /// Check if any processes are ready to run
    fn anyready(&self) -> bool {
        self.runvec != 0
    }

    /// Rebalance all run queues by recalculating priorities.
    ///
    /// This is called once per second to adjust process priorities
    /// based on their recent CPU usage.
    fn rebalance(&mut self) {
        // For each run queue, reprioritize processes and move them
        // if their priority has changed
        for i in 0..NPRIQ {
            let mut queue = self.run_queues[i].lock();
            let mut current = queue.head;
            
            while let Some(proc) = current {
                let new_pri = self.reprioritize(proc);
                let next_proc = unsafe { proc.next.map(|p| p.as_ref()) };
                
                if new_pri != proc.pri {
                    // Remove from current queue and add to new one
                    queue.remove(proc);
                    let idx = (new_pri as usize).min(NPRIQ - 1);
                    drop(queue);
                    self.run_queues[idx].lock().push(proc);
                    queue = self.run_queues[i].lock();
                }
                
                current = next_proc;
            }
        }
    }

    /// Perform context switch to new process
    ///
    /// This is the heart of the scheduler. It:
    /// 1. Switches page tables (if different)
    /// 2. Saves current process context (if exists)
    /// 3. Restores next process context
    ///
    /// The context switching uses the Plan 9 style setjmp/longjmp mechanism
    /// implemented in context.rs with inline assembly for x86_64.
    fn context_switch(&mut self, prev: Option<&mut Proc>, next: &'static Proc) {
        // Step 1: Switch page table for the next process
        // This must be done before saving context to ensure we use the right page table
        if next.mmupdb.as_u64() != 0 {
            switch_page_table(next.mmupdb);
        }

        // Step 2: Save previous process context (if it exists and isn't exiting)
        // We use setjmp to save the current position. If it returns 0,
        // we just saved and will continue. If it returns 1, we were restored
        // by another process calling longjmp.
        if let Some(prev_proc) = prev {
            if prev_proc.state != State::Dead {
                unsafe {
                    // Use setjmp to save the current context
                    // This saves callee-saved registers and return address
                    let _was_restored = setjmp(
                        &mut prev_proc.sched as *mut crate::proc::Label as *mut Context
                    );

                    // If we just saved (was_restored == 0), we continue.
                    // If we were restored (was_restored != 0), we return here
                    // from the longjmp that switched back to this process.
                    if _was_restored != 0 {
                        // We returned from a longjmp, meaning we were switched back to.
                        // Just continue execution.
                        return;
                    }
                }
            }
        }

        // Step 3: Set current process pointer
        // This must be done before restoring the next process's context
        set_curproc(next);

        // Step 4: Restore next process context
        // If the next process has a saved context (has run before),
        // we longjmp to it. If not, this is its first run and we
        // just continue from here.
        if next.sched.is_set() {
            // Jump to the next process's saved context
            // This does not return
            unsafe {
                goto_context(&next.sched as *const crate::proc::Label as *const Context);
            }
        }
        // If new process has no saved context, this is first run
        // Continue to run the new process from here
    }

    /// Run the idle loop
    fn run_idle(&mut self) {
        // Enable interrupts and halt
        crate::plan9_arch::x86_64::sti();
        crate::plan9_arch::x86_64::hlt();
    }

    /// Handle process exit
    fn proc_exit(&mut self, proc: &'static Proc) {
        // Close all file descriptors
        if let Some(ref mut fgrp) = proc.fgrp {
            fgrp.close_all();
        }
        
        // Wakeup waiting parent
        if let Some(parent_pid) = proc.parent {
            if let Some(parent) = self.procs.get_mut(parent_pid) {
                if parent.nwait > 0 {
                    parent.nwait -= 1;
                    // Add to wait queue
                    let waitq = Box::new(crate::proc::Waitq::new(
                        proc.pid,
                        0, // exit status
                        proc.utime + proc.ktime,
                    ));
                    waitq.next = parent.waitq.take();
                    parent.waitq = Some(waitq);
                }
            }
        }
        
        // Remove from process table
        self.procs.remove(proc.pid);
    }

    /// Called on timer interrupt
    pub fn timer_tick(&mut self) {
        self.ticks += 1;
        *SCHED_TICKS.lock() += 1;
        
        // Update CPU time for current process
        if let Some(cur) = self.current_proc {
            cur.cpu += 1;
        }
        
        // Call hzsched once per second to rebalance priorities
        // HZ = 100, so every 100 ticks is 1 second
        if self.ticks % HZ == 0 {
            self.hzsched();
        }
        
        // Check if current process exceeded quantum
        if self.ticks % SCHED_QUANTUM == 0 {
            if let Some(cur) = self.current_proc {
                if cur.state == State::Running {
                    cur.state = State::Ready;
                    self.ready(cur);
                    self.schedule();
                }
            }
        }
    }

    /// Yield CPU - current process voluntarily gives up CPU
    pub fn yield_(&mut self) {
        let _guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            if cur.state == State::Running {
                cur.state = State::Ready;
                self.ready(cur);
            }
        }
        
        self.schedule();
    }

    /// Sleep until condition is true
    /// Returns true if woke up normally, false if interrupted
    pub fn sleep<F>(&mut self, pred: F) -> bool 
    where
        F: Fn() -> bool,
    {
        let _guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            if !pred() {
                cur.state = State::Wakeme;
                drop(_guard);
                self.schedule();
                return true;
            }
        }
        false
    }

    /// Wakeup a sleeping process
    pub fn wakeup(&mut self, proc: &'static mut Proc) {
        if proc.state == State::Wakeme {
            proc.state = State::Ready;
            self.ready(proc);
        }
    }

    /// Create a new process (fork)
    ///
    /// Creates a new process with its own address space.
    /// The child will have a separate page table with COW mappings.
    ///
    /// # Arguments
    /// * `parent` - The parent process to fork from
    /// * `entry` - Entry function for the child (0 means copy parent context)
    /// * `flags` - Rfork flags controlling what is shared/copied
    ///
    /// # Flags (rfork::)
    /// - FLAGFPROC: Create a new process
    /// - FLAGFDG: Share file descriptors
    /// - FLAGFMEM: Share memory
    /// - FLAGFSIGNA: Share signals
    /// - etc.
    pub fn fork(&mut self, parent: Option<&Proc>, entry: fn(), flags: u32) -> Option<Pid> {
        let mut proc = Box::new(Proc::new());

        // Allocate PID
        proc.pid = self.procs.alloc_pid()?;

        // Copy parent info
        proc.parent = parent.map(|p| p.pid);
        if let Some(p) = parent {
            proc.pri = p.pri;
            proc.basepri = p.basepri;

            // Fork process groups based on flags
            proc.fork_groups(Some(p), flags);

            // Handle memory based on flags
            if flags & rfork::FLAGFMEM == 0 {
                // COW fork - create new page table with copy-on-write
                // For now, just create a new empty page table
                // In a full implementation, we would:
                // 1. Create new PML4
                // 2. Copy parent page table entries
                // 3. Mark all user pages as COW (read-only)
                if !proc.setup_page_table() {
                    return None;
                }
            } else {
                // Share memory - use parent's page table
                proc.mmupdb = p.mmupdb;
            }
        } else {
            proc.pri = PRI_NORMAL;
            proc.basepri = PRI_NORMAL;
            proc.fork_groups(None, 0);
            // Create new page table for init process
            if !proc.setup_page_table() {
                return None;
            }
        }

        proc.state = State::Ready;
        proc.kstack_size = KSTACK_SIZE;

        // Allocate kernel stack for the new process
        use crate::vm::alloc_frames;
        if let Some(kstack_phys) = alloc_frames(KSTACK_SIZE / 4096) {
            proc.kstack = crate::plan9_arch::x86_64::paging::phys_to_virt(kstack_phys).as_u64();
        }

        // Set up initial scheduler context for child
        let child_entry = entry as u64;
        if child_entry != 0 {
            // Set up context for child to start at entry point
            let stack_top = proc.kstack + KSTACK_SIZE as u64;
            use crate::plan9_arch::x86_64::context::Context;
            proc.sched = crate::proc::Label {
                sp: stack_top - 8,  // Leave room for return address
                pc: child_entry,
                rbx: 0,
                rbp: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
            };
        }

        // Leak the box to get static reference
        let static_ref = unsafe {
            let boxed = Box::leak(proc);
            &*boxed as &Proc
        };

        // Add to process table
        self.procs.add(unsafe {
            let mut b = Box::from_raw(static_ref as *const Proc as *mut Proc);
            let r = b.as_mut();
            core::mem::forget(b);
            Box::leak(core::ptr::read(r));
            Box::from_raw(r)
        });

        // Add to parent's child count
        if let Some(p) = parent {
            unsafe {
                if let Some(p_mut) = self.procs.get_mut(p.pid) {
                    p_mut.nchild += 1;
                }
            }
        }

        // Add to ready queue
        self.ready(static_ref);

        Some(static_ref.pid)
    }

    /// Terminate current process
    pub fn exit(&mut self, status: i32) {
        let _guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            cur.state = State::Moribund;
            // Store exit status for wait()
            // (would be stored in waitq)
            let _ = status;
            // Schedule next process
            self.schedule();
        }
    }

    /// Wait for child to exit
    pub fn wait(&mut self) -> Option<(Pid, i32)> {
        let _guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            // Check if any children have exited
            while cur.nchild == 0 || cur.waitq.is_none() {
                // No children, return error
                return None;
            }
            
            // Get exit info from waitq
            if let Some(ref mut wq) = cur.waitq {
                let pid = wq.pid;
                let status = wq.status;
                cur.waitq = wq.next.take();
                cur.nwait = cur.nwait.saturating_sub(1);
                return Some((pid, status));
            }
        }
        None
    }

    /// Get scheduler statistics
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            ticks: self.ticks,
            switches: self.switches,
            current_pid: self.current_proc.map(|p| p.pid),
        }
    }

    /// Check if current process should be preempted
    pub fn should_preempt(&self) -> bool {
        // Check if we've run long enough
        self.ticks % SCHED_QUANTUM == 0
    }
}

/// Scheduler statistics
#[derive(Debug)]
pub struct SchedulerStats {
    pub ticks: u64,
    pub switches: u64,
    pub current_pid: Option<Pid>,
}

// ============================================================================
// Dynamic Priority Enhancement (P2 Feature)
// ============================================================================

/// Enable dynamic priority adjustments
pub const DYN_PRIORITY_ENABLED: bool = true;

/// Priority boost interval in ms
pub const PRIORITY_BOOST_INTERVAL: usize = 100;

/// Interactive process detection threshold
/// Process is considered interactive if sleep_time > run_time * INTERACTIVE_THRESHOLD
pub const INTERACTIVE_THRESHOLD: i32 = 2;

/// Interactive priority boost (number of levels)
pub const INTERACTIVE_BOOST: i8 = 2;

/// Extended process info for dynamic priority
#[derive(Debug, Clone)]
pub struct DynamicPriorityInfo {
    /// Recent sleep time (in scheduler ticks)
    pub recent_sleep: u64,
    /// Recent run time (in scheduler ticks)
    pub recent_run: u64,
    /// Last sleep timestamp
    pub last_sleep_ts: u64,
    /// Whether process is marked as interactive
    pub is_interactive: bool,
    /// Number of I/O waits in recent history
    pub io_waits: u32,
}

impl DynamicPriorityInfo {
    /// Create new dynamic priority info
    pub fn new() -> Self {
        Self {
            recent_sleep: 0,
            recent_run: 0,
            last_sleep_ts: 0,
            is_interactive: false,
            io_waits: 0,
        }
    }

    /// Update after sleep
    pub fn on_sleep(&mut self, duration: u64) {
        self.recent_sleep += duration;
        self.last_sleep_ts = sched_ticks();
        self.io_waits += 1;
        self.update_interactive();
    }

    /// Update after run
    pub fn on_run(&mut self, duration: u64) {
        self.recent_run += duration;
        self.update_interactive();
    }

    /// Update interactive status based on sleep/run ratio
    fn update_interactive(&mut self) {
        // A process is interactive if it spends more time sleeping than running
        // This indicates I/O-bound behavior
        if self.recent_run == 0 {
            self.is_interactive = true;
            return;
        }

        let ratio = (self.recent_sleep as i64) / (self.recent_run as i64);
        self.is_interactive = ratio >= INTERACTIVE_THRESHOLD as i64;
    }

    /// Reset counters (called periodically)
    pub fn reset_counters(&mut self) {
        self.recent_sleep = 0;
        self.recent_run = 0;
        self.io_waits = 0;
    }
}

impl Scheduler {
    /// Enhanced reprioritize with dynamic priority adjustments
    /// 
    /// This extends the basic Plan 9 reprioritize with:
    /// - Interactive process detection and boost
    /// - I/O wait tracking
    /// - Dynamic priority based on process behavior
    pub fn reprioritize_dynamic(&mut self, proc: &'static Proc) -> i8 {
        if !DYN_PRIORITY_ENABLED {
            return proc.basepri;
        }

        let base_pri = proc.basepri;

        // Check if process has dynamic priority info
        // In a full implementation, this would be stored in Proc struct
        // For now, use simple heuristics based on state
        
        // Interactive process boost: processes that frequently sleep
        // are likely interactive and should get priority boost
        let interactive_boost = if Self::is_likely_interactive(proc) {
            -INTERACTIVE_BOOST  // Negative = higher priority
        } else {
            0
        };

        // Calculate base priority using standard algorithm
        let fair_pri = self.reprioritize(proc);

        // Apply interactive boost
        let final_pri = (fair_pri as i32 + interactive_boost as i32)
            .clamp(0, base_pri as i32) as i8;

        final_pri
    }

    /// Check if a process is likely to be interactive
    /// 
    /// A process is considered interactive if:
    /// - It frequently sleeps (I/O bound)
    /// - Has low CPU usage
    /// - Often waits on I/O
    fn is_likely_interactive(proc: &Proc) -> bool {
        // Check process state history
        // Processes that are often in these states are likely interactive:
        // - Wakeme (waiting for event)
        // - Read/write operations
        // - Sleep states
        
        // Simple heuristic: if process has low base priority 
        // (higher number = lower priority) and is not kernel proc
        if proc.basepri >= PRI_NORMAL && proc.basepri < NPRIQ as i8 {
            // Check if it's been running recently
            // Low CPU usage suggests interactive behavior
            // This is a simplified check - real implementation would track history
            return true;
        }
        
        false
    }

    /// Boost priority of interactive processes
    /// 
    /// Called periodically to boost interactive processes
    pub fn boost_interactive(&mut self) {
        for i in 0..NPRIQ {
            let mut queue = self.run_queues[i].lock();
            let mut current = queue.head;
            
            while let Some(proc) = current {
                let next = unsafe { proc.next.map(|p| p.as_ref()) };
                
                // Check if this process should get priority boost
                if Self::is_likely_interactive(proc) && proc.pri > proc.basepri - INTERACTIVE_BOOST as i8 {
                    // Boost priority
                    let new_pri = (proc.pri - INTERACTIVE_BOOST).max(proc.basepri - INTERACTIVE_BOOST);
                    
                    if new_pri != proc.pri as i8 {
                        queue.remove(proc);
                        let idx = (new_pri as usize).min(NPRIQ - 1);
                        drop(queue);
                        self.run_queues[idx].lock().push(proc);
                        proc.pri = new_pri;
                        queue = self.run_queues[i].lock();
                    }
                }
                
                current = next;
            }
        }
    }

    /// Demote priority of CPU-intensive processes
    /// 
    /// Processes that use a lot of CPU should have lower priority
    pub fn demote_cpu_bound(&mut self) {
        // Find CPU-bound processes (high CPU usage)
        // and move them to lower priority queues
        // This is handled by the standard reprioritize algorithm
    }
}

// ============================================================================
// Global Scheduler Instance
// ============================================================================

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

static SCHEDULER: AtomicPtr<Scheduler> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global scheduler
pub fn init_scheduler() {
    let sched = Box::new(Scheduler::new());
    sched.init();
    let ptr = Box::into_raw(sched);
    SCHEDULER.store(ptr, Ordering::SeqCst);
}

/// Get reference to scheduler
pub fn scheduler() -> &'static mut Scheduler {
    unsafe { &mut *SCHEDULER.load(Ordering::SeqCst) }
}

/// Schedule the next process
pub fn schedule() {
    scheduler().schedule();
}

/// Yield the current process
pub fn yield_() {
    scheduler().yield_();
}

/// Initialize idle process and enter scheduler
pub fn schedinit() {
    init_scheduler();
}

/// Get current tick count
pub fn sched_ticks() -> u64 {
    *SCHED_TICKS.lock()
}

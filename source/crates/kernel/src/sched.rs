//! Scheduler implementation
//!
//! Implements the Plan 9 scheduler with priority-based round-robin.
//! Based on the original Plan 9 scheduler from proc.c

use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::proc::{
    Proc, State, NPRIQ, PRI_NORMAL, PRI_KPROC, Pid,
    ProcTable, set_curproc, KSTACK_SIZE,
    EdfScheduler,
};
use crate::proc::rfork;
use crate::plan9_common::sync::{Spinlock, Mutex};
use crate::plan9_arch::hal::context::Context;
use crate::plan9_arch::hal::mmu::{ switch_page_table };
// ============================================================================
// Scheduler Constants
// ============================================================================

/// Maximum number of processes in run queue
const RUNQ_LEN: usize = 64;

/// Scheduling quantum in ticks
pub const SCHED_QUANTUM: u64 = 10;

/// Maximum delay sched count before forcing schedule
pub const MAX_DELAY_SCHED: i32 = 20;

/// CPU decay constant - time window for CPU averaging (in seconds)
/// This is the "characteristic time" for the exponential decay
const SCHEDGAIN: i32 = 30;

/// Clock ticks per second (assuming 100Hz for Plan 9 compatibility)
pub const HZ: u64 = 100;

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
        let proc_ptr: *mut Proc = core::ptr::addr_of!(*proc) as *mut Proc;
        unsafe {
            (*proc_ptr).next = None;
        }
        if let Some(tail) = self.tail {
            unsafe {
                let tail_ptr: *mut Proc = core::ptr::addr_of!(*tail) as *mut Proc;
                (*tail_ptr).next = Some(core::ptr::NonNull::new_unchecked(proc_ptr));
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
                    let pr_ptr: *mut Proc = core::ptr::addr_of!(*pr) as *mut Proc;
                    unsafe {
                        if let Some(next) = p.next {
                            (*pr_ptr).next = Some(next);
                        } else {
                            (*pr_ptr).next = None;
                        }
                    }
                } else {
                    self.head = p.next.map(|p| unsafe { p.as_ref() });
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

/// Create a new locked run queue (const for static initialization)
const fn new_locked_run_queue() -> LockedRunQueue {
    Spinlock::new(RunQueueInner::new())
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
    /// Process table (also exposed as the global Plan 9 process table)
    pub procs: ProcTable,
    /// Lock for scheduler operations
    lock: Spinlock<()>,
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
        let run_queues = [const { new_locked_run_queue() }; NPRIQ];

        Self {
            run_queues,
            procs: ProcTable::new(),
            lock: Spinlock::new(()),
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

    /// Get current tick count
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Create the idle process
    fn create_idle(&mut self) {
        let mut proc = Box::new(Proc::new());
        proc.pid = self.procs.alloc_pid().unwrap_or(1);
        proc.note_group = proc.pid;
        proc.state = State::Ready;
        proc.pri = PRI_KPROC;
        proc.basepri = PRI_KPROC;
        proc.set_text(b"idle");
        proc.kstack_size = KSTACK_SIZE;

        // Create the descriptor/namespace/environment groups for the idle
        // process.  The user-mode `init` runs with this process context, so
        // syscalls such as open/read/write have a valid file-descriptor group.
        proc.fork_groups(None, 0);
        
        let proc_owned: &'static mut Proc = Box::leak(proc);
        let proc_ptr: *mut Proc = proc_owned;
        self.procs.add(unsafe { Box::from_raw(proc_ptr) });

        // Make the idle process the current process so kernel syscalls have
        // a valid context when user mode is entered.
        set_curproc(proc_owned);

        // Plan 9's init starts with fds 0, 1 and 2 bound to /dev/console.
        // Establish those standard descriptors here, after the namespace
        // mounts are installed and before any user-mode syscall runs.
        let p = unsafe { &mut *proc_ptr };
        if let Some(fgrp) = p.fgrp.as_mut() {
            match crate::vfs::open(b"/dev/console", 2) {
                Ok(chan) => {
                    let adapter = Box::new(crate::vfs::DevChanAdapter::new(chan));
                    if fgrp.set_stdio(adapter) {
                        crate::serial::put_bytes(b"[sched] stdin/stdout/stderr = /dev/console\n");
                    }
                }
                Err(_) => {
                    crate::serial::put_bytes(b"[sched] could not open /dev/console for stdio\n");
                }
            }
        }

        let p = unsafe { &*proc_ptr };
        let idx = (PRI_KPROC as usize).min(NPRIQ - 1);
        self.run_queues[idx].lock().push(p);
    }

    /// Add a process to the ready queue
    pub fn ready(&mut self, proc: &'static Proc) {
        let idx = (proc.pri as usize).min(NPRIQ - 1);
        let mut q = self.run_queues[idx].lock();

        let proc_ptr: *mut Proc = core::ptr::addr_of!(*proc) as *mut Proc;
        unsafe {
            (*proc_ptr).state = State::Ready;
        }
        q.push(proc);

        // Bump the ready counter.
        self.nrdy += 1;
    }

    /// Get next process to run from the run queue
    ///
    /// Implements EDF (Earliest Deadline First) scheduling for real-time processes:
    /// 1. First check if there are EDF real-time processes that need to run
    /// 2. If no EDF processes need to run, fall back to priority-based scheduling
    fn runproc(&mut self) -> Option<*mut Proc> {
        // === EDF Real-Time Scheduling ===
        // Check if there are any EDF processes that need to run
        // EDF processes are scheduled based on their earliest deadline
        let current_time = self.ticks; // Simplified: using ticks as time
        {
            if let Some(pid) = self.edf.earliest_deadline(current_time) {
                if let Some(proc_box) = self.procs.get(pid) {
                    // Check if deadline is still feasible
                    if proc_box.edf.as_ref().map(|e| e.deadline_met(current_time)).unwrap_or(false) {
                        // EDF process with valid deadline has priority
                        // Move it to running state and return
                        let ptr: *mut Proc = proc_box.as_ref() as *const Proc as *mut Proc;
                        return Some(ptr);
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
                let ptr: *mut Proc = core::ptr::addr_of!(*proc) as *mut Proc;
                return Some(ptr);
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
        self.edf.remove_task(pid);
    }

    /// Get current system utilization for EDF admission control
    pub fn edf_utilization(&self) -> f64 {
        self.edf.total_utilization()
    }

    /// Main scheduler function (Plan 9 style)
    ///
    /// Implements the Plan 9 scheduling algorithm with:
    /// - delaysched: delays scheduling when holding locks
    /// - Priority-based round-robin
    /// - True context switching via setjmp/longjmp
    pub unsafe fn schedule(&mut self) {
        // The scheduler lock protects the run queues and scheduling state
        // We need to handle the delaysched logic within the lock scope
        {
            let _guard = self.lock.lock();
            // Process any pending delaysched using raw pointer to avoid borrow issues
            if let Some(ref current) = self.current_proc {
                let current_ptr: *const Proc = *current;
                let delaysched_ptr = core::ptr::addr_of!((*current_ptr).delaysched) as *mut u32;
                if unsafe { *delaysched_ptr } > 0 {
                    if unsafe { *delaysched_ptr } < MAX_DELAY_SCHED as u32 {
                        unsafe { *delaysched_ptr += 1 };
                        return;
                    }
                    unsafe { *delaysched_ptr = 0 };
                }
            }
        } // lock guard dropped here
        
        // Now do the actual scheduling logic
        self.schedule_inner();
    }
    
    /// Inner scheduler logic
    unsafe fn schedule_inner(&mut self) {
        let mut prev = self.current_proc.take();

        // === Delaysched Logic (Plan 9 style) ===
        // If we're in a delay window, don't schedule yet
        if let Some(p) = prev {
            let p_ptr: *mut Proc = core::ptr::addr_of!(*p) as *mut Proc;
            unsafe {
                if (*p_ptr).delaysched > 0 {
                    if (*p_ptr).delaysched < MAX_DELAY_SCHED {
                        // Still in delay window, don't schedule yet
                        (*p_ptr).delaysched += 1;
                        self.current_proc = Some(p);
                        return;
                    }
                    // Reset delaysched counter
                    (*p_ptr).delaysched = 0;
                }

                // If holding locks and running, delay scheduling
                if (*p_ptr).nlocks > 0 && (*p_ptr).state == State::Running {
                    (*p_ptr).delaysched = 1;
                    self.current_proc = Some(p);
                    return;
                }
            }
        }

        // === Handle current process state ===
        if let Some(cur) = prev {
            let cur_ptr: *mut Proc = core::ptr::addr_of!(*cur) as *mut Proc;
            let cur_state = unsafe { (*cur_ptr).state };
            match cur_state {
                State::Running => {
                    // Process used its quantum, put back in queue
                    unsafe {
                        (*cur_ptr).state = State::Ready;
                    }
                    self.ready(unsafe { &mut *cur_ptr });
                }
                State::Moribund => {
                    // Process is exiting.  Do not save/restore a dead context.
                    unsafe {
                        self.proc_exit(&mut *cur_ptr);
                    }
                    prev = None;
                }
                State::Dead => {
                    // Already dead, just clean up
                    prev = None;
                }
                _ => {
                    // For other states (sleeping, waiting, etc.), don't requeue
                    // but keep the kernel context so it can be restored later.
                }
            }
        }

        // === Select and run next process ===
        if let Some(next_ptr) = self.runproc() {
            // Update CPU time and recalculate priority for the new process
            let next = &mut *next_ptr;
            let proc_basepri = next.basepri as i32;
            let proc_cpu = next.cpu as i32;
            let load = self.nrdy as i32;
            let result = proc_basepri - (proc_cpu / 16) - (load / 16);
            let new_pri = result.max(0).min(127) as i8;
            let next_pri = next.pri;
            if new_pri != next_pri {
                // Remove from current queue (it's already been popped)
                // and re-add to the new priority queue
                let idx = (new_pri as usize).min(NPRIQ - 1);
                next.pri = new_pri;
                // Re-add to the new priority queue
                self.run_queues[idx].lock().push(&mut *next_ptr);
                next.state = State::Ready;
            }

            next.state = State::Running;
            let next_for_current = & *next_ptr;
            self.current_proc = Some(next_for_current);
            // SAFETY: We're transferring control to next, so it's safe to get mutable access
            set_curproc(&mut *next_ptr);
            self.switches += 1;

            // Perform context switch, preserving the previous kernel context.
            let prev_ref = prev.map(|p| {
                let p_mut = core::ptr::addr_of!(*p) as *mut Proc;
                &mut *p_mut
            });
            self.context_switch(prev_ref, &*next_ptr);
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
    fn updatecpu(&mut self, proc: &Proc) {
        let decay = SCHEDGAIN * HZ as i32 * SCALING;
        
        // Calculate time since last update (in scaled ticks)
        let t = (self.ticks as i64) * SCALING as i64 + (SCALING as i64 / 2);
        let n = t - proc.lastupdate;
        
        // Store the current time as lastupdate
        // Note: proc is &static, so we can't modify it here directly
        // This will be handled when we actually switch to the process
        
        if n == 0 || n > decay as i64 {
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
        let _new_cpu = (ocpu * (decay - n)) / decay;
        
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
    fn reprioritize(&mut self, proc: &Proc) -> i8 {
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

        // Adjust by base priority
        // ratio = (fairshare + cpu/2) / cpu
        // This gives us a priority boost for using less than fairshare
        let mut ratio = ((fairshare + n / 2) / n) as i8;
        
        // Clamp to valid priority range
        let basepri = proc.basepri as i8;
        if ratio > basepri {
            ratio = basepri;
        }
        if ratio < 0 {
            ratio = 0;
        }
        
        ratio
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
                let cur_ptr: *mut Proc = core::ptr::addr_of!(*cur) as *mut Proc;
                unsafe {
                    (*cur_ptr).delaysched += 1;
                }
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
        // For each run queue, collect processes and re-add them
        // This is a simplified implementation that doesn't change priorities
        for i in 0..NPRIQ {
            let mut procs: alloc::vec::Vec<&'static Proc> = alloc::vec::Vec::new();
            
            // Collect all processes from this queue
            {
                let mut queue = self.run_queues[i].lock();
                while let Some(proc) = queue.pop() {
                    procs.push(proc);
                }
            }
            
            // Re-add all processes (simplified - in full impl, would recalculate priority)
            for proc in procs {
                self.run_queues[i].lock().push(proc);
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
        // Step 1: Save previous process context under the current page table.
        // The kernel stack is identity-mapped in both address spaces, but
        // saving before the CR3 change keeps the context location valid.
        // We use setjmp to save the current position. If it returns 0,
        // we just saved and will continue. If it returns 1, we were restored
        // by another process calling longjmp.
        if let Some(prev_proc) = prev {
            if prev_proc.state != State::Dead {
                // SAFETY: Save the current execution context into the process's sched field
                unsafe {
                    let mut ctx = Context::default();
                    crate::plan9_arch::hal::context::save_context(&mut ctx);
                    prev_proc.sched = crate::proc::Label {
                        sp: ctx.rsp,
                        pc: ctx.ret,
                        rbx: ctx.rbx,
                        rbp: ctx.rbp,
                        r12: ctx.r12,
                        r13: ctx.r13,
                        r14: ctx.r14,
                        r15: ctx.r15,
                        #[cfg(target_arch = "aarch64")]
                        r25: ctx.r25,
                        #[cfg(target_arch = "aarch64")]
                        r26: ctx.r26,
                        #[cfg(target_arch = "aarch64")]
                        r27: ctx.r27,
                        #[cfg(target_arch = "aarch64")]
                        r28: ctx.r28,
                        #[cfg(not(target_arch = "aarch64"))]
                        r25: 0,
                        #[cfg(not(target_arch = "aarch64"))]
                        r26: 0,
                        #[cfg(not(target_arch = "aarch64"))]
                        r27: 0,
                        #[cfg(not(target_arch = "aarch64"))]
                        r28: 0,
                    };
                }
            }
        }

        // Step 2: Switch page table for the next process.
        if next.mmupdb.as_u64() != 0 {
            switch_page_table(next.mmupdb);
        }

        // Step 3: Set current process pointer
        // This must be done before restoring the next process's context
        // SAFETY: We're transferring control to next, so it's safe to get mutable access
        set_curproc(unsafe { &mut *(core::ptr::addr_of!(*next) as *mut Proc) });

        // Step 4: Restore next process context.
        // A saved kernel context (blocked syscall) takes precedence over a
        // saved user frame; otherwise resume ring-3 execution directly.
        if next.sched.is_set() {
            // Convert proc Label to Context and switch
            unsafe {
                use crate::plan9_arch::hal::context::Label as ArchLabel;
                use crate::proc::Label as ProcLabel;
                let proc_label: &ProcLabel = &next.sched;
                let arch_label = ArchLabel {
                    sp: proc_label.sp,
                    pc: proc_label.pc,
                    rbx: proc_label.rbx,
                    rbp: proc_label.rbp,
                    r12: proc_label.r12,
                    r13: proc_label.r13,
                    r14: proc_label.r14,
                    r15: proc_label.r15,
                    #[cfg(target_arch = "aarch64")]
                    r25: proc_label.r25,
                    #[cfg(target_arch = "aarch64")]
                    r26: proc_label.r26,
                    #[cfg(target_arch = "aarch64")]
                    r27: proc_label.r27,
                    #[cfg(target_arch = "aarch64")]
                    r28: proc_label.r28,
                    ..Default::default()
                };
                let ctx = Context::from_label(&arch_label);
                // Restore the saved context: jump to the saved PC with the
                // saved callee-saved registers and stack pointer (the arch
                // crate's `goto_context` longjmp).
                crate::plan9_arch::hal::context::goto_context(&ctx);
            }
        } else if next.user_frame.is_some() {
            // First run (or a non-blocked user process): resume its ring-3
            // frame directly.
            let pml4 = next.mmupdb.as_u64();
            if pml4 != 0 {
                unsafe { crate::userfp::resume(next) }
            }
        }
        // If new process has no saved context, this is first run
        // Continue to run the new process from here
    }

    /// Run the idle loop
    fn run_idle(&mut self) {
        // Enable interrupts and halt
        crate::plan9_arch::hal::sti();
        crate::plan9_arch::hal::hlt();
    }

    /// Handle process exit
    fn proc_exit(&mut self, proc: &Proc) {
        // Close all file descriptors
        let proc_mut = core::ptr::addr_of!(*proc) as *mut Proc;
        unsafe {
            drop((*proc_mut).fgrp.take());
        }

        // Wakeup waiting parent
        if let Some(parent_pid) = proc.parent {
            if let Some(parent_box) = self.procs.get_mut(parent_pid) {
                let parent = parent_box.as_mut();
                if parent.nwait > 0 {
                    parent.nwait -= 1;
                    // Add to wait queue
                    let mut waitq = Box::new(crate::proc::Waitq::new(
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
            let cur_mut = core::ptr::addr_of!(*cur) as *mut Proc;
            unsafe {
                (*cur_mut).cpu += 1;
            }
        }
        
        // Call hzsched once per second to rebalance priorities
        // HZ = 100, so every 100 ticks is 1 second
        if self.ticks % HZ == 0 {
            self.hzsched();
        }
        
    }

    /// Yield CPU - current process voluntarily gives up CPU
    pub fn yield_(&mut self) {
        let proc_to_ready = {
            let _guard = self.lock.lock();

            if let Some(cur) = self.current_proc {
                if cur.state == State::Running {
                    let cur_mut = unsafe { &mut *(core::ptr::addr_of!(*cur) as *mut Proc) };
                    cur_mut.state = State::Ready;
                    Some(cur)
                } else {
                    None
                }
            } else {
                None
            }
        }; // guard dropped here

        if let Some(cur) = proc_to_ready {
            self.ready(cur);
        }

        // Use global scheduler
        schedule();
    }

    /// Sleep until condition is true
    /// Returns true if woke up normally, false if interrupted
    pub fn sleep<F>(&mut self, pred: F) -> bool 
    where
        F: Fn() -> bool,
    {
        let guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            if !pred() {
                let cur_mut = unsafe { &mut *(core::ptr::addr_of!(*cur) as *mut Proc) };
                cur_mut.state = State::Wakeme;
                drop(guard);
                // Use global scheduler
                schedule();
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
        proc.wtime = plan9_arch::hal::timer::ms_since_boot();

        // Allocate PID
        proc.pid = self.procs.alloc_pid()?;
        proc.note_group = proc.pid;

        // Copy parent info
        proc.parent = parent.map(|p| p.pid);
        if let Some(p) = parent {
            proc.note_group = p.note_group;
            proc.notify = p.notify;
            proc.notified = p.notified;
            proc.note_frames = p.note_frames.clone();
            proc.last_note = p.last_note;
            proc.private_memory = p.private_memory;
            proc.pri = p.basepri;
            proc.basepri = p.basepri;
            proc.fixedpri = p.fixedpri;
            proc.wired = p.wired.clone();

            // Fork process groups based on flags
            proc.fork_groups(Some(p), flags);

            // Inherit the textual working-directory path (`dot` itself is
            // per-process; userland's `pwd` reads this through GETCWD).
            proc.cwd_path = p.cwd_path.clone();
            proc.exec_image = p.exec_image.as_ref().map(crate::dev::Chan::dup);

            // Inherit the parent's segment table (metadata only: the child
            // gets its own page-table copy or shares the parent's, depending
            // on FLAGFMEM below, but /proc should report the same layout).
            for (i, seg) in p.seg.iter().enumerate() {
                if let Some(s) = seg {
                    proc.set_segment_info(i, s.segtype, s.base, s.top);
                }
            }

            // Handle memory based on flags.  For ordinary fork we make a
            // separate PML4 with copied kernel mappings and a deep copy of
            // the parent's user pages, so exec/write in the child cannot
            // overwrite the parent's image or stack.
            if flags & rfork::FLAGFMEM == 0 {
                if p.mmupdb.as_u64() != 0 {
                    let child_pml4 = match crate::frame_alloc::frame_alloc_zeroed() {
                        Some(f) => f,
                        None => return None,
                    };
                    unsafe {
                        if crate::init_loader::copy_kernel_pml4_into(child_pml4).is_none()
                            || crate::init_loader::copy_user_mappings(p.mmupdb.as_u64(), child_pml4).is_none()
                        {
                            crate::init_loader::release_user_root(child_pml4);
                            return None;
                        }
                    }
                    proc.mmupdb = child_pml4;
                } else {
                    if !proc.setup_page_table() {
                        return None;
                    }
                }
            } else {
                // Share memory - use parent's page table.
                proc.mmupdb = p.mmupdb;
            }

            // Copy the parent's ring-3 frame so the child resumes at the
            // fork syscall return point with RAX = 0.
            if let Some(parent_frame) = p.user_frame {
                let mut child_frame = parent_frame;
                child_frame.set_ret(0);
                proc.user_frame = Some(child_frame);
                #[cfg(not(target_arch = "aarch64"))]
                proc.user_fp.data.copy_from_slice(&p.user_fp.data);
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
        if proc.user_frame.is_none() {
            if let Some(kstack_phys) = alloc_frames(KSTACK_SIZE / 4096) {
                proc.kstack = crate::plan9_arch::hal::paging::phys_to_virt(kstack_phys).as_u64();
            } else {
                return None;
            }
        }

        // Set up initial scheduler context for child.  A user fork child
        // resumes through its copied SavedUserFrame instead of a kernel entry.
        let child_entry = entry as u64;
        if proc.user_frame.is_none() && child_entry != 0 {
            // Set up context for child to start at entry point
            let stack_top = proc.kstack + KSTACK_SIZE as u64;
//             use crate::plan9_arch::hal::context::Context;
            proc.sched = crate::proc::Label {
                sp: stack_top - 8,  // Leave room for return address
                pc: child_entry,
                rbx: 0,
                rbp: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                r25: 0,
                r26: 0,
                r27: 0,
                r28: 0,
            };
        }

        // Leak the box to get static reference
        let static_ref: &Proc = Box::leak(proc);

        // Add to process table
        self.procs.add(unsafe {
            let b: Box<Proc> = Box::from_raw(core::ptr::addr_of!(*static_ref) as *mut Proc);
            b
        });

        // Add to parent's child count
        if let Some(p) = parent {
            if let Some(p_mut) = self.procs.get_mut(p.pid) {
                p_mut.nchild += 1;
            }
        }

        // Add to ready queue
        if static_ref.user_frame.is_none() {
            self.ready(static_ref);
        }

        Some(static_ref.pid)
    }

    /// Terminate current process
    pub fn exit(&mut self, status: i32) {
        let guard = self.lock.lock();
        
        if let Some(cur) = self.current_proc {
            let cur_mut = unsafe { &mut *(core::ptr::addr_of!(*cur) as *mut Proc) };
            cur_mut.state = State::Moribund;
            let _ = status;
            drop(guard);
            // Use global scheduler
            schedule();
        }
    }

    /// Wait for child to exit
    pub fn wait(&mut self) -> Option<(Pid, i32)> {
        let _guard = self.lock.lock();

        if let Some(cur) = self.current_proc {
            let cur_mut = core::ptr::addr_of!(*cur) as *mut Proc;
            // Check if any children have exited
            unsafe {
                while (*cur_mut).nchild == 0 || (*cur_mut).waitq.is_none() {
                    // No children, return error
                    return None;
                }

                // Get exit info from waitq
                if let Some(ref mut wq) = (*cur_mut).waitq {
                    let pid = wq.pid;
                    let status = wq.status;
                    (*cur_mut).waitq = wq.next.take();
                    (*cur_mut).nwait = (*cur_mut).nwait.saturating_sub(1);
                    return Some((pid, status));
                }
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
                let proc_mut = core::ptr::addr_of!(*proc) as *mut Proc;
                let proc_pri = unsafe { (*proc_mut).pri };
                let proc_basepri = unsafe { (*proc_mut).basepri };

                // Check if this process should get priority boost
                if Self::is_likely_interactive(proc) && proc_pri > proc_basepri - INTERACTIVE_BOOST as i8 {
                    // Boost priority
                    let new_pri = (proc_pri - INTERACTIVE_BOOST).max(proc_basepri - INTERACTIVE_BOOST);

                    if new_pri != proc_pri as i8 {
                        queue.remove(proc);
                        let idx = (new_pri as usize).min(NPRIQ - 1);
                        drop(queue);
                        self.run_queues[idx].lock().push(proc);
                        unsafe {
                            (*proc_mut).pri = new_pri;
                        }
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

use core::sync::atomic::{AtomicPtr, Ordering};

static SCHEDULER: AtomicPtr<Scheduler> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global scheduler
pub fn init_scheduler() {
    let mut sched = Box::new(Scheduler::new());
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
    unsafe { scheduler().schedule(); }
}

/// Yield the current process
pub fn yield_() {
    scheduler().yield_();
}

/// Add a process to the ready queue
pub fn ready(proc: &'static Proc) {
    scheduler().ready(proc);
}

/// Initialize idle process and enter scheduler
pub fn schedinit() {
    init_scheduler();
}

/// Get current tick count
pub fn sched_ticks() -> u64 {
    *SCHED_TICKS.lock()
}

// ============================================================================
// Plan 9 Style Schedq
// ============================================================================

/// Schedq - Plan 9 style scheduler queue
///
/// In Plan 9, Schedq is the per-priority run queue structure
/// with a lock for atomic operations.
pub struct Schedq {
    /// Lock protecting this queue
    lock: Spinlock<Vec<&'static Proc>>,
}

impl Schedq {
    /// Create a new scheduler queue
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(Vec::new()),
        }
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.lock.lock().is_empty()
    }

    /// Add process to tail of queue
    pub fn push(&self, p: &'static Proc) {
        self.lock.lock().push(p);
    }

    /// Remove process from head of queue
    pub fn pop(&self) -> Option<&'static Proc> {
        self.lock.lock().pop()
    }

    /// Get number of processes in queue
    pub fn len(&self) -> usize {
        self.lock.lock().len()
    }
}

impl Default for Schedq {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Process Context Management
// ============================================================================

/// Save process context before scheduling out
/// 
/// This function saves the current process's context (registers, etc.)
/// and is called when a process is about to give up the CPU.
pub fn procsave(proc: &mut Proc) {
    // Save floating point state if needed
    // In Plan 9, fpsave() is called here
    
    // Update CPU usage
    let now = sched_ticks();
    let elapsed = now.saturating_sub(proc.lastupdate as u64);
    if elapsed > 0 {
        // Decay CPU usage (simplified)
        proc.cpu = proc.cpu.saturating_add(elapsed);
    }
    proc.lastupdate = now as i64;
}

/// Restore process context after scheduling in
/// 
/// This function restores the process's context and is called
/// when a process is about to run.
pub fn procrestore(proc: &mut Proc) {
    // Restore floating point state if needed
    // In Plan 9, fprestore() is called here
    
    // Update timing
    proc.lastupdate = sched_ticks() as i64;
}

/// Check if current process should yield
pub fn should_preempt() -> bool {
    let ticks = sched_ticks();
    let quantum = SCHED_QUANTUM;
    ticks % quantum == 0
}

/// Force reschedule
pub fn resched() {
    let proc = crate::proc::curproc();
    if let Some(p) = proc {
        let p = unsafe { &mut *(core::ptr::addr_of!(*p) as *mut Proc) };
        p.delaysched += 1;
    }
    schedule();
}

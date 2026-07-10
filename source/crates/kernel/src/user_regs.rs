//! User register frame structure
//!
//! This module defines the user register frame that is pushed onto the stack
//! when entering the kernel from user mode, and is used for signal handling
//! and context restoration.
//!
//! This module also provides the timer queue implementation for:
//! - Process timers (alarm)
//! - Sleep/wakeup synchronization
//! - TCP retransmission timers
//! - Periodic scheduling


extern crate alloc;

use alloc::boxed::Box;
use crate::plan9_common::types::{ VirtAddr };use crate::plan9_common::sync::Spinlock;

// ============================================================================
// User Register Frame
// ============================================================================

/// User register frame - pushed by the CPU on interrupts/traps from user mode
/// This matches the layout expected by the syscall and trap handlers
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserRegs {
    /// R15
    pub r15: u64,
    /// R14
    pub r14: u64,
    /// R13
    pub r13: u64,
    /// R12
    pub r12: u64,
    /// RBP
    pub rbp: u64,
    /// RBX
    pub rbx: u64,
    /// R11
    pub r11: u64,
    /// R10
    pub r10: u64,
    /// R9
    pub r9: u64,
    /// R8
    pub r8: u64,
    /// RAX (return value)
    pub rax: u64,
    /// RCX (syscall number / return address)
    pub rcx: u64,
    /// RDX
    pub rdx: u64,
    /// RSI
    pub rsi: u64,
    /// RDI
    pub rdi: u64,
    /// Original syscall number (for/restart)
    pub orig_rax: u64,
    /// RIP
    pub rip: u64,
    /// CS
    pub cs: u64,
    /// RFLAGS
    pub rflags: u64,
    /// RSP
    pub rsp: u64,
    /// SS
    pub ss: u64,
}

impl Default for UserRegs {
    fn default() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        }
    }
}

impl UserRegs {
    /// Create a new register frame for a new process
    pub fn new_user_frame(entry: VirtAddr, stack_top: VirtAddr, _args: &[u64]) -> Self {
        let mut regs = Self::default();
        
        // Set instruction pointer to entry point
        regs.rip = entry.as_u64();
        
        // Set stack pointer
        regs.rsp = stack_top.as_u64();
        
        // Set up arguments (argc, argv, envp on stack)
        // For now, just set up a minimal frame
        regs.rdi = 0; // argc = 0
        regs.rsi = stack_top.as_u64(); // argv = stack
        regs.rdx = stack_top.as_u64() + 8; // envp = stack + 8
        
        // User mode CS/SS (3) and RFLAGS
        regs.cs = 0x1B; // User code segment (RPL=3)
        regs.ss = 0x23; // User data segment (RPL=3)
        regs.rflags = 0x202; // IF bit set
        
        regs
    }

    /// Check if the frame is from user mode
    pub fn is_user_mode(&self) -> bool {
        // Check if CS RPL is 3 (user mode)
        (self.cs & 0x3) == 0x3
    }

    /// Get the system call number from orig_rax
    pub fn syscall_number(&self) -> u64 {
        self.orig_rax
    }

    /// Set the return value
    pub fn set_return(&mut self, value: u64) {
        self.rax = value;
    }

    /// Get argument at index (for syscalls)
    pub fn arg(&self, index: usize) -> u64 {
        match index {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            _ => 0,
        }
    }
}

// ============================================================================
// Note (Signal) Structure
// ============================================================================

/// Note (signal) structure for Plan 9 style signals
#[derive(Debug, Clone, Copy)]
pub struct Note {
    /// Flag fields
    pub flag: u32,
    /// Process/TID to send note to
    pub pid: u32,
    /// Note label string pointer
    pub msg: u64,
}

impl Default for Note {
    fn default() -> Self {
        Note::empty()
    }
}

impl Note {
    /// Create a new note
    pub const fn new(pid: u32, msg: u64, flag: u32) -> Self {
        Self { flag, pid, msg }
    }

    /// Create an empty (zeroed) note - const-compatible
    pub const fn empty() -> Self {
        Self { flag: 0, pid: 0, msg: 0 }
    }

    /// Segfault note flag
    pub const SEGFAULT: Note = Note { flag: 1, pid: 0, msg: 0 };

    /// Check if note is empty
    pub fn is_empty(&self) -> bool {
        self.msg == 0
    }
}

/// Maximum number of notes per process
pub const NNOTE: usize = 16;

/// Note flags
pub mod note_flag {
    pub const NNOTE: u32 = 0x0001;  // Note is in note[]
    pub const NEXIT: u32 = 0x0002;  // Send note on exit
    pub const NCLONE: u32 = 0x0004; // Clone note to children
    pub const NREND: u32 = 0x0008;  // Note is rendezvous
}

// ============================================================================
// Timer Structure
// ============================================================================

/// Timer structure for process timers (alarm, sleep)
#[derive(Debug, Clone)]
pub struct Timer {
    /// Next timer in list
    pub next: Option<Box<Timer>>,
    /// When timer expires (in ticks)
    pub when: u64,
    /// Timer type
    pub type_: TimerType,
    /// Timer argument
    pub arg: u64,
}

// SAFETY: Timer contains raw pointers but is designed to be shared between threads
// in the kernel's timer management. Proper synchronization is done at the usage site.
unsafe impl Send for Timer {}
unsafe impl Sync for Timer {}

impl Default for Timer {
    fn default() -> Self {
        Self {
            next: None,
            when: 0,
            type_: TimerType::Relative,
            arg: 0,
        }
    }
}

impl Timer {
    /// Create a new timer
    pub fn new(when: u64, type_: TimerType, arg: u64) -> Self {
        Self {
            next: None,
            when,
            type_,
            arg,
        }
    }

    /// Check if timer has expired
    pub fn expired(&self, now: u64) -> bool {
        now >= self.when
    }
}

/// Timer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimerType {
    Relative = 0,   // Relative to current time
    Absolute = 1,   // Absolute time
    Periodic = 2,   // Periodic timer
}

/// Timer callback function type
pub type TimerCallback = fn(arg: u64);

// ============================================================================
// Error Label for setjmp/longjmp
// ============================================================================

/// Maximum number of error labels per process
pub const NERR: usize = 16;

/// Error recovery label structure
/// Similar to Label but used for error recovery with setjmp/longjmp
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrLabel {
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
    /// Callee-saved registers
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl ErrLabel {
    /// Create a new empty error label
    pub const fn new() -> Self {
        Self {
            sp: 0,
            pc: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }

    /// Check if label is set
    pub fn is_set(&self) -> bool {
        self.sp != 0 || self.pc != 0
    }
}

// ============================================================================
// Timer Queue Implementation
// ============================================================================

/// Global timer list - sorted by expiration time
/// Timers are stored in a linked list sorted by `when` field
static TIMER_LIST: Spinlock<Option<Box<Timer>>> = Spinlock::new(None);

/// Timer list lock for thread-safe access
static TIMER_LOCK: Spinlock<()> = Spinlock::new(());

impl Timer {
    /// Create a new timer with type and interval
    pub fn with_type(when: u64, type_: TimerType, arg: u64) -> Self {
        Self {
            next: None,
            when,
            type_,
            arg,
        }
    }

    /// Create a relative timer that expires after `ms` milliseconds
    pub fn relative(ms: u64) -> Self {
        Self {
            next: None,
            when: current_ticks() + ms,
            type_: TimerType::Relative,
            arg: 0,
        }
    }

    /// Create a periodic timer with interval in milliseconds
    pub fn periodic(interval_ms: u64) -> Self {
        Self {
            next: None,
            when: current_ticks() + interval_ms,
            type_: TimerType::Periodic,
            arg: interval_ms,
        }
    }
}

/// Get current tick count
fn current_ticks() -> u64 {
    // This would be integrated with the scheduler's tick counter
    crate::sched::sched_ticks()
}

/// Insert a timer into the sorted timer list
/// Timers are sorted by expiration time (earliest first)
fn timer_insert(head: &mut Option<Box<Timer>>, mut new_timer: Box<Timer>) {
    let when = new_timer.when;
    new_timer.next = None;

    match head {
        None => {
            // Empty list, new timer becomes head
            *head = Some(new_timer);
        }
        Some(head_box) => {
            if when < head_box.when {
                // Insert before head
                new_timer.next = head_box.next.take();
                *head = Some(new_timer);
            } else {
                // Insert in order
                timer_insert(&mut head_box.next, new_timer);
            }
        }
    }
}

/// Add a timer to the global timer queue
///
/// # Safety
/// The timer must not already be in the queue
pub unsafe fn timerset(t: &mut Timer) {
    let mut list = TIMER_LIST.lock();

    // Take ownership of the timer
    let timer_box = Box::new(core::ptr::read(t));

    timer_insert(&mut list, timer_box);
}

/// Remove a timer from the global timer queue
///
/// Returns the timer if found, or None if not in queue
pub fn timerdel(t: *const Timer) -> Option<Box<Timer>> {
    let mut list = TIMER_LIST.lock();

    // Check if it's the head
    if let Some(ref mut head) = *list {
        if core::ptr::eq(head.as_ref() as *const Timer, t) {
            // Remove head
            let next = head.next.take();
            let result = list.take();
            *list = next;
            return result;
        }
    }

    // Search in the list
    timer_remove(&mut list, t)
}

/// Helper to remove a timer from a list
fn timer_remove(list: &mut Option<Box<Timer>>, t: *const Timer) -> Option<Box<Timer>> {
    match list {
        None => None,
        Some(ref mut head) => {
            if let Some(ref mut next_box) = head.next {
                let next_ptr: *const Timer = &**next_box;
                if core::ptr::eq(next_ptr, t) {
                    // Found it - remove from next
                    let mut removed = head.next.take();
                    if let Some(ref mut n) = removed {
                        head.next = n.next.take();
                    }
                    return removed;
                } else {
                    return timer_remove(&mut head.next, t);
                }
            }
            None
        }
    }
}

/// Process expired timers
///
/// Called from the timer interrupt handler
/// Returns the number of timers that expired
pub fn timerintr() -> usize {
    let now = current_ticks();
    let mut count = 0;

    let mut list = TIMER_LIST.lock();

    while let Some(ref mut head) = *list {
        if head.when <= now {
            // Timer has expired
            count += 1;

            // Handle periodic timers
            match head.type_ {
                TimerType::Relative | TimerType::Absolute => {
                    // One-shot timer - remove it
                    let next = head.next.take();
                    *list = next;
                }
                TimerType::Periodic => {
                    // Reschedule periodic timer
                    let interval = head.arg;
                    let next_time = now + interval;

                    // Remove from current position
                    let mut timer = list.take().unwrap();

                    // Update when and reinsert
                    timer.when = next_time;

                    // Reinsert in correct position
                    timer_insert(&mut *list, timer);
                }
            }

            // Call the timer handler if registered
            // In a full implementation, timers would have callback functions
            // For now, we just process the timer queue
        } else {
            // List is sorted, so no more expired timers
            break;
        }
    }

    count
}

/// Get the next timer expiration time
///
/// Returns None if no timers are pending
pub fn timer_when() -> Option<u64> {
    let list = TIMER_LIST.lock();
    list.as_ref().map(|t| t.when)
}

/// Check if there are pending timers
pub fn timer_pending() -> bool {
    TIMER_LIST.lock().is_some()
}

/// Timer queue statistics
#[derive(Debug)]
pub struct TimerStats {
    /// Number of pending timers
    pub count: usize,
    /// Next timer expiration time
    pub next_when: Option<u64>,
}

impl TimerStats {
    /// Get timer queue statistics
    pub fn get() -> Self {
        let list = TIMER_LIST.lock();
        let mut count = 0;
        let mut curr: Option<&Box<Timer>> = list.as_ref();

        while let Some(t) = curr {
            count += 1;
            curr = t.next.as_ref();
        }

        Self {
            count,
            next_when: list.as_ref().map(|t| t.when),
        }
    }
}

/// Sleep for a specified number of milliseconds
///
/// This is a simple blocking sleep that uses the timer queue
pub fn sleep_ms(ms: u64) {
    let start = current_ticks();
    let end = start + ms;

    while current_ticks() < end {
        // Busy wait - in a real implementation, this would sleep
        // For now, just spin
        core::hint::spin_loop();
    }
}

/// Wakeup waiting process
///
/// Called when a process should be woken up from sleep
/// The `arg` should be a pointer to the process's sleep channel
pub fn wakeup(arg: u64) {
    // In a full implementation, this would:
    // 1. Find the process waiting on `arg`
    // 2. Remove its sleep timer if any
    // 3. Set its state to Ready
    let _ = arg;
}

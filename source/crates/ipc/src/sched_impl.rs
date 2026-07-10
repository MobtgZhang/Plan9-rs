//! Thread scheduler implementation for Plan 9 style threading
//!
//! Implements the user-space scheduler loop for lightweight threads.
//! Each Plan 9 process can have multiple threads; this module manages
//! their ready/rendezvous states and performs context switches.

#![allow(dead_code)]

use crate::thread::{ThreadId, thread_manager, DEFAULT_STACK_SIZE};
use crate::context::ThreadContext;
use crate::stack::ThreadStack;

static mut CURRENT_THREAD_ID: ThreadId = 0;
static mut CURRENT_CONTEXT: ThreadContext = ThreadContext::empty();
static mut ENTRY_CONTEXT: ThreadContext = ThreadContext::empty();
static mut SCHED_RUNNING: bool = false;

/// Enter the scheduler loop for the current process.
pub fn sched_enter() {
    unsafe {
        if SCHED_RUNNING {
            return;
        }
        SCHED_RUNNING = true;
    }

    loop {
        let next = {
            let guard = thread_manager().lock();
            guard.as_ref().and_then(|tm| tm.next_ready())
        };

        match next {
            Some(thread) => {
                let tid = thread.lock().id();
                {
                    let mut guard = thread_manager().lock();
                    if let Some(ref mut tm) = *guard {
                        tm.set_current(thread.clone());
                    }
                }
                unsafe {
                    CURRENT_THREAD_ID = tid;
                }

                if let Some(_stack) = ThreadStack::alloc(DEFAULT_STACK_SIZE) {
                    // For now, skip context switching as it requires more setup
                    break;
                }
            }
            None => break,
        }
    }

    unsafe {
        SCHED_RUNNING = false;
    }
}

/// Yield the current thread to the scheduler.
pub fn sched_yield() {
    {
        let guard = thread_manager().lock();
        if let Some(ref tm) = *guard {
            tm.yield_current();
        }
    }
}

/// Sleep for specified milliseconds.
pub fn sched_sleep(_ms: u32) {
    // Would implement actual sleeping with scheduler
}

/// Wake a specific thread.
pub fn sched_wake(_thread_id: ThreadId) {
    // Wake logic would go here
}

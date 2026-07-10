//! IPC
//!
//! Inter-process and inter-thread communication primitives for Plan 9 style
//! threading. Includes channels, rendezvous, pipes, message passing.

#![no_std]

extern crate alloc;
extern crate plan9_common;

// Submodules
pub mod pipe;
pub mod msg;
pub mod rendez;
pub mod channel;
pub mod channel_impl;
pub mod thread;
pub mod note;
pub mod context;
pub mod sched_impl;
pub mod proc;
pub mod stack;

// Re-export channel types from channel module
pub use channel_impl::{
    // Channel
    Channel, chancreate, chaninit, chanclose, chanisclosed,

    // Operations
    send, recv, nbsend, nbrecv,

    // Typed operations
    sendul, recvul, nbsendul, nbrecvul,
    sendp, recvp,

    // ALT
    alt, AltEntry, AltOpType, ChanState,

    // Builder
    ChanBuilder,

    // Type-safe channel
    chan,
};

// Re-export rendezvous functions
pub use rendez::{
    _threadrendezvous, _threadflagrendez, _threadbreakrendez,
    _nextthreadid, _rendezvous_count,
    RThread,
};

// Re-export pipe
pub use pipe::{Pipe, pipe};

// Re-export thread functions
pub use thread::{
    Thread, ThreadId, ThreadState, ThreadManager,
    thread_id, thread_name, thread_yield, thread_create, thread_exit, thread_sleep_ms,
    init_threads,
    DEFAULT_STACK_SIZE,
};

// Re-export note functions
pub use note::{
    Note, NotePriority, NoteHandler, NoteMode, ThreadNotes,
    thread_post_note, thread_kill, thread_interrupt, thread_raise,
    note_names,
};

// Re-export scheduler and context primitives
pub use context::{ThreadContext, thread_context_save, thread_context_restore};
pub use sched_impl::{sched_enter, sched_yield, sched_sleep, sched_wake};
pub use proc::ThreadProc;
pub use stack::ThreadStack;

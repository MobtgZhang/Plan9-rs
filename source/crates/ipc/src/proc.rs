//! Process/thread group management for Plan 9 style threading
//!
//! Manages groups of threads within a process context. In Plan 9, a process
//! contains one or more threads; this module provides the shared process state.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::thread::{Thread, ThreadId};

/// Thread group identifier
pub type ThreadGroupId = u64;

/// Shared process/thread group state
#[derive(Debug)]
pub struct ThreadProc {
    id: ThreadGroupId,
    threads: spin::Mutex<Vec<Arc<Thread>>>,
    next_thread_id: AtomicU64,
}

impl ThreadProc {
    /// Create a new thread group
    pub fn new() -> Self {
        Self {
            id: 0,
            threads: spin::Mutex::new(Vec::new()),
            next_thread_id: AtomicU64::new(1),
        }
    }

    /// Set the thread group id
    pub fn set_id(&mut self, id: ThreadGroupId) {
        self.id = id;
    }

    /// Get the thread group id
    pub fn id(&self) -> ThreadGroupId {
        self.id
    }

    /// Register a thread in this group
    pub fn add_thread(&self, thread: Arc<Thread>) {
        self.threads.lock().push(thread);
    }

    /// Get all threads in this group
    pub fn threads(&self) -> Vec<Arc<Thread>> {
        self.threads.lock().clone()
    }

    /// Allocate a new thread id within this group
    pub fn alloc_thread_id(&self) -> ThreadId {
        self.next_thread_id.fetch_add(1, Ordering::SeqCst)
    }
}

impl Default for ThreadProc {
    fn default() -> Self {
        Self::new()
    }
}

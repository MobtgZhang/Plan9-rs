//! Thread stack management for Plan 9 style threading
//!
//! Provides stack allocation and initialization for lightweight threads.
//! Threads share the process address space but have their own stack pages.

#![allow(dead_code)]

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;

/// Thread stack
pub struct ThreadStack {
    base: *mut u8,
    size: usize,
}

impl ThreadStack {
    /// Allocate a new thread stack
    pub fn alloc(size: usize) -> Option<Self> {
        if size == 0 {
            return None;
        }

        let layout = Layout::from_size_align(size, 16).ok()?;
        unsafe {
            let base = alloc(layout);
            if base.is_null() {
                None
            } else {
                ptr::write_bytes(base, 0, size);
                Some(Self { base, size })
            }
        }
    }

    /// Get the top of the stack (grows down on x86_64)
    pub fn top(&self) -> *mut u8 {
        unsafe { self.base.add(self.size) }
    }

    /// Get the base of the stack
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Get the stack size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Check if an address is within this stack
    pub fn contains(&self, addr: *const u8) -> bool {
        let start = self.base;
        let end = unsafe { self.base.add(self.size) };
        addr >= start && addr < end
    }
}

impl Drop for ThreadStack {
    fn drop(&mut self) {
        if !self.base.is_null() {
            let layout = Layout::from_size_align(self.size, 16).expect("invalid stack layout");
            unsafe {
                dealloc(self.base, layout);
            }
        }
    }
}

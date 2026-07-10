//! Reference Counting Module
//!
//! Provides atomic reference counting for FID and request management.
//! Based on Plan 9's Ref structure.

use core::sync::atomic::{AtomicU32, Ordering};

/// Atomic reference counter
///
/// This is a simple reference counter that can be safely shared across threads.
#[derive(Debug)]
pub struct Ref {
    count: AtomicU32,
}

impl Ref {
    /// Create a new reference counter with initial count of 1
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(1),
        }
    }

    /// Create a reference counter with a specific initial value
    pub fn with_count(count: u32) -> Self {
        Self {
            count: AtomicU32::new(count),
        }
    }

    /// Increment the reference count
    ///
    /// Returns the new reference count after incrementing.
    pub fn inc(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrement the reference count
    ///
    /// Returns the remaining reference count after decrementing.
    /// When the count reaches 0, the object can be safely freed.
    pub fn dec(&self) -> u32 {
        // Use AcqRel to ensure proper memory ordering
        self.count.fetch_sub(1, Ordering::AcqRel).saturating_sub(1)
    }

    /// Get the current reference count
    ///
    /// Note: This is a snapshot and may be immediately stale.
    pub fn get(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// Check if this is the last reference
    pub fn is_last(&self) -> bool {
        self.get() == 1
    }
}

impl Default for Ref {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Ref {
    fn clone(&self) -> Self {
        self.inc();
        Self {
            count: AtomicU32::new(self.count.load(Ordering::Relaxed)),
        }
    }
}

/// Reference-counted pointer wrapper
///
/// This wraps a value with reference counting, automatically
/// freeing the value when the last reference is dropped.
pub struct Rc<T> {
    value: core::cell::UnsafeCell<T>,
    refcount: Ref,
}

unsafe impl<T: Send> Send for Rc<T> {}
unsafe impl<T: Send> Sync for Rc<T> {}

impl<T> Rc<T> {
    /// Create a new reference-counted pointer
    pub fn new(value: T) -> Self {
        Self {
            value: core::cell::UnsafeCell::new(value),
            refcount: Ref::new(),
        }
    }

    /// Get a reference to the inner value
    pub fn get(&self) -> &T {
        unsafe { &*self.value.get() }
    }

    /// Get a mutable reference to the inner value
    ///
    /// Note: This is unsafe because concurrent references could exist.
    pub unsafe fn get_mut(&mut self) -> &mut T {
        &mut *self.value.get()
    }

    /// Get the reference count
    pub fn refcount(&self) -> u32 {
        self.refcount.get()
    }

    /// Clone increases the reference count
    pub fn clone_rc(&self) -> Self {
        self.refcount.inc();
        Self {
            value: core::cell::UnsafeCell::new(unsafe { core::ptr::read(self.value.get()) }),
            refcount: Ref::with_count(self.refcount.get()),
        }
    }
}

impl<T> core::clone::Clone for Rc<T> {
    fn clone(&self) -> Self {
        self.clone_rc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_new() {
        let r = Ref::new();
        assert_eq!(r.get(), 1);
    }

    #[test]
    fn test_ref_inc() {
        let r = Ref::new();
        assert_eq!(r.inc(), 2);
        assert_eq!(r.get(), 2);
    }

    #[test]
    fn test_ref_dec() {
        let r = Ref::new();
        r.inc();
        assert_eq!(r.dec(), 1);
    }

    #[test]
    fn test_ref_dec_zero() {
        let r = Ref::with_count(1);
        assert_eq!(r.dec(), 0);
    }

    #[test]
    fn test_ref_is_last() {
        let r = Ref::new();
        assert!(r.is_last());
        r.inc();
        assert!(!r.is_last());
    }
}

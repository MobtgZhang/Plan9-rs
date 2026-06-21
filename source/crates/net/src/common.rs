//! Common types for the network stack
//!
//! Provides local stub types for no_std compatibility.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Error types for network operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Operation already in progress
    Ealready,
    /// Not connected
    Enotconn,
    /// Try again (would block)
    Eagain,
    /// Address already in use
    Eaddrinuse,
    /// Invalid argument
    Einval,
    /// Out of memory
    Enomem,
    /// Operation not permitted
    Eperm,
    /// Connection timed out
    Etimedout,
    /// Connection refused
    Econnrefused,
    /// Network unreachable
    Enetunreach,
    /// Host unreachable
    Ehostunreach,
    /// Unknown error
    Unknown,
}

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = u64;

/// Qid for 9P protocol
#[derive(Debug, Clone, Copy, Default)]
pub struct Qid {
    pub qtype: u8,
    pub vers: u32,
    pub path: u64,
}

/// Mode flags for 9P protocol
#[derive(Debug, Clone, Copy, Default)]
pub struct Mode(pub u32);

impl Mode {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const EXEC: u32 = 2;
}

/// Synchronization utilities
pub mod sync {
    use core::sync::atomic::{AtomicPtr, Ordering};
    use core::cell::UnsafeCell;
    
    /// Simple spinlock for protecting data in no_std environments
    pub struct Spinlock<T> {
        locked: AtomicPtr<u8>,
        data: UnsafeCell<T>,
    }

    impl<T> Spinlock<T> {
        /// Create a new spinlock with initial data
        pub const fn new(data: T) -> Self {
            Self {
                locked: AtomicPtr::new(core::ptr::null_mut()),
                data: UnsafeCell::new(data),
            }
        }

        /// Lock and get mutable access to data
        pub fn lock(&self) -> SpinlockGuard<'_, T> {
            SpinlockGuard {
                lock: &self.locked,
                data: unsafe { &mut *self.data.get() },
            }
        }
    }

    impl<T> Default for Spinlock<T>
    where
        T: Default,
    {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    /// RAII guard for spinlock
    pub struct SpinlockGuard<'a, T> {
        lock: &'a AtomicPtr<u8>,
        data: &'a mut T,
    }

    impl<T> Drop for SpinlockGuard<'_, T> {
        fn drop(&mut self) {
            // No-op in single-threaded context
        }
    }

    impl<T> core::ops::Deref for SpinlockGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            self.data
        }
    }

    impl<T> core::ops::DerefMut for SpinlockGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.data
        }
    }
}

/// Atomic reference count for buffer management
pub struct AtomicRefCount {
    count: AtomicU32,
}

impl AtomicRefCount {
    pub const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    pub fn load(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }

    pub fn store(&self, val: u32) {
        self.count.store(val, Ordering::Release);
    }

    pub fn fetch_add(&self, val: u32) -> u32 {
        self.count.fetch_add(val, Ordering::AcqRel)
    }

    pub fn fetch_sub(&self, val: u32) -> u32 {
        self.count.fetch_sub(val, Ordering::AcqRel)
    }
}

impl Default for AtomicRefCount {
    fn default() -> Self {
        Self::new()
    }
}

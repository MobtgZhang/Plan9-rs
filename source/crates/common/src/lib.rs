//! Plan 9 Common Crate
//!
//! Common types, error handling, and synchronization primitives.

#![no_std]

extern crate alloc;

pub mod types;
pub mod error;
pub mod sync;

pub use types::*;
pub use error::{Error, Result};
pub use sync::*;

// Re-export alloc types for dependent crates
pub use alloc::boxed::Box;
pub use alloc::vec::Vec;
pub use alloc::string::String;

// Re-export commonly used items
pub use types::{
    PhysAddr, VirtAddr, Page, PageFrame, Qid, Mode, Ureg,
    Pid, Uid, Gid, Label,
    PAGE_SIZE, PAGE_SHIFT, PAGE_MASK,
    NSEG, NOFILE, MAXPATH, MAXNAME, MAXSTRING, ERRMAX, NCPU,
    QTFILE, QTDIR, QTSYMLINK,
};

//! Server Processes Crate
//!
//! Provides file, process, and authentication server implementations.

#![no_std]

extern crate alloc;

pub mod fs;
pub mod proc;
pub mod auth;

pub use fs::{FileServer, MountTable, MountEntry};
pub use proc::{ProcServer, ProcTable, ProcInfo, ProcState};
pub use auth::{AuthServer, AuthError, Key, KeyType};

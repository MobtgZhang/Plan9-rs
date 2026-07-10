//! String Allocation
//!
//! Reference: sys/src/libString/s_alloc.c

use super::s_string::S;

/// Allocate a new string
pub fn s_alloc() -> S {
    S::new()
}

/// Free a string
pub fn s_free(_s: &mut S) {
    // In Rust, strings are automatically freed when dropped
    // This function exists for API compatibility
}

/// Allocate a string with initial data
pub fn s_allocdata(data: &[u8]) -> S {
    S::from_bytes(data)
}

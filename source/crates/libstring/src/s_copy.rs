//! String Copy
//!
//! Reference: sys/src/libString/s_copy.c

use super::s_string::S;

/// Copy a string
/// 
/// Returns a new string that is a copy of the input
pub fn s_copy(s: &S) -> S {
    S::from_bytes(s.as_bytes())
}

/// Copy string from C string
pub fn s_copyn(s: &[u8]) -> S {
    S::from_bytes(s)
}

/// Duplicate string (like strdup)
pub fn s_dup(s: &S) -> S {
    s_copy(s)
}

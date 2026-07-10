//! String Reset
//!
//! Reference: sys/src/libString/s_reset.c

use super::s_string::S;

/// Reset string to empty
pub fn s_reset(s: &mut S) {
    s.reset();
}

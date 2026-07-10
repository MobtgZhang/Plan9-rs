//! String Grow
//!
//! Reference: sys/src/libString/s_grow.c

use super::s_string::S;

/// Grow string to accommodate `n` more bytes
///
/// Calls `Vec::reserve` on the underlying buffer so that subsequent
/// appends do not reallocate. Without this, the no-op implementation in
/// earlier versions would silently truncate writes once the internal
/// `Vec` capacity was exceeded during `s_append` / `S::append`.
pub fn s_grow(s: &mut S, n: usize) {
    let needed = s.len() + n;
    if s.cap() < needed {
        // Reserve the slack so the Vec grows to fit. `cap()` returns the
        // cached capacity field, so we reserve the delta explicitly.
        let extra = needed - s.cap();
        let bytes = s.as_mut_bytes();
        let _ = bytes; // ensure mutability
        s.reserve_capacity(extra);
    }
}

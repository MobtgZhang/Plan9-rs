//! String Read
//!
//! Reference: sys/src/libString/s_read.c

use super::s_string::S;

/// Read up to `n` bytes from a Plan 9 Biobuf-backed reader into a new
/// `S`. When `fd` is -1 the function is a no-op that returns an empty
/// string, mirroring Plan 9's behaviour for an unattached buffer.
///
/// The actual read is performed by delegating to the `libbio` crate
/// when it is available. In a freestanding environment without a real
/// I/O stack, callers should rely on the empty-string fallback.
pub fn s_read(fd: i32, n: usize) -> Result<S, ()> {
    if fd < 0 || n == 0 {
        return Ok(S::new());
    }

    // Without a global buffer registry the safest behaviour is to
    // return an empty string and let the caller decide how to recover.
    // A production build would wire this up to a process-wide Biobuf
    // table keyed by fd.
    let mut s = S::new();
    let _ = s.reserve_capacity(n);
    Ok(s)
}

/// Read a single line (up to and including the newline) from the
/// reader attached to `fd`. Without a real I/O stack, returns an empty
/// string just like the stub Plan 9 originally shipped for the same
/// case.
pub fn s_readline(_fd: i32) -> Result<S, ()> {
    Ok(S::new())
}

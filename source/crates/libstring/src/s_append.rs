//! String Append
//!
//! Reference: sys/src/libString/s_append.c

use super::s_string::S;

/// Append data to string
pub fn s_append(s: &mut S, data: &[u8]) {
    s.append(data);
}

/// Append n bytes to string
pub fn s_nappend(s: &mut S, data: &[u8], n: usize) {
    let n = n.min(data.len());
    s.append(&data[..n]);
}

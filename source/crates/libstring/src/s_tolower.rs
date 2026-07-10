//! String To Lower
//!
//! Reference: sys/src/libString/s_tolower.c

use super::s_string::S;

/// Convert string to lowercase (in place)
pub fn s_tolower(s: &mut S) {
    let bytes = s.as_mut_bytes();
    for byte in bytes.iter_mut() {
        if *byte >= b'A' && *byte <= b'Z' {
            *byte = *byte + 32;  // ASCII lowercase offset
        }
    }
}

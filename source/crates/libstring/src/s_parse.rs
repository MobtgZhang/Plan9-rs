//! String Parse
//!
//! Reference: sys/src/libString/s_parse.c

use super::s_string::S;

/// Skip whitespace in string
pub fn s_skip(s: &[u8], p: usize) -> usize {
    let mut i = p;
    while i < s.len() {
        match s[i] {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => break,
        }
    }
    i
}

/// Parse to end of token
pub fn s_end(s: &[u8], p: usize) -> usize {
    let mut i = p;
    while i < s.len() {
        match s[i] {
            b' ' | b'\t' | b'\n' | b'\r' => break,
            _ => i += 1,
        }
    }
    i
}

/// Extract token from string
pub fn s_parse(s: &[u8]) -> (Option<S>, usize) {
    let start = s_skip(s, 0);
    let end = s_end(s, start);
    
    if start >= s.len() {
        return (None, s.len());
    }
    
    let token = S::from_bytes(&s[start..end]);
    (Some(token), end)
}

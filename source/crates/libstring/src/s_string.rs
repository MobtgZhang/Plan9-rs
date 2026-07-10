//! S String Structure
//!
//! Implements the Plan 9 S (String) structure.

use core::fmt;
use alloc::vec::Vec;

/// Plan 9 style String structure
/// 
/// This is a reference-counted string that can be shared between threads.
/// It is similar to a growable byte buffer with Plan 9 semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S {
    /// Pointer to data
    ptr: Vec<u8>,
    /// Length of string
    len: usize,
    /// Capacity
    cap: usize,
}

impl S {
    /// Create a new empty string
    pub fn new() -> Self {
        Self {
            ptr: Vec::new(),
            len: 0,
            cap: 0,
        }
    }

    /// Create from byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut s = Self::new();
        s.ptr.extend_from_slice(bytes);
        s.len = bytes.len();
        s.cap = bytes.len();
        s
    }

    /// Create from C string (null-terminated)
    pub fn from_cstr(cstr: *const u8) -> Self {
        if cstr.is_null() {
            return Self::new();
        }
        
        let mut len = 0;
        unsafe {
            while *cstr.add(len) != 0 {
                len += 1;
            }
        }
        
        let mut s = Self::new();
        s.ptr.reserve(len);
        for i in 0..len {
            unsafe {
                s.ptr.push(*cstr.add(i));
            }
        }
        s.len = len;
        s.cap = len;
        s
    }

    /// Get pointer to data
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Get mutable pointer to data
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_mut_ptr()
    }

    /// Get string length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Get capacity
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.ptr[..self.len]
    }

    /// Get as mutable byte slice
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.ptr[..self.len]
    }

    /// Append byte slice
    pub fn append(&mut self, bytes: &[u8]) {
        self.ptr.extend_from_slice(bytes);
        self.len += bytes.len();
        self.cap = self.ptr.capacity();
    }

    /// Append single byte
    pub fn putc(&mut self, byte: u8) {
        self.ptr.push(byte);
        self.len += 1;
        self.cap = self.ptr.capacity();
    }

    /// Reset string to empty
    pub fn reset(&mut self) {
        self.ptr.clear();
        self.len = 0;
    }

    /// Ensure that the underlying buffer has at least `additional`
    /// bytes of spare capacity in addition to the current length.
    pub fn reserve_capacity(&mut self, additional: usize) {
        self.ptr.reserve(additional);
        self.cap = self.ptr.capacity();
    }

    /// Get null-terminated C string (for FFI)
    /// Returns pointer to internal buffer - caller must ensure
    /// the string is not modified while using the pointer
    pub fn to_cstring(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Convert to String (std)
    pub fn to_string_lossy(&self) -> alloc::string::String {
        alloc::string::String::from_utf8_lossy(self.as_bytes()).into_owned()
    }

    /// Get iterator over bytes
    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.as_bytes().iter()
    }
}

impl Default for S {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for S {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl From<&str> for S {
    fn from(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }
}

impl From<&[u8]> for S {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

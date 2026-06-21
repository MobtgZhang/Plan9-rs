//! SHA-1 Hash Function
//!
//! Implements the SHA-1 (Secure Hash Algorithm 1) cryptographic hash function.
//!
//! ## DEPRECATED - Security Warning
//!
//! **WARNING: SHA-1 is cryptographically broken for security purposes.**
//!
//! Known vulnerabilities include:
//! - SHAttered attack (2017) - First practical collision
//! - freestart collision (2015)
//! - Theoretical weaknesses since 2005 (Wang et al.)
//!
//! SHA-1 should NOT be used for:
//! - Digital signatures
//! - TLS/SSL certificates
//! - Any security-critical applications
//!
//! ## Migration Guide
//!
//! Replace SHA-1 with one of these secure alternatives:
//! - **SHA-256**: `plan9_security::hash::sha256::hash()`
//! - **SHA-512**: `plan9_security::hash::sha512::hash()`
//!
//! ## Usage
//!
//! ```ignore
//! use plan9_security::sha1;
//!
//! let data = b"Hello, World!";
//! let hash = sha1::hash(data);
//! ```

use alloc::vec::Vec;

/// SHA-1 output size in bytes
pub const SHA1_SIZE: usize = 20;

/// SHA-1 block size in bytes
const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 state
///
/// # Deprecation
///
/// **This struct is deprecated and should not be used in new code.**
///
/// SHA-1 has multiple known cryptographic vulnerabilities:
/// - Collision attacks (SHAttered, 2017)
/// - Preimage attacks (theoretical)
/// - Length extension attacks
///
/// Use `SHA-256` or `SHA-512` from the `hash` module instead.
#[derive(Clone)]
#[deprecated(
    since = "0.2.0",
    note = "SHA-1 is cryptographically weak. Use SHA-256 or SHA-512 instead."
)]
pub struct State {
    h: [u32; 5],
}

/// SHA-1 constants
const K1: u32 = 0x5A827999; // 0 ≤ t ≤ 19
const K2: u32 = 0x6ED9EBA1; // 20 ≤ t ≤ 39
const K3: u32 = 0x8F1BBCDC; // 40 ≤ t ≤ 59
const K4: u32 = 0xCA62C1D6; // 60 ≤ t ≤ 79

impl State {
    /// Create a new SHA-1 state
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
    #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
    pub fn new() -> Self {
        Self {
            h: [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            ],
        }
    }

    /// Update state with data
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
    #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        let len = data.len();
        
        // Process complete blocks
        while offset + SHA1_BLOCK_SIZE <= len {
            self.process_block(&data[offset..offset + SHA1_BLOCK_SIZE]);
            offset += SHA1_BLOCK_SIZE;
        }
    }

    /// Process a 64-byte block
    fn process_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), SHA1_BLOCK_SIZE);

        let mut w = [0u32; 80];

        // Copy block into first 16 words (big-endian)
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }

        // Extend to 80 words
        for i in 16..80 {
            let x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = x.rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Rounds 0-19 (K1)
        for i in 0..20 {
            let f = (b & c) | ((!b) & d);
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i]).wrapping_add(K1);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Rounds 20-39 (K2)
        for i in 20..40 {
            let f = b ^ c ^ d;
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i]).wrapping_add(K2);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Rounds 40-59 (K3)
        for i in 40..60 {
            let f = (b & c) | (b & d) | (c & d);
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i]).wrapping_add(K3);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Rounds 60-79 (K4)
        for i in 60..80 {
            let f = b ^ c ^ d;
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i]).wrapping_add(K4);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Add to hash
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    /// Finalize and return hash
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
    #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
    pub fn finalize(mut self, data: &[u8]) -> [u8; SHA1_SIZE] {
        // Calculate padding
        let len = data.len();
        // Need at least 9 bytes for: 0x80 (1 byte) + 8 bytes for length
        let mut padding_len = 1usize;
        if (len + 1 + 8) % SHA1_BLOCK_SIZE != 0 {
            // Need more padding to reach next block
            padding_len += SHA1_BLOCK_SIZE - ((len + 1 + 8) % SHA1_BLOCK_SIZE);
        }

        // Calculate total length in bits
        let total_len = (len as u64) * 8;

        // Build padded message
        let mut padded = Vec::with_capacity(len + padding_len + 8);
        padded.extend_from_slice(data);
        padded.push(0x80);
        padded.resize(padded.len() + padding_len, 0);
        padded.extend_from_slice(&total_len.to_be_bytes());

        // Process final blocks
        for block in padded.chunks(SHA1_BLOCK_SIZE) {
            self.process_block(block);
        }

        // Convert to bytes
        let mut out = [0u8; SHA1_SIZE];
        for (i, &h) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

/// SHA-1 module
///
/// # Deprecation
///
/// **This module is deprecated and should not be used in new code.**
/// Use `plan9_security::hash::sha256` or `plan9_security::hash::sha512` instead.
pub mod sha1 {
    use super::*;

    /// SHA-1 output size
    pub const SIZE: usize = SHA1_SIZE;

    /// Compute SHA-1 hash
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// 20-byte hash value
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
    #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
    pub fn hash(data: &[u8]) -> [u8; SHA1_SIZE] {
        let state = State::new();
        state.finalize(data)
    }

    /// Incremental SHA-1 hasher
    #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
    pub struct Hasher {
        state: State,
        data: Vec<u8>,
    }

    impl Hasher {
        /// Create a new hasher
        ///
        /// # Deprecation
        ///
        /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
        #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
        pub fn new() -> Self {
            Self {
                state: State::new(),
                data: Vec::new(),
            }
        }

        /// Update with more data
        ///
        /// # Deprecation
        ///
        /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
        #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
        pub fn update(&mut self, data: &[u8]) {
            self.data.extend_from_slice(data);
        }

        /// Finalize and return hash
        ///
        /// # Deprecation
        ///
        /// **This function is deprecated. Use SHA-256 or SHA-512 instead.**
        #[deprecated(since = "0.2.0", note = "SHA-1 is deprecated. Use SHA-256 instead.")]
        pub fn finalize(self) -> [u8; SHA1_SIZE] {
            self.state.finalize(&self.data)
        }
    }

    impl Default for Hasher {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Re-export at module level for convenience
pub use sha1::{hash, Hasher};

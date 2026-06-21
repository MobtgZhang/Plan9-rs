//! RC4 Stream Cipher
//!
//! RC4 is a stream cipher designed by Ron Rivest.
//!
//! ## DEPRECATED - Security Warning
//!
//! **WARNING: RC4 is cryptographically broken and should NOT be used in any new systems.**
//!
//! Known vulnerabilities include:
//! - Fluhrer, Mantin, and Shamir attack (2001)
//! - Klein's attack on RC4 (2005)
//! - RC4 NOMORE attack (2015)
//! - Biases in the RC4 keystream
//!
//! This implementation is provided ONLY for compatibility with legacy systems.
//!
//! ## Migration Guide
//!
//! Replace RC4 with one of these secure alternatives:
//! - **ChaCha20**: `plan9_security::chacha20::ChaCha20`
//! - **AES-256-GCM**: `plan9_security::aes` module
//!
//! ## Usage
//!
//! ```ignore
//! use plan9_security::rc4::Rc4;
//!
//! let key = b"secret";
//! let mut cipher = Rc4::new(key);
//!
//! let mut data = b"Hello".to_vec();
//! cipher.crypt(&mut data);
//! ```

/// RC4 state
///
/// # Deprecation
///
/// **This struct is deprecated and should not be used in new code.**
///
/// RC4 has multiple known cryptographic vulnerabilities:
/// - Biased output bytes
/// - Weak key schedule
/// - Vulnerable to related-key attacks
///
/// Use `ChaCha20` or `AES` instead.
#[deprecated(
    since = "0.2.0",
    note = "RC4 is cryptographically broken. Use ChaCha20 or AES instead."
)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use ChaCha20 instead.**
    #[deprecated(since = "0.2.0", note = "RC4 is deprecated. Use ChaCha20 instead.")]
    pub fn new(key: &[u8]) -> Self {
        let mut cipher = Self {
            state: [0; 256],
            i: 0,
            j: 0,
        };
        cipher.key_setup(key);
        cipher
    }

    /// Initialize the key schedule
    fn key_setup(&mut self, key: &[u8]) {
        // Initialize state with identity permutation
        for i in 0..256 {
            self.state[i] = i as u8;
        }

        // Key scheduling algorithm
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(self.state[i]).wrapping_add(key[i % key.len()]);
            self.state.swap(i, j as usize);
        }
    }

    /// Encrypt/decrypt data in place
    ///
    /// RC4 is symmetric - encryption and decryption are the same operation
    ///
    /// # Deprecation
    ///
    /// **This function is deprecated. Use ChaCha20 instead.**
    #[deprecated(since = "0.2.0", note = "RC4 is deprecated. Use ChaCha20 instead.")]
    pub fn crypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);

            self.state.swap(self.i as usize, self.j as usize);

            let k = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

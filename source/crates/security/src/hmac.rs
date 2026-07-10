//! HMAC (Hash-based Message Authentication Code)
//!
//! Provides HMAC implementations using SHA-256 and SHA-512.
//!
//! ## HMAC Algorithm
//!
//! HMAC(key, message) = H((K' ^ opad) || H((K' ^ ipad) || message))
//!
//! Where:
//! - H is a cryptographic hash function
//! - K' is the key (padded or hashed to block size)
//! - ipad = 0x36 repeated
//! - opad = 0x5C repeated
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::hmac::{hmac_sha256, hmac_sha512};
//!
//! let key = b"my_secret_key";
//! let message = b"Hello, World!";
//!
//! let mac = hmac_sha256(key, message);
//! let mac512 = hmac_sha512(key, message);
//! ```

use alloc::vec::Vec;
use crate::hash::{sha256, sha512};
use crate::SecurityError;

/// Block size for HMAC (SHA-256 block size)
const SHA256_BLOCK_SIZE: usize = 64;
/// Block size for HMAC (SHA-512 block size)
const SHA512_BLOCK_SIZE: usize = 128;

/// Compute HMAC-SHA1
/// 
/// # Arguments
/// 
/// * `key` - Secret key
/// * `message` - Message to authenticate
/// 
/// # Returns
/// 
/// 20-byte authentication code
// (hmac_sha1 removed: SHA-1 is deprecated; use hmac_sha256 instead.)

/// Verify HMAC-SHA1
/// 
/// Performs constant-time comparison to prevent timing attacks.
// (verify_hmac_sha1 removed: SHA-1 is deprecated; use verify_hmac_sha256 instead.)

/// HMAC-SHA1 incremental hasher
// (HmacSha1 removed: SHA-1 is deprecated; use HmacSha256 instead.)

/// Compute HMAC-SHA256
/// 
/// # Arguments
/// 
/// * `key` - Secret key
/// * `message` - Message to authenticate
/// 
/// # Returns
/// 
/// 32-byte authentication code
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // Process key to get K' (padded or hashed to block size)
    let mut k = [0u8; SHA256_BLOCK_SIZE];
    
    if key.len() > SHA256_BLOCK_SIZE {
        // If key is longer than block size, hash it
        let hash = sha256::hash(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // XOR key with ipad (0x36)
    let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
    for (i, byte) in ipad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    // XOR key with opad (0x5C)
    let mut opad = [0x5Cu8; SHA256_BLOCK_SIZE];
    for (i, byte) in opad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    // Inner hash: H(K' ^ ipad || message)
    let mut inner_data = Vec::with_capacity(SHA256_BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha256::hash(&inner_data);

    // Outer hash: H(K' ^ opad || inner_hash)
    let mut outer_data = Vec::with_capacity(SHA256_BLOCK_SIZE + 32);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    
    sha256::hash(&outer_data)
}

/// Compute HMAC-SHA512
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    // Process key to get K' (padded or hashed to block size)
    let mut k = [0u8; SHA512_BLOCK_SIZE];
    
    if key.len() > SHA512_BLOCK_SIZE {
        let hash = sha512::hash(key);
        k[..64].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // XOR key with ipad (0x36)
    let mut ipad = [0x36u8; SHA512_BLOCK_SIZE];
    for (i, byte) in ipad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    // XOR key with opad (0x5C)
    let mut opad = [0x5Cu8; SHA512_BLOCK_SIZE];
    for (i, byte) in opad.iter_mut().enumerate() {
        *byte ^= k[i];
    }

    // Inner hash
    let mut inner_data = Vec::with_capacity(SHA512_BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha512::hash(&inner_data);

    // Outer hash
    let mut outer_data = Vec::with_capacity(SHA512_BLOCK_SIZE + 64);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    
    sha512::hash(&outer_data)
}

/// Verify HMAC-SHA256
/// 
/// Performs constant-time comparison to prevent timing attacks.
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], expected: &[u8; 32]) -> Result<(), SecurityError> {
    let computed = hmac_sha256(key, message);
    
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    
    if diff == 0 {
        Ok(())
    } else {
        Err(SecurityError::AuthenticationFailed)
    }
}

/// Verify HMAC-SHA512
pub fn verify_hmac_sha512(key: &[u8], message: &[u8], expected: &[u8; 64]) -> Result<(), SecurityError> {
    let computed = hmac_sha512(key, message);
    
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    
    if diff == 0 {
        Ok(())
    } else {
        Err(SecurityError::AuthenticationFailed)
    }
}

/// HMAC state for incremental computation
pub struct HmacSha256 {
    inner: sha256::State,
    outer: sha256::State,
}

impl HmacSha256 {
    /// Create new HMAC-SHA256 context
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; SHA256_BLOCK_SIZE];
        
        if key.len() > SHA256_BLOCK_SIZE {
            let hash = sha256::hash(key);
            k[..32].copy_from_slice(&hash);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        // XOR with ipad
        let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
        for (i, byte) in ipad.iter_mut().enumerate() {
            *byte ^= k[i];
        }

        let mut inner = sha256::State::new();
        inner.update(&ipad);

        // XOR with opad
        let mut opad = [0x5Cu8; SHA256_BLOCK_SIZE];
        for (i, byte) in opad.iter_mut().enumerate() {
            *byte ^= k[i];
        }

        let mut outer = sha256::State::new();
        outer.update(&opad);

        Self { inner, outer }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return HMAC
    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&inner_hash);
        outer.finalize()
    }
}

/// HMAC state for SHA-512
pub struct HmacSha512 {
    inner: sha512::State,
    outer: sha512::State,
}

impl HmacSha512 {
    /// Create new HMAC-SHA512 context
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; SHA512_BLOCK_SIZE];
        
        if key.len() > SHA512_BLOCK_SIZE {
            let hash = sha512::hash(key);
            k[..64].copy_from_slice(&hash);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; SHA512_BLOCK_SIZE];
        for (i, byte) in ipad.iter_mut().enumerate() {
            *byte ^= k[i];
        }

        let mut inner = sha512::State::new();
        inner.update(&ipad);

        let mut opad = [0x5Cu8; SHA512_BLOCK_SIZE];
        for (i, byte) in opad.iter_mut().enumerate() {
            *byte ^= k[i];
        }

        let mut outer = sha512::State::new();
        outer.update(&opad);

        Self { inner, outer }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return HMAC
    pub fn finalize(self) -> [u8; 64] {
        let inner_hash = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&inner_hash);
        outer.finalize()
    }
}

//! PBKDF2 Key Derivation Function
//!
//! Password-Based Key Derivation Function 2 (PBKDF2) as defined in RFC 2898.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::pbkdf2;
//!
//! let password = b"password";
//! let salt = b"salt";
//! let key = pbkdf2::derive_key(password, salt, 10000, 32);
//! ```

use alloc::vec::Vec;
use crate::hash::sha256;
use crate::hmac::hmac_sha256;

/// PBKDF2-HMAC-SHA256 key derivation
/// 
/// # Arguments
/// 
/// * `password` - Password to derive from
/// * `salt` - Salt value
/// * `iterations` - Number of iterations (recommended: 10000+)
/// * `key_len` - Desired key length in bytes
/// 
/// # Returns
/// 
/// Derived key of the specified length
pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let hash_len = 32; // SHA-256 output size
    let blocks_needed = (key_len + hash_len - 1) / hash_len;
    
    let mut result = Vec::with_capacity(key_len);
    
    for block_num in 1..=blocks_needed {
        let block = compute_block(password, salt, iterations, block_num as u32);
        result.extend_from_slice(&block);
    }
    
    result.truncate(key_len);
    result
}

/// Compute a single PBKDF2 block
fn compute_block(password: &[u8], salt: &[u8], iterations: u32, block_num: u32) -> [u8; 32] {
    // U_1 = PRF(Password, Salt || INT(i))
    let mut salt_with_idx = Vec::with_capacity(salt.len() + 4);
    salt_with_idx.extend_from_slice(salt);
    salt_with_idx.extend_from_slice(&block_num.to_be_bytes());
    
    let mut u = hmac_sha256(password, &salt_with_idx);
    let mut result = u;
    
    // U_2 = PRF(Password, U_1), U_3 = PRF(Password, U_2), ...
    // Result = U_1 XOR U_2 XOR U_3 ...
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (i, byte) in result.iter_mut().enumerate() {
            *byte ^= u[i];
        }
    }
    
    result
}

/// Verify a password against a stored hash
/// 
/// # Arguments
/// 
/// * `password` - Password to verify
/// * `salt` - Salt that was used for derivation
/// * `iterations` - Number of iterations
/// * `expected` - Expected derived key
/// 
/// # Returns
/// 
/// Ok(()) if verification succeeds, Err otherwise
pub fn verify(password: &[u8], salt: &[u8], iterations: u32, expected: &[u8]) -> Result<(), ()> {
    let derived = derive_key(password, salt, iterations, expected.len());
    
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in derived.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    
    if diff == 0 {
        Ok(())
    } else {
        Err(())
    }
}

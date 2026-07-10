//! HKDF - HMAC-based Key Derivation Function
//!
//! Implements HKDF as specified in RFC 5869.
//!
//! ## Usage
//!
//! ```ignore
//! use plan9_security::hkdf::{hkdf_extract, hkdf_expand};
//!
//! // Extract a pseudorandom key from input key material and salt
//! let prk = hkdf_extract(hash::SHA256, Some(salt), ikm);
//!
//! // Expand the PRK into output keying material
//! let okm = hkdf_expand(hash::SHA256, &prk, info, 32);
//! ```


extern crate alloc;

use alloc::vec::Vec;
use crate::hmac::{hmac_sha256, hmac_sha512};

/// HKDF algorithm parameters
#[derive(Debug, Clone)]
pub struct HkdfParams {
    /// Hash algorithm identifier
    pub hash: HashType,
    /// Input key material (IKM)
    pub ikm: Vec<u8>,
    /// Salt (can be empty)
    pub salt: Option<Vec<u8>>,
    /// Context and application specific information
    pub info: Vec<u8>,
}

/// Hash algorithm type for HKDF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
}

/// HKDF Extract operation
/// 
/// Combines the input key material (IKM) with a salt to produce a pseudorandom key (PRK).
/// 
/// # Arguments
/// * `hash` - The hash algorithm to use (SHA-256 or SHA-512)
/// * `salt` - Optional salt value (if None, uses a string of zeros of hash length)
/// * `ikm` - Input key material
/// 
/// # Returns
/// * The pseudorandom key (PRK) of hash length bytes
pub fn hkdf_extract(
    hash: HashType,
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Vec<u8> {
    match hash {
        HashType::Sha256 => hkdf_extract_sha256(salt, ikm),
        HashType::Sha512 => hkdf_extract_sha512(salt, ikm),
    }
}

/// HKDF Extract with SHA-256
fn hkdf_extract_sha256(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    // If salt is not provided, use a string of zeros of hash length
    let salt = salt.unwrap_or(&[0u8; 32]);
    hmac_sha256(salt, ikm).to_vec()
}

/// HKDF Extract with SHA-512
fn hkdf_extract_sha512(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    // If salt is not provided, use a string of zeros of hash length
    let salt = salt.unwrap_or(&[0u8; 64]);
    hmac_sha512(salt, ikm).to_vec()
}

/// HKDF Expand operation
/// 
/// Expands the pseudorandom key (PRK) into output keying material (OKM).
/// 
/// # Arguments
/// * `hash` - The hash algorithm to use (SHA-256 or SHA-512)
/// * `prk` - Pseudorandom key (must be at least hash length bytes)
/// * `info` - Context and application specific information
/// * `len` - Desired length of output keying material in bytes
/// 
/// # Returns
/// * The output keying material (OKM) of the requested length
pub fn hkdf_expand(
    hash: HashType,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Vec<u8> {
    match hash {
        HashType::Sha256 => hkdf_expand_sha256(prk, info, len),
        HashType::Sha512 => hkdf_expand_sha512(prk, info, len),
    }
}

/// HKDF Expand with SHA-256
fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hash_len = 32; // SHA-256 output length
    let n = (len + hash_len - 1) / hash_len; // Number of iterations
    
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);
        
        t = hmac_sha256(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }
    
    okm.truncate(len);
    okm
}

/// HKDF Expand with SHA-512
fn hkdf_expand_sha512(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hash_len = 64; // SHA-512 output length
    let n = (len + hash_len - 1) / hash_len; // Number of iterations
    
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);
        
        t = hmac_sha512(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }
    
    okm.truncate(len);
    okm
}

/// HKDF extract and expand in one step
/// 
/// Convenience function that combines HKDF-Extract and HKDF-Expand.
/// 
/// # Arguments
/// * `hash` - The hash algorithm to use
/// * `salt` - Optional salt value
/// * `ikm` - Input key material
/// * `info` - Context and application specific information
/// * `len` - Desired length of output keying material in bytes
/// 
/// # Returns
/// * The output keying material (OKM) of the requested length
pub fn hkdf(
    hash: HashType,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Vec<u8> {
    let prk = hkdf_extract(hash, salt, ikm);
    hkdf_expand(hash, &prk, info, len)
}

/// TLS 1.2 PRF (Pseudo-Random Function)
/// 
/// Used in TLS 1.2 for key expansion.
/// 
/// # Arguments
/// * `secret` - The secret value (master secret or premaster secret)
/// * `label` - The label string (e.g., "key expansion")
/// * `seed` - The seed value (client_random + server_random)
/// * `len` - Desired output length
/// 
/// # Returns
/// * The PRF output
pub fn tls12_prf(
    secret: &[u8],
    label: &str,
    seed: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let label_bytes = label.as_bytes();
    
    // A = HMAC_hash(secret, label + seed)
    let mut a = hmac_sha256(secret, &[label_bytes, seed].concat()).to_vec();
    
    let mut offset = 0;
    while offset < len {
        // HMAC_hash(secret, A + label + seed)
        let block = hmac_sha256(secret, &[&a, label_bytes, seed].concat());
        
        // A = HMAC_hash(secret, A)
        a = hmac_sha256(secret, &a).to_vec();
        
        for b in &block {
            if offset >= len {
                break;
            }
            out.push(*b);
            offset += 1;
        }
    }
    
    out
}

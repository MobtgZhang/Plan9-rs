//! Plan9-Security Library
//!
//! Provides cryptographic and security primitives for the Plan 9 Rust kernel.
//!
//! ## Features
//!
//! - Hash functions (SHA-256, SHA-512, SHA-1 [deprecated])
//! - HMAC for message authentication
//! - AES encryption
//! - ChaCha20 encryption
//! - Cryptographically secure random number generation (CSPRNG)
//! - Key derivation (PBKDF2)
//! - Big integer arithmetic
//!
//! ## Security Notes
//!
//! The following algorithms are deprecated due to cryptographic weaknesses:
//! - **SHA-1**: Use SHA-256 or SHA-512 instead
//! - **RC4**: Use ChaCha20 or AES instead
//!
//! ## Usage
//!
//! ```ignore
//! use plan9_security::hash::{sha256, sha512};
//! use plan9_security::hmac::hmac_sha256;
//! use plan9_security::random;
//!
//! let data = b"Hello, World!";
//! let hash = sha256::hash(data);
//! let mac = hmac_sha256(b"key", data);
//!
//! // Initialize random with seed
//! let seed = [0x42u8; 32];
//! random::init(&seed);
//! let mut buf = [0u8; 32];
//! random::fill(&mut buf);
//! ```

#![no_std]

extern crate alloc;

pub mod hash;

#[allow(deprecated)]
pub mod sha1;  // Deprecated: use hash::sha256 instead

pub mod hmac;
pub mod aes;
pub mod des;
pub mod blowfish;

#[allow(deprecated)]
pub mod rc4;  // Deprecated: use chacha20 instead

pub mod chacha20;
pub mod cmac;

/// Cryptographically secure random number generation
pub mod random;
pub mod pbkdf2;
pub mod bigint;
pub mod prime;
pub mod rsa;
pub mod dsa;
pub mod elgamal;
pub mod asn1;
pub mod x509;
pub mod pem;

pub use crate::bigint::BigInt;
pub use crate::random::{Csprng, fill, fill_secure, u32, u64, usize, init, add_entropy, rand_bound};

/// Result type for security operations
pub type Result<T> = core::result::Result<T, SecurityError>;

/// Security-related errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid IV/nonce length
    InvalidIvLength,
    /// Invalid input length
    InvalidInputLength,
    /// Authentication failed
    AuthenticationFailed,
    /// Random number generation failed
    RandomGenerationFailed,
    /// Operation not supported
    NotSupported,
    /// Computation error
    ComputationError,
}

impl SecurityError {
    /// Convert to error message
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityError::InvalidKeyLength => "invalid key length",
            SecurityError::InvalidIvLength => "invalid IV/nonce length",
            SecurityError::InvalidInputLength => "invalid input length",
            SecurityError::AuthenticationFailed => "authentication failed",
            SecurityError::RandomGenerationFailed => "random generation failed",
            SecurityError::NotSupported => "operation not supported",
            SecurityError::ComputationError => "computation error",
        }
    }
}

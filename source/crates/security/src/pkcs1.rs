//! PKCS#1 v1.5 Padding
//!
//! Implements RSA PKCS#1 v1.5 padding schemes for encryption and signatures.

#![allow(dead_code)]

use alloc::vec::Vec;
use crate::bigint::BigInt;
use crate::SecurityError;

/// PKCS#1 v1.5 padding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// Encryption padding (type 2)
    Encryption,
    /// Signature padding (type 1)
    Signature,
}

/// Error type
#[derive(Debug)]
pub enum Pkcs1Error {
    InvalidPadding,
    DecryptionFailed,
    InvalidLength,
}

impl From<Pkcs1Error> for SecurityError {
    fn from(e: Pkcs1Error) -> Self {
        match e {
            Pkcs1Error::InvalidPadding => SecurityError::InvalidPadding,
            Pkcs1Error::DecryptionFailed => SecurityError::DecryptionFailed,
            Pkcs1Error::InvalidLength => SecurityError::InvalidLength,
        }
    }
}

// ============================================================================
// RSAES-PKCS1-v1_5
// ============================================================================

/// RSAES-PKCS1-v1_5 encryption padding
pub struct RsaEncryptionPadding {
    /// Label (for OAEP compatibility, empty for v1.5)
    label: Vec<u8>,
}

impl RsaEncryptionPadding {
    /// Create new padding
    pub fn new() -> Self {
        Self { label: Vec::new() }
    }
    
    /// Create with label
    pub fn with_label(label: &[u8]) -> Self {
        Self { label: label.to_vec() }
    }
    
    /// Add padding to message for encryption
    pub fn pad(&self, message: &[u8], key_size: usize) -> Result<Vec<u8>, Pkcs1Error> {
        // k = key size in bytes
        let k = key_size;
        
        // mLen = message length
        let m_len = message.len();
        
        // Check: mLen <= k - 11
        if m_len > k - 11 {
            return Err(Pkcs1Error::InvalidLength);
        }
        
        // Generate padding:
        // 0x00 || 0x02 || PS || 0x00 || T
        // where PS is at least 8 random non-zero bytes
        let mut em = Vec::with_capacity(k);
        
        // First byte: 0x00
        em.push(0x00);
        
        // Second byte: 0x02 (encryption)
        em.push(0x02);
        
        // PS: random bytes, at least 8, all non-zero
        let ps_len = k - m_len - 3;
        let mut rng = crate::random::Csrng::new();
        for _ in 0..ps_len {
            let mut byte = rng.read_byte();
            // Ensure non-zero
            while byte == 0 {
                byte = rng.read_byte();
            }
            em.push(byte);
        }
        
        // Separator
        em.push(0x00);
        
        // Message
        em.extend_from_slice(message);
        
        Ok(em)
    }
    
    /// Remove padding from encrypted block
    pub fn unpad(&self, encrypted: &[u8], key_size: usize) -> Result<Vec<u8>, Pkcs1Error> {
        let k = key_size;
        
        // Check length
        if encrypted.len() != k {
            return Err(Pkcs1Error::InvalidLength);
        }
        
        // Check format
        if encrypted[0] != 0x00 || encrypted[1] != 0x02 {
            return Err(Pkcs1Error::InvalidPadding);
        }
        
        // Find separator 0x00
        let mut pos = 2;
        let mut found_sep = false;
        while pos < k {
            if encrypted[pos] == 0x00 {
                found_sep = true;
                break;
            }
            pos += 1;
        }
        
        // Check minimum padding length
        if !found_sep || pos < 10 {
            return Err(Pkcs1Error::InvalidPadding);
        }
        
        // Extract message
        let message = encrypted[pos + 1..].to_vec();
        
        Ok(message)
    }
}

// ============================================================================
// RSASSA-PKCS1-v1_5
// ============================================================================

/// RSASSA-PKCS1-v1_5 signature padding
pub struct RsaSignaturePadding {
    /// Hash algorithm OID prefix
    oid_prefix: Vec<u8>,
}

impl RsaSignaturePadding {
    /// Create new padding with hash algorithm
    pub fn new(hash_algo: HashAlgorithm) -> Self {
        Self {
            oid_prefix: hash_algo.oid_prefix(),
        }
    }
    
    /// Add padding to digest for signature
    pub fn pad(&self, digest: &[u8], key_size: usize) -> Result<Vec<u8>, Pkcs1Error> {
        let k = key_size;
        
        // Algorithm ID (T = OID || hash digest)
        let t = self.oid_prefix(digest);
        let t_len = t.len();
        
        // Check: t_len + 11 <= k
        if t_len + 11 > k {
            return Err(Pkcs1Error::InvalidLength);
        }
        
        // EM = 0x00 || 0x01 || PS || 0x00 || T
        let mut em = Vec::with_capacity(k);
        
        // First byte: 0x00
        em.push(0x00);
        
        // Second byte: 0x01 (signature)
        em.push(0x01);
        
        // PS: 0xFF bytes
        let ps_len = k - t_len - 3;
        em.resize(em.len() + ps_len, 0xFF);
        
        // Separator
        em.push(0x00);
        
        // T (algorithm ID + digest)
        em.extend_from_slice(&t);
        
        Ok(em)
    }
    
    /// Remove padding from signature block
    pub fn unpad(&self, signature: &[u8], key_size: usize) -> Result<Vec<u8>, Pkcs1Error> {
        let k = key_size;
        
        if signature.len() != k {
            return Err(Pkcs1Error::InvalidLength);
        }
        
        // Check format
        if signature[0] != 0x00 || signature[1] != 0x01 {
            return Err(Pkcs1Error::InvalidPadding);
        }
        
        // Find separator 0x00
        let mut pos = 2;
        while pos < k {
            if signature[pos] == 0x00 {
                break;
            }
            if signature[pos] != 0xFF {
                return Err(Pkcs1Error::InvalidPadding);
            }
            pos += 1;
        }
        
        if pos < 10 {
            return Err(Pkcs1Error::InvalidPadding);
        }
        
        // Extract T
        let t = signature[pos + 1..].to_vec();
        
        Ok(t)
    }
    
    /// Build T = OID || hash digest
    fn oid_prefix(&self, digest: &[u8]) -> Vec<u8> {
        let mut t = self.oid_prefix.clone();
        t.extend_from_slice(digest);
        t
    }
}

/// Hash algorithm for signature padding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// MD5 (legacy)
    Md5,
    /// SHA-1
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HashAlgorithm {
    /// Get DER-encoded OID prefix
    pub fn oid_prefix(&self) -> Vec<u8> {
        match self {
            HashAlgorithm::Md5 => {
                // OID 1.2.840.113549.2.5
                vec![0x30, 0x20, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
                     0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]
            }
            HashAlgorithm::Sha1 => {
                // OID 1.3.14.3.2.26
                vec![0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
                     0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]
            }
            HashAlgorithm::Sha256 => {
                // OID 2.16.840.1.101.3.4.2.1
                vec![0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
                     0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
            }
            HashAlgorithm::Sha384 => {
                // OID 2.16.840.1.101.3.4.2.2
                vec![0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
                     0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
            }
            HashAlgorithm::Sha512 => {
                // OID 2.16.840.1.101.3.4.2.3
                vec![0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
                     0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
            }
        }
    }
    
    /// Get hash output size
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Md5 => 16,
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if key size is valid for padding
pub fn valid_key_size(size: usize) -> bool {
    // Key sizes 512 to 65536 bits
    size >= 64 && size <= 8192 && size % 8 == 0
}

/// Get minimum message length for encryption
pub fn min_encrypted_len(key_size: usize) -> usize {
    key_size
}

/// Get minimum signature length
pub fn min_signature_len(key_size: usize) -> usize {
    key_size
}

/// Get minimum plaintext length for encryption
pub fn max_message_len(key_size: usize) -> usize {
    key_size - 11
}

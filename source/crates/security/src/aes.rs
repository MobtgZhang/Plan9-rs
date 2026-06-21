//! AES Block Cipher
//!
//! Implements AES-128, AES-192, and AES-256 in CBC mode.
//!
//! ## AES Algorithm
//!
//! AES (Advanced Encryption Standard) is a symmetric block cipher
//! that processes data in 128-bit (16-byte) blocks.
//!
//! ## Key Sizes
//!
//! - AES-128: 128-bit key (16 bytes)
//! - AES-192: 192-bit key (24 bytes)  
//! - AES-256: 256-bit key (32 bytes)
//!
//! ## Modes
//!
//! - ECB (Electronic Codebook) - not recommended
//! - CBC (Cipher Block Chaining) - recommended
//! - CTR (Counter) - recommended
//! - GCM (Galois/Counter Mode) - provides authentication
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::aes::{AesCbc, Aes256};
//!
//! let key = [0u8; 32]; // 256-bit key
//! let iv = [0u8; 16];  // Initialization vector
//! let plaintext = b"Hello, World!";
//!
//! let cipher = AesCbc::new::<Aes256>(&key, &iv);
//! let ciphertext = cipher.encrypt(plaintext);
//! let decrypted = cipher.decrypt(&ciphertext).unwrap();
//! ```

use alloc::vec;
use alloc::vec::Vec;
use crate::SecurityError;

/// AES block size (128 bits)
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-128 key size
pub const AES_128_KEY_SIZE: usize = 16;
/// AES-192 key size
pub const AES_192_KEY_SIZE: usize = 24;
/// AES-256 key size
pub const AES_256_KEY_SIZE: usize = 32;

/// AES round constants
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

/// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES-128 marker
pub struct Aes128;
/// AES-192 marker
pub struct Aes192;
/// AES-256 marker
pub struct Aes256;

/// AES cipher context
pub struct AesCbc<A> {
    /// Round keys
    round_keys: Vec<[u8; 16]>,
    /// Number of rounds
    rounds: usize,
    /// IV (for CBC mode)
    iv: [u8; 16],
    /// Phantom marker for key type
    _phantom: core::marker::PhantomData<A>,
}

impl AesCbc<Aes128> {
    /// Create new AES-128 cipher
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != AES_128_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(SecurityError::InvalidIvLength);
        }

        let mut cipher = Self {
            round_keys: Vec::with_capacity(11),
            rounds: 10,
            iv: [0u8; 16],
            _phantom: core::marker::PhantomData,
        };
        cipher.iv.copy_from_slice(iv);
        
        key_expansion(&mut cipher.round_keys, key, 10);
        
        Ok(cipher)
    }
}

impl AesCbc<Aes192> {
    /// Create new AES-192 cipher
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != AES_192_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(SecurityError::InvalidIvLength);
        }

        let mut cipher = Self {
            round_keys: Vec::with_capacity(13),
            rounds: 12,
            iv: [0u8; 16],
            _phantom: core::marker::PhantomData,
        };
        cipher.iv.copy_from_slice(iv);
        
        key_expansion(&mut cipher.round_keys, key, 12);
        
        Ok(cipher)
    }
}

impl AesCbc<Aes256> {
    /// Create new AES-256 cipher
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(SecurityError::InvalidKeyLength);
        }
        if iv.len() != AES_BLOCK_SIZE {
            return Err(SecurityError::InvalidIvLength);
        }

        let mut cipher = Self {
            round_keys: Vec::with_capacity(15),
            rounds: 14,
            iv: [0u8; 16],
            _phantom: core::marker::PhantomData,
        };
        cipher.iv.copy_from_slice(iv);
        
        key_expansion(&mut cipher.round_keys, key, 14);
        
        Ok(cipher)
    }
}

impl<A> AesCbc<A> {
    /// Encrypt data (CBC mode with PKCS7 padding)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            ((plaintext.len() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
        );
        
        let mut prev_block = self.iv;
        let mut remaining = plaintext;
        
        while !remaining.is_empty() {
            let mut block = [0u8; AES_BLOCK_SIZE];
            let to_copy = remaining.len().min(AES_BLOCK_SIZE);
            block[..to_copy].copy_from_slice(&remaining[..to_copy]);
            
            // XOR with previous ciphertext (or IV)
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= prev_block[i];
            }
            
            // Encrypt block
            let encrypted = self.encrypt_block(&block);
            prev_block.copy_from_slice(&encrypted);
            result.extend_from_slice(&encrypted);
            
            remaining = &remaining[to_copy..];
        }
        
        // Add PKCS7 padding
        let pad_len = AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
        let pad = vec![pad_len as u8; pad_len];
        for (i, byte) in pad.iter().enumerate() {
            prev_block[i] ^= *byte;
        }
        let encrypted_pad = self.encrypt_block(&prev_block);
        result.extend_from_slice(&encrypted_pad);
        
        result
    }

    /// Decrypt data (CBC mode with PKCS7 padding removal)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(SecurityError::InvalidInputLength);
        }
        if ciphertext.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }

        let mut result = Vec::with_capacity(ciphertext.len());
        let mut prev_block = self.iv;
        
        for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
            let mut block = [0u8; AES_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            
            let mut decrypted = self.decrypt_block(&block);
            
            // XOR with previous ciphertext
            for (i, byte) in decrypted.iter_mut().enumerate() {
                *byte ^= prev_block[i];
            }
            
            prev_block.copy_from_slice(chunk);
            
            // Don't add padding to last block yet
            if chunk.len() == AES_BLOCK_SIZE && chunk == &ciphertext[ciphertext.len() - AES_BLOCK_SIZE..] {
                // This is the last block - remove padding
                if let Some(&pad_len) = decrypted.last() {
                    if pad_len as usize <= AES_BLOCK_SIZE {
                        let actual_len = decrypted.len() - pad_len as usize;
                        result.extend_from_slice(&decrypted[..actual_len]);
                        return Ok(result);
                    }
                }
            }
            
            result.extend_from_slice(&decrypted);
        }
        
        Ok(result)
    }

    /// Encrypt a single block
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        
        // Initial round key addition
        xor_round_key(&mut state, &self.round_keys[0]);
        
        // Main rounds
        for round in 1..self.rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            xor_round_key(&mut state, &self.round_keys[round]);
        }
        
        // Final round (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        xor_round_key(&mut state, &self.round_keys[self.rounds]);
        
        state
    }

    /// Decrypt a single block
    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        
        // Initial round
        xor_round_key(&mut state, &self.round_keys[self.rounds]);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        
        // Main rounds
        for round in (1..self.rounds).rev() {
            xor_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
        }
        
        // Final round
        xor_round_key(&mut state, &self.round_keys[0]);
        
        state
    }
}

/// XOR state with round key
fn xor_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(round_key.iter()) {
        *s ^= *k;
    }
}

/// AES SubBytes transformation
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

/// AES InvSubBytes transformation
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// AES ShiftRows transformation
fn shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    let tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;
    
    // Row 2: shift left by 2
    let tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    let tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    
    // Row 3: shift left by 3
    let tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

/// AES InvShiftRows transformation
fn inv_shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift right by 1
    let tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;
    
    // Row 2: shift right by 2
    let tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    let tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    
    // Row 3: shift right by 3
    let tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

/// AES MixColumns transformation
fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let idx = i * 4;
        let s0 = state[idx];
        let s1 = state[idx + 1];
        let s2 = state[idx + 2];
        let s3 = state[idx + 3];
        
        state[idx] = gfmul(0x02, s0) ^ gfmul(0x03, s1) ^ s2 ^ s3;
        state[idx + 1] = s0 ^ gfmul(0x02, s1) ^ gfmul(0x03, s2) ^ s3;
        state[idx + 2] = s0 ^ s1 ^ gfmul(0x02, s2) ^ gfmul(0x03, s3);
        state[idx + 3] = gfmul(0x03, s0) ^ s1 ^ s2 ^ gfmul(0x02, s3);
    }
}

/// AES InvMixColumns transformation
fn inv_mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let idx = i * 4;
        let s0 = state[idx];
        let s1 = state[idx + 1];
        let s2 = state[idx + 2];
        let s3 = state[idx + 3];
        
        state[idx] = gfmul(0x0e, s0) ^ gfmul(0x0b, s1) ^ gfmul(0x0d, s2) ^ gfmul(0x09, s3);
        state[idx + 1] = gfmul(0x09, s0) ^ gfmul(0x0e, s1) ^ gfmul(0x0b, s2) ^ gfmul(0x0d, s3);
        state[idx + 2] = gfmul(0x0d, s0) ^ gfmul(0x09, s1) ^ gfmul(0x0e, s2) ^ gfmul(0x0b, s3);
        state[idx + 3] = gfmul(0x0b, s0) ^ gfmul(0x0d, s1) ^ gfmul(0x09, s2) ^ gfmul(0x0e, s3);
    }
}

/// Galois Field multiplication
fn gfmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    
    p
}

/// Key expansion for AES
fn key_expansion(round_keys: &mut Vec<[u8; 16]>, key: &[u8], rounds: usize) {
    let key_words = match key.len() {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => return,
    };
    
    // First round key is the key itself
    let mut key_schedule = Vec::with_capacity((rounds + 1) * 4);
    for i in 0..key_words {
        let mut word = [0u8; 4];
        word.copy_from_slice(&key[i * 4..(i + 1) * 4]);
        key_schedule.push(word);
    }
    
    // Generate remaining words
    for i in key_words..(rounds + 1) * 4 {
        let mut temp = key_schedule[i - 1];
        
        if i % key_words == 0 {
            // RotWord
            let t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for byte in temp.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
            
            // XOR with Rcon
            temp[0] ^= RCON[i / key_words];
        } else if key_words > 6 && i % key_words == 4 {
            // SubWord for AES-256
            for byte in temp.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
        }
        
        let prev = key_schedule[i - key_words];
        let mut new_word = [0u8; 4];
        for (j, byte) in new_word.iter_mut().enumerate() {
            *byte = prev[j] ^ temp[j];
        }
        key_schedule.push(new_word);
    }
    
    // Convert to round keys
    for round in 0..=rounds {
        let mut rk = [0u8; 16];
        for i in 0..4 {
            let word = &key_schedule[round * 4 + i];
            rk[i * 4..(i + 1) * 4].copy_from_slice(word);
        }
        round_keys.push(rk);
    }
}

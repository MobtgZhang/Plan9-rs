//! DES and 3DES Block Cipher
//!
//! Implements DES (Data Encryption Standard) and Triple DES.
//!
//! ## DES Algorithm
//!
//! DES is a symmetric block cipher that processes data in 64-bit (8-byte) blocks
//! using a 56-bit key (stored as 64 bits with parity).
//!
//! ## Triple DES
//!
//! 3DES applies DES three times with different keys: E(k1, D(k2, E(k3)))
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::des::{DesCipher, TripleDes};
//!
//! let key = [0u8; 8]; // 64-bit DES key
//! let cipher = DesCipher::new(&key);
//!
//! let plaintext = [0u8; 8];
//! let mut ciphertext = [0u8; 8];
//! cipher.encrypt_block(&plaintext, &mut ciphertext);
//! ```

use alloc::vec;
use alloc::vec::Vec;
use crate::SecurityError;

/// DES block size (64 bits)
pub const DES_BLOCK_SIZE: usize = 8;

/// DES key size (64 bits, but only 56 are used)
pub const DES_KEY_SIZE: usize = 8;

/// Triple DES key size (192 bits)
pub const TRIPLE_DES_KEY_SIZE: usize = 24;

/// DES S-boxes (8 S-boxes, each 4x16)
const S_BOXES: [[u8; 64]; 8] = [
    // S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    // S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    // S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    // S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    // S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    // S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    // S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 9, 2, 8, 5, 6, 0,
        8, 13, 15, 12, 9, 7, 0, 3, 14, 4, 6, 10, 2, 5, 11, 1,
    ],
    // S8
    [
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0,
    ],
];

/// Initial permutation
const IP: [usize; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final permutation
const FP: [usize; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// DES key permutation (PC-1)
const PC1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

/// Key schedule permutation (PC-2)
const PC2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Left shift schedule for key generation
const LS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// DES single block cipher
pub struct DesCipher {
    round_keys: [u64; 16],
}

impl DesCipher {
    /// Create a new DES cipher with the given key
    pub fn new(key: &[u8; DES_KEY_SIZE]) -> Self {
        let mut cipher = Self { round_keys: [0; 16] };
        cipher.key_setup(key);
        cipher
    }

    /// Set up the key schedule
    fn key_setup(&mut self, key: &[u8; DES_KEY_SIZE]) {
        // Apply PC-1 permutation
        let mut cd = 0u64;
        for i in 0..56 {
            let bit = (key[PC1[i] / 8 - 1] >> (8 - PC1[i] % 8)) & 1;
            cd |= (bit as u64) << (55 - i);
        }

        // Generate 16 round keys
        let mut c = cd >> 28;
        let mut d = cd & 0x0FFFFFFF;

        for i in 0..16 {
            // Left shift
            let shift = LS[i];
            c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
            d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;

            // Combine and apply PC-2
            let cd = (c << 28) | d;
            let mut round_key = 0u64;
            for j in 0..48 {
                let bit = (cd >> (63 - PC2[j])) & 1;
                round_key |= bit << (47 - j);
            }
            self.round_keys[i] = round_key;
        }
    }

    /// Encrypt a single block
    pub fn encrypt_block(&self, block: &[u8; DES_BLOCK_SIZE], out: &mut [u8; DES_BLOCK_SIZE]) {
        self.crypt(block, out, false);
    }

    /// Decrypt a single block
    pub fn decrypt_block(&self, block: &[u8; DES_BLOCK_SIZE], out: &mut [u8; DES_BLOCK_SIZE]) {
        self.crypt(block, out, true);
    }

    /// Core DES operation
    fn crypt(&self, block: &[u8; DES_BLOCK_SIZE], out: &mut [u8; DES_BLOCK_SIZE], decrypt: bool) {
        // Apply initial permutation
        let mut bits = 0u64;
        for i in 0..64 {
            let bit = (block[IP[i] / 8 - 1] >> (8 - IP[i] % 8)) & 1;
            bits |= (bit as u64) << (63 - i);
        }

        // Split into L and R (lower 32 bits = L, upper 32 bits = R)
        let mut l = bits & 0xFFFFFFFF;
        let mut r = (bits >> 32) & 0xFFFFFFFF;

        // 16 rounds
        for i in 0..16 {
            let key_idx = if decrypt { 15 - i } else { i };
            let old_r = r;
            let f_out = self.f_function(r as u32, self.round_keys[key_idx] as u32);
            r = l ^ (f_out as u64);
            l = old_r;
        }

        // Combine (R first, then L)
        let combined = (r << 32) | l;

        // Apply final permutation
        for i in 0..64 {
            let bit = (combined >> (63 - FP[i])) & 1;
            out[FP[i] / 8 - 1] |= (bit as u8) << (8 - FP[i] % 8);
        }
    }

    /// The F function of DES
    fn f_function(&self, r: u32, key: u32) -> u32 {
        // Expansion (E-box) - takes 32 bits, produces 48 bits (stored in u64)
        let expanded = expand_bits(r);

        // XOR with round key (lower 32 bits of 48-bit key)
        let xored = expanded ^ ((key as u64) & 0xFFFFFFFFFFFF);

        // S-box substitution
        let mut output = 0u32;
        for i in 0..8 {
            let bits = ((xored >> (42 - i * 6)) & 0x3F) as u8;
            let row = ((bits & 0x20) >> 4) | (bits & 0x01);
            let col = (bits >> 1) & 0x0F;
            output |= (S_BOXES[i][(row as usize) * 16 + (col as usize)] as u32) << (28 - i * 4);
        }

        // Permutation (P-box)
        permute(output)
    }
}

/// Expand 32 bits to 48 using E-box
fn expand_bits(r: u32) -> u64 {
    const E: [u32; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];

    let mut result = 0u64;
    for i in 0..48 {
        let bit = (r >> (32 - E[i])) & 1;
        result |= (bit as u64) << (47 - i);
    }
    result
}

/// Permutation P-box
fn permute(x: u32) -> u32 {
    const P: [u32; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ];

    let mut result = 0u32;
    for i in 0..32 {
        let bit = (x >> (32 - P[i])) & 1;
        result |= bit << (31 - i);
    }
    result
}

/// Triple DES (3DES) cipher
pub struct TripleDes {
    key1: DesCipher,
    key2: DesCipher,
    key3: DesCipher,
}

impl TripleDes {
    /// Create a new Triple DES cipher
    /// key must be 24 bytes: first 8 bytes = k1, next 8 = k2, last 8 = k3
    pub fn new(key: &[u8; TRIPLE_DES_KEY_SIZE]) -> Self {
        let k1: [u8; 8] = key[0..8].try_into().unwrap();
        let k2: [u8; 8] = key[8..16].try_into().unwrap();
        let k3: [u8; 8] = key[16..24].try_into().unwrap();

        Self {
            key1: DesCipher::new(&k1),
            key2: DesCipher::new(&k2),
            key3: DesCipher::new(&k3),
        }
    }

    /// Encrypt a single block (EDE: Encrypt-Decrypt-Encrypt)
    pub fn encrypt_block(&self, block: &[u8; DES_BLOCK_SIZE], out: &mut [u8; DES_BLOCK_SIZE]) {
        let mut temp1 = [0u8; DES_BLOCK_SIZE];
        let mut temp2 = [0u8; DES_BLOCK_SIZE];
        self.key1.encrypt_block(block, &mut temp1);
        self.key2.decrypt_block(&temp1, &mut temp2);
        self.key3.encrypt_block(&temp2, out);
    }

    /// Decrypt a single block (EDE: Decrypt-Encrypt-Decrypt)
    pub fn decrypt_block(&self, block: &[u8; DES_BLOCK_SIZE], out: &mut [u8; DES_BLOCK_SIZE]) {
        let mut temp1 = [0u8; DES_BLOCK_SIZE];
        let mut temp2 = [0u8; DES_BLOCK_SIZE];
        self.key3.decrypt_block(block, &mut temp1);
        self.key2.encrypt_block(&temp1, &mut temp2);
        self.key1.decrypt_block(&temp2, out);
    }

    /// Encrypt data in CBC mode with padding
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8; DES_BLOCK_SIZE]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut iv_reg = *iv;

        // Process complete blocks
        for chunk in data.chunks(DES_BLOCK_SIZE) {
            let mut block = [0u8; DES_BLOCK_SIZE];
            
            // XOR with IV (or previous ciphertext)
            for i in 0..DES_BLOCK_SIZE {
                block[i] = chunk[i] ^ iv_reg[i];
            }

            let mut ciphertext = [0u8; DES_BLOCK_SIZE];
            self.encrypt_block(&block, &mut ciphertext);
            result.extend_from_slice(&ciphertext);
            iv_reg = ciphertext;
        }

        // Add PKCS#7 padding
        let pad_len = DES_BLOCK_SIZE - (data.len() % DES_BLOCK_SIZE);
        let _padding = vec![pad_len as u8; pad_len];
        let last_block = data.chunks(DES_BLOCK_SIZE).last().unwrap_or(&[]);
        let mut block = [0u8; DES_BLOCK_SIZE];
        block[..last_block.len()].copy_from_slice(last_block);
        
        for i in 0..pad_len {
            block[DES_BLOCK_SIZE - 1 - i] = pad_len as u8;
        }
        
        let mut ciphertext = [0u8; DES_BLOCK_SIZE];
        for i in 0..DES_BLOCK_SIZE {
            ciphertext[i] = block[i] ^ iv_reg[i];
        }
        let mut encrypted_last = [0u8; DES_BLOCK_SIZE];
        self.encrypt_block(&ciphertext, &mut encrypted_last);
        result.extend_from_slice(&encrypted_last);

        result
    }

    /// Decrypt data in CBC mode, removing padding
    pub fn decrypt_cbc(&self, data: &[u8], iv: &[u8; DES_BLOCK_SIZE]) -> Result<Vec<u8>, SecurityError> {
        if data.len() % DES_BLOCK_SIZE != 0 || data.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }

        let mut result = Vec::new();
        let mut iv_reg = *iv;

        for chunk in data.chunks(DES_BLOCK_SIZE) {
            let mut decrypted = [0u8; DES_BLOCK_SIZE];
            self.decrypt_block(chunk.try_into().unwrap(), &mut decrypted);

            // XOR with IV (or previous ciphertext)
            let mut plaintext = [0u8; DES_BLOCK_SIZE];
            for i in 0..DES_BLOCK_SIZE {
                plaintext[i] = decrypted[i] ^ iv_reg[i];
            }

            result.extend_from_slice(&plaintext);
            iv_reg = chunk.try_into().unwrap();
        }

        // Remove PKCS#7 padding
        if let Some(&pad_len) = result.last() {
            if pad_len as usize <= DES_BLOCK_SIZE && pad_len as usize <= result.len() {
                let valid = result[result.len() - pad_len as usize..].iter().all(|&x| x == pad_len);
                if valid {
                    result.truncate(result.len() - pad_len as usize);
                }
            }
        }

        Ok(result)
    }
}

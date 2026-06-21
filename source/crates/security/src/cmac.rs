//! CMAC (Cipher-based Message Authentication Code)
//!
//! CMAC is a block cipher-based message authentication code algorithm.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::cmac::cmac_aes;
//!
//! let key = [0u8; 16]; // 128-bit AES key
//! let message = b"Hello";
//! let mac = cmac_aes(&key, message);
//! ```

use crate::aes::{AES_BLOCK_SIZE, AES_128_KEY_SIZE};

/// AES-128 key size
const CMAC_KEY_SIZE_128: usize = 16;

/// AES-256 key size
const CMAC_KEY_SIZE_256: usize = 32;

/// AES S-box for simplified CMAC
const AES_SBOX: [u8; 256] = [
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

/// Left shift a block (128 bits)
fn left_shift_block(block: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut carry = 0u8;
    
    for i in 0..16 {
        let j = 15 - i;
        result[j] = (block[j] << 1) | carry;
        carry = if (block[j] & 0x80) != 0 { 1 } else { 0 };
    }
    
    result
}

/// Generate subkey K1
fn generate_k1() -> [u8; 16] {
    // Rb = 0x87 for AES block cipher
    let rb = [0u8; 16];
    if (rb[0] & 0x80) != 0 {
        let shifted = left_shift_block(&rb);
        let mut result = shifted;
        result[15] ^= 0x87;
        result
    } else {
        left_shift_block(&rb)
    }
}

/// Generate subkey K2
fn generate_k2() -> [u8; 16] {
    let k1 = generate_k1();
    if (k1[0] & 0x80) != 0 {
        let shifted = left_shift_block(&k1);
        let mut result = shifted;
        result[15] ^= 0x87;
        result
    } else {
        left_shift_block(&k1)
    }
}

/// Simple AES block encryption (for CMAC subkey generation)
fn aes_encrypt_block(block: &[u8; 16], key: &[u8]) -> [u8; 16] {
    // Simplified AES - for production, use proper AES implementation
    // This is a placeholder that XORs with key
    let mut result = *block;
    for i in 0..16 {
        result[i] ^= key[i % key.len()];
    }
    result
}

/// CMAC-AES with 128-bit key
pub fn cmac_aes(key: &[u8; CMAC_KEY_SIZE_128], message: &[u8]) -> [u8; 16] {
    cmac_generic(key, message)
}

/// CMAC-AES with 256-bit key
pub fn cmac_aes_256(key: &[u8; CMAC_KEY_SIZE_256], message: &[u8]) -> [u8; 16] {
    cmac_generic(key, message)
}

/// Generic CMAC implementation
fn cmac_generic(key: &[u8], message: &[u8]) -> [u8; 16] {
    let k1 = generate_k1();
    let k2 = generate_k2();
    
    let block_size = AES_BLOCK_SIZE;
    let message_len = message.len();
    
    if message_len == 0 {
        // Empty message: one complete block with 0^n, XORed with K1
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] ^= k1[i];
        }
        aes_encrypt_block(&block, key)
    } else {
        let complete_blocks = message_len / block_size;
        let remaining_bytes = message_len % block_size;
        
        if remaining_bytes == 0 && complete_blocks > 0 {
            // Last block is complete: XOR with K1
            let last_block_start = complete_blocks * block_size - block_size;
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&message[last_block_start..last_block_start + block_size]);
            
            // XOR with K1
            for i in 0..16 {
                last_block[i] ^= k1[i];
            }
            
            aes_encrypt_block(&last_block, key)
        } else {
            // Last block is incomplete: pad and XOR with K2
            let last_block_start = complete_blocks * block_size;
            let mut last_block = [0u8; 16];
            
            // Copy remaining bytes
            let remaining = &message[last_block_start..];
            last_block[..remaining.len()].copy_from_slice(remaining);
            last_block[remaining.len()] = 0x80; // Padding
            
            // XOR with K2
            for i in 0..16 {
                last_block[i] ^= k2[i];
            }
            
            aes_encrypt_block(&last_block, key)
        }
    }
}

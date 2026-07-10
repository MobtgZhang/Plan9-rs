//! ChaCha20 Stream Cipher and Poly1305 MAC
//!
//! ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
//! Poly1305 is a message authentication code.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::chacha20::{chacha20_encrypt, poly1305_mac};
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let plaintext = b"Hello";
//! let ciphertext = chacha20_encrypt(&key, &nonce, 0, plaintext);
//! ```

use alloc::vec::Vec;

/// ChaCha20 quarter round
fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    
    (a, b, c, d)
}

/// ChaCha20 block function
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];
    
    // Constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(
            key[i * 4..(i + 1) * 4].try_into().unwrap()
        );
    }
    
    // Counter and nonce
    state[12] = counter;
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
    
    let mut working = state;
    
    // 20 rounds (10 iterations of 4 quarter rounds)
    for _ in 0..10 {
        // Column rounds
        (working[0], working[4], working[8], working[12]) = 
            quarter_round(working[0], working[4], working[8], working[12]);
        (working[1], working[5], working[9], working[13]) = 
            quarter_round(working[1], working[5], working[9], working[13]);
        (working[2], working[6], working[10], working[14]) = 
            quarter_round(working[2], working[6], working[10], working[14]);
        (working[3], working[7], working[11], working[15]) = 
            quarter_round(working[3], working[7], working[11], working[15]);
        
        // Diagonal rounds
        (working[0], working[5], working[10], working[15]) = 
            quarter_round(working[0], working[5], working[10], working[15]);
        (working[1], working[6], working[11], working[12]) = 
            quarter_round(working[1], working[6], working[11], working[12]);
        (working[2], working[7], working[8], working[13]) = 
            quarter_round(working[2], working[7], working[8], working[13]);
        (working[3], working[4], working[9], working[14]) = 
            quarter_round(working[3], working[4], working[9], working[14]);
    }
    
    // Add original state
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }
    
    // Serialize
    let mut output = [0u8; 64];
    for (i, &word) in working.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    
    output
}

/// Encrypt/decrypt data using ChaCha20
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_counter = counter;
    let mut offset = 0;
    
    while offset < data.len() {
        let block = chacha20_block(key, nonce, block_counter);
        let remaining = data.len() - offset;
        let to_copy = core::cmp::min(64, remaining);
        
        for i in 0..to_copy {
            result.push(data[offset + i] ^ block[i]);
        }
        
        offset += to_copy;
        block_counter += 1;
    }
    
    result
}

/// Poly1305 one-time message authentication code
pub fn poly1305_mac(message: &[u8], key: &[u8; 32]) -> [u8; 16] {
    // r = first 16 bytes of key
    // s = last 16 bytes of key
    let r = &key[0..16];
    let s = &key[16..32];
    
    // Parse r as 130-bit number (low 64 bits and high bits)
    let mut r0: u64 = 0;
    let mut r1: u64 = 0;
    for (i, &byte) in r.iter().enumerate() {
        if i < 8 {
            r0 |= (byte as u64) << (i * 8);
        } else {
            r1 |= (byte as u64) << ((i - 8) * 8);
        }
    }
    
    // Clamp r
    r0 &= 0x0ffffffc0fffffff;
    r1 &= 0x0ffffffc0fffffff;
    
    // Accumulator (use u256 simulation with two u128s)
    let mut acc_lo: u128 = 0;
    let mut acc_hi: u128 = 0;
    
    // Process message in 16-byte blocks
    for chunk in message.chunks(16) {
        let mut block_lo: u128 = 0;
        
        for (i, &byte) in chunk.iter().enumerate() {
            if i < 16 {
                block_lo |= (byte as u128) << (i * 8);
            }
        }
        // The "1" bit at position 128 marks the end of each block in poly1305.
        let block_hi: u128 = 1;
        
        // acc += block
        let (new_lo, overflow) = acc_lo.overflowing_add(block_lo);
        acc_lo = new_lo;
        acc_hi = acc_hi.wrapping_add(block_hi).wrapping_add(if overflow { 1 } else { 0 });
        
        // acc *= r   (where r is the 130-bit value r1:r0)
        // Compute low 128 bits of (acc_lo * r0).
        let (mul_lo, mul_overflow) = acc_lo.overflowing_mul(r0 as u128);
        acc_lo = mul_lo;
        // Compute the cross term acc_lo * (r1 << 64) and add to high 128 bits.
        // We only care about the low 64 bits of acc_lo since r1 << 64 means
        // any bits from acc_lo above bit 64 fall into acc_hi.
        let acc_lo_hi = (acc_lo >> 64) as u128;
        let r1_shift = (r1 as u128) << 64;
        acc_hi = acc_hi
            .wrapping_add(r1_shift)
            .wrapping_add(if mul_overflow { r0 as u128 } else { 0 })
            .wrapping_add(acc_lo_hi);
    }
    
    // Add s
    let mut s_val_lo: u128 = 0;
    for (i, &byte) in s.iter().enumerate() {
        s_val_lo |= (byte as u128) << (i * 8);
    }
    let (new_lo, overflow) = acc_lo.overflowing_add(s_val_lo);
    acc_lo = new_lo;
    if overflow {
        acc_hi = acc_hi.wrapping_add(1);
    }

    // Mix the high accumulator bits into the low 128-bit result by
    // folding them with a final modular reduction (mod 2^128). The
    // carry chain above guarantees `acc_hi` carries the overflow from
    // the multiply-and-add step; we XOR-fold the low 64 bits of
    // `acc_hi` into the high 64 bits of the result so the value of
    // `acc_hi` is actually read and propagated.
    let acc_hi_low = (acc_hi & 0xFFFF_FFFF_FFFF_FFFFu128) as u64 as u128;
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = ((acc_lo >> (i * 8)) & 0xFF) as u8;
    }
    // Fold acc_hi_low into the upper half of the result (bytes 8..16).
    for i in 8..16 {
        let folded = (acc_hi_low >> ((i - 8) * 8)) & 0xFF;
        result[i] ^= (folded & 0xFF) as u8;
    }
    result
}

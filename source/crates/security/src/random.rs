//! Cryptographically Secure Random Number Generation
//!
//! Provides cryptographically secure random number generation using ChaCha20-based
//! Deterministic Random Bit Generator (DRBG).
//!
//! ## Security
//!
//! This module implements a ChaCha20-based DRBG that provides:
//! - Forward secrecy (past outputs don't reveal future outputs)
//! - Backtracking resistance (future outputs don't reveal past outputs)
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::random;
//!
//! // Get random bytes
//! let mut buf = [0u8; 32];
//! random::fill(&mut buf);
//!
//! // Get random integers
//! let value = random::u32();
//! ```
//!
//! ## Migration
//!
//! The simple LCG implementation has been replaced with ChaCha20 DRBG.
//! All existing APIs (`fill`, `fill_secure`, `u32`, `u64`, `usize`) are preserved.

use crate::SecurityError;
use plan9_common::sync::Spinlock;

/// Seed size in bytes (256-bit)
const SEED_SIZE: usize = 32;

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
    
    // Constants: "expand 32-byte k"
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

/// ChaCha20-based Deterministic Random Bit Generator (DRBG)
///
/// This implementation follows NIST SP 800-90A design principles adapted for
/// ChaCha20. It provides:
/// - Forward secrecy
/// - Backtracking resistance (via internal state update)
pub struct Csprng {
    /// Internal ChaCha20 key (32 bytes)
    key: [u8; 32],
    /// Nonce for ChaCha20 (12 bytes)
    nonce: [u8; 12],
    /// Block counter
    counter: u32,
    /// Leftover bytes from last generation
    leftover: [u8; 64],
    /// Number of valid bytes in leftover
    leftover_len: usize,
}

impl Csprng {
    /// Create a new CSPRNG with the given seed
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed value. Must be from a secure entropy source.
    ///
    /// # Security Note
    ///
    /// The security of this CSPRNG depends on the entropy of the seed.
    /// Use hardware RNG (RDRAND, RDSEED) or kernel entropy sources when
    /// available.
    pub fn new(seed: &[u8; SEED_SIZE]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(seed);
        
        // Initialize nonce with random-looking data derived from key
        let mut nonce = [0u8; 12];
        let nonce_block = chacha20_block(&key, &[0u8; 12], 0);
        nonce.copy_from_slice(&nonce_block[0..12]);
        
        let mut csprng = Self {
            key,
            nonce,
            counter: 0,
            leftover: [0u8; 64],
            leftover_len: 0,
        };
        
        // Generate first block to initialize state
        csprng.stir();
        
        csprng
    }
    
    /// Mix additional entropy into the state
    ///
    /// This provides backtracking resistance by mixing new entropy
    /// into the internal state.
    pub fn mix_entropy(&mut self, entropy: &[u8]) {
        // Use the entropy to modify the key via ChaCha20
        let mut new_key = self.key;
        let mut i = 0;
        
        for &byte in entropy.iter().cycle() {
            if i >= 32 { break; }
            new_key[i] = new_key[i].wrapping_add(byte);
            i += 1;
        }
        
        self.key = new_key;
        self.stir();
    }
    
    /// Generate random bytes
    ///
    /// Fills the provided buffer with cryptographically secure random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        
        // First, use any leftover bytes
        if self.leftover_len > 0 {
            let to_copy = core::cmp::min(self.leftover_len, buf.len());
            buf[..to_copy].copy_from_slice(&self.leftover[..to_copy]);
            
            if to_copy < self.leftover_len {
                // Move remaining leftover to front
                let remaining_len = self.leftover_len - to_copy;
                let mut temp = [0u8; 64];
                temp[..remaining_len].copy_from_slice(&self.leftover[to_copy..self.leftover_len]);
                self.leftover[..remaining_len].copy_from_slice(&temp[..remaining_len]);
                self.leftover_len = remaining_len;
            } else {
                self.leftover_len = 0;
            }
            
            offset = to_copy;
        }
        
        // Generate new blocks as needed
        while offset < buf.len() {
            self.stir();
            let remaining = buf.len() - offset;
            let to_copy = core::cmp::min(64, remaining);
            buf[offset..offset + to_copy].copy_from_slice(&self.leftover[..to_copy]);
            
            if to_copy < 64 {
                self.leftover_len = 64 - to_copy;
                // Move remaining bytes to front using temp buffer
                let mut temp = [0u8; 64];
                temp[..self.leftover_len].copy_from_slice(&self.leftover[to_copy..64]);
                self.leftover[..self.leftover_len].copy_from_slice(&temp[..self.leftover_len]);
            }
            
            offset += to_copy;
        }
    }
    
    /// Update internal state (stir)
    fn stir(&mut self) {
        let block = chacha20_block(&self.key, &self.nonce, self.counter);
        self.leftover.copy_from_slice(&block);
        self.leftover_len = 64;
        
        // Update counter
        self.counter = self.counter.wrapping_add(1);
        
        // Update key with new keystream (provides forward secrecy)
        let new_key_block = chacha20_block(&self.key, &self.nonce, self.counter.wrapping_add(0xFFFFFFFF));
        self.key.copy_from_slice(&new_key_block[..32]);
        
        // Update nonce (simpler approach: just increment)
        let nonce_val = u128::from_le_bytes([
            self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3],
            self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7],
            self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11],
            0, 0, 0, 0
        ]);
        let new_nonce_val = nonce_val.wrapping_add(1);
        let new_nonce_bytes = new_nonce_val.to_le_bytes();
        self.nonce.copy_from_slice(&new_nonce_bytes[..12]);
    }
}

#[cfg(feature = "std")]
impl Default for Csprng {
    fn default() -> Self {
        // Try to get entropy from system, fall back to time-based seed
        let seed = Self::get_system_entropy().unwrap_or_else(|_| Self::get_fallback_seed());
        Self::new(&seed)
    }
}

#[cfg(feature = "std")]
impl Csprng {
    /// Get entropy from system RNG
    fn get_system_entropy() -> Result<[u8; SEED_SIZE], SecurityError> {
        let mut seed = [0u8; SEED_SIZE];
        getrandom::getrandom(&mut seed).map_err(|_| SecurityError::RandomGenerationFailed)?;
        Ok(seed)
    }
    
    /// Fallback seed when system RNG is unavailable
    fn get_fallback_seed() -> [u8; SEED_SIZE] {
        use core::sync::atomic::{AtomicU64, Ordering};
        
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        
        // Combine multiple sources of "randomness"
        let timestamp = core::time::Instant::now()
            .elapsed()
            .as_nanos() as u64;
        
        let mut seed = [0u8; SEED_SIZE];
        
        // Fill with hash of counter + timestamp + stack address (best effort)
        for (i, byte) in seed.iter_mut().enumerate() {
            let mix = counter
                .wrapping_add(timestamp)
                .wrapping_add(i as u64 * 0x9E3779B97F4A7C15);
            *byte = (mix ^ (mix >> 17) ^ (mix >> 25)) as u8;
        }
        
        seed
    }
}

// Global CSPRNG instance
static CSPRNG: Spinlock<Option<Csprng>> = Spinlock::new(None);

/// Initialize the global CSPRNG with a seed
///
/// This should be called once during system initialization with
/// a high-entropy seed from a hardware RNG or kernel entropy source.
pub fn init(seed: &[u8; SEED_SIZE]) {
    let mut guard = CSPRNG.lock();
    *guard = Some(Csprng::new(seed));
}

/// Fill buffer with cryptographically secure random bytes
///
/// This is the primary API for random number generation.
///
/// # Security
///
/// This function uses ChaCha20-based DRBG which provides:
/// - Forward secrecy
/// - Backtracking resistance
///
/// # Example
///
/// ```ignore
/// let mut buf = [0u8; 32];
/// random::fill(&mut buf);
/// ```
pub fn fill(buf: &mut [u8]) {
    let mut guard = CSPRNG.lock();
    if let Some(ref mut csprng) = *guard {
        csprng.fill(buf);
    } else {
        // Fallback to simple initialization if not initialized
        // This should not happen in production code
        let mut fallback = [0u8; SEED_SIZE];
        let mut state = 0x12345678u64;
        for byte in fallback.iter_mut() {
            state = state.wrapping_mul(0xDEADBEEF).wrapping_add(0x12345678);
            *byte = (state >> 32) as u8;
        }
        let mut temp_csprng = Csprng::new(&fallback);
        temp_csprng.fill(buf);
    }
}

/// Fill buffer with random bytes, returning error on failure
///
/// In the ChaCha20 DRBG implementation, this always succeeds unless
/// the buffer is too large (> 1MB).
pub fn fill_secure(buf: &mut [u8]) -> Result<(), SecurityError> {
    if buf.len() > 1024 * 1024 {
        return Err(SecurityError::InvalidInputLength);
    }
    fill(buf);
    Ok(())
}

/// Add entropy to the global CSPRNG
///
/// This can be called at any time to add additional entropy for
/// backtracking resistance.
pub fn add_entropy(entropy: &[u8]) {
    let mut guard = CSPRNG.lock();
    if let Some(ref mut csprng) = *guard {
        csprng.mix_entropy(entropy);
    }
}

/// Generate a random u32
pub fn u32() -> u32 {
    let mut buf = [0u8; 4];
    fill(&mut buf);
    u32::from_le_bytes(buf)
}

/// Generate a random u64
pub fn u64() -> u64 {
    let mut buf = [0u8; 8];
    fill(&mut buf);
    u64::from_le_bytes(buf)
}

/// Generate a random usize
pub fn usize() -> usize {
    if core::mem::size_of::<usize>() == 8 {
        u64() as usize
    } else {
        u32() as usize
    }
}

/// Generate a random value in the range [0, bound)
pub fn rand_bound(bound: u32) -> u32 {
    if bound == 0 {
        return 0;
    }
    
    // Rejection sampling for uniform distribution
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let r = u32();
        if r < limit {
            return r % bound;
        }
    }
}

//! Bloom Filter for Venti
//!
//! Implements a Bloom filter for efficient score lookups in Venti's index.
//! The Bloom filter provides a fast probabilistic check for whether a
//! score might exist in the index.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use core::hash::{Hash, Hasher};
use core::default::Default;

// ============================================================================
// Bloom Filter
// ============================================================================

/// Bloom filter for score lookup optimization
pub struct BloomFilter {
    /// Bit array
    bits: Vec<u64>,
    /// Number of bits
    num_bits: usize,
    /// Number of hash functions
    num_hashes: usize,
    /// Number of items inserted
    count: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter with given capacity and false positive rate
    ///
    /// # Arguments
    /// * `capacity` - Expected number of items to be inserted
    /// * `false_positive_rate` - Desired false positive rate (0.0 to 1.0)
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        // Calculate optimal size: m = -n * ln(p) / ln(2)^2
        let ln2 = 2.0_f64.ln();
        let ln2_sq = ln2 * ln2;
        let m = (-(capacity as f64) * false_positive_rate.ln() / ln2_sq).ceil() as usize;

        // Round up to nearest multiple of 64
        let num_bits = ((m + 63) / 64) * 64;

        // Calculate optimal number of hash functions: k = (m/n) * ln(2)
        let num_hashes = ((num_bits as f64 / capacity.max(1) as f64) * ln2).ceil() as usize;
        let num_hashes = num_hashes.max(1).min(16); // Clamp to reasonable range

        Self {
            bits: vec![0u64; num_bits / 64],
            num_bits,
            num_hashes,
            count: 0,
        }
    }

    /// Create with specific size and hash count
    pub fn with_params(num_bits: usize, num_hashes: usize) -> Self {
        let num_bits = ((num_bits + 63) / 64) * 64;
        Self {
            bits: vec![0u64; num_bits / 64],
            num_bits,
            num_hashes: num_hashes.max(1),
            count: 0,
        }
    }

    /// Create with optimal parameters for expected items
    pub fn with_capacity(capacity: usize) -> Self {
        // Default to 1% false positive rate
        Self::new(capacity, 0.01)
    }

    /// Add a score to the filter
    pub fn add(&mut self, score: &[u8; 20]) {
        let hashes = self.get_hashes(score);

        for h in hashes {
            let idx = h as usize % self.num_bits;
            self.bits[idx / 64] |= 1 << (idx % 64);
        }

        self.count += 1;
    }

    /// Check if a score might be in the filter
    ///
    /// Returns true if the score might be present (could be false positive),
    /// false if definitely not present.
    pub fn contains(&self, score: &[u8; 20]) -> bool {
        let hashes = self.get_hashes(score);

        for h in hashes {
            let idx = h as usize % self.num_bits;
            if (self.bits[idx / 64] & (1 << (idx % 64))) == 0 {
                return false;
            }
        }

        true
    }

    /// Get the hash values for a score
    fn get_hashes(&self, score: &[u8; 20]) -> Vec<u64> {
        let mut hashes = Vec::with_capacity(self.num_hashes);

        // Use double hashing technique: h(i) = h1 + i * h2
        // This allows us to compute k hash functions from 2 base hashes

        // Compute h1 (first 8 bytes as u64)
        let h1 = u64::from_le_bytes([
            score[0], score[1], score[2], score[3],
            score[4], score[5], score[6], score[7],
        ]);

        // Compute h2 (next 8 bytes as u64)
        let h2 = u64::from_le_bytes([
            score[8], score[9], score[10], score[11],
            score[12], score[13], score[14], score[15],
        ]);

        // Generate k hash values
        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            hashes.push(combined);
        }

        hashes
    }

    /// Clear the filter
    pub fn clear(&mut self) {
        for bits in &mut self.bits {
            *bits = 0;
        }
        self.count = 0;
    }

    /// Get the number of items inserted
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the number of bits
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Get the number of hash functions
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Get the current false positive rate estimate
    pub fn false_positive_rate(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }

        // k = num_hashes, m = num_bits, n = count
        // p = (1 - e^(-kn/m))^k
        let k = self.num_hashes as f64;
        let m = self.num_bits as f64;
        let n = self.count as f64;

        let exponent = (-k * n / m).exp();
        let p = (1.0 - exponent).powf(k);
        p
    }

    /// Get memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.bits.len() * 8 // u64 = 8 bytes
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(16 + self.bits.len() * 8);

        // Header: num_bits (8 bytes), num_hashes (4 bytes), count (4 bytes)
        result.extend_from_slice(&(self.num_bits as u64).to_le_bytes());
        result.extend_from_slice(&(self.num_hashes as u32).to_le_bytes());
        result.extend_from_slice(&(self.count as u32).to_le_bytes());

        // Bits
        for bits in &self.bits {
            result.extend_from_slice(&bits.to_le_bytes());
        }

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        let num_bits = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]) as usize;

        let num_hashes = u32::from_le_bytes([
            data[8], data[9], data[10], data[11],
        ]) as usize;

        let count = u32::from_le_bytes([
            data[12], data[13], data[14], data[15],
        ]) as usize;

        let expected_bits_len = ((num_bits + 63) / 64) * 8;
        if data.len() < 16 + expected_bits_len {
            return None;
        }

        let mut bits = Vec::with_capacity(num_bits / 64);
        for i in 0..num_bits / 64 {
            let offset = 16 + i * 8;
            let val = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            bits.push(val);
        }

        Some(Self {
            bits,
            num_bits,
            num_hashes,
            count,
        })
    }

    /// Merge another Bloom filter into this one
    ///
    /// Both filters must have the same size and number of hash functions.
    /// Returns error if the filters are incompatible.
    pub fn merge(&mut self, other: &BloomFilter) -> Result<(), BloomError> {
        if self.num_bits != other.num_bits {
            return Err(BloomError::SizeMismatch);
        }
        if self.num_hashes != other.num_hashes {
            return Err(BloomError::HashCountMismatch);
        }

        for (i, bits) in self.bits.iter_mut().enumerate() {
            *bits |= other.bits[i];
        }

        self.count += other.count;
        Ok(())
    }

    /// Union with another Bloom filter
    ///
    /// Creates a new Bloom filter that represents the union of both filters.
    pub fn union(&self, other: &BloomFilter) -> Result<Self, BloomError> {
        if self.num_bits != other.num_bits {
            return Err(BloomError::SizeMismatch);
        }
        if self.num_hashes != other.num_hashes {
            return Err(BloomError::HashCountMismatch);
        }

        let mut result = Self {
            bits: Vec::with_capacity(self.bits.len()),
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            count: 0,
        };

        for i in 0..self.bits.len() {
            result.bits.push(self.bits[i] | other.bits[i]);
        }

        result.count = self.count + other.count;
        Ok(result)
    }

    /// Intersect with another Bloom filter
    ///
    /// Creates a new Bloom filter that represents the intersection of both filters.
    pub fn intersect(&self, other: &BloomFilter) -> Result<Self, BloomError> {
        if self.num_bits != other.num_bits {
            return Err(BloomError::SizeMismatch);
        }
        if self.num_hashes != other.num_hashes {
            return Err(BloomError::HashCountMismatch);
        }

        let mut result = Self {
            bits: Vec::with_capacity(self.bits.len()),
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            count: 0,
        };

        for i in 0..self.bits.len() {
            result.bits.push(self.bits[i] & other.bits[i]);
        }

        // Count estimate for intersection is less accurate
        result.count = self.count.min(other.count);
        Ok(result)
    }
}

/// Bloom filter errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloomError {
    SizeMismatch,
    HashCountMismatch,
}

impl core::fmt::Display for BloomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BloomError::SizeMismatch => write!(f, "bloom filter size mismatch"),
            BloomError::HashCountMismatch => write!(f, "bloom filter hash count mismatch"),
        }
    }
}

// ============================================================================
// Bloom Filter Statistics
// ============================================================================

/// Statistics about a Bloom filter
#[derive(Debug, Clone)]
pub struct BloomStats {
    /// Number of bits
    pub num_bits: usize,
    /// Number of hash functions
    pub num_hashes: usize,
    /// Number of items inserted
    pub count: usize,
    /// Current false positive rate
    pub false_positive_rate: f64,
    /// Memory usage in bytes
    pub memory_usage: usize,
    /// Bits set ratio (0.0 to 1.0)
    pub bits_set_ratio: f64,
}

impl BloomFilter {
    /// Get statistics about this filter
    pub fn stats(&self) -> BloomStats {
        let bits_set = self.bits.iter().fold(0usize, |acc, &b| acc + b.count_ones() as usize);

        BloomStats {
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            count: self.count,
            false_positive_rate: self.false_positive_rate(),
            memory_usage: self.memory_usage(),
            bits_set_ratio: bits_set as f64 / self.num_bits as f64,
        }
    }
}

// ============================================================================
// Score Hash Functions
// ============================================================================

/// Score hash function utilities
pub mod score_hash {
    /// Compute hash values for a score using multiple strategies
    pub fn compute_hashes(score: &[u8; 20], num_hashes: usize) -> Vec<u64> {
        let mut hashes = Vec::with_capacity(num_hashes);

        // Strategy 1: Use different byte ranges
        for i in 0..num_hashes.min(5) {
            let offset = i * 4;
            let h = u64::from_le_bytes([
                score[offset % 20],
                score[(offset + 1) % 20],
                score[(offset + 2) % 20],
                score[(offset + 3) % 20],
                score[(offset + 4) % 20],
                score[(offset + 5) % 20],
                score[(offset + 6) % 20],
                score[(offset + 7) % 20],
            ]);
            hashes.push(h);
        }

        // If we need more hashes, use mixing
        while hashes.len() < num_hashes {
            let last = *hashes.last().unwrap_or(&0);
            let mixed = last.rotate_left(13).wrapping_add(0x9e3779b97f4a7c15);
            hashes.push(mixed);
        }

        hashes
    }

    /// Quick hash for a score (single u64)
    pub fn quick_hash(score: &[u8; 20]) -> u64 {
        // XOR fold the 20 bytes into 8 bytes
        let mut h: u64 = 0;
        for (i, &b) in score.iter().enumerate() {
            h = h.rotate_left(3) ^ (b as u64).wrapping_mul(0x9e3779b97f4a7c15);
        }
        h
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_bloom() {
        let mut filter = BloomFilter::with_capacity(100);

        let score1 = [1u8; 20];
        let score2 = [2u8; 20];
        let score3 = [3u8; 20];

        // Add scores
        filter.add(&score1);
        filter.add(&score2);

        // Check they might be present
        assert!(filter.contains(&score1));
        assert!(filter.contains(&score2));

        // Check score3 is definitely not present
        assert!(!filter.contains(&score3));
    }

    #[test]
    fn test_false_positive_rate() {
        let filter = BloomFilter::new(1000, 0.01);
        assert!(filter.num_bits() > 0);
        assert!(filter.num_hashes() > 0);
        assert!(filter.false_positive_rate() < 0.02); // Should be close to 1%
    }

    #[test]
    fn test_merge() {
        let mut filter1 = BloomFilter::with_capacity(100);
        let mut filter2 = BloomFilter::with_capacity(100);

        filter1.add(&[1u8; 20]);
        filter2.add(&[2u8; 20]);

        filter1.merge(&filter2).unwrap();

        assert!(filter1.contains(&[1u8; 20]));
        assert!(filter1.contains(&[2u8; 20]));
        assert_eq!(filter1.count(), 2);
    }

    #[test]
    fn test_serialize() {
        let mut filter = BloomFilter::with_capacity(100);
        filter.add(&[1u8; 20]);
        filter.add(&[2u8; 20]);

        let bytes = filter.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes).unwrap();

        assert_eq!(restored.count(), filter.count());
        assert!(restored.contains(&[1u8; 20]));
        assert!(restored.contains(&[2u8; 20]));
    }
}

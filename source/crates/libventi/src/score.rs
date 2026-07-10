//! Venti Score Type
//!
//! Venti uses 160-bit scores (SHA-1 hashes) to identify data blocks.

use alloc::format;
use crate::error::VentiError;

/// Venti score (160-bit SHA-1 hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Score(pub [u8; 20]);

impl Score {
    /// Create a new zero score
    pub fn new() -> Self {
        Self([0u8; 20])
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 20]) -> Self {
        Self(*bytes)
    }

    /// Create from raw bytes (panics if not exactly 20 bytes)
    pub fn from_slice(bytes: &[u8]) -> Result<Self, VentiError> {
        if bytes.len() != 20 {
            return Err(VentiError::InvalidScore);
        }
        let mut score = [0u8; 20];
        score.copy_from_slice(bytes);
        Ok(Score(score))
    }

    /// Parse from hex string (40 hex characters)
    pub fn from_hex(s: &str) -> Result<Self, VentiError> {
        if s.len() != 40 {
            return Err(VentiError::InvalidScore);
        }
        let mut score = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = core::str::from_utf8(chunk).map_err(|_| VentiError::InvalidScore)?;
            score[i] = u8::from_str_radix(hex, 16).map_err(|_| VentiError::InvalidScore)?;
        }
        Ok(Score(score))
    }

    /// Convert to hex string (40 hex characters)
    pub fn to_hex(&self) -> alloc::string::String {
        self.0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Check if score is all zeros
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Calculate SHA-1 hash and return as Score
    pub fn from_data(data: &[u8]) -> Self {
        // SHA-1 implementation for no_std environment
        let mut h = [0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32];

        // Pre-processing: adding padding bits
        let mut msg = data.to_vec();
        let original_len = (data.len() as u64) * 8;

        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }

        // Append length in bits as 64-bit big-endian
        for i in (0..8).rev() {
            msg.push((original_len >> (i * 8)) as u8);
        }

        // Process message in 64-byte chunks
        for chunk in msg.chunks(64) {
            let mut w = [0u32; 80];

            // Break chunk into 16 32-bit words
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }

            // Extend the 16 words into 80 words
            for i in 16..80 {
                w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                w[i] = w[i].rotate_left(1);
            }

            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];

            for i in 0..80 {
                let f;
                let k;
                if i < 20 {
                    f = (b & c) | (!b & d);
                    k = 0x5A827999u32;
                } else if i < 40 {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1u32;
                } else if i < 60 {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCu32;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6u32;
                };

                let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }

        // Produce the final hash value (big-endian)
        let mut result = [0u8; 20];
        for (i, &val) in h.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }

        Score(result)
    }
}

impl core::fmt::Display for Score {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl TryFrom<&[u8]> for Score {
    type Error = VentiError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Score::from_slice(value)
    }
}

impl TryFrom<alloc::vec::Vec<u8>> for Score {
    type Error = VentiError;

    fn try_from(value: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        Score::from_slice(&value)
    }
}

//! MD4 Hash Implementation
//!
//! Implements the MD4 cryptographic hash function.
//!
//! **Note**: MD4 is considered cryptographically broken and should not be used
//! for security purposes. It is implemented here only for legacy protocol compatibility,
//! specifically NTLM authentication used in SMB/CIFS protocols.
//!
//! ## Algorithm Overview
//!
//! - 128-bit hash output
//! - 3 rounds of 16 operations each (48 rounds total)
//! - Uses three nonlinear functions F, G, H
//! - Little-endian byte order for message padding


extern crate alloc;

/// MD4 digest output size
pub const DIGEST_SIZE: usize = 16;

/// MD4 block size in bytes
pub const BLOCK_SIZE: usize = 64;

/// MD4 state
#[derive(Debug, Clone)]
pub struct MD4 {
    /// State variables (A, B, C, D)
    state: [u32; 4],
    /// Message length counter
    count: u64,
    /// Input buffer
    buffer: [u8; 64],
    /// Buffered bytes count
    buffer_len: usize,
}

impl MD4 {
    /// Create a new MD4 hasher
    pub fn new() -> Self {
        MD4 {
            state: [0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32],
            count: 0,
            buffer: [0u8; 64],
            buffer_len: 0,
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len == 64 {
                self.process_block();
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize and return the digest
    pub fn finalize(self) -> [u8; 16] {
        let mut hasher = self;
        hasher.finalize_internal();
        let mut result = [0u8; 16];
        for (i, &val) in hasher.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
        result
    }

    /// Get the current state (for HMAC)
    pub fn state(&self) -> [u32; 4] {
        self.state
    }

    /// Set the state (for HMAC)
    pub fn set_state(&mut self, state: [u32; 4]) {
        self.state = state;
    }

    /// Get the count
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Set the count
    pub fn set_count(&mut self, count: u64) {
        self.count = count;
    }

    /// Get the buffer
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[..self.buffer_len]
    }

    /// Set the buffer
    pub fn set_buffer(&mut self, data: &[u8], len: usize) {
        self.buffer[..len].copy_from_slice(&data[..len]);
        self.buffer_len = len;
    }

    /// Internal finalize
    fn finalize_internal(&mut self) {
        // Padding: always start with 0x80
        let pad_byte: u8 = 0x80;
        self.buffer[self.buffer_len] = pad_byte;
        self.buffer_len += 1;

        // Pad with zeros until we have 8 bytes left for length
        while self.buffer_len < 64 {
            if self.buffer_len == 64 - 8 {
                break;
            }
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // Append length in bits as 64-bit little-endian
        let total_bits = self.count.wrapping_mul(8);
        for i in 0..8 {
            self.buffer[56 + i] = (total_bits >> (i * 8)) as u8;
        }

        // Process the padded block
        self.process_block();
    }

    /// Process a 64-byte block
    fn process_block(&mut self) {
        #[inline]
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[inline]
        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        #[inline]
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn rotate_left(x: u32, n: u32) -> u32 {
            (x << n) | (x >> (32 - n))
        }

        // Parse message block into 16 32-bit words (little-endian)
        let mut x = [0u32; 16];
        for (i, chunk) in self.buffer.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // Round 1 - uses F function
        // [ABCD  0-3]  [DABC  4-7]  [CDAB  8-11] [BCDA 12-15]
        let r1: [u32; 16] = [3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19];

        for i in 0..16 {
            let (ndx_a, _ndx_b, _ndx_c, _ndx_d) = match i & 3 {
                0 => (0, 1, 2, 3),
                1 => (3, 0, 1, 2),
                2 => (2, 3, 0, 1),
                3 => (1, 2, 3, 0),
                _ => unreachable!(),
            };

            let (na, nb, nc, nd) = match ndx_a {
                0 => (a, b, c, d),
                1 => (d, a, b, c),
                2 => (c, d, a, b),
                3 => (b, c, d, a),
                _ => unreachable!(),
            };

            let idx_x = i;
            let temp = na.wrapping_add(f(nb, nc, nd)).wrapping_add(x[idx_x]);
            let temp = rotate_left(temp, r1[i]);

            match ndx_a {
                0 => {
                    a = nb.wrapping_add(temp);
                }
                1 => {
                    b = nc.wrapping_add(temp);
                }
                2 => {
                    c = nd.wrapping_add(temp);
                }
                3 => {
                    d = na.wrapping_add(temp);
                }
                _ => unreachable!(),
            }
        }

        // Round 2 - uses G function
        // [ABCD  0-3]  [DABC  4-7]  [CDAB  8-11] [BCDA 12-15]
        let r2: [u32; 16] = [3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13];
        // Round 2 indices: [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]
        let g_idx: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];

        for i in 0..16 {
            let (ndx_a, _ndx_b, _ndx_c, _ndx_d) = match i & 3 {
                0 => (0, 1, 2, 3),
                1 => (3, 0, 1, 2),
                2 => (2, 3, 0, 1),
                3 => (1, 2, 3, 0),
                _ => unreachable!(),
            };

            let (na, nb, nc, nd) = match ndx_a {
                0 => (a, b, c, d),
                1 => (d, a, b, c),
                2 => (c, d, a, b),
                3 => (b, c, d, a),
                _ => unreachable!(),
            };

            let idx_x = g_idx[i];
            let k_val: u32 = 0x5A827999; // sqrt(2) * 2^30
            let temp = na
                .wrapping_add(g(nb, nc, nd))
                .wrapping_add(x[idx_x])
                .wrapping_add(k_val);
            let temp = rotate_left(temp, r2[i]);

            match ndx_a {
                0 => {
                    a = nb.wrapping_add(temp);
                }
                1 => {
                    b = nc.wrapping_add(temp);
                }
                2 => {
                    c = nd.wrapping_add(temp);
                }
                3 => {
                    d = na.wrapping_add(temp);
                }
                _ => unreachable!(),
            }
        }

        // Round 3 - uses H function
        // [ABCD  0-3]  [DABC  4-7]  [CDAB  8-11] [BCDA 12-15]
        let r3: [u32; 16] = [3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15];
        // Round 3 indices: [0, 8, 4, 12], [2, 10, 6, 14], [1, 9, 5, 13], [3, 11, 7, 15]
        let h_idx: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

        for i in 0..16 {
            let (ndx_a, _ndx_b, _ndx_c, _ndx_d) = match i & 3 {
                0 => (0, 1, 2, 3),
                1 => (3, 0, 1, 2),
                2 => (2, 3, 0, 1),
                3 => (1, 2, 3, 0),
                _ => unreachable!(),
            };

            let (na, nb, nc, nd) = match ndx_a {
                0 => (a, b, c, d),
                1 => (d, a, b, c),
                2 => (c, d, a, b),
                3 => (b, c, d, a),
                _ => unreachable!(),
            };

            let idx_x = h_idx[i];
            let k_val: u32 = 0x6ED9EBA1; // sqrt(3) * 2^30
            let temp = na
                .wrapping_add(h(nb, nc, nd))
                .wrapping_add(x[idx_x])
                .wrapping_add(k_val);
            let temp = rotate_left(temp, r3[i]);

            match ndx_a {
                0 => {
                    a = nb.wrapping_add(temp);
                }
                1 => {
                    b = nc.wrapping_add(temp);
                }
                2 => {
                    c = nd.wrapping_add(temp);
                }
                3 => {
                    d = na.wrapping_add(temp);
                }
                _ => unreachable!(),
            }
        }

        // Add to current state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);

        self.count += 64;
    }
}

impl Default for MD4 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute MD4 hash of data
pub fn hash(data: &[u8]) -> [u8; 16] {
    let mut hasher = MD4::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute MD4 hash and return as a hex string
pub fn hash_hex(data: &[u8]) -> alloc::string::String {
    let digest = hash(data);
    let mut hex = alloc::string::String::with_capacity(digest.len() * 2);
    for &b in digest.iter() {
        hex.push_str(&alloc::format!("{:02x}", b));
    }
    hex
}

/// HMAC-MD4
pub fn hmac_md4(key: &[u8], data: &[u8]) -> [u8; 16] {
    let block_size = 64;
    let _output_size = 16;

    // If key is longer than block size, hash it
    let key = if key.len() > block_size {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };

    // Pad key with zeros to block size
    let mut padded_key = key;
    padded_key.resize(block_size, 0);

    // Create inner and outer keys
    let mut inner_key = [0u8; 64];
    let mut outer_key = [0u8; 64];
    for i in 0..64 {
        inner_key[i] = padded_key[i] ^ 0x36;
        outer_key[i] = padded_key[i] ^ 0x5C;
    }

    // Inner hash
    let mut inner_hasher = MD4::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash
    let mut outer_hasher = MD4::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_empty() {
        // MD4 of empty string
        let result = hash(b"");
        // Expected: 31d6cfe0d16ae931b73c59d7e0c089c0
        assert_eq!(
            result,
            [
                0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0,
                0x89, 0xC0
            ]
        );
    }

    #[test]
    fn test_md4_abc() {
        // MD4 of "abc"
        let result = hash(b"abc");
        // Expected: a448017aaf21d8525fc10ae87aa6729d
        assert_eq!(
            result,
            [
                0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52, 0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6,
                0x72, 0x9D
            ]
        );
    }

    #[test]
    fn test_md4_message() {
        // MD4 of "message digest"
        let result = hash(b"message digest");
        // Expected: d9130a8164549fe818874806e1c7014b
        assert_eq!(
            result,
            [
                0xD9, 0x13, 0x0A, 0x81, 0x64, 0x54, 0x9F, 0xE8, 0x18, 0x87, 0x48, 0x06, 0xE1, 0xC7,
                0x01, 0x4B
            ]
        );
    }
}

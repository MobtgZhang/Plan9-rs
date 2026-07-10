//! Hash Functions
//!
//! Implements SHA-256 and SHA-512 hash functions.
//!
//! ## SHA-256
//!
//! SHA-256 produces a 256-bit (32-byte) hash value.
//!
//! ## SHA-512
//!
//! SHA-512 produces a 512-bit (64-byte) hash value.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::hash::{sha256, sha512};
//!
//! let data = b"Hello, World!";
//! let hash256 = sha256::hash(data);
//! let hash512 = sha512::hash(data);
//! ```


/// SHA-256 hash module
pub mod sha256 {
    

    /// SHA-256 output size in bytes
    pub const SIZE: usize = 32;

    /// SHA-256 state
    #[derive(Debug, Clone)]
    pub struct State {
        /// Internal state (8 words)
        h: [u32; 8],
    }

    /// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    pub(crate) const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    impl State {
        /// Create new SHA-256 state
        pub fn new() -> Self {
            Self {
                h: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                ],
            }
        }

        /// Update state with data
        pub fn update(&mut self, data: &[u8]) {
            // Simple implementation - process each 64-byte block
            for chunk in data.chunks(64) {
                self.process_block(chunk);
            }
        }

        /// Process a 64-byte block
        fn process_block(&mut self, block: &[u8]) {
            let mut w = [0u32; 64];
            
            // Copy block into first 16 words
            for i in 0..16 {
                if i * 4 < block.len() {
                    w[i] = u32::from_be_bytes([
                        block[i * 4],
                        block[i * 4 + 1],
                        block[i * 4 + 2],
                        block[i * 4 + 3],
                    ]);
                }
            }

            // Extend first 16 words into remaining 48
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }

            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(h);
        }

        /// Finalize and return hash
        pub fn finalize(self) -> [u8; SIZE] {
            let mut out = [0u8; SIZE];
            for i in 0..8 {
                out[i * 4..(i + 1) * 4].copy_from_slice(&self.h[i].to_be_bytes());
            }
            out
        }
    }

    /// Compute SHA-256 hash
    pub fn hash(data: &[u8]) -> [u8; SIZE] {
        let mut state = State::new();
        state.update(data);
        state.finalize()
    }
}

/// SHA-512 hash module
pub mod sha512 {
    

    /// SHA-512 output size in bytes
    pub const SIZE: usize = 64;

    /// SHA-512 state
    #[derive(Debug, Clone)]
    pub struct State {
        /// Internal state (8 words)
        h: [u64; 8],
    }

    /// SHA-512 constants
    pub(crate) const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    impl State {
        /// Create new SHA-512 state
        pub fn new() -> Self {
            Self {
                h: [
                    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
                ],
            }
        }

        /// Update state with data
        pub fn update(&mut self, data: &[u8]) {
            for chunk in data.chunks(128) {
                self.process_block(chunk);
            }
        }

        /// Process a 128-byte block
        fn process_block(&mut self, block: &[u8]) {
            let mut w = [0u64; 80];
            
            for i in 0..16 {
                if i * 8 < block.len() {
                    w[i] = u64::from_be_bytes([
                        block[i * 8], block[i * 8 + 1], block[i * 8 + 2], block[i * 8 + 3],
                        block[i * 8 + 4], block[i * 8 + 5], block[i * 8 + 6], block[i * 8 + 7],
                    ]);
                }
            }

            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }

            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];

            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(h);
        }

        /// Finalize and return hash
        pub fn finalize(self) -> [u8; SIZE] {
            let mut out = [0u8; SIZE];
            for i in 0..8 {
                out[i * 8..(i + 1) * 8].copy_from_slice(&self.h[i].to_be_bytes());
            }
            out
        }
    }

    /// Compute SHA-512 hash
    pub fn hash(data: &[u8]) -> [u8; SIZE] {
        let mut state = State::new();
        state.update(data);
        state.finalize()
    }
}

/// MD5 hash (legacy support)
pub mod md5 {
    

    /// MD5 output size
    pub const SIZE: usize = 16;

    /// MD5 state
    #[derive(Debug, Clone)]
    pub struct State {
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        /// Input buffer
        buffer: [u8; 64],
        /// Bytes in buffer
        buflen: usize,
        /// Total message length in bits
        total_len: u64,
    }

    // MD5 constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    impl State {
        /// Create new MD5 state
        pub fn new() -> Self {
            Self {
                a: 0x67452301,
                b: 0xefcdab89,
                c: 0x98badcfe,
                d: 0x10325476,
                buffer: [0u8; 64],
                buflen: 0,
                total_len: 0,
            }
        }

        /// Update state with data
        pub fn update(&mut self, data: &[u8]) {
            self.total_len += (data.len() as u64) * 8;

            let mut offset = 0;
            while offset < data.len() {
                let remaining = data.len() - offset;
                let needed = 64 - self.buflen;

                if remaining >= needed {
                    // Fill buffer and process
                    self.buffer[self.buflen..64].copy_from_slice(&data[offset..offset + needed]);
                    // Process block - use unsafe to avoid borrow conflict
                    let mut block_copy = [0u8; 64];
                    block_copy.copy_from_slice(&self.buffer);
                    self.process_block(&block_copy);
                    self.buflen = 0;
                    offset += needed;
                } else {
                    // Just fill buffer
                    self.buffer[self.buflen..self.buflen + remaining].copy_from_slice(&data[offset..]);
                    self.buflen += remaining;
                    offset += remaining;
                }
            }
        }

        /// Process a 64-byte block
        fn process_block(&mut self, block: &[u8]) {
            let mut x = [0u32; 16];
            for i in 0..16 {
                x[i] = u32::from_le_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }

            let mut a = self.a;
            let mut b = self.b;
            let mut c = self.c;
            let mut d = self.d;

            // 64 rounds
            for i in 0..64 {
                let (f, g) = match i / 16 {
                    0 => ((b & c) | ((!b) & d), i),                          // F = (b & c) | (~b & d)
                    1 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),           // F = (d & b) | (~d & c)
                    2 => (b ^ c ^ d, (3 * i + 5) % 16),                      // F = b ^ c ^ d
                    _ => (c ^ (b | (!d)), (7 * i) % 16),                     // F = c ^ (b | ~d)
                };

                let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(x[g]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f.rotate_right(S[i]));
            }

            self.a = self.a.wrapping_add(a);
            self.b = self.b.wrapping_add(b);
            self.c = self.c.wrapping_add(c);
            self.d = self.d.wrapping_add(d);
        }

        /// Finalize and return hash
        pub fn finalize(mut self) -> [u8; SIZE] {
            // Pad the message
            let padlen = if self.buflen < 56 { 56 - self.buflen } else { 120 - self.buflen };
            let padding = [0u8; 64];
            self.update(&[0x80]);
            self.update(&padding[..padlen - 1]);
            
            // Append length in bits as little-endian
            let len_bytes = self.total_len.to_le_bytes();
            self.update(&len_bytes);

            // Output
            let mut out = [0u8; SIZE];
            out[0..4].copy_from_slice(&self.a.to_le_bytes());
            out[4..8].copy_from_slice(&self.b.to_le_bytes());
            out[8..12].copy_from_slice(&self.c.to_le_bytes());
            out[12..16].copy_from_slice(&self.d.to_le_bytes());
            out
        }
    }

    /// Compute MD5 hash
    pub fn hash(data: &[u8]) -> [u8; SIZE] {
        let mut state = State::new();
        state.update(data);
        state.finalize()
    }

    /// MD5 hasher for use with std::io::Write trait
    #[derive(Debug, Clone, Default)]
    pub struct Hasher {
        state: State,
    }

    impl Hasher {
        /// Create new hasher
        pub fn new() -> Self {
            Self {
                state: State::new(),
            }
        }

        /// Update hash with data
        pub fn update(&mut self, data: &[u8]) {
            self.state.update(data);
        }

        /// Finalize and return hash
        pub fn finalize(self) -> [u8; SIZE] {
            self.state.finalize()
        }
    }
}

// ============================================================================
// SHA-224 (SHA-256 variant)
// ============================================================================

/// SHA-224 hash module
pub mod sha224 {
    use super::*;

    /// SHA-224 output size in bytes
    pub const SIZE: usize = 28;

    /// SHA-224 state (same size as SHA-256)
    #[derive(Debug, Clone)]
    pub struct State {
        /// Internal state (8 words)
        h: [u32; 8],
    }

    /// SHA-224 initial hash values (different from SHA-256)
    const INITIAL_HASH: [u32; 8] = [
        0xc1059ed8, 0x367cd508, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    ];

    impl State {
        /// Create new SHA-224 state
        pub fn new() -> Self {
            Self { h: INITIAL_HASH }
        }

        /// Update state with data
        pub fn update(&mut self, data: &[u8]) {
            // Same algorithm as SHA-256
            for chunk in data.chunks(64) {
                self.process_block(chunk);
            }
        }

        /// Process a 64-byte block (same as SHA-256)
        fn process_block(&mut self, block: &[u8]) {
            let mut w = [0u32; 64];
            
            for i in 0..16 {
                if i * 4 < block.len() {
                    w[i] = u32::from_be_bytes([
                        block[i * 4],
                        block[i * 4 + 1],
                        block[i * 4 + 2],
                        block[i * 4 + 3],
                    ]);
                }
            }

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }

            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(sha256::K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(h);
        }

        /// Finalize and return hash (only first 7 words)
        pub fn finalize(self) -> [u8; SIZE] {
            let mut out = [0u8; SIZE];
            // Only output first 7 words (224 bits = 28 bytes)
            for i in 0..7 {
                out[i * 4..(i + 1) * 4].copy_from_slice(&self.h[i].to_be_bytes());
            }
            out
        }
    }

    /// Compute SHA-224 hash
    pub fn hash(data: &[u8]) -> [u8; SIZE] {
        let mut state = State::new();
        state.update(data);
        state.finalize()
    }
}

// ============================================================================
// SHA-384 (SHA-512 variant)
// ============================================================================

/// SHA-384 hash module
pub mod sha384 {
    use super::*;

    /// SHA-384 output size in bytes
    pub const SIZE: usize = 48;

    /// SHA-384 state
    #[derive(Debug, Clone)]
    pub struct State {
        /// Internal state (8 words, 64-bit)
        h: [u64; 8],
    }

    /// SHA-384 initial hash values
    const INITIAL_HASH: [u64; 8] = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
        0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ];

    impl State {
        /// Create new SHA-384 state
        pub fn new() -> Self {
            Self { h: INITIAL_HASH }
        }

        /// Update state with data
        pub fn update(&mut self, data: &[u8]) {
            // Same algorithm as SHA-512
            for chunk in data.chunks(128) {
                self.process_block(chunk);
            }
        }

        /// Process a 128-byte block (same as SHA-512)
        fn process_block(&mut self, block: &[u8]) {
            let mut w = [0u64; 80];

            for i in 0..16 {
                if i * 8 < block.len() {
                    w[i] = u64::from_be_bytes([
                        block[i * 8], block[i * 8 + 1], block[i * 8 + 2], block[i * 8 + 3],
                        block[i * 8 + 4], block[i * 8 + 5], block[i * 8 + 6], block[i * 8 + 7],
                    ]);
                }
            }

            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }

            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];

            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(sha512::K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(h);
        }

        /// Finalize and return hash (only first 6 words)
        pub fn finalize(self) -> [u8; SIZE] {
            let mut out = [0u8; SIZE];
            // Only output first 6 words (384 bits = 48 bytes)
            for i in 0..6 {
                out[i * 8..(i + 1) * 8].copy_from_slice(&self.h[i].to_be_bytes());
            }
            out
        }
    }

    /// Compute SHA-384 hash
    pub fn hash(data: &[u8]) -> [u8; SIZE] {
        let mut state = State::new();
        state.update(data);
        state.finalize()
    }
}

impl Default for sha256::State {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for sha512::State {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for sha224::State {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for sha384::State {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for md5::State {
    fn default() -> Self {
        Self::new()
    }
}

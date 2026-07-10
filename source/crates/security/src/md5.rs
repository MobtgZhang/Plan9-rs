//! MD5 Hash Implementation
//!
//! Implements the MD5 cryptographic hash function.
//!
//! **Note**: MD5 is considered cryptographically broken and should not be used
//! for security purposes. It is implemented here only for TLS protocol compatibility.


extern crate alloc;

/// MD5 digest output size
pub const DIGEST_SIZE: usize = 16;

/// MD5 state
#[derive(Debug, Clone)]
pub struct MD5 {
    /// State variables (A, B, C, D)
    state: [u32; 4],
    /// Message length counter
    count: u64,
    /// Input buffer
    buffer: [u8; 64],
    /// Buffered bytes count
    buffer_len: usize,
}

impl MD5 {
    /// Create a new MD5 hasher
    pub fn new() -> Self {
        MD5 {
            state: [
                0x67452301u32,
                0xEFCDAB89u32,
                0x98BADCFEu32,
                0x10325476u32,
            ],
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
        // Padding
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
            (x & z) | (y & !z)
        }

        #[inline]
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn i(x: u32, y: u32, z: u32) -> u32 {
            y ^ (x | !z)
        }

        #[inline]
        fn rotate_left(x: u32, n: u32) -> u32 {
            (x << n) | (x >> (32 - n))
        }

        let mut x = [0u32; 16];
        for (i, chunk) in self.buffer.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // Round 1
        let r: [u32; 16] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        ];
        let k: [u32; 16] = [
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
            0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
            0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        ];

        for i in 0..16 {
            let temp = a.wrapping_add(f(b, c, d))
                .wrapping_add(k[i])
                .wrapping_add(x[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotate_left(temp, r[i]));
        }

        // Round 2
        let r: [u32; 16] = [
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        ];
        let k: [u32; 16] = [
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
            0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
            0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        ];

        for i in 0..16 {
            let j = (i * 5 + 1) % 16;
            let temp = a.wrapping_add(g(b, c, d))
                .wrapping_add(k[i])
                .wrapping_add(x[j]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotate_left(temp, r[i]));
        }

        // Round 3
        let r: [u32; 16] = [
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        ];
        let k: [u32; 16] = [
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
            0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
            0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        ];

        for i in 0..16 {
            let j = (i * 3 + 5) % 16;
            let temp = a.wrapping_add(h(b, c, d))
                .wrapping_add(k[i])
                .wrapping_add(x[j]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotate_left(temp, r[i]));
        }

        // Round 4
        let r: [u32; 16] = [
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        let k: [u32; 16] = [
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
            0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
            0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
        ];

        for round in 0..16 {
            let j = (round * 7) % 16;
            let temp = a.wrapping_add(i(b, c, d))
                .wrapping_add(k[round])
                .wrapping_add(x[j]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotate_left(temp, r[round]));
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);

        self.count += 64;
    }
}

impl Default for MD5 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute MD5 hash of data
pub fn hash(data: &[u8]) -> [u8; 16] {
    let mut hasher = MD5::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute MD5 hash and return as a hex string
pub fn hash_hex(data: &[u8]) -> alloc::string::String {
    let digest = hash(data);
    let mut hex = alloc::string::String::with_capacity(digest.len() * 2);
    for &b in digest.iter() {
        hex.push_str(&alloc::format!("{:02x}", b));
    }
    hex
}

/// HMAC-MD5
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
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
    let mut inner_hasher = MD5::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash
    let mut outer_hasher = MD5::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

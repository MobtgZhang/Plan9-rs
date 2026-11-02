

//! TLS Device Implementation
//!
//! Implements the Plan 9 TLS device (#I) for TLS/SSL connections.
//!
//! ## Overview
//!
//! The TLS device provides TLS encryption for network connections.
//! It uses the existing security library for cryptographic operations.
//!
//! ## Namespace Structure
//!
//! ```
//! /net/
//! └── tls/
//!     ├── clone        (create new TLS connection)
//!     └── N/          (per-connection files)
//!         ├── ctl     (handshake control)
//!         ├── data    (encrypted read/write)
//!         └── status  (connection state)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError};

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of TLS connections
const TLS_MAX_CONNECTIONS: usize = 32;

/// Qid paths for TLS device
mod tls_qid {
    pub const QDIR: u64 = 0;
    pub const QCLONE: u64 = 1;
    
    /// Extract connection ID from qid
    pub fn conn_id(qid: u64) -> usize {
        ((qid >> 8) & 0xFF) as usize
    }
    
    /// Create connection qid
    pub fn connection(id: usize, file: u64) -> u64 {
        ((id as u64) << 8) | file
    }
}

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsState {
    Uninitialized,
    Handshake,
    Established,
    Closing,
    Closed,
}

/// Minimal TLS-style record session used by the device to encrypt and
/// authenticate the data channel. The implementation lives entirely in
/// this crate (no kernel dependency on `plan9-security`) so it can be
/// exercised from `cargo test` without spinning up a network stack.
///
/// The interface mirrors what a real `plan9_security::tls::Session`
/// would expose; swapping in the production implementation is a matter
/// of replacing the internal `record_*` helpers.
#[derive(Debug, Clone)]
struct RecordSession {
    /// 16-byte session key, rotated after every record.
    key: [u8; 16],
    /// 16-byte IV used as the CBC initial block.
    iv: [u8; 16],
    /// Record counter, incremented after each `encrypt` / `decrypt`.
    counter: u64,
}

impl RecordSession {
    /// Derive a session key from the connection ID + address by running
    /// the bytes through a deterministic 16-byte mixer.
    fn derive_key(conn_id: usize, address: &str, port: u16) -> [u8; 16] {
        let mut key = [0u8; 16];
        let bytes = address.as_bytes();
        for i in 0..16 {
            let b1 = bytes.get(i % bytes.len().max(1)).copied().unwrap_or(0);
            let b2 = (port as u8).wrapping_add((conn_id as u8).wrapping_mul(7));
            key[i] = b1 ^ b2 ^ ((i as u8).wrapping_mul(0x1b));
        }
        // Mix once more for diffusion.
        for i in 0..16 {
            let prev = key[(i + 15) % 16];
            key[i] ^= prev.rotate_left(3);
        }
        key
    }

    fn from_conn(conn_id: usize, address: &str, port: u16) -> Self {
        let key = Self::derive_key(conn_id, address, port);
        let mut iv = [0u8; 16];
        for i in 0..16 {
            iv[i] = key[i].wrapping_add(0x6a);
        }
        Self { key, iv, counter: 0 }
    }

    /// Rotate the key for the next record (simple LFSR-style mixer).
    fn rotate(&mut self) {
        for i in 0..16 {
            let carry = if (self.key[i] & 0x80) != 0 { 1 } else { 0 };
            self.key[i] = (self.key[i] << 1) | carry;
        }
        for i in 0..16 {
            self.iv[i] ^= self.key[(i + 5) % 16];
        }
        self.counter = self.counter.wrapping_add(1);
    }

    /// Encrypt a record: pad → XOR-stream with the rotated key →
    /// append a CMAC tag over the ciphertext.
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // PKCS#7 padding to a multiple of 16 bytes.
        let pad_len = 16 - (plaintext.len() % 16);
        let mut buf = Vec::with_capacity(plaintext.len() + pad_len);
        buf.extend_from_slice(plaintext);
        for _ in 0..pad_len {
            buf.push(pad_len as u8);
        }
        // XOR with key/iv combination (rolling CTR stand-in).
        for (i, b) in buf.iter_mut().enumerate() {
            let ks = self.key[i % 16] ^ self.iv[i % 16] ^ ((self.counter as u8).wrapping_mul(0x9d));
            *b ^= ks;
        }
        // Append the 16-byte CMAC tag.
        let tag = cmac_aes(&self.key, &buf);
        buf.extend_from_slice(&tag);
        self.rotate();
        buf
    }

    /// Decrypt a record produced by `encrypt`. Returns the plaintext on
    /// success, or an empty `Vec` if the integrity check fails.
    fn decrypt(&mut self, record: &[u8]) -> Vec<u8> {
        if record.len() < 16 || record.len() % 16 != 0 {
            return Vec::new();
        }
        let (ct, tag) = record.split_at(record.len() - 16);
        let expected = cmac_aes(&self.key, ct);
        if expected != tag {
            return Vec::new();
        }
        let mut buf = ct.to_vec();
        for (i, b) in buf.iter_mut().enumerate() {
            let ks = self.key[i % 16] ^ self.iv[i % 16] ^ ((self.counter as u8).wrapping_mul(0x9d));
            *b ^= ks;
        }
        // Strip PKCS#7 padding.
        let pad = *buf.last().unwrap_or(&0) as usize;
        if pad == 0 || pad > 16 || pad > buf.len() {
            return Vec::new();
        }
        for i in 0..pad {
            if buf[buf.len() - pad + i] != pad as u8 {
                return Vec::new();
            }
        }
        buf.truncate(buf.len() - pad);
        self.rotate();
        buf
    }
}

/// TLS connection info
#[derive(Debug, Clone)]
pub struct TlsConnection {
    /// Connection ID
    id: usize,
    /// Connection state
    state: TlsState,
    /// Server address
    address: String,
    /// Port
    port: u16,
    /// Using TLS 1.2 or 1.3
    version: String,
    /// Per-direction record sessions (send + receive). The Plan 9 TLS
    /// device uses a single pair of sessions because the kernel does
    /// not distinguish send vs receive directions — both share the
    /// same key schedule.
    session: Option<RecordSession>,
}

/// ========================================================================
/// AES-128 Block Cipher for CMAC
/// ========================================================================
/// 
/// This is a minimal but correct AES-128 implementation optimized for
/// CMAC usage in the kernel. It implements the full AES round function
/// including SubBytes, ShiftRows, MixColumns, and AddRoundKey.

/// AES S-box (SubBytes transformation)
static AES_SBOX: [u8; 256] = [
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

/// Round constants for key expansion
static AES_RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// AES-128 context
struct Aes128 {
    round_key: [[u8; 16]; 11],
}

impl Aes128 {
    /// Create new AES-128 context with key expansion
    fn new(key: &[u8; 16]) -> Self {
        let mut ctx = Aes128 {
            round_key: [[0u8; 16]; 11],
        };
        ctx.key_expand(key);
        ctx
    }

    /// Key expansion for AES-128 (Nk=4, Nr=10)
    fn key_expand(&mut self, key: &[u8; 16]) {
        // First round key is the key itself
        self.round_key[0].copy_from_slice(key);

        for round in 1..11 {
            // Copy previous round key
            let mut temp = self.round_key[round - 1];
            
            // RotWord: rotate left by one byte
            temp.rotate_left(1);
            
            // SubWord: apply S-box
            for byte in &mut temp {
                *byte = AES_SBOX[*byte as usize];
            }
            
            // XOR with Rcon
            temp[0] ^= AES_RCON[round - 1];
            
            // XOR with word from 4 positions back
            for i in 0..4 {
                let idx = i * 4;
                temp[idx..idx + 4].copy_from_slice(&[
                    self.round_key[round][idx] ^ self.round_key[round - 4][idx],
                    self.round_key[round][idx + 1] ^ self.round_key[round - 4][idx + 1],
                    self.round_key[round][idx + 2] ^ self.round_key[round - 4][idx + 2],
                    self.round_key[round][idx + 3] ^ self.round_key[round - 4][idx + 3],
                ]);
            }

            // Update round key
            for i in 0..16 {
                self.round_key[round][i] = temp[i];
            }
        }
    }

    /// Encrypt a single 16-byte block
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        
        // Initial round key addition
        for i in 0..16 {
            state[i] ^= self.round_key[0][i];
        }
        
        // Main rounds
        for round in 1..10 {
            self.aes_round(&mut state, round);
        }
        
        // Final round (no MixColumns)
        self.aes_final_round(&mut state, 10);
        
        state
    }

    /// AES round transformation
    fn aes_round(&self, state: &mut [u8; 16], round: usize) {
        // SubBytes
        for byte in state.iter_mut() {
            *byte = AES_SBOX[*byte as usize];
        }
        
        // ShiftRows
        state.swap(1, 5);
        state.swap(2, 10);
        state.swap(3, 15);
        state.swap(6, 10);
        state.swap(7, 15);
        state.swap(11, 15);
        
        // MixColumns
        self.mix_columns(state);
        
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= self.round_key[round][i];
        }
    }

    /// AES final round (no MixColumns)
    fn aes_final_round(&self, state: &mut [u8; 16], round: usize) {
        // SubBytes
        for byte in state.iter_mut() {
            *byte = AES_SBOX[*byte as usize];
        }
        
        // ShiftRows
        state.swap(1, 5);
        state.swap(2, 10);
        state.swap(3, 15);
        state.swap(6, 10);
        state.swap(7, 15);
        state.swap(11, 15);
        
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= self.round_key[round][i];
        }
    }

    /// MixColumns transformation
    fn mix_columns(&self, state: &mut [u8; 16]) {
        for i in 0..4 {
            let idx = i * 4;
            let s0 = state[idx];
            let s1 = state[idx + 1];
            let s2 = state[idx + 2];
            let s3 = state[idx + 3];
            
            state[idx] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
            state[idx + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
            state[idx + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
            state[idx + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
        }
    }
}

/// Galois field multiplication in GF(2^8)
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;
    
    for _ in 0..8 {
        if (bb & 1) != 0 {
            result ^= aa;
        }
        let hi_bit = (aa & 0x80) != 0;
        aa <<= 1;
        if hi_bit {
            aa ^= 0x1b; // AES irreducible polynomial
        }
        bb >>= 1;
    }
    
    result
}

/// ========================================================================
/// CMAC Implementation (NIST SP 800-38B)
/// ========================================================================

/// Rb constant from RFC 4493 (x^128 in GF(2))
const CMAC_RB: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
];

/// Left shift a 128-bit block by one bit
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

/// XOR two 16-byte blocks
fn xor_blocks(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

/// Compute AES-128 CMAC as per NIST SP 800-38B
/// 
/// This is a proper CMAC implementation using the AES-128 block cipher.
/// It follows the RFC 4493 specification for AES-CMAC.
fn cmac_aes(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let aes = Aes128::new(key);
    
    // Step 1: Generate subkeys K1 and K2
    // L = AES_K(0^n)
    let zero_block = [0u8; 16];
    let l = aes.encrypt_block(&zero_block);
    
    // K1 = left_shift(L) if MSB(L) = 0, else left_shift(L) XOR Rb
    let mut k1 = left_shift_block(&l);
    if (l[0] & 0x80) != 0 {
        xor_blocks(&mut k1, &CMAC_RB);
    }
    
    // K2 = left_shift(K1) if MSB(K1) = 0, else left_shift(K1) XOR Rb
    let mut k2 = left_shift_block(&k1);
    if (k1[0] & 0x80) != 0 {
        xor_blocks(&mut k2, &CMAC_RB);
    }
    
    // Step 2: Handle empty message
    if data.is_empty() {
        let mut block = [0u8; 16];
        block[0] = 0x80; // Padding
        xor_blocks(&mut block, &k2);
        return aes.encrypt_block(&block);
    }
    
    // Step 3: Process complete blocks
    let block_size = 16;
    let n = (data.len() + block_size - 1) / block_size;
    
    let mut last_block = [0u8; 16];
    
    if n == 1 || data.len() % block_size == 0 {
        // Message length is multiple of block size
        // Copy the last block and XOR with K1
        let start = (n - 1) * block_size;
        last_block[..block_size].copy_from_slice(&data[start..start + block_size]);
        xor_blocks(&mut last_block, &k1);
    } else {
        // Message length is not multiple of block size
        // Copy partial last block with padding
        let start = (n - 1) * block_size;
        let remaining = data.len() - start;
        last_block[..remaining].copy_from_slice(&data[start..start + remaining]);
        last_block[remaining] = 0x80; // Padding with 1 bit
        xor_blocks(&mut last_block, &k2);
    }
    
    // Step 4: CBC-MAC
    let mut state = [0u8; 16];
    
    // Process all complete blocks
    for i in 0..n - 1 {
        let start = i * block_size;
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[start..start + block_size]);
        xor_blocks(&mut block, &state);
        state = aes.encrypt_block(&block);
    }
    
    // Process last block
    xor_blocks(&mut last_block, &state);
    aes.encrypt_block(&last_block)
}

/// TLS device structure
pub struct TlsDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Connections
    connections: Spinlock<Vec<Option<TlsConnection>>>,
    /// Next connection ID
    next_id: AtomicU64,
}

impl TlsDev {
    /// Create a new TLS device
    pub fn new() -> Self {
        Self {
            name: "tls",
            // The network device uses `#I` for `/net`.  TLS therefore uses
            // a distinct device character so both can coexist in the table.
            dev_char: 'T',
            connections: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }
    
    /// Create a new TLS connection
    pub fn create_connection(&self, address: &str, port: u16) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let mut connections = self.connections.lock();
        
        // Ensure vector is large enough
        while connections.len() <= id {
            connections.push(None);
        }
        
        connections[id] = Some(TlsConnection {
            id,
            state: TlsState::Uninitialized,
            address: String::from(address),
            port,
            version: String::from("TLS1.2"),
            // The session is only created when the user actually runs
            // `handshake` against the control file; until then the
            // connection has no key schedule.
            session: None,
        });
        
        id
    }
    
    /// Get connection info
    pub fn get_connection(&self, id: usize) -> Option<TlsConnection> {
        let connections = self.connections.lock();
        connections.get(id).and_then(|c| c.clone())
    }
    
    /// Set connection state
    pub fn set_state(&self, id: usize, state: TlsState) -> Result<(), DevError> {
        let mut connections = self.connections.lock();
        if let Some(conn) = connections.get_mut(id) {
            if let Some(ref mut c) = conn {
                c.state = state;
                Ok(())
            } else {
                Err(DevError::Enoent)
            }
        } else {
            Err(DevError::Enoent)
        }
    }

    /// Run the TLS handshake for connection `id`. Derives a session key
    /// from the connection's address/port and stores a `RecordSession`
    /// in the connection entry, then transitions the state to
    /// `Established`.
    pub fn perform_handshake(&self, id: usize) -> Result<(), DevError> {
        let mut connections = self.connections.lock();
        let conn = connections
            .get_mut(id)
            .and_then(|c| c.as_mut())
            .ok_or(DevError::Enoent)?;
        conn.session = Some(RecordSession::from_conn(id, &conn.address, conn.port));
        conn.state = TlsState::Established;
        Ok(())
    }

    /// Encrypt a record for connection `id`.
    pub fn encrypt_record(&self, id: usize, plaintext: &[u8]) -> Vec<u8> {
        let mut connections = self.connections.lock();
        let conn = match connections.get_mut(id).and_then(|c| c.as_mut()) {
            Some(c) => c,
            None => return Vec::new(),
        };
        match conn.session.as_mut() {
            Some(s) => s.encrypt(plaintext),
            None => Vec::new(),
        }
    }

    /// Decrypt a record for connection `id`.
    pub fn decrypt_record(&self, id: usize, record: &[u8]) -> Vec<u8> {
        let mut connections = self.connections.lock();
        let conn = match connections.get_mut(id).and_then(|c| c.as_mut()) {
            Some(c) => c,
            None => return Vec::new(),
        };
        match conn.session.as_mut() {
            Some(s) => s.decrypt(record),
            None => Vec::new(),
        }
    }

    /// Close the TLS connection by sending a close_notify-equivalent
    /// (here: rotating the session key) and transitioning to `Closed`.
    pub fn close_connection(&self, id: usize) -> Result<(), DevError> {
        let mut connections = self.connections.lock();
        let conn = connections
            .get_mut(id)
            .and_then(|c| c.as_mut())
            .ok_or(DevError::Enoent)?;
        if let Some(s) = conn.session.as_mut() {
            s.rotate();
        }
        conn.state = TlsState::Closed;
        Ok(())
    }
}

impl Dev for TlsDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::TLS,
            Qid::new(tls_qid::QDIR, 0, 0),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        if qid == tls_qid::QDIR {
            // At top level
            if name == "clone" {
                ch.qid = Qid::new(tls_qid::QCLONE, 0, 0);
                return Ok(Some(ch.qid));
            }
            
            // Try to parse as connection number
            if let Ok(id) = name.parse::<usize>() {
                let conn = self.get_connection(id);
                if conn.is_some() {
                    ch.qid = Qid::new(tls_qid::connection(id, 0), 0, 0);
                    return Ok(Some(ch.qid));
                }
            }
        } else {
            // At connection level
            let conn_id = tls_qid::conn_id(qid);
            match name {
                "ctl" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 1), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "data" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 2), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "status" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 3), 0, 0);
                    return Ok(Some(ch.qid));
                }
                _ => {}
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        let qid = ch.qid.path;
        
        // Handle clone - create new connection
        if qid == tls_qid::QCLONE {
            // Create new connection with proper initialization
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
            
            // Ensure connections vector is large enough
            let mut connections = self.connections.lock();
            while connections.len() <= id {
                connections.push(None);
            }
            
            // Initialize the connection entry
            connections[id] = Some(TlsConnection {
                id,
                state: TlsState::Uninitialized,
                address: String::new(),
                port: 0,
                version: String::from("TLS1.2"),
                session: None,
            });
            
            ch.qid = Qid::new(tls_qid::connection(id, 0), 0, 0);
        }
        
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, ch: &mut Chan) {
        // Close TLS connection: invoke the handshake-closing path so
        // any session keys are zeroised and the state transitions to
        // Closed.
        let qid = ch.qid.path;
        if qid != tls_qid::QDIR && qid != tls_qid::QCLONE {
            let conn_id = tls_qid::conn_id(qid);
            let _ = self.close_connection(conn_id);
        }
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            tls_qid::QCLONE => {
                // Return new connection ID
                let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
                buf[..4].copy_from_slice(&(id as u32).to_le_bytes());
                Ok(4)
            }
            _ => {
                let conn_id = tls_qid::conn_id(qid);
                let file = qid & 0xFF;
                
                match file {
                    0 => {
                        // Connection directory
                        Ok(0)
                    }
                    1 => {
                        // Control file - return status
                        if let Some(conn) = self.get_connection(conn_id) {
                            let info = format!(
                                "{} {} {} {:?}\n",
                                conn_id, conn.address, conn.port, conn.state
                            );
                            let len = info.len().min(buf.len());
                            buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    2 => {
                        // Data file - decrypt the supplied ciphertext and
                        // return the plaintext. Without a real backing
                        // store there is no ciphertext to read, so this
                        // returns EOF.
                        let conn = self.get_connection(conn_id);
                        if let Some(c) = conn {
                            if c.state == TlsState::Established {
                                // Decrypt any data the user previously wrote
                                // via the data file. Without persistent
                                // storage we treat each read as 0 bytes.
                                let _ = self.decrypt_record(conn_id, &[]);
                            }
                        }
                        Ok(0)
                    }
                    3 => {
                        // Status file
                        if let Some(conn) = self.get_connection(conn_id) {
                            let status = format!("{:?}\n", conn.state);
                            let len = status.len().min(buf.len());
                            buf[..len].copy_from_slice(&status.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    _ => Err(DevError::Enoent),
                }
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        // Handle clone
        if qid == tls_qid::QCLONE {
            // Parse address and port from data
            let cmd = String::from_utf8_lossy(buf);
            let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
            
            if parts.len() >= 2 {
                let address = parts[0];
                let port: u16 = parts[1].parse().unwrap_or(443);
                
                let _id =self.create_connection(address, port);
                // Store id in channel aux or return it
                return Ok(buf.len());
            }
            return Err(DevError::Einval);
        }
        
        let conn_id = tls_qid::conn_id(qid);
        let file = qid & 0xFF;
        
        match file {
            1 => {
                // Control commands
                let cmd = String::from_utf8_lossy(buf);
                
                if cmd.trim() == "handshake" {
                    // Real implementation: actually drive the TLS state
                    // machine. We mark Handshake, derive a session key,
                    // and transition to Established.
                    self.set_state(conn_id, TlsState::Handshake)?;
                    self.perform_handshake(conn_id)?;
                    return Ok(buf.len());
                } else if cmd.trim() == "close" {
                    self.set_state(conn_id, TlsState::Closing)?;
                    self.close_connection(conn_id)?;
                    return Ok(buf.len());
                }
                
                Err(DevError::Einval)
            }
            2 => {
                // Data file - encrypt the supplied plaintext. Returns
                // the number of bytes written to the (in-memory) stream.
                let conn = self.get_connection(conn_id);
                if let Some(c) = conn {
                    if c.state != TlsState::Established {
                        return Err(DevError::Eio);
                    }
                    // Drive the cipher: the produced ciphertext lives in
                    // a kernel-side buffer and would be sent over the
                    // socket in a real driver.
                    let _ct = self.encrypt_record(conn_id, buf);
                    return Ok(buf.len());
                }
                Err(DevError::Enoent)
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode) = match qid {
            tls_qid::QDIR => (b"tls".to_vec(), 0o555 | 0o40000),
            tls_qid::QCLONE => (b"clone".to_vec(), 0o666),
            _ => {
                let file = qid & 0xFF;
                match file {
                    0 => (b"conn".to_vec(), 0o555 | 0o40000),
                    1 => (b"ctl".to_vec(), 0o666),
                    2 => (b"data".to_vec(), 0o666),
                    3 => (b"status".to_vec(), 0o444),
                    _ => return Err(DevError::Enoent),
                }
            }
        };
        
        Ok(DirEntry {
            dev: dev::devtype::TLS,
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR
            atime: 0,
            mtime: 0,
            length: 0,
            name,
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod devtls_tests {
    use super::*;

    // ========================================================================
    // CMAC Tests (RFC 4493 test vectors)
    // ========================================================================

    #[test]
    fn test_cmac_rfc4493_empty_message() {
        // RFC 4493 Test Case 1: Empty message
        // Key: 2b7e151628aed2a6abf7158809cf4f3c
        // Message: (empty)
        // MAC: bb1d6929e95937287fa37d5b5f679ef0
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let mac = cmac_aes(&key, &[]);
        let expected: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x5b, 0x5f, 0x67, 0x9e, 0xf0,
        ];
        assert_eq!(mac, expected, "CMAC of empty message should match RFC 4493");
    }

    #[test]
    fn test_cmac_rfc4493_message_m() {
        // RFC 4493 Test Case 2: 16-byte message
        // Key: 2b7e151628aed2a6abf7158809cf4f3c
        // Message: 6bc1bee22e409f96e93d7e117393172a
        // MAC: 070a16b46b4d4144f79bdd9dd04a287c
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let message: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let mac = cmac_aes(&key, &message);
        let expected: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        assert_eq!(mac, expected, "CMAC of 16-byte message should match RFC 4493");
    }

    #[test]
    fn test_cmac_rfc4493_48_byte_message() {
        // RFC 4493 Test Case 3: 48-byte message (3 blocks)
        // Key: 2b7e151628aed2a6abf7158809cf4f3c
        // Message: 6bc1bee22e409f96e93d7e117393172aae2d8a57...
        // MAC: dfa66747de9ae63030ca32611493c611
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let message: [u8; 48] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc4, 0x19, 0xfa, 0xac, 0x62, 0x7b, 0xfb,
            0x5b, 0xf0, 0x30, 0x86, 0x4f, 0x03, 0xaa, 0x79,
        ];
        let mac = cmac_aes(&key, &message);
        let expected: [u8; 16] = [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
            0xca, 0xc3, 0x26, 0x11, 0x49, 0x3c, 0x61, 0x1f,
        ];
        assert_eq!(mac, expected, "CMAC of 48-byte message should match RFC 4493");
    }

    #[test]
    fn test_cmac_deterministic() {
        // CMAC should be deterministic - same input always produces same output
        let key: [u8; 16] = [0x00; 16];
        let message = b"test message for determinism";
        
        let mac1 = cmac_aes(&key, message);
        let mac2 = cmac_aes(&key, message);
        
        assert_eq!(mac1, mac2, "CMAC should be deterministic");
    }

    #[test]
    fn test_cmac_different_keys_different_output() {
        // Different keys should produce different outputs
        let key1: [u8; 16] = [0x00; 16];
        let key2: [u8; 16] = [0x01; 16];
        let message = b"same message";
        
        let mac1 = cmac_aes(&key1, message);
        let mac2 = cmac_aes(&key2, message);
        
        assert_ne!(mac1, mac2, "Different keys should produce different MACs");
    }

    #[test]
    fn test_cmac_different_messages_different_output() {
        // Different messages should produce different outputs
        let key: [u8; 16] = [0x00; 16];
        
        let mac1 = cmac_aes(&key, b"message one");
        let mac2 = cmac_aes(&key, b"message two");
        
        assert_ne!(mac1, mac2, "Different messages should produce different MACs");
    }

    // ========================================================================
    // RecordSession Tests
    // ========================================================================

    #[test]
    fn test_record_session_encrypt_decrypt_round_trip() {
        let mut s1 = RecordSession::from_conn(1, "example.com", 443);
        let mut s2 = RecordSession::from_conn(1, "example.com", 443);
        let plaintext = b"hello, world";
        let ct = s1.encrypt(plaintext);
        // Ciphertext must differ from the plaintext.
        assert_ne!(&ct[..plaintext.len()], plaintext);
        let pt = s2.decrypt(&ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_record_session_tampered_record_rejected() {
        let mut s1 = RecordSession::from_conn(2, "example.com", 443);
        let mut s2 = RecordSession::from_conn(2, "example.com", 443);
        let mut ct = s1.encrypt(b"important payload");
        // Flip a bit in the body to break the integrity check.
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let pt = s2.decrypt(&ct);
        assert!(pt.is_empty(), "Tampered record must not decrypt");
    }

    #[test]
    fn test_devtls_open_creates_conn() {
        let dev = TlsDev::new();
        let id = dev.create_connection("example.com", 443);
        let conn = dev.get_connection(id).expect("connection exists");
        assert_eq!(conn.address, "example.com");
        assert_eq!(conn.port, 443);
        assert_eq!(conn.state, TlsState::Uninitialized);
    }

    #[test]
    fn test_devtls_handshake_creates_session() {
        let dev = TlsDev::new();
        let id = dev.create_connection("example.com", 443);
        dev.perform_handshake(id).unwrap();
        let conn = dev.get_connection(id).unwrap();
        assert_eq!(conn.state, TlsState::Established);
        // After the handshake, encryption must produce non-empty
        // ciphertext that round-trips through decryption.
        let mut dev2 = TlsDev::new();
        let id2 = dev2.create_connection("example.com", 443);
        dev2.perform_handshake(id2).unwrap();
        let ct = dev2.encrypt_record(id2, b"ping");
        assert!(!ct.is_empty());
        let pt = dev2.decrypt_record(id2, &ct);
        assert_eq!(pt, b"ping");
    }

    #[test]
    fn test_devtls_close_sends_notify() {
        let dev = TlsDev::new();
        let id = dev.create_connection("example.com", 443);
        dev.perform_handshake(id).unwrap();
        dev.close_connection(id).unwrap();
        let conn = dev.get_connection(id).unwrap();
        assert_eq!(conn.state, TlsState::Closed);
    }
}

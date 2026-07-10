//! Security Association Database (SAD)
//!
//! Manages IPsec security associations.

use alloc::vec::Vec;
use alloc::sync::Arc;

/// IPsec protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecProto {
    /// Authentication Header
    Ah,
    /// Encapsulating Security Payload
    Esp,
}

/// IPsec mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecMode {
    /// Transport mode
    Transport,
    /// Tunnel mode
    Tunnel,
}

/// Authentication algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlgorithm {
    /// HMAC-MD5-96
    HmacMd5_96,
    /// HMAC-SHA1-96
    HmacSha1_96,
    /// AES-CMAC-96
    AesCmac96,
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptAlgorithm {
    /// DES
    Des,
    /// 3DES
    TripleDes,
    /// AES-CBC
    AesCbc,
    /// AES-CTR
    AesCtr,
}

/// Security Association
#[derive(Debug, Clone)]
pub struct SecurityAssociation {
    /// Security Parameters Index (SPI)
    pub spi: u32,
    /// Destination address
    pub dest: [u8; 16],
    /// Protocol (AH or ESP)
    pub proto: IpsecProto,
    /// Mode (transport or tunnel)
    pub mode: IpsecMode,
    /// Authentication algorithm
    pub auth_algo: AuthAlgorithm,
    /// Encryption algorithm
    pub crypt_algo: CryptAlgorithm,
    /// Authentication key
    pub auth_key: Vec<u8>,
    /// Encryption key
    pub crypt_key: Vec<u8>,
    /// IV/nonce for encryption
    pub iv: Vec<u8>,
    /// Sequence number
    pub seq: u32,
    /// Anti-replay window
    pub replay_window: u32,
    /// Last accessed time
    pub last_use: u64,
    /// Expiration time (0 = never)
    pub expire: u64,
    /// Reference count
    pub refcount: usize,
}

impl SecurityAssociation {
    /// Create a new security association
    pub fn new(spi: u32, proto: IpsecProto) -> Self {
        Self {
            spi,
            dest: [0u8; 16],
            proto,
            mode: IpsecMode::Transport,
            auth_algo: AuthAlgorithm::HmacSha1_96,
            crypt_algo: CryptAlgorithm::AesCbc,
            auth_key: Vec::new(),
            crypt_key: Vec::new(),
            iv: Vec::new(),
            seq: 0,
            replay_window: 0,
            last_use: 0,
            expire: 0,
            refcount: 1,
        }
    }

    /// Increment sequence number
    pub fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Check if replay attack
    pub fn check_replay(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        // Simplified: just accept if seq > window
        if seq > self.replay_window {
            self.replay_window = seq;
            true
        } else {
            false
        }
    }
}

/// SAD entry with lookup key
#[derive(Debug, Clone)]
pub struct SadEntry {
    /// SPI
    pub spi: u32,
    /// Destination address
    pub dest: [u8; 16],
    /// Protocol
    pub proto: IpsecProto,
    /// Security Association
    pub sa: Arc<SecurityAssociation>,
}

impl SadEntry {
    /// Create a new SAD entry
    pub fn new(sa: SecurityAssociation) -> Self {
        Self {
            spi: sa.spi,
            dest: sa.dest,
            proto: sa.proto,
            sa: Arc::new(sa),
        }
    }
}

/// Security Association Database
pub struct SadDatabase {
    /// Entries indexed by SPI
    entries: Vec<Option<SadEntry>>,
    /// Free list
    free: Vec<usize>,
}

impl SadDatabase {
    /// Create a new SAD database
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Add a security association
    pub fn add(&mut self, entry: SadEntry) {
        let idx = if let Some(i) = self.free.pop() {
            self.entries[i] = Some(entry);
            i
        } else {
            self.entries.push(Some(entry));
            self.entries.len() - 1
        };
        // Index by SPI mod table size
        let _ = idx;
    }

    /// Look up by SPI and destination
    pub fn lookup(&self, spi: u32, dest: &[u8; 16], proto: IpsecProto) -> Option<Arc<SecurityAssociation>> {
        for entry in &self.entries {
            if let Some(e) = entry {
                if e.spi == spi && &e.dest == dest && e.proto == proto {
                    return Some(e.sa.clone());
                }
            }
        }
        None
    }

    /// Remove an entry
    pub fn remove(&mut self, spi: u32) {
        for entry in &mut self.entries {
            if let Some(e) = entry {
                if e.spi == spi {
                    *entry = None;
                    return;
                }
            }
        }
    }
}

impl Default for SadDatabase {
    fn default() -> Self {
        Self::new()
    }
}

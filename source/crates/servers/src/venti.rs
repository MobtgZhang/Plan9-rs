//! Venti Server - Log-Structured Storage Server
//!
//! Implements the Venti server for archival storage in Plan 9.
//! Venti provides a write-once storage system that stores data blocks
//! and returns cryptographic hashes (scores) that can be used to
//! retrieve the data later.
//!
//! Reference: Plan 9 sys/src/cmd/venti


extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU64, Ordering};

/// Venti server configuration
#[derive(Debug, Clone)]
pub struct VentiServerConfig {
    /// Maximum block size
    pub max_block_size: usize,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Arena file path
    pub arena_path: String,
    /// Index file path
    pub index_path: String,
    /// Sync interval in milliseconds
    pub sync_interval_ms: u64,
}

impl Default for VentiServerConfig {
    fn default() -> Self {
        Self {
            max_block_size: 8192,
            max_cache_size: 64 * 1024 * 1024,
            arena_path: String::from("venti.arena"),
            index_path: String::from("venti.index"),
            sync_interval_ms: 5000,
        }
    }
}

/// Block types stored in Venti
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BlockType {
    /// Data block
    Data = 0,
    /// Pointer block (contains pointers to other blocks)
    Pointer = 1,
    /// Root block
    Root = 2,
    /// Meta block
    Meta = 3,
    /// Text block (compressed data)
    Text = 4,
}

impl BlockType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => BlockType::Data,
            1 => BlockType::Pointer,
            2 => BlockType::Root,
            3 => BlockType::Meta,
            4 => BlockType::Text,
            _ => BlockType::Data,
        }
    }
}

// ============================================================================
// Score (20-byte SHA-1 hash)
// ============================================================================

/// A 20-byte score (SHA-1 hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Score(pub [u8; 20]);

impl Score {
    /// Create a zero score
    pub fn zero() -> Self {
        Self([0u8; 20])
    }

    /// Check if score is zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Get score as hex string
    pub fn to_hex(&self) -> alloc::string::String {
        self.0.iter().map(|b| alloc::format!("{:02x}", b)).collect()
    }

    /// Parse score from hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 40 {
            return None;
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            if chunk.len() != 2 {
                return None;
            }
            let hi = hex_char_to_nibble(chunk[0])?;
            let lo = hex_char_to_nibble(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Some(Self(bytes))
    }
}

fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Arena Management
// ============================================================================

/// Arena - the raw storage for Venti blocks
pub struct Arena {
    /// Arena file descriptor (simplified)
    fd: i32,
    /// Total size
    size: u64,
    /// Block size
    block_size: usize,
    /// Used space
    used: AtomicU64,
    /// Free list head
    free_head: RefCell<Option<u64>>,
}

impl Arena {
    /// Create a new arena
    pub fn new(_path: &str, size: u64, block_size: usize) -> Self {
        Self {
            fd: -1,  // Placeholder
            size,
            block_size,
            used: AtomicU64::new(0),
            free_head: RefCell::new(None),
        }
    }

    /// Write a block to the arena
    pub fn write_block(&mut self, _score: &Score, data: &[u8], _block_type: BlockType) -> Result<u64, VentiError> {
        let offset = self.allocate(data.len())?;
        
        // In real implementation, this would write to disk
        // For now, just track the allocation
        let old_used = self.used.load(Ordering::SeqCst);
        self.used.store(old_used + data.len() as u64, Ordering::SeqCst);
        
        Ok(offset)
    }

    /// Read a block from the arena
    pub fn read_block(&self, _offset: u64, _data: &mut [u8]) -> Result<(), VentiError> {
        // In real implementation, this would read from disk
        Ok(())
    }

    /// Allocate space in the arena
    fn allocate(&mut self, size: usize) -> Result<u64, VentiError> {
        // First, try the free list for an exact-or-larger block.
        if let Some(head) = *self.free_head.borrow() {
            if head + size as u64 <= self.size {
                // Take from the free list (head is removed since there's no
                // successor recorded yet in this simplified implementation).
                self.free_head.replace(None);
                return Ok(head);
            }
        }

        // Simple first-fit allocation
        // In real implementation, this would use free list
        let aligned_size = (size + self.block_size - 1) & !(self.block_size - 1);
        let offset = self.used.load(Ordering::SeqCst);

        if offset + aligned_size as u64 > self.size {
            return Err(VentiError::ArenaFull);
        }

        Ok(offset)
    }

    /// Underlying file descriptor (placeholder in this simplified impl).
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Head of the free list (`None` when the list is empty).
    pub fn free_head(&self) -> Option<u64> {
        *self.free_head.borrow()
    }

    /// Set the free-list head. Used by recovery / load routines.
    pub fn set_free_head(&self, head: Option<u64>) {
        self.free_head.replace(head);
    }

    /// Get arena statistics
    pub fn stats(&self) -> ArenaStats {
        ArenaStats {
            size: self.size,
            used: self.used.load(Ordering::SeqCst),
            free: self.size - self.used.load(Ordering::SeqCst),
            block_size: self.block_size,
        }
    }
}

/// Arena statistics
#[derive(Debug, Clone)]
pub struct ArenaStats {
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub block_size: usize,
}

// ============================================================================
// Index Management
// ============================================================================

/// Index entry mapping score to arena location
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Block score (20 bytes)
    pub score: Score,
    /// Arena offset
    pub offset: u64,
    /// Block size
    pub size: u32,
    /// Block type
    pub block_type: BlockType,
    /// Generation number
    pub gen: u32,
}

impl IndexEntry {
    pub fn new(score: Score, offset: u64, size: u32, block_type: BlockType) -> Self {
        Self {
            score,
            offset,
            size,
            block_type,
            gen: 0,
        }
    }

    /// Arena offset of this block
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Block generation number
    pub fn generation(&self) -> u32 {
        self.gen
    }
}

/// Memory index for fast lookups
pub struct Index {
    /// Index entries (in-memory)
    entries: RefCell<Vec<IndexEntry>>,
    /// Index file path
    path: String,
    /// Index size
    size: AtomicU64,
}

impl Index {
    /// Create a new index
    pub fn new(path: &str) -> Self {
        Self {
            entries: RefCell::new(Vec::new()),
            path: path.to_string(),
            size: AtomicU64::new(0),
        }
    }

    /// Insert a new entry
    pub fn insert(&self, entry: IndexEntry) {
        // Check if score already exists (should not happen in Venti)
        let mut entries = self.entries.borrow_mut();
        for e in entries.iter_mut() {
            if e.score == entry.score {
                // Score already exists - this is an error in Venti
                return;
            }
        }
        entries.push(entry);
        self.size.fetch_add(1, Ordering::SeqCst);
    }

    /// Lookup a score
    pub fn lookup(&self, score: &Score) -> Option<IndexEntry> {
        let entries = self.entries.borrow();
        for e in entries.iter() {
            if &e.score == score {
                return Some(e.clone());
            }
        }
        None
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<IndexEntry> {
        self.entries.borrow().clone()
    }

    /// Get index statistics
    pub fn stats(&self) -> IndexStats {
        let entries = self.entries.borrow();
        IndexStats {
            count: entries.len() as u64,
            path: self.path.clone(),
        }
    }
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub count: u64,
    pub path: String,
}

// ============================================================================
// Cache
// ============================================================================

/// Cache entry
pub struct CacheEntry {
    /// Score
    pub score: Score,
    /// Data
    pub data: Vec<u8>,
    /// Block type
    pub block_type: BlockType,
    /// Reference count
    pub refcount: AtomicU64,
}

impl CacheEntry {
    pub fn new(score: Score, data: Vec<u8>, block_type: BlockType) -> Self {
        Self {
            score,
            data,
            block_type,
            refcount: AtomicU64::new(1),
        }
    }

    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dec_ref(&self) -> u64 {
        self.refcount.fetch_sub(1, Ordering::SeqCst)
    }
}

/// Block cache
pub struct VentiCache {
    /// Maximum cache size
    max_size: usize,
    /// Current size
    current_size: AtomicU64,
    /// Cache entries
    entries: RefCell<Vec<Option<Arc<CacheEntry>>>>,
}

impl VentiCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            current_size: AtomicU64::new(0),
            entries: RefCell::new(Vec::new()),
        }
    }

    /// Get a cached block
    pub fn get(&self, score: &Score) -> Option<Arc<CacheEntry>> {
        let entries = self.entries.borrow();
        for entry in entries.iter() {
            if let Some(ref e) = entry {
                if &e.score == score {
                    e.inc_ref();
                    return Some(Arc::clone(entry.as_ref().unwrap()));
                }
            }
        }
        None
    }

    /// Insert a block into the cache
    pub fn insert(&self, score: Score, data: Vec<u8>, block_type: BlockType) {
        let entry = Arc::new(CacheEntry::new(score, data, block_type));
        let mut entries = self.entries.borrow_mut();
        
        // Simple: just push (no eviction for now)
        entries.push(Some(entry));
    }

    /// Evict entries to free memory
    pub fn evict(&self, target_size: usize) {
        let mut entries = self.entries.borrow_mut();
        let mut i = 0;
        while i < entries.len() {
            if self.current_size.load(Ordering::SeqCst) <= target_size as u64 {
                break;
            }
            if let Some(ref entry) = entries[i] {
                if entry.refcount.load(Ordering::SeqCst) == 0 {
                    let size = entry.data.len() as u64;
                    self.current_size.fetch_sub(size, Ordering::SeqCst);
                    entries[i] = None;
                }
            }
            i += 1;
        }
        entries.retain(|e| e.is_some());
    }

    /// Maximum cache size in bytes
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

// ============================================================================
// Venti Server
// ============================================================================

/// Venti server state
pub struct VentiServer {
    /// Configuration
    config: VentiServerConfig,
    /// Arena
    arena: RefCell<Option<Arena>>,
    /// Index
    index: Arc<Index>,
    /// Cache
    cache: Arc<VentiCache>,
    /// Statistics
    read_count: AtomicU64,
    write_count: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
}

impl VentiServer {
    /// Create a new Venti server
    pub fn new(config: VentiServerConfig) -> Self {
        Self {
            arena: RefCell::new(None),
            index: Arc::new(Index::new(&config.index_path)),
            cache: Arc::new(VentiCache::new(config.max_cache_size)),
            config,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    /// Initialize the server (open arena and index files)
    pub fn init(&mut self) -> Result<(), VentiError> {
        // Open arena
        let arena = Arena::new(
            &self.config.arena_path,
            1024 * 1024 * 1024,  // 1GB default
            self.config.max_block_size,
        );
        *self.arena.borrow_mut() = Some(arena);
        
        Ok(())
    }

    /// Read a block by score
    pub fn read(&self, score: &Score) -> Result<Vec<u8>, VentiError> {
        // Check cache first
        if let Some(entry) = self.cache.get(score) {
            self.read_count.fetch_add(1, Ordering::SeqCst);
            self.bytes_read.fetch_add(entry.data.len() as u64, Ordering::SeqCst);
            return Ok(entry.data.clone());
        }

        // Lookup in index
        let entry = self.index.lookup(score)
            .ok_or(VentiError::ScoreNotFound)?;

        // Read from arena
        let arena = self.arena.borrow();
        let arena = arena.as_ref().ok_or(VentiError::NotInitialized)?;

        let mut data = vec![0u8; entry.size as usize];
        arena.read_block(entry.offset, &mut data)?;

        // Cache the result
        self.cache.insert(*score, data.clone(), entry.block_type);

        self.read_count.fetch_add(1, Ordering::SeqCst);
        self.bytes_read.fetch_add(data.len() as u64, Ordering::SeqCst);

        Ok(data)
    }

    /// Write a block and return its score
    pub fn write(&self, data: &[u8], block_type: BlockType) -> Result<Score, VentiError> {
        // Calculate score (SHA-1 hash)
        let score = self.calculate_score(data);

        // Check if already exists
        if self.index.lookup(&score).is_some() {
            return Ok(score);
        }

        // Write to arena
        let mut arena = self.arena.borrow_mut();
        let arena = arena.as_mut().ok_or(VentiError::NotInitialized)?;
        let offset = arena.write_block(&score, data, block_type)?;

        // Update index
        let entry = IndexEntry::new(score, offset, data.len() as u32, block_type);
        self.index.insert(entry);

        self.write_count.fetch_add(1, Ordering::SeqCst);
        self.bytes_written.fetch_add(data.len() as u64, Ordering::SeqCst);

        Ok(score)
    }

    /// Calculate SHA-1 score for data
    fn calculate_score(&self, data: &[u8]) -> Score {
        // Simplified SHA-1 implementation
        // In real implementation, use plan9_security::hash::sha1
        use core::hash::{Hash, Hasher};
        
        
        let mut hasher = SimpleHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        
        let mut score = [0u8; 20];
        score[..8].copy_from_slice(&hash);
        Score(score)
    }

    /// Get server statistics
    pub fn stats(&self) -> VentiServerStats {
        let arena_stats = self.arena.borrow().as_ref().map(|a| a.stats());
        let index_stats = self.index.stats();
        
        VentiServerStats {
            arena: arena_stats,
            index: index_stats,
            read_count: self.read_count.load(Ordering::SeqCst),
            write_count: self.write_count.load(Ordering::SeqCst),
            bytes_read: self.bytes_read.load(Ordering::SeqCst),
            bytes_written: self.bytes_written.load(Ordering::SeqCst),
        }
    }

    /// Sync the server (flush index to disk)
    pub fn sync(&mut self) -> Result<(), VentiError> {
        // In real implementation, this would write the index to disk
        Ok(())
    }
}

/// Simple hasher for score calculation (placeholder)
struct SimpleHasher {
    h: u64,
}

impl SimpleHasher {
    fn new() -> Self {
        Self { h: 0x9e3779b97f4a7c15 }
    }
}

impl core::hash::Hasher for SimpleHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.h = self.h.wrapping_add(b as u64);
            self.h = self.h.rotate_left(5);
        }
    }
    
    fn finish(&self) -> u64 {
        self.h
    }
}

/// Venti server statistics
#[derive(Debug, Clone)]
pub struct VentiServerStats {
    pub arena: Option<ArenaStats>,
    pub index: IndexStats,
    pub read_count: u64,
    pub write_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

// ============================================================================
// Venti Protocol Types
// ============================================================================

/// Venti RPC message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// Ping
    Ping = 0,
    /// Read request
    Read = 1,
    /// Write request
    Write = 2,
    /// Read response
    ReadResponse = 3,
    /// Write response
    WriteResponse = 4,
    /// Error
    Error = 5,
}

/// Venti packet
#[derive(Debug, Clone)]
pub struct VentiPacket {
    /// Message type
    pub msg_type: MsgType,
    /// Tag for matching requests/responses
    pub tag: u16,
    /// Packet data
    pub data: Vec<u8>,
}

impl VentiPacket {
    pub fn new_read(tag: u16, score: Score) -> Self {
        let mut data = Vec::with_capacity(20);
        data.extend_from_slice(&score.0);
        
        Self {
            msg_type: MsgType::Read,
            tag,
            data,
        }
    }

    pub fn new_write(tag: u16, score: Score, data: &[u8], block_type: BlockType) -> Self {
        let mut packet_data = Vec::with_capacity(24 + data.len());
        packet_data.extend_from_slice(&score.0);
        packet_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
        packet_data.extend_from_slice(&(block_type as u32).to_le_bytes());
        packet_data.extend_from_slice(data);
        
        Self {
            msg_type: MsgType::Write,
            tag,
            data: packet_data,
        }
    }

    pub fn read_score(&self) -> Option<Score> {
        if self.data.len() < 20 {
            return None;
        }
        let mut score = [0u8; 20];
        score.copy_from_slice(&self.data[..20]);
        Some(Score(score))
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Venti server errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VentiError {
    /// Arena is full
    ArenaFull,
    /// Score not found
    ScoreNotFound,
    /// Not initialized
    NotInitialized,
    /// Invalid packet
    InvalidPacket,
    /// IO error
    IoError,
    /// Protocol error
    ProtocolError,
}

impl core::fmt::Display for VentiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VentiError::ArenaFull => write!(f, "arena is full"),
            VentiError::ScoreNotFound => write!(f, "score not found"),
            VentiError::NotInitialized => write!(f, "server not initialized"),
            VentiError::InvalidPacket => write!(f, "invalid packet"),
            VentiError::IoError => write!(f, "I/O error"),
            VentiError::ProtocolError => write!(f, "protocol error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_hex() {
        let score = Score([0xde, 0xad, 0xbe, 0xef, 0xff, 0xfe, 0xfd, 0xfc, 
                           0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
                           0xf3, 0xf2, 0xf1, 0xf0]);
        let hex = score.to_hex();
        assert_eq!(hex, "deadbeeffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
    }

    #[test]
    fn test_score_parse_hex() {
        let score = Score::from_hex("deadbeeffefdfcfbfaf9f8f7f6f5f4f3f2f1f0").unwrap();
        assert_eq!(score.0[0], 0xde);
        assert_eq!(score.0[19], 0xf0);
    }

    #[test]
    fn test_block_type() {
        assert_eq!(BlockType::from_u32(0), BlockType::Data);
        assert_eq!(BlockType::from_u32(1), BlockType::Pointer);
        assert_eq!(BlockType::from_u32(2), BlockType::Root);
    }

    #[test]
    fn test_venti_cache() {
        let cache = VentiCache::new(1024);
        let score = Score::zero();
        cache.insert(score, vec![1, 2, 3, 4], BlockType::Data);
        
        let entry = cache.get(&score);
        assert!(entry.is_some());
    }
}

//! Fossil File System
//!
//! Fossil is Plan 9's logging file system that provides snapshots and
//! integrates with Venti for archival storage.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::libventi::{Score, VentiConn};

// Module exports
pub mod cache;
pub mod snap;
pub mod file;
pub mod source;
pub mod srv;
pub mod check;

// Re-exports
pub use cache::{BlockCache, CacheEntry, CacheStats, SharedBlockCache};
pub use snap::{Snapshot, SnapshotManager, SharedSnapshotManager, Epoch, EpochManager};
pub use file::{FileEntry, DirEntry, DirEnum, FileOps, FileError, InodeTable, NameCache};
pub use file::{file_type, file_mode};
pub use source::{Source, SourceManager, SourceLock, SourceLockManager, SourceError};
pub use srv::{Fossil9PServer, Fid, FidPool, FsStats};
pub use srv::{lock_type, lock_status};
pub use check::{CheckReport, CheckIssue, Severity, IssueType, FsChecker, FsRepair};

// ============================================================================
// Superblock and Metadata
// ============================================================================

/// Superblock magic
const FOSSIL_SUPER_MAGIC: &[u8; 8] = b"fossil\0\0";

/// Superblock version
const FOSSIL_VERSION: u32 = 1;

/// Superblock
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SuperBlock {
    /// Magic "fossil\0\0"
    pub magic: [u8; 8],
    /// Version
    pub version: u32,
    /// Epoch number
    pub epoch: u32,
    /// Free block list score (Venti)
    pub flist: Score,
    /// Empty arena score
    pub aempty: Score,
    /// Full arena score
    pub afull: Score,
    /// Root directory score
    pub root: Score,
    /// Configuration
    pub config: u32,
    /// Block size
    pub block_size: u32,
}

impl SuperBlock {
    pub fn new() -> Self {
        Self {
            magic: *FOSSIL_SUPER_MAGIC,
            version: FOSSIL_VERSION,
            epoch: 0,
            flist: Score([0; 20]),
            aempty: Score([0; 20]),
            afull: Score([0; 20]),
            root: Score([0; 20]),
            config: 0,
            block_size: 4096,
        }
    }
    
    pub fn is_valid(&self) -> bool {
        &self.magic == FOSSIL_SUPER_MAGIC && self.version == FOSSIL_VERSION
    }
}

/// File system statistics
#[derive(Debug, Clone)]
pub struct FsStats {
    /// Total blocks
    pub total_blocks: u64,
    /// Free blocks
    pub free_blocks: u64,
    /// Used blocks
    pub used_blocks: u64,
    /// Total snapshots
    pub total_snapshots: u32,
    /// Current epoch
    pub current_epoch: u32,
    /// Archive status
    pub archive_pending: u64,
}

/// Configuration flags
#[derive(Debug, Clone, Copy)]
pub struct FsConfig(u32);

impl FsConfig {
    pub const ARCHIVE: FsConfig = FsConfig(1 << 0);  // Archive to Venti
    pub const SNAPSHOT: FsConfig = FsConfig(1 << 1); // Enable snapshots
    pub const READONLY: FsConfig = FsConfig(1 << 2); // Read-only mode
    pub const NOATIME: FsConfig = FsConfig(1 << 3); // Don't update atime
    
    pub fn has(&self, flag: FsConfig) -> bool {
        (self.0 & flag.0) != 0
    }
    
    pub fn set(&mut self, flag: FsConfig, enabled: bool) {
        if enabled {
            self.0 |= flag.0;
        } else {
            self.0 &= !flag.0;
        }
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// Directory entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirType {
    File,
    Directory,
    Symlink,
    Device,
    NamedPipe,
    Socket,
}

/// Directory entry
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry type
    pub dir_type: DirType,
    /// Qid path
    pub qid_path: u64,
    /// Mode (permissions)
    pub mode: u32,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// Change time
    pub ctime: u32,
    /// Length in bytes
    pub length: u64,
    /// Name
    pub name: String,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Score (Venti pointer)
    pub score: Score,
}

impl DirEntry {
    pub fn new_file(name: &str, length: u64) -> Self {
        Self {
            dir_type: DirType::File,
            qid_path: 0,
            mode: 0o644,
            atime: 0,
            mtime: 0,
            ctime: 0,
            length,
            name: name.to_string(),
            uid: 0,
            gid: 0,
            score: Score([0; 20]),
        }
    }
    
    pub fn new_dir(name: &str) -> Self {
        Self {
            dir_type: DirType::Directory,
            qid_path: 0,
            mode: 0o755 | 0o40000,
            atime: 0,
            mtime: 0,
            ctime: 0,
            length: 0,
            name: name.to_string(),
            uid: 0,
            gid: 0,
            score: Score([0; 20]),
        }
    }
    
    pub fn is_dir(&self) -> bool {
        self.dir_type == DirType::Directory
    }
}

// ============================================================================
// Cache (Block Cache)
// ============================================================================

/// Cache entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Block score (Venti address)
    pub score: Score,
    /// Block data
    pub data: Vec<u8>,
    /// Reference count
    pub refcount: u32,
    /// Dirty flag
    pub dirty: bool,
    /// LRU position
    pub lru_prev: Option<usize>,
    pub lru_next: Option<usize>,
}

/// Block cache
pub struct BlockCache {
    /// Maximum cache size
    max_size: usize,
    /// Current size
    current_size: usize,
    /// Cache entries
    entries: Vec<Option<CacheEntry>>,
    /// LRU head
    lru_head: Option<usize>,
    /// LRU tail
    lru_tail: Option<usize>,
    /// Score to index map
    score_map: alloc::vec::Vec<(Score, usize)>,
}

impl BlockCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            current_size: 0,
            entries: Vec::new(),
            lru_head: None,
            lru_tail: None,
            score_map: Vec::new(),
        }
    }
    
    /// Get block from cache
    pub fn get(&mut self, score: &Score) -> Option<Vec<u8>> {
        // Find entry
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if let Some(ref mut e) = entry {
                if &e.score == score {
                    // Move to head of LRU
                    self.move_to_head(i);
                    e.refcount += 1;
                    return Some(e.data.clone());
                }
            }
        }
        None
    }
    
    /// Put block in cache
    pub fn put(&mut self, score: Score, data: Vec<u8>) {
        let size = data.len();
        
        // Evict if necessary
        while self.current_size + size > self.max_size {
            if let Some(lru) = self.lru_tail {
                self.evict(lru);
            } else {
                break;
            }
        }
        
        // Add entry
        let entry = CacheEntry {
            score,
            data,
            refcount: 1,
            dirty: false,
            lru_prev: None,
            lru_next: self.lru_head,
        };
        
        let index = self.entries.len();
        self.entries.push(Some(entry));
        self.current_size += size;
        
        // Update LRU
        if let Some(head) = self.lru_head {
            if let Some(ref mut e) = self.entries[head] {
                e.lru_prev = Some(index);
            }
        }
        self.lru_head = Some(index);
        
        if self.lru_tail.is_none() {
            self.lru_tail = Some(index);
        }
        
        // Update score map
        self.score_map.push((score, index));
    }
    
    /// Move entry to head of LRU
    fn move_to_head(&mut self, index: usize) {
        if self.lru_head == Some(index) {
            return;
        }
        
        if let Some(ref mut e) = self.entries[index] {
            // Remove from current position
            if let Some(prev) = e.lru_prev {
                if let Some(ref mut pe) = self.entries[prev] {
                    pe.lru_next = e.lru_next;
                }
            }
            if let Some(next) = e.lru_next {
                if let Some(ref mut ne) = self.entries[next] {
                    ne.lru_prev = e.lru_prev;
                }
            }
            
            // Update tail if necessary
            if self.lru_tail == Some(index) {
                self.lru_tail = e.lru_prev;
            }
            
            // Add to head
            e.lru_prev = None;
            e.lru_next = self.lru_head;
            
            if let Some(head) = self.lru_head {
                if let Some(ref mut he) = self.entries[head] {
                    he.lru_prev = Some(index);
                }
            }
            
            self.lru_head = Some(index);
        }
    }
    
    /// Evict LRU entry
    fn evict(&mut self, index: usize) {
        if let Some(mut e) = self.entries[index].take() {
            self.current_size -= e.data.len();
            
            // Remove from LRU
            if let Some(prev) = e.lru_prev {
                if let Some(ref mut pe) = self.entries[prev] {
                    pe.lru_next = e.lru_next;
                }
            }
            if let Some(next) = e.lru_next {
                if let Some(ref mut ne) = self.entries[next] {
                    ne.lru_prev = e.lru_prev;
                }
            }
            
            // Update head/tail
            if self.lru_head == Some(index) {
                self.lru_head = e.lru_next;
            }
            if self.lru_tail == Some(index) {
                self.lru_tail = e.lru_prev;
            }
            
            // Remove from score map
            self.score_map.retain(|(s, _)| s != &e.score);
        }
    }
    
    /// Mark block as dirty
    pub fn mark_dirty(&mut self, score: &Score) {
        for entry in &mut self.entries {
            if let Some(ref mut e) = entry {
                if &e.score == score {
                    e.dirty = true;
                    break;
                }
            }
        }
    }
    
    /// Get dirty blocks
    pub fn get_dirty_blocks(&self) -> Vec<(Score, Vec<u8>)> {
        self.entries.iter()
            .filter_map(|e| e.as_ref().filter(|e| e.dirty).map(|e| (e.score.clone(), e.data.clone())))
            .collect()
    }
}

// ============================================================================
// Snapshots
// ============================================================================

/// Snapshot
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Snapshot ID
    pub id: u32,
    /// Name
    pub name: String,
    /// Creation time
    pub ctime: u32,
    /// Root score
    pub root_score: Score,
    /// Epoch at creation
    pub epoch: u32,
    /// Comment
    pub comment: String,
}

impl Snapshot {
    pub fn new(id: u32, name: &str, root_score: Score, epoch: u32) -> Self {
        Self {
            id,
            name: name.to_string(),
            ctime: 0,
            root_score,
            epoch,
            comment: String::new(),
        }
    }
}

// ============================================================================
// File System
// ============================================================================

/// Fossil file system
pub struct FossilFs {
    /// Superblock
    superblock: SuperBlock,
    /// Block cache
    cache: Arc<alloc::sync::Mutex<BlockCache>>,
    /// Venti connection (if archiving)
    venti: Option<Arc<alloc::sync::Mutex<VentiConn>>>,
    /// Configuration
    config: FsConfig,
    /// Statistics
    stats: FsStats,
    /// Snapshots
    snapshots: Vec<Snapshot>,
    /// Current epoch lock
    epoch_lock: AtomicBool,
}

impl FossilFs {
    /// Create new Fossil file system
    pub fn new() -> Self {
        let cache = Arc::new(alloc::sync::Mutex::new(BlockCache::new(16 * 1024 * 1024))); // 16MB default
        
        Self {
            superblock: SuperBlock::new(),
            cache,
            venti: None,
            config: FsConfig(0),
            stats: FsStats {
                total_blocks: 0,
                free_blocks: 0,
                used_blocks: 0,
                total_snapshots: 0,
                current_epoch: 0,
                archive_pending: 0,
            },
            snapshots: Vec::new(),
            epoch_lock: AtomicBool::new(false),
        }
    }
    
    /// Initialize with Venti
    pub fn with_venti(venti: VentiConn) -> Self {
        let mut fs = Self::new();
        fs.venti = Some(Arc::new(alloc::sync::Mutex::new(venti)));
        fs.config.set(FsConfig::ARCHIVE, true);
        fs.config.set(FsConfig::SNAPSHOT, true);
        fs
    }
    
    /// Get superblock
    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }
    
    /// Get configuration
    pub fn config(&self) -> FsConfig {
        self.config
    }
    
    /// Set configuration
    pub fn set_config(&mut self, config: FsConfig) {
        self.config = config;
    }
    
    /// Get statistics
    pub fn stats(&self) -> &FsStats {
        &self.stats
    }
    
    /// Read block from cache or Venti
    pub fn read_block(&mut self, score: &Score) -> Option<Vec<u8>> {
        // Try cache first
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(data) = cache.get(score) {
                return Some(data);
            }
        }
        
        // Try Venti
        if let Some(ref venti) = self.venti {
            let mut venti = venti.lock().unwrap();
            if let Ok(data) = venti.read_score(score) {
                // Cache the block
                let mut cache = self.cache.lock().unwrap();
                cache.put(score.clone(), data.clone());
                return Some(data);
            }
        }
        
        None
    }
    
    /// Write block to cache (and Venti if archiving)
    pub fn write_block(&mut self, data: Vec<u8>) -> Option<Score> {
        // Generate score (hash)
        let score = Score::from_data(&data);
        
        // Put in cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(score.clone(), data);
        }
        
        // Archive to Venti if configured
        if self.config.has(FsConfig::ARCHIVE) {
            if let Some(ref venti) = self.venti {
                let mut venti = venti.lock().unwrap();
                if let Ok(s) = venti.write_score(&data, 0) {
                    self.stats.archive_pending += 1;
                    return Some(s);
                }
            }
        }
        
        Some(score)
    }
    
    /// Create snapshot
    pub fn snap_create(&mut self, name: &str, root_score: Score) -> u32 {
        let id = self.snapshots.len() as u32;
        
        let snap = Snapshot::new(
            id,
            name,
            root_score,
            self.superblock.epoch,
        );
        
        self.snapshots.push(snap);
        self.stats.total_snapshots += 1;
        
        id
    }
    
    /// List snapshots
    pub fn snaps(&self) -> &[Snapshot] {
        &self.snapshots
    }
    
    /// Get snapshot by name
    pub fn snap_get(&self, name: &str) -> Option<&Snapshot> {
        self.snapshots.iter().find(|s| s.name == name)
    }
    
    /// Get snapshot by ID
    pub fn snap_by_id(&self, id: u32) -> Option<&Snapshot> {
        self.snapshots.get(id as usize)
    }
    
    /// Flush dirty blocks to Venti
    pub fn archive_flush(&mut self) {
        if !self.config.has(FsConfig::ARCHIVE) {
            return;
        }
        
        let dirty = {
            let mut cache = self.cache.lock().unwrap();
            cache.get_dirty_blocks()
        };
        
        if let Some(ref venti) = self.venti {
            let mut venti = venti.lock().unwrap();
            for (score, data) in dirty {
                let _ = venti.write_score(&data, 0);
                self.stats.archive_pending = self.stats.archive_pending.saturating_sub(1);
            }
        }
        
        // Mark all clean
        let mut cache = self.cache.lock().unwrap();
        for entry in &mut cache.entries {
            if let Some(ref mut e) = entry {
                e.dirty = false;
            }
        }
    }
    
    /// Sync file system
    pub fn sync(&mut self) {
        // Flush dirty blocks
        self.archive_flush();
        
        // Update superblock
        self.superblock.epoch += 1;
        self.stats.current_epoch = self.superblock.epoch;
    }
    
    /// Check if archiving is enabled
    pub fn is_archiving(&self) -> bool {
        self.config.has(FsConfig::ARCHIVE) && self.venti.is_some()
    }
    
    /// Get cache stats
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().unwrap();
        (cache.current_size, cache.max_size)
    }
}

// ============================================================================
// 9P Interface
// ============================================================================

use crate::dev::{Dev, Chan, Qid, DirEntry as DevDirEntry, Error as DevError, qidtype};

/// Fossil device
pub struct FossilDev {
    /// File system
    fs: Arc<alloc::sync::Mutex<FossilFs>>,
}

impl FossilDev {
    pub fn new(fs: FossilFs) -> Self {
        Self {
            fs: Arc::new(alloc::sync::Mutex::new(fs)),
        }
    }
}

impl Dev for FossilDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::FS,
            Qid::new(0, 0, qidtype::DIR),
            0oOREAD,
        ))
    }
    
    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }
    
    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let fs = self.fs.lock().unwrap();
        
        // Return directory listing or file content
        let _ = offset;
        let _ = buf;
        
        Ok(0)
    }
    
    fn write(&mut self, ch: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        let mut fs = self.fs.lock().unwrap();
        
        // Write data
        let _ = offset;
        let _ = buf;
        
        Ok(0)
    }
    
    fn dev_char(&self) -> char {
        'F'  // 'F' for Fossil
    }
    
    fn name(&self) -> &'static str {
        "fossil"
    }
}

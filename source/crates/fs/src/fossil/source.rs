//! Source Management for Fossil File System
//!
//! Source represents the active file tree root and manages access to it.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::sync::Mutex;
use alloc::boxed::Box;

use crate::venti::Score;
use crate::fossil::file::{FileEntry, DirEntry, FileError, InodeTable, NameCache};
use crate::fossil::snap::{SnapshotManager, SharedSnapshotManager};

// ============================================================================
// Source
// ============================================================================

/// A Source represents the current file tree root
#[derive(Debug, Clone)]
pub struct Source {
    /// Source name (e.g., "main", "snapshot1")
    pub name: String,
    /// Root directory score (Venti address)
    pub root_score: Score,
    /// Root directory entry
    pub root: FileEntry,
    /// Epoch number
    pub epoch: u32,
    /// Active flag
    pub active: bool,
    /// Reference count
    refcount: u32,
}

impl Source {
    /// Create a new source
    pub fn new(name: &str, root_score: Score, epoch: u32) -> Self {
        let mut root = FileEntry::new_dir("/", 0, 0);
        root.qid_path = 1;
        root.qid_vers = 0;
        root.score = root_score;

        Self {
            name: name.to_string(),
            root_score,
            root,
            epoch,
            active: false,
            refcount: 0,
        }
    }

    /// Create the default main source
    pub fn main() -> Self {
        Self::new("main", Score([0; 20]), 0)
    }

    /// Check if this is the active source
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activate this source
    pub fn activate(&mut self) {
        self.active = true;
        self.refcount += 1;
    }

    /// Deactivate this source
    pub fn deactivate(&mut self) {
        self.active = false;
        self.refcount = self.refcount.saturating_sub(1);
    }

    /// Acquire a reference
    pub fn acquire(&mut self) {
        self.refcount += 1;
    }

    /// Release a reference
    pub fn release(&mut self) {
        self.refcount = self.refcount.saturating_sub(1);
    }

    /// Get reference count
    pub fn refs(&self) -> u32 {
        self.refcount
    }
}

// ============================================================================
// Source Manager
// ============================================================================

/// Manages sources for a Fossil file system
pub struct SourceManager {
    /// All sources
    sources: Vec<Source>,
    /// Active source ID
    active: Option<usize>,
    /// Next source ID
    next_id: usize,
    /// Inode table
    inodes: InodeTable,
    /// Name cache
    name_cache: NameCache,
    /// Snapshot manager
    snapshots: SharedSnapshotManager,
}

impl SourceManager {
    /// Create a new source manager
    pub fn new(max_inodes: usize) -> Self {
        let mut manager = Self {
            sources: Vec::new(),
            active: None,
            next_id: 0,
            inodes: InodeTable::new(max_inodes),
            name_cache: NameCache::new(max_inodes),
            snapshots: SharedSnapshotManager::new(),
        };

        // Create main source
        let main = Source::main();
        manager.sources.push(main);
        manager.active = Some(0);
        manager.next_id = 1;

        // Allocate root inode
        let root = FileEntry::new_dir("/", 0, 0);
        let _ = manager.inodes.alloc(root);

        manager
    }

    /// Get the active source
    pub fn active_source(&self) -> Option<&Source> {
        self.active.and_then(|i| self.sources.get(i))
    }

    /// Get the active source mutably
    pub fn active_source_mut(&mut self) -> Option<&mut Source> {
        self.active.and_then(|i| self.sources.get_mut(i))
    }

    /// Get source by ID
    pub fn get(&self, id: usize) -> Option<&Source> {
        self.sources.get(id)
    }

    /// Get source by name
    pub fn get_by_name(&self, name: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.name == name)
    }

    /// Create a new source
    pub fn create(&mut self, name: &str, root_score: Score) -> Option<usize> {
        let id = self.next_id;
        self.next_id += 1;

        let source = Source::new(name, root_score, 0);
        self.sources.push(source);

        Some(id)
    }

    /// Set active source
    pub fn set_active(&mut self, id: usize) -> bool {
        if id >= self.sources.len() {
            return false;
        }

        // Deactivate current
        if let Some(current) = self.active {
            self.sources[current].deactivate();
        }

        // Activate new
        self.sources[id].activate();
        self.active = Some(id);

        true
    }

    /// Get the inode table
    pub fn inodes(&self) -> &InodeTable {
        &self.inodes
    }

    /// Get mutable inode table
    pub fn inodes_mut(&mut self) -> &mut InodeTable {
        &mut self.inodes
    }

    /// Get the name cache
    pub fn name_cache(&self) -> &NameCache {
        &self.name_cache
    }

    /// Get mutable name cache
    pub fn name_cache_mut(&mut self) -> &mut NameCache {
        &mut self.name_cache
    }

    /// Get the snapshot manager
    pub fn snapshots(&self) -> &SharedSnapshotManager {
        &self.snapshots
    }

    /// List all sources
    pub fn list(&self) -> &[Source] {
        &self.sources
    }

    /// Get active source ID
    pub fn active_id(&self) -> Option<usize> {
        self.active
    }

    /// Get source count
    pub fn count(&self) -> usize {
        self.sources.len()
    }

    /// Create a snapshot of the current source
    pub fn snapshot(&mut self, name: &str) -> Option<u32> {
        if let Some(source) = self.active_source() {
            let id = self.snapshots.create(name, source.root_score, source.epoch)?;
            Some(id)
        } else {
            None
        }
    }

    /// Restore from a snapshot
    pub fn restore(&mut self, snapshot_id: u32) -> bool {
        if let Some(snap) = self.snapshots.get(snapshot_id) {
            if let Some(active) = self.active {
                self.sources[active].root_score = snap.root_score;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Get root directory score
    pub fn root_score(&self) -> Score {
        self.active_source()
            .map(|s| s.root_score)
            .unwrap_or(Score([0; 20]))
    }

    /// Set root directory score
    pub fn set_root_score(&mut self, score: Score) {
        if let Some(source) = self.active_source_mut() {
            source.root_score = score;
        }
    }
}

// ============================================================================
// Source Lock
// ============================================================================

/// Represents a lock on a source
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLockType {
    Read,
    Write,
}

/// A lock on a source
#[derive(Debug, Clone)]
pub struct SourceLock {
    /// Source ID
    pub source_id: usize,
    /// Lock type
    pub lock_type: SourceLockType,
    /// Lock holder identifier
    pub holder: u32,
    /// Lock start offset
    pub start: u64,
    /// Lock length (0 = entire source)
    pub length: u64,
}

impl SourceLock {
    /// Create a new lock
    pub fn new(source_id: usize, lock_type: SourceLockType, holder: u32) -> Self {
        Self {
            source_id,
            lock_type,
            holder,
            start: 0,
            length: 0,
        }
    }

    /// Create a range lock
    pub fn range(source_id: usize, lock_type: SourceLockType, holder: u32, start: u64, length: u64) -> Self {
        Self {
            source_id,
            lock_type,
            holder,
            start,
            length,
        }
    }

    /// Check if this is a write lock
    pub fn is_write(&self) -> bool {
        self.lock_type == SourceLockType::Write
    }

    /// Check if this is a read lock
    pub fn is_read(&self) -> bool {
        self.lock_type == SourceLockType::Read
    }

    /// Check if lock conflicts with another
    pub fn conflicts(&self, other: &SourceLock) -> bool {
        if self.source_id != other.source_id {
            return false;
        }

        // Write locks conflict with everything
        if self.is_write() || other.is_write() {
            // Check range overlap
            if self.length == 0 || other.length == 0 {
                return true; // Full source lock
            }
            return self.overlaps(other);
        }

        false
    }

    /// Check if ranges overlap
    fn overlaps(&self, other: &SourceLock) -> bool {
        if self.start >= other.start + other.length {
            return false;
        }
        if other.start >= self.start + self.length {
            return false;
        }
        true
    }
}

/// Lock manager for sources
pub struct SourceLockManager {
    /// Active locks
    locks: Vec<SourceLock>,
    /// Lock counter
    next_id: u32,
}

impl SourceLockManager {
    /// Create a new lock manager
    pub fn new() -> Self {
        Self {
            locks: Vec::new(),
            next_id: 1,
        }
    }

    /// Acquire a lock
    pub fn acquire(&mut self, lock: SourceLock) -> Result<u32, ()> {
        // Check for conflicts
        for existing in &self.locks {
            if lock.conflicts(existing) {
                return Err(());
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        self.locks.push(lock);
        Ok(id)
    }

    /// Release a lock
    pub fn release(&mut self, lock_id: u32) -> bool {
        if let Some(pos) = self.locks.iter().position(|l| l.holder == lock_id) {
            self.locks.remove(pos);
            true
        } else {
            false
        }
    }

    /// Release all locks for a holder
    pub fn release_all(&mut self, holder: u32) -> usize {
        let initial = self.locks.len();
        self.locks.retain(|l| l.holder != holder);
        initial - self.locks.len()
    }

    /// Get locks for a source
    pub fn get_locks(&self, source_id: usize) -> Vec<&SourceLock> {
        self.locks.iter().filter(|l| l.source_id == source_id).collect()
    }

    /// Check if a source has any locks
    pub fn has_locks(&self, source_id: usize) -> bool {
        self.locks.iter().any(|l| l.source_id == source_id)
    }

    /// Get lock count
    pub fn count(&self) -> usize {
        self.locks.len()
    }
}

impl Default for SourceLockManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Source Operations
// ============================================================================

/// Source operations errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    NotFound,
    Busy,
    LockFailed,
    Invalid,
}

impl SourceError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "source not found",
            Self::Busy => "source busy",
            Self::LockFailed => "lock failed",
            Self::Invalid => "invalid operation",
        }
    }
}

/// Source operation result
pub type SourceResult<T> = Result<T, SourceError>;

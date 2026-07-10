//! Fossil 9P Server Interface
//!
//! Implements the 9P protocol interface for the Fossil file system.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::sync::Mutex;
use alloc::boxed::Box;

use crate::venti::Score;
use crate::fossil::lib::{FossilFs, SuperBlock, DirEntry, DirType};
use crate::fossil::file::{FileEntry, DirEntry as FileDirEntry, InodeTable, NameCache, FileError};
use crate::fossil::source::{SourceManager, SourceError};
use crate::fossil::snap::{SnapshotManager, SharedSnapshotManager};

// ============================================================================
// 9P Message Types
// ============================================================================

/// 9P Fid representation
#[derive(Debug, Clone)]
pub struct Fid {
    /// Fid number
    pub fid: u32,
    /// QID path
    pub qid_path: u64,
    /// Open mode (for open files)
    pub mode: u8,
    /// Open flag
    pub open: bool,
    /// User ID
    pub uid: u32,
    /// Offset (for sequential access)
    pub offset: u64,
}

impl Fid {
    /// Create a new fid
    pub fn new(fid: u32, qid_path: u64, uid: u32) -> Self {
        Self {
            fid,
            qid_path,
            mode: 0,
            open: false,
            uid,
            offset: 0,
        }
    }

    /// Check if file is open
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Check if opened for reading
    pub fn can_read(&self) -> bool {
        self.open && (self.mode & 0x3) == 0
    }

    /// Check if opened for writing
    pub fn can_write(&self) -> bool {
        self.open && (self.mode & 0x3) == 1
    }

    /// Check if opened for appending
    pub fn can_append(&self) -> bool {
        self.open && (self.mode & 0x3) == 2
    }
}

/// Fid pool for managing fids
pub struct FidPool {
    /// Fid entries
    fids: Vec<Option<Fid>>,
    /// Free list
    free: Vec<u32>,
}

impl FidPool {
    /// Create a new fid pool
    pub fn new() -> Self {
        Self {
            fids: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Allocate a new fid
    pub fn alloc(&mut self, qid_path: u64, uid: u32) -> Result<u32, ()> {
        let fid = if let Some(f) = self.free.pop() {
            f
        } else {
            let f = self.fids.len() as u32;
            self.fids.push(None);
            f
        };

        self.fids[fid as usize] = Some(Fid::new(fid, qid_path, uid));
        Ok(fid)
    }

    /// Free a fid
    pub fn free(&mut self, fid: u32) -> Option<Fid> {
        if (fid as usize) < self.fids.len() {
            let entry = self.fids[fid as usize].take();
            if entry.is_some() {
                self.free.push(fid);
            }
            entry
        } else {
            None
        }
    }

    /// Get a fid
    pub fn get(&self, fid: u32) -> Option<&Fid> {
        self.fids.get(fid as usize).and_then(|f| f.as_ref())
    }

    /// Get a mutable fid
    pub fn get_mut(&mut self, fid: u32) -> Option<&mut Fid> {
        self.fids.get_mut(fid as usize).and_then(|f| f.as_mut())
    }

    /// Check if fid exists
    pub fn exists(&self, fid: u32) -> bool {
        self.get(fid).is_some()
    }

    /// Clone a fid (for Twalk)
    pub fn clone_fid(&mut self, old: u32, new: u32) -> Result<(), ()> {
        let entry = self.get(old).cloned();
        if let Some(mut fid) = entry {
            if (new as usize) >= self.fids.len() {
                self.fids.resize(new as usize + 1, None);
            }
            fid.fid = new;
            self.fids[new as usize] = Some(fid);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Clear all fids for a user
    pub fn clear_user(&mut self, uid: u32) {
        for (fid, entry) in self.fids.iter_mut().enumerate() {
            if let Some(ref e) = entry {
                if e.uid == uid {
                    *entry = None;
                    self.free.push(fid as u32);
                }
            }
        }
    }

    /// Get fid count
    pub fn count(&self) -> usize {
        self.fids.iter().filter(|f| f.is_some()).count()
    }
}

impl Default for FidPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Fossil 9P Server
// ============================================================================

/// Fossil 9P server implementation
pub struct Fossil9PServer {
    /// File system
    fs: Arc<Mutex<FossilFs>>,
    /// Source manager
    sources: Arc<Mutex<SourceManager>>,
    /// Fid pool
    fids: FidPool,
    /// Maximum message size
    msize: u32,
    /// User name
    user: String,
    /// Attached flag
    attached: bool,
    /// Root fid
    root_fid: Option<u32>,
}

impl Fossil9PServer {
    /// Create a new Fossil 9P server
    pub fn new(fs: FossilFs, msize: u32) -> Self {
        Self {
            fs: Arc::new(Mutex::new(fs)),
            sources: Arc::new(Mutex::new(SourceManager::new(65536))),
            fids: FidPool::new(),
            msize,
            user: String::from("none"),
            attached: false,
            root_fid: None,
        }
    }

    /// Get the maximum message size
    pub fn msize(&self) -> u32 {
        self.msize
    }

    /// Set the maximum message size
    pub fn set_msize(&mut self, msize: u32) {
        self.msize = msize;
    }

    /// Check if attached
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    // ========================================================================
    // 9P Operations
    // ========================================================================

    /// Handle Tversion
    pub fn handle_version(&mut self, msize: u32, version: &str) -> (u32, String) {
        // Negotiate version
        let version = if version.starts_with("9P2000") {
            "9P2000".to_string()
        } else {
            version.to_string()
        };

        // Negotiate msize
        let msize = msize.min(self.msize);
        self.msize = msize;

        (msize, version)
    }

    /// Handle Tattach
    pub fn handle_attach(&mut self, fid: u32, afid: u32, uname: &str, aname: &str) -> Result<u64, &'static str> {
        // Allocate fid
        self.fids.alloc(1, 0).map_err(|_| "fid allocation failed")?;

        self.user = uname.to_string();
        self.attached = true;
        self.root_fid = Some(fid);

        Ok(1) // Root directory QID path
    }

    /// Handle Twalk
    pub fn handle_walk(&mut self, fid: u32, new_fid: u32, names: &[String]) -> Result<Vec<u64>, &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let mut qids = Vec::new();
        let mut current_path = self.fids.get(fid)
            .ok_or("invalid fid")?
            .qid_path;

        for name in names {
            let sources = self.sources.lock().unwrap();
            let inodes = sources.inodes();

            // Look up in name cache first
            if let Some(child_qid) = sources.name_cache().lookup(current_path, name) {
                current_path = child_qid;
                qids.push(child_qid);
            } else if let Some(entry) = inodes.get(current_path) {
                if entry.is_dir() {
                    // Would need to search directory
                    // For now, return empty on walk failure
                    if qids.is_empty() {
                        return Err("path not found");
                    }
                    break;
                } else {
                    return Err("not a directory");
                }
            } else {
                return Err("invalid path");
            }
        }

        // Clone fid if successful
        if !qids.is_empty() || names.is_empty() {
            self.fids.clone_fid(fid, new_fid).map_err(|_| "clone failed")?;
        }

        Ok(qids)
    }

    /// Handle Topen
    pub fn handle_open(&mut self, fid: u32, mode: u8) -> Result<(u64, u32), &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get_mut(fid).ok_or("invalid fid")?;
        f.open = true;
        f.mode = mode;

        Ok((f.qid_path, 0)) // Return QID path and iounit
    }

    /// Handle Tcreate
    pub fn handle_create(&mut self, fid: u32, name: &str, mode: u32, perm: u32) -> Result<(u64, u32), &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let mut sources = self.sources.lock().unwrap();
        let inodes = sources.inodes_mut();

        // Create new file entry
        let mut entry = if perm & 0o170000 == 0o40000 {
            FileEntry::new_dir(name, 0, 0)
        } else {
            FileEntry::new_file(name, 0, 0)
        };
        entry.mode = mode;

        // Allocate inode
        let qid_path = inodes.alloc(entry).map_err(|_| "inode allocation failed")?;

        // Add to name cache
        let parent = self.fids.get(fid)
            .ok_or("invalid fid")?
            .qid_path;
        sources.name_cache_mut().add(parent, name, qid_path);

        // Clone fid for the new file
        self.fids.clone_fid(fid, fid).map_err(|_| "clone failed")?;

        if let Some(f) = self.fids.get_mut(fid) {
            f.qid_path = qid_path;
            f.open = true;
            f.mode = mode as u8;
        }

        Ok((qid_path, 0))
    }

    /// Handle Tread
    pub fn handle_read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get(fid).ok_or("invalid fid")?;

        let sources = self.sources.lock().unwrap();
        let inodes = sources.inodes();

        if let Some(entry) = inodes.get(f.qid_path) {
            // Return stat data if directory
            if entry.is_dir() {
                let mut buf = Vec::new();
                let children = sources.name_cache().list_dir(f.qid_path);

                for (name, child_qid) in children {
                    if let Some(child) = inodes.get(child_qid) {
                        let dir_entry = FileDirEntry::from_file(child);
                        buf.extend_from_slice(&dir_entry.to_stat());
                    }
                }

                // Trim to requested count
                let start = offset as usize;
                let end = (offset + count as u64).min(buf.len() as u64) as usize;
                let data = if start < buf.len() { buf[start..end].to_vec() } else { Vec::new() };

                Ok(data)
            } else {
                // Read file content (placeholder)
                Ok(Vec::new())
            }
        } else {
            Err("file not found")
        }
    }

    /// Handle Twrite
    pub fn handle_write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get(fid).ok_or("invalid fid")?;

        if !f.can_write() {
            return Err("not opened for writing");
        }

        // Write data (placeholder - would actually write to blocks)
        Ok(data.len() as u32)
    }

    /// Handle Tclunk
    pub fn handle_clunk(&mut self, fid: u32) -> Result<(), &'static str> {
        self.fids.free(fid);
        Ok(())
    }

    /// Handle Tremove
    pub fn handle_remove(&mut self, fid: u32) -> Result<(), &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get(fid).ok_or("invalid fid")?;
        let qid_path = f.qid_path;

        let mut sources = self.sources.lock().unwrap();

        // Remove from name cache
        if let Some(parent) = self.root_fid.and_then(|r| self.fids.get(r)) {
            for (name, child) in sources.name_cache().list_dir(parent.qid_path) {
                if child == qid_path {
                    sources.name_cache_mut().remove(parent.qid_path, &name);
                    break;
                }
            }
        }

        // Free inode
        sources.inodes_mut().free(qid_path).map_err(|_| "free failed")?;

        // Free fid
        self.fids.free(fid);

        Ok(())
    }

    /// Handle Tstat
    pub fn handle_stat(&mut self, fid: u32) -> Result<FileDirEntry, &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get(fid).ok_or("invalid fid")?;

        let sources = self.sources.lock().unwrap();
        let inodes = sources.inodes();

        let entry = inodes.get(f.qid_path).ok_or("not found")?;

        Ok(FileDirEntry::from_file(entry))
    }

    /// Handle Twstat
    pub fn handle_wstat(&mut self, fid: u32, _entry: &FileEntry) -> Result<(), &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get_mut(fid).ok_or("invalid fid")?;

        let mut sources = self.sources.lock().unwrap();

        if let Some(entry) = sources.inodes_mut().get_mut(f.qid_path) {
            // Update fields
            // entry.mode = _entry.mode;
            // entry.mtime = _entry.mtime;
            Ok(())
        } else {
            Err("not found")
        }
    }

    /// Handle Tflush
    pub fn handle_flush(&mut self, _oldtag: u16) -> Result<(), &'static str> {
        // Flush pending operations (placeholder)
        Ok(())
    }

    // ========================================================================
    // Snapshot Operations
    // ========================================================================

    /// Create a snapshot
    pub fn snapshot(&mut self, name: &str) -> Result<u32, &'static str> {
        let mut sources = self.sources.lock().unwrap();
        sources.snapshot(name).ok_or("snapshot failed")
    }

    /// List snapshots
    pub fn list_snapshots(&self) -> Vec<(u32, String)> {
        let sources = self.sources.lock().unwrap();
        sources.snapshots().list()
            .iter()
            .map(|s| (s.id, s.name.clone()))
            .collect()
    }

    /// Restore from snapshot
    pub fn restore_snapshot(&mut self, id: u32) -> Result<(), &'static str> {
        let mut sources = self.sources.lock().unwrap();
        sources.restore(id).then_some(()).ok_or("restore failed")
    }

    /// Get file system statistics
    pub fn stats(&self) -> FsStats {
        let fs = self.fs.lock().unwrap();
        let sources = self.sources.lock().unwrap();

        FsStats {
            msize: self.msize,
            attached: self.attached,
            fid_count: self.fids.count(),
            inode_count: sources.inodes().used(),
            snapshot_count: sources.snapshots().count(),
            epoch: fs.superblock().epoch,
        }
    }
}

/// File system statistics
#[derive(Debug, Clone)]
pub struct FsStats {
    pub msize: u32,
    pub attached: bool,
    pub fid_count: usize,
    pub inode_count: usize,
    pub snapshot_count: usize,
    pub epoch: u32,
}

// ============================================================================
// Lock Operations (9P2000.L)
// ============================================================================

/// Lock type constants
pub mod lock_type {
    pub const UNLOCK: u8 = 0;
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 2;
}

/// Lock status constants
pub mod lock_status {
    pub const ERROR: u8 = 0;
    pub const SUCCESS: u8 = 1;
    pub const BLOCKED: u8 = 2;
}

impl Fossil9PServer {
    /// Handle Tlock
    pub fn handle_lock(&mut self, fid: u32, lock_type: u8, flags: u32, start: u64, length: u64, proc_id: &[u8]) -> Result<u8, &'static str> {
        use crate::fossil::source::SourceLockManager;
        use crate::fossil::source::{SourceLock, SourceLockType};

        if !self.attached {
            return Err("not attached");
        }

        let f = self.fids.get(fid).ok_or("invalid fid")?;

        // Create lock request
        let lt = match lock_type {
            lock_type::READ => SourceLockType::Read,
            lock_type::WRITE => SourceLockType::Write,
            _ => return Err("invalid lock type"),
        };

        let holder = proc_id.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
        let lock = SourceLock::range(f.qid_path, lt, holder, start, length);

        // Would use a lock manager to acquire the lock
        // For now, always succeed
        Ok(lock_status::SUCCESS)
    }

    /// Handle Tgetlock
    pub fn handle_getlock(&mut self, fid: u32, lock_type: u8, start: u64, length: u64, proc_id: &[u8]) -> Result<(u8, u8, u64, u64, Vec<u8>), &'static str> {
        if !self.attached {
            return Err("not attached");
        }

        // Return no lock held
        Ok((lock_status::SUCCESS, lock_type, start, length, proc_id.to_vec()))
    }
}

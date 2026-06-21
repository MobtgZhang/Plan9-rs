//! File System Server
//!
//! Implements the Plan 9 file system server.

#![no_std]

extern crate alloc;

use crate::common::error::{Error, Result};
use crate::common::types::Qid;
use crate::fs::{RamFileSystem, FatFileSystem, Vfs};

// ============================================================================
// 9P Server
// ============================================================================

/// File server state
pub struct FileServer {
    /// Root file system
    pub root: RamFileSystem,
    /// VFS instance
    pub vfs: Vfs,
    /// Current user
    pub uid: u32,
    /// Current group
    pub gid: u32,
    /// User name
    pub uname: String,
    /// Authentication FID
    pub auth_fid: Option<u32>,
}

impl FileServer {
    /// Create new file server
    pub fn new() -> Self {
        Self {
            root: RamFileSystem::new(),
            vfs: Vfs::new(),
            uid: 0,
            gid: 0,
            uname: "glenda".to_string(),
            auth_fid: None,
        }
    }

    /// Handle attach
    pub fn attach(&mut self, fid: u32, _afid: u32, uname: &str, _aname: &str) -> Result<Qid> {
        self.uname = uname.to_string();
        self.uid = 0; // Would look up UID
        self.gid = 0;

        // Return root QID
        Ok(Qid::new(1, 0, 1)) // path=1, vers=0, type=directory
    }

    /// Handle walk
    pub fn walk(&mut self, _fid: u32, new_fid: u32, names: &[&str]) -> Result<Vec<Qid>> {
        let mut qids = Vec::new();

        // Walk the path
        // In a real implementation, would create new fid and walk

        Ok(qids)
    }

    /// Handle open
    pub fn open(&mut self, fid: u32, mode: u8) -> Result<(Qid, u32)> {
        // Open the file
        Ok((Qid::nil(), 8192)) // Return QID and IO unit
    }

    /// Handle read
    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>> {
        // Read from the file
        Ok(Vec::new())
    }

    /// Handle write
    pub fn write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32> {
        // Write to the file
        Ok(data.len() as u32)
    }

    /// Handle clunk
    pub fn clunk(&mut self, fid: u32) -> Result<()> {
        // Close the file descriptor
        Ok(())
    }

    /// Handle stat
    pub fn stat(&mut self, fid: u32) -> Result<Vec<u8>> {
        // Return stat data
        Ok(Vec::new())
    }
}

// ============================================================================
// Mount Table
// ============================================================================

/// Mount table entry
#[derive(Debug, Clone)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub spec: String,
    pub flags: u32,
    pub server: Option<u32>,
}

impl MountEntry {
    pub fn new(source: &str, target: &str, spec: &str) -> Self {
        Self {
            source: source.to_string(),
            target: target.to_string(),
            spec: spec.to_string(),
            flags: 0,
            server: None,
        }
    }
}

/// Mount table
pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add mount entry
    pub fn mount(&mut self, source: &str, target: &str, spec: &str) {
        self.entries.push(MountEntry::new(source, target, spec));
    }

    /// Remove mount entry
    pub fn unmount(&mut self, target: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.target == target) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Find mount for path
    pub fn find(&self, path: &str) -> Option<&MountEntry> {
        let mut best: Option<&MountEntry> = None;
        let mut best_len = 0;

        for entry in &self.entries {
            if path.starts_with(&entry.target) && entry.target.len() > best_len {
                best = Some(entry);
                best_len = entry.target.len();
            }
        }

        best
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

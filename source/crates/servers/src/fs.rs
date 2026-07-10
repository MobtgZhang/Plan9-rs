//! File System Server
//!
//! Implements the Plan 9 file system server with Tree-based backend.


extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;

use crate::tree::{Qid, qidtype, Tree, File};

// ============================================================================
// 9P Server
// ============================================================================

/// File server state
pub struct FileServer {
    /// Root file system tree
    pub root: Arc<Tree>,
    /// Current user ID
    pub uid: u32,
    /// Current group ID
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
            root: Tree::new("none", "none", 0o755, None),
            uid: 0,
            gid: 0,
            uname: "glenda".to_string(),
            auth_fid: None,
        }
    }

    /// Handle attach
    pub fn attach(&mut self, _fid: u32, _afid: u32, uname: &str, _aname: &str) -> Qid {
        self.uname = uname.to_string();
        self.uid = 0; // Would look up UID
        self.gid = 0;

        // Return root QID
        Qid::new(1, 0, qidtype::DIR) // path=1, vers=0, type=directory
    }

    /// Handle walk
    pub fn walk(&self, _fid: u32, _new_fid: u32, names: &[&str]) -> Option<Arc<File>> {
        // Walk the path from root
        let path = format!("/{}", names.join("/"));
        self.root.walk(&path)
    }

    /// Handle open
    pub fn open(&self, fid: u32, mode: u8) -> Option<(Qid, u32)> {
        // Open the file and return QID and IO unit
        // For now, return a placeholder
        let _ = fid;
        let _ = mode;
        Some((Qid::new(0, 0, 0), 8192))
    }

    /// Handle read
    pub fn read(&self, fid: u32, offset: u64, count: u32) -> Vec<u8> {
        // Read from the file
        // For now, return empty
        let _ = fid;
        let _ = offset;
        let _ = count;
        Vec::new()
    }

    /// Handle write
    pub fn write(&self, fid: u32, offset: u64, data: &[u8]) -> u32 {
        // Write to the file
        let _ = fid;
        let _ = offset;
        data.len() as u32
    }

    /// Handle clunk
    pub fn clunk(&self, fid: u32) {
        // Close the file descriptor
        let _ = fid;
    }

    /// Handle stat
    pub fn stat(&self, fid: u32) -> Option<StatData> {
        // Return stat data
        let _ = fid;
        Some(StatData::default())
    }
}

impl Default for FileServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Stat data for file
#[derive(Debug, Clone, Default)]
pub struct StatData {
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub mode: u32,
    pub length: u64,
    pub atime: u32,
    pub mtime: u32,
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

//! File Operations for Fossil File System
//!
//! Implements file and directory operations for the Fossil file system.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::sync::Mutex;
use alloc::boxed::Box;

use crate::venti::Score;
use crate::fossil::snap::SnapshotManager;

// ============================================================================
// File Types
// ============================================================================

/// File type constants
pub mod file_type {
    pub const REGULAR: u8 = 0;
    pub const DIRECTORY: u8 = 1;
    pub const SYMLINK: u8 = 2;
    pub const DEVICE: u8 = 3;
    pub const PIPE: u8 = 4;
    pub const SOCKET: u8 = 5;
}

/// File mode constants
pub mod file_mode {
    pub const READ: u32 = 0o4;
    pub const WRITE: u32 = 0o2;
    pub const EXEC: u32 = 0o1;

    pub const READ_WRITE: u32 = READ | WRITE;
    pub const ALL: u32 = READ | WRITE | EXEC;

    pub const DIR: u32 = 0o40000;
    pub const FILE: u32 = 0o100000;
    pub const SYMLINK: u32 = 0o120000;
    pub const DEVICE: u32 = 0o60000;
    pub const PIPE: u32 = 0o140000;
    pub const SOCKET: u32 = 0o160000;

    pub const APPEND: u32 = 0o20000;
    pub const EXCL: u32 = 0o40000;
    pub const MOUNT: u32 = 0o100000;
    pub const TMPFILE: u32 = 0o1000000;
}

// ============================================================================
// File Entry
// ============================================================================

/// File entry in the file system
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// File name
    pub name: String,
    /// File type
    pub file_type: u8,
    /// File mode (permissions)
    pub mode: u32,
    /// File size in bytes
    pub size: u64,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// Change time
    pub ctime: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Venti score for file content
    pub score: Score,
    /// Direct block scores
    pub direct: [Score; 13],
    /// Indirect block score
    pub indirect: Score,
    /// Double indirect block score
    pub double_indirect: Score,
    /// Number of blocks
    pub blocks: u32,
    /// QID path
    pub qid_path: u64,
    /// QID version
    pub qid_vers: u32,
}

impl FileEntry {
    /// Create a new file entry
    pub fn new_file(name: &str, uid: u32, gid: u32) -> Self {
        Self {
            name: name.to_string(),
            file_type: file_type::REGULAR,
            mode: 0o644,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            uid,
            gid,
            score: Score([0; 20]),
            direct: [Score([0; 20]); 13],
            indirect: Score([0; 20]),
            double_indirect: Score([0; 20]),
            blocks: 0,
            qid_path: 0,
            qid_vers: 0,
        }
    }

    /// Create a new directory entry
    pub fn new_dir(name: &str, uid: u32, gid: u32) -> Self {
        Self {
            name: name.to_string(),
            file_type: file_type::DIRECTORY,
            mode: 0o755 | file_mode::DIR,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            uid,
            gid,
            score: Score([0; 20]),
            direct: [Score([0; 20]); 13],
            indirect: Score([0; 20]),
            double_indirect: Score([0; 20]),
            blocks: 0,
            qid_path: 0,
            qid_vers: 0,
        }
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type == file_type::DIRECTORY
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type == file_type::REGULAR
    }

    /// Check if this is a symlink
    pub fn is_symlink(&self) -> bool {
        self.file_type == file_type::SYMLINK
    }

    /// Get the QID type
    pub fn qid_type(&self) -> u8 {
        match self.file_type {
            file_type::DIRECTORY => 0x80, // QTDIR
            file_type::SYMLINK => 0x40,  // QTAPPEND
            _ => 0,
        }
    }

    /// Set modification time
    pub fn set_mtime(&mut self, mtime: u32) {
        self.mtime = mtime;
    }

    /// Set access time
    pub fn set_atime(&mut self, atime: u32) {
        self.atime = atime;
    }

    /// Increment QID version
    pub fn bump_version(&mut self) {
        self.qid_vers += 1;
    }

    /// Allocate a new QID path
    pub fn allocate_qid(&mut self, path: u64) {
        self.qid_path = path;
    }

    /// Update file size
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
        self.blocks = ((size + 4095) / 4096) as u32;
    }

    /// Check read permission
    pub fn can_read(&self, _uid: u32) -> bool {
        (self.mode & file_mode::READ) != 0
    }

    /// Check write permission
    pub fn can_write(&self, _uid: u32) -> bool {
        (self.mode & file_mode::WRITE) != 0
    }

    /// Check execute permission
    pub fn can_exec(&self, _uid: u32) -> bool {
        (self.mode & file_mode::EXEC) != 0
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// Directory entry with file information
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// QID path
    pub qid_path: u64,
    /// QID version
    pub qid_vers: u32,
    /// QID type
    pub qid_type: u8,
    /// Mode
    pub mode: u32,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// Size
    pub size: u64,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

impl DirEntry {
    /// Create from a file entry
    pub fn from_file(file: &FileEntry) -> Self {
        Self {
            name: file.name.clone(),
            qid_path: file.qid_path,
            qid_vers: file.qid_vers,
            qid_type: file.qid_type(),
            mode: file.mode,
            atime: file.atime,
            mtime: file.mtime,
            size: file.size,
            uid: file.uid,
            gid: file.gid,
        }
    }

    /// Convert to directory entry data for 9P protocol
    pub fn to_stat(&self) -> Vec<u8> {
        use alloc::string::String;

        let name = &self.name;
        let name_len = name.len();
        let stat_size = 2 + name_len + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 8 + 4 + 4 + 4;

        let mut buf = Vec::with_capacity(2 + stat_size as usize);

        // Stat size
        buf.extend_from_slice(&(stat_size as u16).to_le_bytes());

        // Name
        buf.extend_from_slice(&(name_len as u16).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());

        // Uid (empty)
        buf.extend_from_slice(&(0u16).to_le_bytes());

        // Gid (empty)
        buf.extend_from_slice(&(0u16).to_le_bytes());

        // Muid (empty)
        buf.extend_from_slice(&(0u16).to_le_bytes());

        // Mode
        buf.extend_from_slice(&self.mode.to_le_bytes());

        // Atime
        buf.extend_from_slice(&self.atime.to_le_bytes());

        // Mtime
        buf.extend_from_slice(&self.mtime.to_le_bytes());

        // Size
        buf.extend_from_slice(&self.size.to_le_bytes());

        // n_uid
        buf.extend_from_slice(&self.uid.to_le_bytes());

        // n_gid
        buf.extend_from_slice(&self.gid.to_le_bytes());

        // n_muid
        buf.extend_from_slice(&(0u32).to_le_bytes());

        buf
    }
}

// ============================================================================
// Directory Enumerator
// ============================================================================

/// Directory enumerator for iterating through directory entries
pub struct DirEnum {
    /// Current position
    offset: u64,
    /// Entries to enumerate
    entries: Vec<DirEntry>,
    /// Current index
    index: usize,
}

impl DirEnum {
    /// Create a new directory enumerator
    pub fn new(entries: Vec<DirEntry>) -> Self {
        Self {
            offset: 0,
            entries,
            index: 0,
        }
    }

    /// Read next entries from the directory
    pub fn read(&mut self, buf: &mut [u8], max_count: usize) -> usize {
        let mut total = 0;

        while self.index < self.entries.len() && total + 64 < max_count {
            let entry = &self.entries[self.index];
            let data = entry.to_stat();

            if total + data.len() > max_count {
                break;
            }

            buf[total..total + data.len()].copy_from_slice(&data);
            total += data.len();
            self.offset += 1;
            self.index += 1;
        }

        total
    }

    /// Get current offset
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Set offset
    pub fn seek(&mut self, offset: u64) {
        self.offset = offset;
        self.index = offset as usize;
    }

    /// Check if there are more entries
    pub fn has_more(&self) -> bool {
        self.index < self.entries.len()
    }

    /// Get remaining count
    pub fn remaining(&self) -> usize {
        self.entries.len().saturating_sub(self.index)
    }
}

// ============================================================================
// File Operations Trait
// ============================================================================

/// File operations trait
pub trait FileOps {
    /// Create a file
    fn create(&mut self, name: &str, mode: u32, uid: u32, gid: u32) -> Result<u64, FileError>;

    /// Remove a file
    fn remove(&mut self, path: u64) -> Result<(), FileError>;

    /// Read from file
    fn read(&mut self, path: u64, offset: u64, buf: &mut [u8]) -> Result<usize, FileError>;

    /// Write to file
    fn write(&mut self, path: u64, offset: u64, data: &[u8]) -> Result<usize, FileError>;

    /// Truncate file
    fn truncate(&mut self, path: u64, size: u64) -> Result<(), FileError>;

    /// Get file info
    fn stat(&self, path: u64) -> Result<FileEntry, FileError>;

    /// Set file info
    fn wstat(&mut self, path: u64, entry: &FileEntry) -> Result<(), FileError>;

    /// Walk directory
    fn walk(&self, path: u64, name: &str) -> Result<Option<u64>, FileError>;

    /// List directory
    fn listdir(&self, path: u64) -> Result<Vec<DirEntry>, FileError>;

    /// Create directory
    fn mkdir(&mut self, name: &str, mode: u32, uid: u32, gid: u32) -> Result<u64, FileError>;

    /// Remove directory
    fn rmdir(&mut self, path: u64) -> Result<(), FileError>;

    /// Rename
    fn rename(&mut self, old_path: u64, new_name: &str, new_parent: u64) -> Result<(), FileError>;
}

/// File operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    NotFound,
    Exists,
    NotEmpty,
    IsDir,
    NotDir,
    PermissionDenied,
    IoError,
    Invalid,
    TooMany,
    StorageError,
}

impl FileError {
    /// Get error code
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "file not found",
            Self::Exists => "file exists",
            Self::NotEmpty => "directory not empty",
            Self::IsDir => "is a directory",
            Self::NotDir => "not a directory",
            Self::PermissionDenied => "permission denied",
            Self::IoError => "I/O error",
            Self::Invalid => "invalid argument",
            Self::TooMany => "too many files",
            Self::StorageError => "storage error",
        }
    }
}

// ============================================================================
// Inode Table
// ============================================================================

/// Inode table for managing file entries
pub struct InodeTable {
    /// Inodes indexed by QID path
    inodes: Vec<Option<FileEntry>>,
    /// Free list
    free_list: Vec<u64>,
    /// Next available QID
    next_qid: u64,
    /// Maximum inodes
    max_inodes: usize,
}

impl InodeTable {
    /// Create a new inode table
    pub fn new(max_inodes: usize) -> Self {
        Self {
            inodes: Vec::with_capacity(max_inodes),
            free_list: Vec::new(),
            next_qid: 1,
            max_inodes,
        }
    }

    /// Allocate a new inode
    pub fn alloc(&mut self, entry: FileEntry) -> Result<u64, FileError> {
        let qid = if let Some(free) = self.free_list.pop() {
            free
        } else {
            if self.inodes.len() >= self.max_inodes {
                return Err(FileError::TooMany);
            }
            let qid = self.next_qid;
            self.next_qid += 1;
            self.inodes.push(None);
            qid
        };

        let index = (qid - 1) as usize;
        if index < self.inodes.len() {
            let mut entry = entry;
            entry.allocate_qid(qid);
            self.inodes[index] = Some(entry);
            Ok(qid)
        } else {
            Err(FileError::IoError)
        }
    }

    /// Free an inode
    pub fn free(&mut self, qid: u64) -> Result<(), FileError> {
        let index = (qid - 1) as usize;
        if index >= self.inodes.len() {
            return Err(FileError::Invalid);
        }

        if self.inodes[index].is_none() {
            return Err(FileError::NotFound);
        }

        self.inodes[index] = None;
        self.free_list.push(qid);
        Ok(())
    }

    /// Get an inode
    pub fn get(&self, qid: u64) -> Option<&FileEntry> {
        let index = (qid - 1) as usize;
        self.inodes.get(index).and_then(|e| e.as_ref())
    }

    /// Get a mutable inode
    pub fn get_mut(&mut self, qid: u64) -> Option<&mut FileEntry> {
        let index = (qid - 1) as usize;
        self.inodes.get_mut(index).and_then(|e| e.as_mut())
    }

    /// Check if inode exists
    pub fn exists(&self, qid: u64) -> bool {
        self.get(qid).is_some()
    }

    /// Get the number of used inodes
    pub fn used(&self) -> usize {
        self.inodes.iter().filter(|e| e.is_some()).count()
    }

    /// Get the total number of inodes
    pub fn total(&self) -> usize {
        self.inodes.len()
    }

    /// Get the number of free inodes
    pub fn free_count(&self) -> usize {
        self.free_list.len() + (self.max_inodes - self.used())
    }

    /// Clear all inodes
    pub fn clear(&mut self) {
        for entry in &mut self.inodes {
            *entry = None;
        }
        self.free_list.clear();
        self.next_qid = 1;
    }
}

// ============================================================================
// File Name Cache
// ============================================================================

/// Cache for directory entries (name -> qid mapping)
pub struct NameCache {
    /// Parent qid -> (name -> child qid) mapping
    entries: Vec<Vec<(String, u64)>>,
    /// Maximum entries per directory
    max_per_dir: usize,
}

impl NameCache {
    /// Create a new name cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_per_dir: 1024,
        }
    }

    /// Ensure directory has a cache entry
    fn ensure_dir(&mut self, parent: u64) {
        let index = parent as usize;
        while self.entries.len() <= index {
            self.entries.push(Vec::new());
        }
    }

    /// Add an entry
    pub fn add(&mut self, parent: u64, name: &str, qid: u64) {
        self.ensure_dir(parent);
        let index = parent as usize;
        // Check if entry exists
        for (n, _) in &mut self.entries[index] {
            if n == name {
                *n = name.to_string();
                return;
            }
        }
        // Add new entry
        self.entries[index].push((name.to_string(), qid));
    }

    /// Remove an entry
    pub fn remove(&mut self, parent: u64, name: &str) {
        let index = parent as usize;
        if index >= self.entries.len() {
            return;
        }
        self.entries[index].retain(|(n, _)| n != name);
    }

    /// Look up an entry
    pub fn lookup(&self, parent: u64, name: &str) -> Option<u64> {
        let index = parent as usize;
        if index >= self.entries.len() {
            return None;
        }
        self.entries[index]
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, qid)| *qid)
    }

    /// Clear a directory's entries
    pub fn clear_dir(&mut self, parent: u64) {
        let index = parent as usize;
        if index < self.entries.len() {
            self.entries[index].clear();
        }
    }

    /// Get all entries in a directory
    pub fn list_dir(&self, parent: u64) -> Vec<(String, u64)> {
        let index = parent as usize;
        if index >= self.entries.len() {
            return Vec::new();
        }
        self.entries[index].clone()
    }
}

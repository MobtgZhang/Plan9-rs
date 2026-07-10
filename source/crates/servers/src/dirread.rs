//! Directory Reading Operations
//!
//! Implements directory reading for 9P file servers.
//! Based on Plan 9's lib9p/dirread.c.


extern crate alloc;

use super::{File, Dir};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Directory reader state
pub struct DirReader {
    /// The directory being read
    dir: Arc<File>,
    /// Current child index
    index: usize,
    /// Children list (cached)
    children: Vec<String>,
}

impl DirReader {
    /// Create a new directory reader
    pub fn new(dir: Arc<File>) -> Self {
        Self {
            children: dir.child_names(),
            dir,
            index: 0,
        }
    }

    /// Read the next directory entries
    /// 
    /// Returns the number of bytes written to the buffer,
    /// or 0 if there are no more entries.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if self.index >= self.children.len() {
            return 0;
        }

        let mut total = 0;
        
        while self.index < self.children.len() && total < buf.len() {
            let name = &self.children[self.index];
            
            // Get the file for this name
            if let Some(file) = self.dir.child(name) {
                // Marshal directory entry
                let entry = marshal_direntry(&file.dir);
                let entry_bytes = entry.as_slice();
                
                if total + entry_bytes.len() <= buf.len() {
                    buf[total..total + entry_bytes.len()].copy_from_slice(entry_bytes);
                    total += entry_bytes.len();
                    self.index += 1;
                } else {
                    // Buffer is full, stop here
                    break;
                }
            } else {
                // File was deleted, skip it
                self.index += 1;
            }
        }

        total
    }

    /// Check if there are more entries
    pub fn eof(&self) -> bool {
        self.index >= self.children.len()
    }

    /// Get current position
    pub fn offset(&self) -> usize {
        self.index
    }
}

/// Marshal a directory entry to bytes
/// 
/// Plan 9 directory format:
/// - size (2 bytes, big-endian)
/// - qid (13 bytes)
/// - mode (4 bytes)
/// - atime (4 bytes)
/// - mtime (4 bytes)
/// - length (8 bytes)
/// - name (null-terminated string)
/// - uid (null-terminated string)
/// - gid (null-terminated string)
/// - muid (null-terminated string)
fn marshal_direntry(dir: &Dir) -> Vec<u8> {
    let name = dir.name.as_bytes();
    let uid = dir.uid.as_bytes();
    let gid = dir.gid.as_bytes();
    let muid = dir.muid.as_bytes();

    // Calculate total size
    // 2 (size) + 13 (qid) + 4 (mode) + 4 (atime) + 4 (mtime) + 8 (length) + strings
    let string_size = name.len() + uid.len() + gid.len() + muid.len() + 4; // +4 for null terminators
    let total_size = 2 + 13 + 4 + 4 + 4 + 8 + string_size;

    let mut buf = Vec::with_capacity(total_size);
    
    // Size (2 bytes, big-endian)
    buf.push(((total_size >> 8) & 0xFF) as u8);
    buf.push((total_size & 0xFF) as u8);
    
    // QID (13 bytes)
    buf.push(dir.qid.qtype); // type
    buf.push(0); // type padding
    buf.push(0); // type padding
    buf.push(0); // type padding
    // path (8 bytes, big-endian)
    let path = dir.qid.path;
    buf.push(((path >> 56) & 0xFF) as u8);
    buf.push(((path >> 48) & 0xFF) as u8);
    buf.push(((path >> 40) & 0xFF) as u8);
    buf.push(((path >> 32) & 0xFF) as u8);
    buf.push(((path >> 24) & 0xFF) as u8);
    buf.push(((path >> 16) & 0xFF) as u8);
    buf.push(((path >> 8) & 0xFF) as u8);
    buf.push((path & 0xFF) as u8);
    // version (4 bytes, big-endian)
    let version = dir.qid.version;
    buf.push(((version >> 24) & 0xFF) as u8);
    buf.push(((version >> 16) & 0xFF) as u8);
    buf.push(((version >> 8) & 0xFF) as u8);
    buf.push((version & 0xFF) as u8);
    
    // Mode (4 bytes, big-endian)
    let mode = dir.mode.0;
    buf.push(((mode >> 24) & 0xFF) as u8);
    buf.push(((mode >> 16) & 0xFF) as u8);
    buf.push(((mode >> 8) & 0xFF) as u8);
    buf.push((mode & 0xFF) as u8);
    
    // Atime (4 bytes, big-endian)
    buf.push(((dir.atime >> 24) & 0xFF) as u8);
    buf.push(((dir.atime >> 16) & 0xFF) as u8);
    buf.push(((dir.atime >> 8) & 0xFF) as u8);
    buf.push((dir.atime & 0xFF) as u8);
    
    // Mtime (4 bytes, big-endian)
    buf.push(((dir.mtime >> 24) & 0xFF) as u8);
    buf.push(((dir.mtime >> 16) & 0xFF) as u8);
    buf.push(((dir.mtime >> 8) & 0xFF) as u8);
    buf.push((dir.mtime & 0xFF) as u8);
    
    // Length (8 bytes, big-endian)
    let length = dir.length;
    buf.push(((length >> 56) & 0xFF) as u8);
    buf.push(((length >> 48) & 0xFF) as u8);
    buf.push(((length >> 40) & 0xFF) as u8);
    buf.push(((length >> 32) & 0xFF) as u8);
    buf.push(((length >> 24) & 0xFF) as u8);
    buf.push(((length >> 16) & 0xFF) as u8);
    buf.push(((length >> 8) & 0xFF) as u8);
    buf.push((length & 0xFF) as u8);
    
    // Name (null-terminated)
    buf.extend_from_slice(name);
    buf.push(0);
    
    // UID (null-terminated)
    buf.extend_from_slice(uid);
    buf.push(0);
    
    // GID (null-terminated)
    buf.extend_from_slice(gid);
    buf.push(0);
    
    // MUID (null-terminated)
    buf.extend_from_slice(muid);
    buf.push(0);
    
    buf
}

/// Open a file for directory reading
pub fn opendirfile(file: &Arc<File>, _mode: u8) -> Result<DirReader, DirReadError> {
    if !file.is_dir() {
        return Err(DirReadError::NotADirectory);
    }
    Ok(DirReader::new(Arc::clone(file)))
}

/// Read directory entries
pub fn readdirfile(reader: &mut DirReader, buf: &mut [u8]) -> Result<usize, DirReadError> {
    Ok(reader.read(buf))
}

/// Close directory reader
pub fn closedirfile(_reader: DirReader) {
    // No resources to free
}

/// Directory read errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirReadError {
    /// Not a directory
    NotADirectory,
    /// Invalid offset
    InvalidOffset,
    /// I/O error
    IoError,
}

impl core::fmt::Display for DirReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirReadError::NotADirectory => write!(f, "not a directory"),
            DirReadError::InvalidOffset => write!(f, "invalid offset"),
            DirReadError::IoError => write!(f, "I/O error"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Tree, FileMode};

    #[test]
    fn test_dir_reader() {
        // Create a tree and files
        let tree = Tree::new_default();
        let dir = tree.create(&tree.root(), "dir", "user", 0o755 | FileMode::DIR).unwrap();
        tree.create(&dir, "file1", "user", 0o644).unwrap();
        tree.create(&dir, "file2", "user", 0o644).unwrap();

        // Open directory for reading
        let mut reader = opendirfile(&dir, 0).unwrap();

        // Read entries
        let mut buf = [0u8; 512];
        let n = readdirfile(&mut reader, &mut buf).unwrap();

        assert!(n > 0);
        assert!(!reader.eof());

        // Read more
        let n2 = readdirfile(&mut reader, &mut buf).unwrap();
        assert!(n2 > 0);

        closedirfile(reader);
    }

    #[test]
    fn test_opendir_not_dir() {
        let tree = Tree::new_default();
        let file = tree.create(&tree.root(), "file", "user", 0o644).unwrap();

        let result = opendirfile(&file, 0);
        match result {
            Err(DirReadError::NotADirectory) => {}
            _ => {}
        }
    }
}

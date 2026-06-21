//! RAM File System Implementation
//!
//! An in-memory file system for temporary storage.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;

use super::common::error::Error;
use super::common::types::Qid;
use crate::vfs::{
    FileOperations, DirectoryOperations, DirEntry, Inode, FileType, Result,
};

// ============================================================================
// RAMFS Node
// ============================================================================

/// RAMFS node types
#[derive(Debug, Clone)]
pub enum RamfsNode {
    /// Regular file
    File(RamfsFile),
    /// Directory
    Directory(RamfsDir),
    /// Symlink
    Symlink {
        target: Vec<u8>,
    },
}

impl RamfsNode {
    /// Get file size
    pub fn size(&self) -> u64 {
        match self {
            RamfsNode::File(f) => f.size(),
            _ => 0,
        }
    }

    /// Check if directory
    pub fn is_dir(&self) -> bool {
        matches!(self, RamfsNode::Directory(_))
    }

    /// Check if file
    pub fn is_file(&self) -> bool {
        matches!(self, RamfsNode::File(_))
    }

    /// Check if symlink
    pub fn is_symlink(&self) -> bool {
        matches!(self, RamfsNode::Symlink { .. })
    }
}

/// RAMFS file data
#[derive(Debug, Clone, Default)]
pub struct RamfsFile {
    /// File data
    data: Vec<u8>,
    /// Current offset
    offset: u64,
}

impl RamfsFile {
    /// Create new file
    pub fn new() -> Self {
        Self::default()
    }

    /// Create file with initial data
    pub fn with_data(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    /// Get file size
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Read from file
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.data.len() as u64 {
            return 0;
        }

        let start = offset as usize;
        let end = (start + buf.len()).min(self.data.len());
        let count = end - start;

        buf[..count].copy_from_slice(&self.data[start..end]);
        count
    }

    /// Write to file
    pub fn write(&mut self, offset: u64, data: &[u8]) -> usize {
        let start = offset as usize;

        // Extend if needed
        if start + data.len() > self.data.len() {
            self.data.resize(start + data.len(), 0);
        }

        self.data[start..start + data.len()].copy_from_slice(data);
        data.len()
    }

    /// Truncate file
    pub fn truncate(&mut self, size: u64) {
        self.data.truncate(size as usize);
    }

    /// Get reference to data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable reference to data
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

/// RAMFS directory
#[derive(Debug, Clone, Default)]
pub struct RamfsDir {
    /// Children
    children: Vec<RamfsEntry>,
}

impl RamfsDir {
    /// Create new directory
    pub fn new() -> Self {
        Self::default()
    }

    /// Add child
    pub fn add(&mut self, entry: RamfsEntry) {
        self.children.push(entry);
    }

    /// Remove child by name
    pub fn remove(&mut self, name: &[u8]) -> Option<RamfsEntry> {
        if let Some(pos) = self.children.iter().position(|e| e.name() == name) {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }

    /// Find child by name
    pub fn find(&self, name: &[u8]) -> Option<&RamfsEntry> {
        self.children.iter().find(|e| e.name() == name)
    }

    /// Find child by name (mutable)
    pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut RamfsEntry> {
        self.children.iter_mut().find(|e| e.name() == name)
    }

    /// List children
    pub fn list(&self) -> &[RamfsEntry] {
        &self.children
    }

    /// Get number of children
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

/// RAMFS entry
#[derive(Debug, Clone)]
pub struct RamfsEntry {
    /// Entry name
    name: Vec<u8>,
    /// Node type
    node: RamfsNode,
    /// Metadata
    metadata: RamfsMetadata,
    /// QID
    qid: Qid,
}

impl RamfsEntry {
    /// Create new entry
    pub fn new(name: &[u8], node: RamfsNode) -> Self {
        static mut NEXT_PATH: u64 = 1;

        let qid_type = match &node {
            RamfsNode::File(_) => 0,
            RamfsNode::Directory(_) => 1,
            RamfsNode::Symlink { .. } => 2,
        };

        let qid = unsafe {
            let q = Qid::new(NEXT_PATH, 1, qid_type);
            NEXT_PATH += 1;
            q
        };

        Self {
            name: name.to_vec(),
            node,
            metadata: RamfsMetadata::default(),
            qid,
        }
    }

    /// Create file entry
    pub fn file(name: &[u8]) -> Self {
        Self::new(name, RamfsNode::File(RamfsFile::new()))
    }

    /// Create directory entry
    pub fn directory(name: &[u8]) -> Self {
        Self::new(name, RamfsNode::Directory(RamfsDir::new()))
    }

    /// Create symlink entry
    pub fn symlink(name: &[u8], target: &[u8]) -> Self {
        Self::new(name, RamfsNode::Symlink { target: target.to_vec() })
    }

    /// Get name
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Get node
    pub fn node(&self) -> &RamfsNode {
        &self.node
    }

    /// Get mutable node
    pub fn node_mut(&mut self) -> &mut RamfsNode {
        &mut self.node
    }

    /// Get metadata
    pub fn metadata(&self) -> &RamfsMetadata {
        &self.metadata
    }

    /// Get mutable metadata
    pub fn metadata_mut(&mut self) -> &mut RamfsMetadata {
        &mut self.metadata
    }

    /// Get qid
    pub fn qid(&self) -> Qid {
        self.qid
    }
}

/// RAMFS metadata
#[derive(Debug, Clone, Default)]
pub struct RamfsMetadata {
    /// Permissions
    pub mode: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// Creation time
    pub ctime: u32,
}

impl RamfsMetadata {
    /// Create new metadata
    pub fn new(mode: u32) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    /// Check if readable
    pub fn readable(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            return (self.mode >> 6) & 7 != 0;
        }
        if gid == self.gid {
            return (self.mode >> 3) & 7 != 0;
        }
        (self.mode & 7) != 0
    }

    /// Check if writable
    pub fn writable(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            return (self.mode >> 6) & 2 != 0;
        }
        if gid == self.gid {
            return (self.mode >> 3) & 2 != 0;
        }
        (self.mode & 2) != 0
    }

    /// Check if executable
    pub fn executable(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            return (self.mode >> 6) & 1 != 0;
        }
        if gid == self.gid {
            return (self.mode >> 3) & 1 != 0;
        }
        (self.mode & 1) != 0
    }
}

// ============================================================================
// RAMFS Implementation
// ============================================================================

/// RAM File System
pub struct RamFileSystem {
    /// Root directory
    root: RamfsDir,
    /// Current working directory
    cwd: Vec<u8>,
}

impl RamFileSystem {
    /// Create new RAMFS
    pub fn new() -> Self {
        let mut root = RamfsDir::new();

        // Create standard directories
        root.add(RamfsEntry::directory(b"dev"));
        root.add(RamfsEntry::directory(b"tmp"));
        root.add(RamfsEntry::directory(b"proc"));
        root.add(RamfsEntry::directory(b"fd"));

        Self {
            root,
            cwd: b"/".to_vec(),
        }
    }

    /// Get root entry
    pub fn root(&self) -> &RamfsEntry {
        // Return a reference to root as a virtual entry
        // In practice, we need a different approach
        unimplemented!("Use lookup for root")
    }

    /// Look up path
    pub fn lookup(&self, path: &[u8]) -> Option<&RamfsEntry> {
        if path.is_empty() || path == b"/" {
            return None; // Root is virtual
        }

        let components: Vec<&[u8]> = if path[0] == b'/' {
            let mut c = Vec::new();
            for part in path[1..].split(|&c| c == b'/') {
                if !part.is_empty() {
                    c.push(part);
                }
            }
            c
        } else {
            let mut c = Vec::new();
            for part in path.split(|&c| c == b'/') {
                if !part.is_empty() {
                    c.push(part);
                }
            }
            c
        };

        let mut current = &self.root;

        for comp in components {
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                continue;
            }

            if let Some(entry) = current.find(comp) {
                match entry.node() {
                    RamfsNode::Directory(dir) => {
                        current = dir;
                    }
                    _ => return Some(entry),
                }
            } else {
                return None;
            }
        }

        // Return last found entry
        None
    }

    /// Look up path (mutable)
    pub fn lookup_mut(&mut self, path: &[u8]) -> Option<&mut RamfsEntry> {
        if path.is_empty() || path == b"/" {
            return None;
        }

        let components: Vec<Vec<u8>> = if path[0] == b'/' {
            path[1..].split(|&c| c == b'/')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_vec())
                .collect()
        } else {
            path.split(|&c| c == b'/')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_vec())
                .collect()
        };

        // For simplicity, just search
        fn search<'a>(dir: &'a mut RamfsDir, components: &[Vec<u8>], index: usize) -> Option<&'a mut RamfsEntry> {
            if index >= components.len() {
                return None;
            }

            let comp = &components[index];

            // Find the entry
            for entry in dir.children.iter_mut() {
                if entry.name() == comp.as_slice() {
                    if index == components.len() - 1 {
                        return Some(entry);
                    }

                    if let RamfsNode::Directory(child_dir) = entry.node_mut() {
                        return search(child_dir, components, index + 1);
                    }
                    return None;
                }
            }
            None
        }

        if components.is_empty() {
            return None;
        }

        search(&mut self.root, &components, 0)
    }

    /// Create file
    pub fn create_file(&mut self, path: &[u8], data: Vec<u8>) -> Result<()> {
        // Get parent directory
        let parent_path = path.rsplit(|&c| c == b'/').skip(1).collect::<Vec<_>>().join(&b'/');
        let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);

        let parent = self.lookup_mut(&parent_path).ok_or(Error::Enoent)?;
        let parent_dir = match parent.node_mut() {
            RamfsNode::Directory(dir) => dir,
            _ => return Err(Error::Enotdir),
        };

        if parent_dir.find(name).is_some() {
            return Err(Error::Eexist);
        }

        parent_dir.add(RamfsEntry::new(name, RamfsNode::File(RamfsFile::with_data(data))));
        Ok(())
    }

    /// Create directory
    pub fn create_dir(&mut self, path: &[u8]) -> Result<()> {
        let parent_path = path.rsplit(|&c| c == b'/').skip(1).collect::<Vec<_>>().join(&b'/');
        let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);

        let parent = self.lookup_mut(&parent_path).ok_or(Error::Enoent)?;
        let parent_dir = match parent.node_mut() {
            RamfsNode::Directory(dir) => dir,
            _ => return Err(Error::Enotdir),
        };

        if parent_dir.find(name).is_some() {
            return Err(Error::Eexist);
        }

        parent_dir.add(RamfsEntry::directory(name));
        Ok(())
    }

    /// Remove file
    pub fn remove(&mut self, path: &[u8]) -> Result<()> {
        let parent_path = path.rsplit(|&c| c == b'/').skip(1).collect::<Vec<_>>().join(&b'/');
        let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);

        let parent = self.lookup_mut(&parent_path).ok_or(Error::Enoent)?;
        let parent_dir = match parent.node_mut() {
            RamfsNode::Directory(dir) => dir,
            _ => return Err(Error::Enotdir),
        };

        if parent_dir.remove(name).is_none() {
            return Err(Error::Enoent);
        }

        Ok(())
    }

    /// List directory
    pub fn list_dir(&self, path: &[u8]) -> Result<Vec<RamfsEntry>> {
        let entry = self.lookup(path).ok_or(Error::Enoent)?;

        match entry.node() {
            RamfsNode::Directory(dir) => Ok(dir.list().to_vec()),
            _ => Err(Error::Enotdir),
        }
    }

    /// Read file
    pub fn read_file(&self, path: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let entry = self.lookup(path).ok_or(Error::Enoent)?;

        match entry.node() {
            RamfsNode::File(file) => {
                let mut f = file.clone();
                Ok(f.read(offset, buf))
            }
            _ => Err(Error::Eisdir),
        }
    }

    /// Write file
    pub fn write_file(&mut self, path: &[u8], offset: u64, data: &[u8]) -> Result<usize> {
        let entry = self.lookup_mut(path).ok_or(Error::Enoent)?;

        match entry.node_mut() {
            RamfsNode::File(file) => Ok(file.write(offset, data)),
            _ => Err(Error::Eisdir),
        }
    }

    /// Get file size
    pub fn file_size(&self, path: &[u8]) -> Result<u64> {
        let entry = self.lookup(path).ok_or(Error::Enoent)?;
        Ok(entry.node().size())
    }
}

impl Default for RamFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RAMFS File Operations
// ============================================================================

impl FileOperations for RamfsFile {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(self.read(offset, buf))
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        Ok(self.write(offset, buf))
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn file_type(&self) -> FileType {
        FileType::File
    }

    fn qid(&self) -> Qid {
        Qid::nil()
    }

    fn truncate(&mut self, size: u64) -> Result<()> {
        self.truncate(size);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}

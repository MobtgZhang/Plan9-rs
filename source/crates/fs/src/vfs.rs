//! Virtual File System
//!
//! Implements the Plan 9 VFS abstraction layer for file systems.

use alloc::vec::Vec;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

use super::common::error::Error;
use super::common::types::{Qid, Mode};
use super::common::sync::{Spinlock, SpinlockGuard};

/// Result type with Error as default error type
pub type Result<T> = core::result::Result<T, Error>;

// ============================================================================
// VFS Constants
// ============================================================================

/// Maximum path components
pub const MAX_PATH_COMPONENTS: usize = 128;

/// Maximum file name length
pub const MAX_FILE_NAME: usize = 256;

/// File types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    File,
    Directory,
    Symlink,
    Device,
    NamedPipe,
    Socket,
}

/// Directory entry information
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub qid: Qid,
    pub offset: u64,
    pub typ: u8,
    pub name: Vec<u8>,
    pub mode: u32,
    pub length: u64,
}

impl DirEntry {
    pub fn new(name: &[u8], qid: Qid, mode: Mode) -> Self {
        Self {
            qid,
            offset: 0,
            typ: qid.qtype,
            name: name.to_vec(),
            mode: mode.bits(),
            length: 0,
        }
    }
}

// ============================================================================
// File Operations
// ============================================================================

/// File operations trait - implementations provide file system specific operations
pub trait FileOperations: Send + Sync {
    /// Read from file
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    /// Write to file
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize>;
    /// Get file size
    fn size(&self) -> u64;
    /// Get file type
    fn file_type(&self) -> FileType;
    /// Get qid
    fn qid(&self) -> Qid;
    /// Truncate file
    fn truncate(&mut self, size: u64) -> Result<()>;
    /// Sync to disk
    fn sync(&mut self) -> Result<()>;
}

// ============================================================================
// Directory Operations
// ============================================================================

/// Directory operations trait
pub trait DirectoryOperations: Send + Sync {
    /// Read directory entries
    fn read_dir(&mut self, offset: u64, count: usize) -> Result<Vec<DirEntry>>;
    /// Create a file
    fn create(&mut self, name: &[u8], mode: Mode, perm: u32) -> Result<(Qid, Box<dyn FileOperations>)>;
    /// Remove a file
    fn remove(&mut self, name: &[u8]) -> Result<()>;
    /// Rename
    fn rename(&mut self, old_name: &[u8], new_name: &[u8]) -> Result<()>;
    /// Create directory
    fn mkdir(&mut self, name: &[u8], mode: Mode) -> Result<Qid>;
    /// Remove directory
    fn rmdir(&mut self, name: &[u8]) -> Result<()>;
    /// Create symlink
    fn symlink(&mut self, name: &[u8], target: &[u8]) -> Result<Qid>;
    /// Read symlink
    fn read_link(&mut self, name: &[u8]) -> Result<Vec<u8>>;
}

// ============================================================================
// Inode (VFS Node)
// ============================================================================

/// VFS inode
#[derive(Debug, Clone)]
pub struct Inode {
    /// Unique identifier
    pub qid: Qid,
    /// File type
    pub typ: FileType,
    /// Permissions
    pub mode: u32,
    /// Device major/minor (for devices)
    pub dev: (u8, u8),
    /// Reference count
    pub refcount: u32,
    /// Size
    pub size: u64,
    /// Parent directory
    pub parent: Option<u64>,
    /// Name
    pub name: Vec<u8>,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// Creation time
    pub ctime: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

impl Inode {
    /// Create new inode
    pub fn new(typ: FileType) -> Self {
        static mut NEXT_QID: u64 = 1;

        let qid = unsafe {
            let q = Qid::new(NEXT_QID, 0, match typ {
                FileType::File => 0,
                FileType::Directory => 1,
                FileType::Symlink => 2,
                FileType::Device => 0,
                _ => 0,
            });
            NEXT_QID += 1;
            q
        };

        Self {
            qid,
            typ,
            mode: 0o644,
            dev: (0, 0),
            refcount: 1,
            size: 0,
            parent: None,
            name: Vec::new(),
            atime: 0,
            mtime: 0,
            ctime: 0,
            uid: 0,
            gid: 0,
        }
    }

    /// Check if directory
    pub fn is_dir(&self) -> bool {
        self.typ == FileType::Directory
    }

    /// Check if file
    pub fn is_file(&self) -> bool {
        self.typ == FileType::File
    }

    /// Check if symlink
    pub fn is_symlink(&self) -> bool {
        self.typ == FileType::Symlink
    }

    /// Check if device
    pub fn is_device(&self) -> bool {
        self.typ == FileType::Device
    }

    /// Increment reference count
    pub fn inc_ref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn dec_ref(&mut self) -> i32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount as i32
    }
}

// ============================================================================
// Mount Point
// ============================================================================

/// Mount point
#[derive(Debug, Clone)]
pub struct MountPoint {
    /// Mount source (device, URL, etc)
    pub source: Vec<u8>,
    /// Mount target (path)
    pub target: Vec<u8>,
    /// File system type
    pub fs_type: Vec<u8>,
    /// Mount flags
    pub flags: u32,
    /// Root inode
    pub root: u64,
    /// Mount ID
    pub id: u32,
}

impl MountPoint {
    pub fn new(source: &[u8], target: &[u8], fs_type: &[u8]) -> Self {
        static mut NEXT_ID: u32 = 1;

        Self {
            source: source.to_vec(),
            target: target.to_vec(),
            fs_type: fs_type.to_vec(),
            flags: 0,
            root: 0,
            id: unsafe { let id = NEXT_ID; NEXT_ID += 1; id },
        }
    }
}

// ============================================================================
// Channel (Open File)
// ============================================================================

/// VFS channel (open file description)
#[derive(Debug)]
pub struct Channel {
    /// File descriptor
    pub fd: i32,
    /// Channel flags
    pub flags: i32,
    /// Offset in file
    pub offset: u64,
    /// Associated inode
    pub inode: u64,
    /// Reference count
    pub refcount: u32,
}

impl Channel {
    pub fn new(fd: i32, inode: u64, flags: i32) -> Self {
        Self {
            fd,
            flags,
            offset: 0,
            inode,
            refcount: 1,
        }
    }

    pub fn is_readable(&self) -> bool {
        (self.flags & 0o3) != 0o1
    }

    pub fn is_writable(&self) -> bool {
        (self.flags & 0o3) != 0o0
    }

    pub fn is_append(&self) -> bool {
        (self.flags & 0o10) != 0
    }

    pub fn is_directory(&self) -> bool {
        (self.flags & 0o200000) != 0
    }
}

// ============================================================================
// VFS Operations
// ============================================================================

/// Virtual file system operations
pub trait VfsOperations: Send + Sync {
    /// Mount the file system
    fn mount(&mut self) -> Result<()>;
    /// Unmount the file system
    fn unmount(&mut self) -> Result<()>;
    /// Get root inode
    fn root(&self) -> Result<Inode>;
    /// Look up inode by path
    fn lookup(&self, path: &[u8]) -> Result<Inode>;
    /// Create file
    fn create(&self, path: &[u8], mode: Mode, perm: u32) -> Result<Inode>;
    /// Remove file
    fn remove(&self, path: &[u8]) -> Result<()>;
    /// Rename
    fn rename(&self, old_path: &[u8], new_path: &[u8]) -> Result<()>;
    /// Create directory
    fn mkdir(&self, path: &[u8], mode: Mode) -> Result<Inode>;
    /// Remove directory
    fn rmdir(&self, path: &[u8]) -> Result<()>;
    /// Stat
    fn stat(&self, path: &[u8]) -> Result<Inode>;
    /// Set stat
    fn wstat(&self, path: &[u8], inode: &Inode) -> Result<()>;
    /// Open file
    fn open(&mut self, path: &[u8], mode: i32) -> Result<Channel>;
    /// Close channel
    fn close(&mut self, ch: &mut Channel) -> Result<()>;
    /// Read from channel
    fn read(&self, ch: &mut Channel, buf: &mut [u8]) -> Result<usize>;
    /// Write to channel
    fn write(&self, ch: &mut Channel, buf: &[u8]) -> Result<usize>;
    /// Seek
    fn seek(&self, ch: &mut Channel, offset: i64, whence: i32) -> Result<u64>;
    /// Read directory
    fn read_dir(&self, ch: &mut Channel, offset: u64, count: usize) -> Result<Vec<DirEntry>>;
}

// ============================================================================
// Path Operations
// ============================================================================

/// Path utilities
pub mod path {
    use alloc::vec::Vec;
    
    /// Split path into components
    pub fn split(path: &[u8]) -> Vec<&[u8]> {
        let mut components: Vec<&[u8]> = Vec::new();
        
        if path.is_empty() {
            return components;
        }
        
        let mut start = 0;
        let mut pos = 0;
        
        // Handle leading slash
        if path[0] == b'/' {
            components.push(&b"/"[..]);
            start = 1;
            pos = 1;
        }
        
        // Find path components
        while pos < path.len() {
            if path[pos] == b'/' {
                if pos > start {
                    components.push(&path[start..pos]);
                }
                start = pos + 1;
            }
            pos += 1;
        }
        
        // Add remaining component
        if start < path.len() {
            components.push(&path[start..]);
        }
        
        components
    }

    /// Join path components
    pub fn join(components: &[&[u8]]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut first = true;

        for comp in components {
            if comp.is_empty() {
                continue;
            }
            if !first && !result.ends_with(b"/") {
                result.push(b'/');
            }
            result.extend_from_slice(comp);
            first = false;
        }

        if result.is_empty() {
            result.push(b'/');
        }

        result
    }

    /// Get parent path
    pub fn parent(path: &[u8]) -> Option<&[u8]> {
        if path == b"/".as_slice() {
            return None;
        }

        let trimmed = trim_trailing_slashes(path);
        if trimmed.is_empty() {
            return Some(b"/".as_slice());
        }

        // Find last '/' manually
        let mut pos = None;
        for (i, &b) in trimmed.iter().enumerate() {
            if b == b'/' {
                pos = Some(i);
            }
        }
        
        if let Some(pos) = pos {
            if pos == 0 {
                Some(b"/".as_slice())
            } else {
                Some(&trimmed[..pos])
            }
        } else {
            Some(b".".as_slice())
        }
    }

    /// Get file name
    pub fn file_name(path: &[u8]) -> Option<&[u8]> {
        let trimmed = trim_trailing_slashes(path);
        if trimmed.is_empty() {
            return None;
        }

        // Find last '/' manually
        let mut pos = None;
        for (i, &b) in trimmed.iter().enumerate() {
            if b == b'/' {
                pos = Some(i);
            }
        }
        
        if let Some(pos) = pos {
            Some(&trimmed[pos + 1..])
        } else {
            Some(trimmed)
        }
    }
    
    /// Trim trailing slashes from path
    fn trim_trailing_slashes(path: &[u8]) -> &[u8] {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        &path[..end]
    }

    /// Normalize path (remove . and ..)
    pub fn normalize(path: &[u8]) -> Vec<u8> {
        let components = split(path);
        let mut result = Vec::new();

        for comp in components {
            match comp {
                b"/" => {
                    result.clear();
                    result.push(b'/');
                }
                b"." => {}
                b".." => {
                    if result.len() > 1 {
                        result.pop(); // Remove trailing /
                        while result.last() != Some(&b'/') && !result.is_empty() {
                            result.pop();
                        }
                    }
                }
                _ => {
                    if !result.ends_with(b"/") && !result.is_empty() {
                        result.push(b'/');
                    }
                    result.extend_from_slice(comp);
                }
            }
        }

        if result.is_empty() {
            return b"/".to_vec();
        }

        result
    }
}

// ============================================================================
// VFS Global State
// ============================================================================

/// Global VFS state
pub struct Vfs {
    /// Mount points
    mounts: Vec<MountPoint>,
    /// Open channels
    channels: Vec<Option<Channel>>,
    /// Next channel ID
    next_fd: i32,
}

impl Vfs {
    /// Create new VFS
    pub fn new() -> Self {
        Self {
            mounts: Vec::new(),
            channels: Vec::new(),
            next_fd: 0,
        }
    }

    /// Allocate a file descriptor
    pub fn alloc_fd(&mut self, ch: Channel) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;

        // Grow channel list if needed
        while self.channels.len() <= fd as usize {
            self.channels.push(None);
        }

        self.channels[fd as usize] = Some(ch);
        fd
    }

    /// Get channel by fd
    pub fn get_channel(&self, fd: i32) -> Option<&Channel> {
        if fd < 0 || fd >= self.next_fd {
            return None;
        }
        self.channels.get(fd as usize).and_then(|c| c.as_ref())
    }

    /// Get mutable channel by fd
    pub fn get_channel_mut(&mut self, fd: i32) -> Option<&mut Channel> {
        if fd < 0 || fd >= self.next_fd {
            return None;
        }
        self.channels.get_mut(fd as usize).and_then(|c| c.as_mut())
    }

    /// Close channel
    pub fn close_fd(&mut self, fd: i32) -> Option<Channel> {
        if fd < 0 || fd >= self.next_fd {
            return None;
        }
        self.channels[fd as usize].take()
    }

    /// Add mount point
    pub fn add_mount(&mut self, mount: MountPoint) {
        self.mounts.push(mount);
    }

    /// Get mount points
    pub fn mounts(&self) -> &[MountPoint] {
        &self.mounts
    }

    /// Find mount for path
    pub fn find_mount(&self, path: &[u8]) -> Option<&MountPoint> {
        let mut best: Option<&MountPoint> = None;
        let mut best_len = 0;

        for mount in &self.mounts {
            if path.starts_with(&mount.target) && mount.target.len() > best_len {
                best = Some(mount);
                best_len = mount.target.len();
            }
        }

        best
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Buffer Cache
// ============================================================================

/// Buffer cache entry
#[derive(Debug)]
pub struct Buffer {
    /// Block number
    pub block: u64,
    /// Data
    pub data: Vec<u8>,
    /// Dirty flag
    pub dirty: bool,
    /// Reference count (atomic for thread safety)
    refcount: AtomicU32,
    /// Last access time
    timestamp: u64,
}

impl Buffer {
    /// Create a new buffer
    pub fn new(block: u64, size: usize) -> Self {
        Self {
            block,
            data: alloc::vec![0; size],
            dirty: false,
            refcount: AtomicU32::new(1),
            timestamp: 0,
        }
    }

    /// Mark buffer as dirty
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Increment reference count (thread-safe)
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Acquire);
    }

    /// Decrement reference count (thread-safe)
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Release).wrapping_sub(1)
    }

    /// Get current refcount (thread-safe)
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Check if buffer is stale (based on timestamp)
    pub fn is_stale(&self, max_age: u64, current_time: u64) -> bool {
        current_time - self.timestamp > max_age
    }

    /// Update timestamp
    pub fn update_timestamp(&mut self, time: u64) {
        self.timestamp = time;
    }
}

/// Buffer cache with thread-safe access
pub struct BufferCache {
    /// Cache entries (hash map from block number to buffer)
    entries: Vec<Option<Buffer>>,
    /// Number of slots
    size: usize,
    /// Maximum number of buffers
    max_buffers: usize,
    /// Current time (for LRU)
    current_time: u64,
    /// Block size
    block_size: usize,
    /// Lock for thread-safe access
    lock: Spinlock<()>,
}

impl BufferCache {
    /// Create a new buffer cache
    pub fn new(size: usize, block_size: usize) -> Self {
        // Create empty entries array
        let mut entries: Vec<Option<Buffer>> = Vec::with_capacity(size);
        for _ in 0..size {
            entries.push(None);
        }

        Self {
            entries,
            size,
            max_buffers: size,
            current_time: 0,
            block_size,
            lock: Spinlock::new(()),
        }
    }

    /// Configured maximum number of buffers the cache may hold.
    pub fn max_buffers(&self) -> usize {
        self.max_buffers
    }

    /// Acquire the cache lock (RAII guard released on drop).
    pub fn lock_cache(&self) -> SpinlockGuard<'_, ()> {
        self.lock.lock()
    }

    /// Hash function for block number
    fn hash(&self, block: u64) -> usize {
        (block as usize) % self.size
    }

    /// Find a buffer by block number
    pub fn find(&self, block: u64) -> Option<usize> {
        let mut idx = self.hash(block);
        for _ in 0..self.size {
            if let Some(ref buf) = self.entries[idx] {
                if buf.block == block {
                    return Some(idx);
                }
            } else {
                return None;
            }
            idx = (idx + 1) % self.size;
        }
        None
    }

    /// Get a buffer (read from device if not cached)
    /// Thread-safe version with proper locking
    pub fn get<D: BlockDeviceReadWrite>(
        &mut self,
        block: u64,
        device: &mut D,
    ) -> Option<&mut Buffer> {
        // Check if already cached
        let idx = self.find(block);

        if let Some(idx) = idx {
            // Found in cache, update timestamp
            if let Some(ref mut buf) = self.entries[idx] {
                buf.timestamp = self.current_time;
            }
            return self.entries[idx].as_mut();
        }

        // Not cached, need to load from device
        let idx = self.find_empty_or_evict(device)?;

        // Read from device into new buffer
        let mut buf = Buffer::new(block, self.block_size);
        if device.read_block(block, &mut buf.data).is_err() {
            return None;
        }

        buf.timestamp = self.current_time;
        self.entries[idx] = Some(buf);
        self.entries[idx].as_mut()
    }

    /// Find empty slot or evict LRU buffer
    /// Uses atomic refcount for thread-safe eviction decisions
    fn find_empty_or_evict<D: BlockDeviceReadWrite>(
        &mut self,
        device: &mut D,
    ) -> Option<usize> {
        let mut oldest_idx = None;
        let mut oldest_time = u64::MAX;

        // First pass: find empty slot
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.is_none() {
                return Some(i);
            }
        }

        // Second pass: find LRU entry with refcount == 0 (thread-safe)
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if let Some(ref buf) = entry {
                // Use atomic refcount() method for thread-safe check
                if buf.refcount() == 0 && buf.timestamp < oldest_time {
                    oldest_time = buf.timestamp;
                    oldest_idx = Some(i);
                }
            }
        }

        // Evict the LRU buffer if found
        if let Some(idx) = oldest_idx {
            if let Some(ref mut buf) = self.entries[idx] {
                if buf.dirty {
                    // Write back to device
                    let _ = device.write_block(buf.block, &buf.data);
                }
            }
            self.entries[idx] = None;
            return Some(idx);
        }

        None
    }

    /// Mark a buffer as dirty
    pub fn mark_dirty(&mut self, block: u64) {
        if let Some(idx) = self.find(block) {
            if let Some(ref mut buf) = self.entries[idx] {
                buf.mark_dirty();
            }
        }
    }

    /// Sync all dirty buffers to disk
    pub fn sync<D: BlockDeviceReadWrite>(&mut self, device: &mut D) {
        for entry in &mut self.entries {
            if let Some(ref mut buf) = entry {
                if buf.dirty {
                    let _ = device.write_block(buf.block, &buf.data);
                    buf.dirty = false;
                }
            }
        }
    }

    /// Increment current time (call periodically)
    pub fn tick(&mut self) {
        self.current_time += 1;
    }

    /// Get number of cached blocks
    pub fn cache_size(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

/// Block device trait for buffer cache (simplified)
pub trait BlockDeviceReadWrite {
    fn read_block(&mut self, block: u64, buf: &mut [u8]) -> Result<()>;
    fn write_block(&mut self, block: u64, buf: &[u8]) -> Result<()>;
}

// ============================================================================
// Block Device to VFS Integration
// ============================================================================

/// Block device file wrapper for VFS
pub struct BlockFile<D: BlockDeviceReadWrite> {
    /// Underlying block device
    device: D,
    /// Buffer cache
    cache: BufferCache,
    /// Block size
    block_size: usize,
    /// File offset (in bytes)
    offset: u64,
}

impl<D: BlockDeviceReadWrite> BlockFile<D> {
    /// Create a new block file
    pub fn new(device: D, cache_size: usize) -> Self {
        let block_size = 512; // Default block size
        Self {
            device,
            cache: BufferCache::new(cache_size, block_size),
            block_size,
            offset: 0,
        }
    }

    /// Read from the block device
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        let start_block = self.offset / self.block_size as u64;
        let mut block_offset = (self.offset % self.block_size as u64) as usize;

        while bytes_read < buf.len() && block_offset < self.block_size {
            // Get buffer for current block
            if let Some(buffer) = self.cache.get(start_block, &mut self.device) {
                let remaining_in_block = self.block_size - block_offset;
                let to_read = (buf.len() - bytes_read).min(remaining_in_block);

                buf[bytes_read..bytes_read + to_read]
                    .copy_from_slice(&buffer.data[block_offset..block_offset + to_read]);

                bytes_read += to_read;
                block_offset += to_read;
            } else {
                break;
            }
        }

        self.offset += bytes_read as u64;
        Ok(bytes_read)
    }

    /// Write to the block device
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;
        let start_block = self.offset / self.block_size as u64;
        let mut block_offset = (self.offset % self.block_size as u64) as usize;

        while bytes_written < buf.len() && block_offset < self.block_size {
            // Get or create buffer for current block
            if let Some(buffer) = self.cache.get(start_block, &mut self.device) {
                let remaining_in_block = self.block_size - block_offset;
                let to_write = (buf.len() - bytes_written).min(remaining_in_block);

                buffer.data[block_offset..block_offset + to_write]
                    .copy_from_slice(&buf[bytes_written..bytes_written + to_write]);
                buffer.mark_dirty();

                bytes_written += to_write;
                block_offset += to_write;
            } else {
                break;
            }
        }

        self.offset += bytes_written as u64;
        Ok(bytes_written)
    }

    /// Seek to a position
    pub fn seek(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Sync to disk
    pub fn sync(&mut self) {
        self.cache.sync(&mut self.device);
    }
}

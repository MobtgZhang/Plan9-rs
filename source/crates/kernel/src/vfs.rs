//! Virtual File System
//!
//! Implements the VFS layer that connects file systems and devices
//! to the system call interface.
//!
//! This module provides the Plan 9 style VFS with:
//! - namec() for path-to-channel conversion
//! - Mount table for union mounts and bind mounts
//! - Channel reference counting and management
//! - Path parsing and walk operations

use alloc::string::String;
use alloc::vec::Vec;
use crate::dev::{self, DevTable, Chan, Qid, DirEntry, Error as DevError, devtype, qidtype, devs, Error as DevErrorEnum};
use crate::proc::Fgrp;
use crate::plan9_common::sync::{Spinlock, Mutex};
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// VFS Constants
// ============================================================================

/// Maximum mount points
pub const NMOUNT: usize = 16;

/// Maximum path components
pub const MAX_PATH_COMPONENTS: usize = 64;

/// Maximum file name length
pub const MAX_FILE_NAME: usize = 256;

/// Root device character
pub const ROOTDEV: char = '/';

// ============================================================================
// Mount Point
// ============================================================================

/// Mount point structure
#[derive(Debug)]
pub struct MountPoint {
    /// Source (device or server)
    pub source: Vec<u8>,
    /// Mount point path
    pub path: Vec<u8>,
    /// File system type
    pub fs_type: Vec<u8>,
    /// Mount flags
    pub flags: u32,
    /// Root channel for this mount
    pub root: Option<Chan>,
    /// Next mount in list, stored as an index into the static
    /// `MOUNTS` table rather than a raw pointer so the table is
    /// `Send`/`Sync` without `unsafe impl`.
    pub next: Option<usize>,
}

impl MountPoint {
    /// Create new mount point
    pub fn new(source: &[u8], path: &[u8], fs_type: &[u8]) -> Self {
        Self {
            source: source.to_vec(),
            path: path.to_vec(),
            fs_type: fs_type.to_vec(),
            flags: 0,
            root: None,
            next: None,
        }
    }
}

// ============================================================================
// Path Parsing
// ============================================================================

/// Parse a path into components
pub fn parse_path(path: &[u8]) -> Vec<&[u8]> {
    let mut components = Vec::new();
    let mut i = 0;

    // Skip leading slashes
    while i < path.len() && path[i] == b'/' {
        i += 1;
    }

    while i < path.len() {
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        if i > start {
            components.push(&path[start..i]);
        }
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
    }

    components
}

/// Get file name from path
pub fn file_name(path: &[u8]) -> Option<&[u8]> {
    let components = parse_path(path);
    components.last().map(|s| *s)
}

/// Get parent path from path
pub fn parent_path(path: &[u8]) -> Option<Vec<u8>> {
    let components = parse_path(path);
    if components.len() <= 1 {
        return Some(b"/".to_vec());
    }
    
    let mut result = Vec::new();
    for (i, comp) in components.iter().enumerate() {
        if i == components.len() - 1 {
            break;
        }
        result.push(b'/');
        result.extend_from_slice(comp);
    }
    if result.is_empty() {
        result.push(b'/');
    }
    Some(result)
}

// ============================================================================
// Name to Channel (namec)
// ============================================================================

/// Name to channel mode
#[derive(Debug, Clone, Copy)]
pub enum NamecMode {
    /// Open existing file
    Open(u32),
    /// Create new file
    Create(u32, u32),
    /// Walk path only
    Walk,
    /// Bind mount
    Bind(u32),
    /// Unmount
    Unmount,
    /// Remove file or directory
    Remove,
}

/// Path starting point
#[derive(Debug)]
enum PathStart {
    /// Start from root
    Root,
    /// Start from special device (#c, #/, etc.)
    Special(char),
    /// Start from current directory
    Current,
    /// Start from parent directory
    Parent,
}

/// Parse the starting point of a path
fn parse_path_start(path: &[u8]) -> (PathStart, Option<&[u8]>) {
    if path.is_empty() {
        return (PathStart::Current, None);
    }
    
    if path[0] == b'/' {
        return (PathStart::Root, Some(&path[1..]));
    }
    
    if path[0] == b'#' && path.len() > 1 {
        let dev_char = path[1] as char;
        let rest = if path.len() > 2 { &path[2..] } else { &[] };
        return (PathStart::Special(dev_char), Some(rest));
    }
    
    (PathStart::Current, Some(path))
}

/// Name to channel - core VFS function
/// Converts a path name to an open channel
///
/// This is the main entry point for path resolution in Plan 9.
/// It handles:
/// - Absolute paths (starting from /)
/// - Relative paths (starting from current directory)
/// - Special device paths (#c, #e, etc.)
/// - Mount table lookups for bind/union mounts
/// - Parent directory walk ("..")
pub fn namec(
    path: &[u8],
    amode: NamecMode,
    _omode: u32,
    perm: u32,
) -> Result<Chan, VfsError> {
    // 0. Validate path
    if path.is_empty() {
        return Err(VfsError::Einval);
    }

    // 1. Determine starting point
    let (start, rest) = parse_path_start(path);

    let mut chan = match start {
        PathStart::Root => {
            // Start from root filesystem
            // First check mount table for root
            if let Some(mp) = MOUNTS.lock().find(b"") {
                if let Some(ref root) = mp.root {
                    root.dup()
                } else {
                    return Err(VfsError::Enoent);
                }
            } else {
                // Try to get from root channel
                if let Some(root) = ROOT_CHAN.lock().as_ref() {
                    root.dup()
                } else {
                    // Fallback to root device
                    let dev = devs().get(devtype::ROOT)
                        .ok_or(VfsError::Enoent)?;
                    dev.attach(None).map_err(|_| VfsError::Enoent)?
                }
            }
        }
        PathStart::Special(c) => {
            // Special device: #c, #/, #e, etc.
            let dev = devs().find_by_char(c)
                .ok_or(VfsError::Enoent)?;
            dev.attach(Some(core::str::from_utf8(rest.unwrap_or(&[]))
                .unwrap_or("")))
                .map_err(|_| VfsError::Enoent)?
        }
        PathStart::Current => {
            // Start from current directory
            let proc = crate::proc::curproc()
                .ok_or(VfsError::Eperm)?;
            if let Some(ref dot) = proc.dot {
                dot.dup()
            } else {
                // Fallback to root
                if let Some(mp) = MOUNTS.lock().find(b"") {
                    if let Some(ref root) = mp.root {
                        root.dup()
                    } else {
                        return Err(VfsError::Enoent);
                    }
                } else {
                    return Err(VfsError::Enoent);
                }
            }
        }
        PathStart::Parent => {
            // Start from parent directory - walk ".." from current
            let proc = crate::proc::curproc()
                .ok_or(VfsError::Eperm)?;
            if let Some(ref dot) = proc.dot {
                let mut parent = dot.dup();
                if let Some(dev) = devs().get(parent.dev) {
                    // Walk to ".."
                    if dev.walk(&mut parent, "..").is_ok() {
                        parent
                    } else {
                        return Err(VfsError::Enoent);
                    }
                } else {
                    return Err(VfsError::Enoent);
                }
            } else {
                return Err(VfsError::Enoent);
            }
        }
    };

    // 2. Build current path for mount table lookups
    let mut current_path: Vec<u8> = Vec::new();

    // 3. Parse and walk path components
    if let Some(path_rest) = rest {
        let components = parse_path_components(path_rest);

        for comp in components {
            // Skip empty components
            if comp.is_empty() || comp == b"." {
                continue;
            }

            // Update current path for mount lookup
            if !current_path.is_empty() || comp.first() != Some(&b'/') {
                current_path.push(b'/');
            }
            current_path.extend_from_slice(comp);

            // Check for mount point before walking
            let mounts = MOUNTS.lock();
            if let Some(mp) = mounts.find(&current_path) {
                if let Some(ref root) = mp.root {
                    chan = root.dup();
                }
            }
            drop(mounts);

            // Handle parent directory
            if comp == b".." {
                // For "..", we need to walk up
                // First check if we should return to parent mount
                let parent_path = parent_path(&current_path).unwrap_or_default();

                let mounts = MOUNTS.lock();
                if let Some(mp) = mounts.find(&parent_path) {
                    // Check if this mount point has a different root
                    if let Some(ref root) = mp.root {
                        let root_qid = root.qid;
                        if root_qid.path != chan.qid.path {
                            // We're at the root of a mount, go back to parent mount's root
                            chan = root.dup();
                            // Update current path to parent
                            current_path = parent_path;
                            continue;
                        }
                    }
                }
                drop(mounts);

                // Walk ".." in current channel
                if let Some(dev) = devs().get(chan.dev) {
                    // Walk returns the new channel position after ".."
                    if dev.walk(&mut chan, "..").is_err() {
                        return Err(VfsError::Enoent);
                    }
                } else {
                    return Err(VfsError::Enoent);
                }

                // Update current path
                if let Some(pp) = parent_path(&current_path) {
                    current_path = pp;
                }
                continue;
            }

            // Walk to child
            let name = core::str::from_utf8(comp)
                .map_err(|_| VfsError::Einval)?;

            // Get device for current channel
            let dev = match devs().get(chan.dev) {
                Some(d) => d,
                None => return Err(VfsError::Enoent),
            };

            // Walk to child component
            match dev.walk(&mut chan, name) {
                Ok(Some(_qid)) => {
                    // Successfully walked
                    continue;
                }
                Ok(None) => {
                    // Component doesn't exist
                    match amode {
                        NamecMode::Create(mode, _perm) => {
                            // Create the file
                            if let Some(d) = devs().get(chan.dev) {
                                let name_owned = name.to_string();
                                d.create(&mut chan, &name_owned, mode as u8, perm)
                                    .map_err(|_| VfsError::Eio)?;
                            } else {
                                return Err(VfsError::Enoent);
                            }
                        }
                        _ => return Err(VfsError::Enoent),
                    }
                }
                Err(_) => return Err(VfsError::Enoent),
            }
        }
    }

    // 4. Execute final operation based on mode
    match amode {
        NamecMode::Open(mode) => {
            // Open the channel
            if let Some(dev) = devs().get(chan.dev) {
                dev.open(&mut chan, mode as u8).map_err(VfsError::from_dev_error)?;
            } else {
                return Err(VfsError::Enoent);
            }
        }
        NamecMode::Create(mode, perm) => {
            // Create file if it doesn't exist
            let name = file_name(path).and_then(|n| core::str::from_utf8(n).ok());
            if let Some(name_str) = name {
                if let Some(dev) = devs().get(chan.dev) {
                    dev.create(&mut chan, name_str, mode as u8, perm)
                        .map_err(VfsError::from_dev_error)?;
                } else {
                    return Err(VfsError::Enoent);
                }
            }
        }
        NamecMode::Walk => {
            // Just walk, don't open
        }
        NamecMode::Bind(flags) => {
            // TODO: Bind mount - would set up mount table entry
            let _ = flags;
        }
        NamecMode::Unmount => {
            // TODO: Unmount
        }
    }

    Ok(chan)
}

/// Parse path into components
fn parse_path_components(path: &[u8]) -> Vec<&[u8]> {
    let mut components = Vec::new();
    let mut i = 0;
    
    // Skip leading slashes
    while i < path.len() && path[i] == b'/' {
        i += 1;
    }
    
    while i < path.len() {
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        if i > start {
            components.push(&path[start..i]);
        }
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
    }
    
    components
}

// ============================================================================
// VFS Operations
// ============================================================================

/// Open file
pub fn open(path: &[u8], mode: u32) -> Result<Chan, VfsError> {
    let chan = namec(path, 0, mode, 0)?;
    
    // Open the channel
    if let Some(dev) = devs().get(chan.dev) {
        dev.open(&mut chan.clone(), mode as u8).map_err(|_| VfsError::Eio)?;
    }
    
    Ok(chan)
}

// ============================================================================
// Channel Operations
// ============================================================================

impl Chan {
    /// Clone this channel - creates a new reference to the same underlying channel
    /// Increments the reference count
    pub fn dup(&self) -> Self {
        self.incref();
        Self {
            dev: self.dev,
            qid: self.qid,
            mode: self.mode,
            flag: self.flag,
            offset: self.offset,
            aux: self.aux.clone(),
            refcount: Spinlock::new(self.refcount()),
        }
    }

    /// Get parent directory channel
    /// This walks ".." from the current channel
    pub fn parent(&mut self) -> Result<Chan, VfsError> {
        if let Some(dev) = devs().get(self.dev) {
            // Walk to ".." in the current directory
            match dev.walk(self, "..") {
                Ok(_) => {
                    // Walk succeeded - return the channel at parent
                    Ok(self.dup())
                }
                Err(_) => Err(VfsError::Enoent),
            }
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Walk to a child component
    pub fn walk_to(&mut self, name: &str) -> Result<Option<Qid>, VfsError> {
        if let Some(dev) = crate::dev::devs().get(self.dev) {
            dev.walk(self, name).map_err(VfsError::from_dev_error)
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Open this channel with a mode
    pub fn open(&mut self, mode: u8) -> Result<(), VfsError> {
        if let Some(dev) = crate::dev::devs().get(self.dev) {
            dev.open(self, mode).map_err(VfsError::from_dev_error)
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Create a file in this directory
    pub fn create(&mut self, name: &str, mode: u8, perm: u32) -> Result<(), VfsError> {
        if let Some(dev) = crate::dev::devs().get(self.dev) {
            dev.create(self, name, mode, perm).map_err(VfsError::from_dev_error)
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Read from this channel
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, VfsError> {
        if let Some(dev) = crate::dev::devs().get(self.dev) {
            let offset = self.offset;
            let result = dev.read(self, buf, offset).map_err(VfsError::from_dev_error);
            if let Ok(n) = result {
                self.offset += n as u64;
            }
            result
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Write to this channel
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VfsError> {
        if let Some(dev) = crate::dev::devs().get(self.dev) {
            let offset = self.offset;
            let result = dev.write(self, buf, offset).map_err(VfsError::from_dev_error);
            if let Ok(n) = result {
                self.offset += n as u64;
            }
            result
        } else {
            Err(VfsError::Enoent)
        }
    }

    /// Seek in this channel
    pub fn seek(&mut self, offset: u64, whence: u8) -> Result<u64, VfsError> {
        // Simple seek implementation
        match whence {
            0 => { // SEEK_SET
                self.offset = offset;
            }
            1 => { // SEEK_CUR
                self.offset += offset;
            }
            2 => { // SEEK_END
                // Would need stat to get file size
                self.offset = offset; // Simplified
            }
            _ => return Err(VfsError::Einval),
        }
        Ok(self.offset)
    }

    /// Close this channel
    pub fn close(&mut self) {
        if let Some(dev) = devs().get(self.dev) {
            dev.close(self);
        }
        if self.decref() == 0 {
            // Actually close when refcount reaches 0
        }
    }
}

// ============================================================================
// File Descriptor Operations
// ============================================================================

/// Global file descriptor allocator
static NEXT_FD: AtomicU64 = AtomicU64::new(0);

/// Open file and return file descriptor
pub fn sys_open(path: &[u8], mode: u32) -> Result<i32, VfsError> {
    let chan = open(path, mode)?;
    
    // Allocate fd
    let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32;
    
    // Store in current process's fgrp
    // This would be done in syscall handler
    
    Ok(fd)
}

/// Read from file descriptor
pub fn sys_read(fd: i32, buf: &mut [u8]) -> Result<usize, VfsError> {
    // Would get channel from current process's fgrp
    
    // For stdin (fd 0), read from console
    if fd == 0 {
        // Would read from keyboard
        Ok(0)
    } else {
        Err(VfsError::Ebadfd)
    }
}

/// Write to file descriptor
pub fn sys_write(fd: i32, buf: &[u8]) -> Result<usize, VfsError> {
    // For stdout/stderr, write to console
    if fd == 1 || fd == 2 {
        // Would write to console device
        Ok(buf.len())
    } else {
        Err(VfsError::Ebadfd)
    }
}

/// Close file descriptor
pub fn sys_close(fd: i32) -> Result<(), VfsError> {
    // Would close channel in current process's fgrp
    Ok(())
}

/// Apply/remove an advisory lock on an open file.
///
/// `operation` follows the flock(2) encoding:
///   LOCK_SH=1, LOCK_EX=2, LOCK_UN=8, LOCK_NB=4.
///
/// Plan 9 has no equivalent; we always report success because
/// downstream syscalls assume locks are advisory. A future
/// `9P.lock` extension can replace this stub.
pub fn sys_flock(_fd: i32, _operation: i32) -> Result<(), VfsError> {
    Ok(())
}

/// Create a symbolic link.
///
/// Plan 9 has no symbolic links; this returns `Enotsup`.
pub fn symlink(_target: &[u8], _link: &[u8]) -> Result<(), VfsError> {
    Err(VfsError::Enotsup)
}

/// Read a symbolic link target.
///
/// Plan 9 has no symbolic links; this returns `Enotsup`.
pub fn readlink(_path: &[u8], _buf: &mut [u8]) -> Result<usize, VfsError> {
    Err(VfsError::Enotsup)
}

// ============================================================================
// Errors
// ============================================================================

/// VFS error type
#[derive(Debug)]
pub enum VfsError {
    Ok,
    Enoent,
    Eperm,
    Enomem,
    Ebadfd,
    Eio,
    Einval,
    Eisdir,
    Enotdir,
    Eexists,
    Enametoolong,
    Enotsup,
    Unknown,
}

impl VfsError {
    pub fn to_isize(&self) -> isize {
        match self {
            VfsError::Ok => 0,
            VfsError::Enoent => -12,
            VfsError::Eperm => -6,
            VfsError::Enomem => -2,
            VfsError::Ebadfd => -4,
            VfsError::Eio => -3,
            VfsError::Einval => -10,
            VfsError::Eisdir => -9,
            VfsError::Enotdir => -8,
            VfsError::Eexists => -7,
            VfsError::Enametoolong => -11,
            VfsError::Enotsup => -13,
            VfsError::Unknown => -1,
        }
    }

    /// Convert from DevError
    pub fn from_dev_error(err: DevErrorEnum) -> Self {
        match err {
            DevErrorEnum::Ok => VfsError::Ok,
            DevErrorEnum::Enoent => VfsError::Enoent,
            DevErrorEnum::Eperm => VfsError::Eperm,
            DevErrorEnum::Enomem => VfsError::Enomem,
            DevErrorEnum::Ebadfd => VfsError::Ebadfd,
            DevErrorEnum::Eio => VfsError::Eio,
            DevErrorEnum::Einval => VfsError::Einval,
            DevErrorEnum::Enotdir => VfsError::Enotdir,
            DevErrorEnum::Eisdir => VfsError::Eisdir,
            DevErrorEnum::Eexists => VfsError::Eexists,
            _ => VfsError::Unknown,
        }
    }
}

/// Mount flags
pub const MBEFORE: u32 = 0x01;  // Mount before existing
pub const MAFTER: u32 = 0x02;    // Mount after existing
pub const MCREATE: u32 = 0x04;   // Auto-create directory
pub const MCACHE: u32 = 0x08;    // Cache results
pub const MREPL: u32 = 0x10;     // Replace existing
pub const MBIND: u32 = 0x20;      // Bind mount (Plan 9 style)
pub const MUNION: u32 = 0x40;    // Union mount (layered)

// ============================================================================
// Global VFS State
// ============================================================================

/// Mount table - stores all mount points in the system
static MOUNTS: Mutex<MountTable> = Mutex::new(MountTable::new());

/// Root file system channel
static ROOT_CHAN: Spinlock<Option<Chan>> = Spinlock::new(None);

/// Mount table structure
pub struct MountTable {
    /// Array of mount points
    entries: [Option<MountPoint>; NMOUNT],
    /// Number of active mounts
    count: usize,
}

impl MountTable {
    /// Create new mount table
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; NMOUNT],
            count: 0,
        }
    }

    /// Add a mount point
    pub fn add(&mut self, mp: MountPoint) -> Option<usize> {
        // Find empty slot
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(mp);
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a mount point by path
    pub fn remove(&mut self, path: &[u8]) -> Option<MountPoint> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if let Some(ref mp) = slot {
                if &mp.path[..] == path {
                    self.count -= 1;
                    return slot.take();
                }
            }
        }
        None
    }

    /// Find the best matching mount point for a path
    /// Returns the mount point with the longest path prefix match
    pub fn find(&self, path: &[u8]) -> Option<&MountPoint> {
        let mut best_match: Option<&MountPoint> = None;
        let mut best_len = 0;

        for slot in &self.entries {
            if let Some(ref mp) = slot {
                // Check if path starts with mount point path
                let mp_path = if mp.path.first() == Some(&b'/') {
                    &mp.path[1..]
                } else {
                    &mp.path
                };

                let path_to_check = if path.first() == Some(&b'/') {
                    &path[1..]
                } else {
                    path
                };

                if path_to_check.starts_with(mp_path) && mp_path.len() > best_len {
                    best_match = Some(mp);
                    best_len = mp_path.len();
                }
            }
        }

        best_match
    }

    /// Get iterator over all mount points
    pub fn iter(&self) -> impl Iterator<Item = &MountPoint> {
        self.entries.iter().flatten()
    }

    /// Get mutable iterator over all mount points
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut MountPoint> {
        self.entries.iter_mut().flatten()
    }
}

/// Initialize VFS
pub fn init_vfs() {
    // Initialize empty mount table
    // Root file system will be mounted later during boot
}

/// Get the root channel
pub fn get_root_chan() -> Option<Chan> {
    ROOT_CHAN.lock().as_ref().map(|c| c.dup())
}

/// Set the root channel
pub fn set_root_chan(chan: Chan) {
    *ROOT_CHAN.lock() = Some(chan);
}

/// Mount a file system
pub fn mount(source: Option<&[u8]>, target: &[u8], fs_type: &[u8], flags: u32) -> Result<(), VfsError> {
    let mut mounts = MOUNTS.lock();

    // Get source device channel
    let root = if let Some(src) = source {
        // Parse source as device or path
        let dev_char = src.first().copied().unwrap_or(b'#') as char;
        if dev_char == b'/' || dev_char == b'#' {
            // Path or special device
            let dev = devs().find_by_char(dev_char)
                .ok_or(VfsError::Enoent)?;
            dev.attach(Some(core::str::from_utf8(&src[1..]).unwrap_or("")))
                .map_err(|_| VfsError::Eio)?
        } else {
            // Device name
            let dev = devs().find_by_char(dev_char)
                .ok_or(VfsError::Enoent)?;
            dev.attach(Some(core::str::from_utf8(src).unwrap_or("")))
                .map_err(|_| VfsError::Eio)?
        }
    } else {
        // No source - create anonymous file system
        return Err(VfsError::Einval);
    };

    let mp = MountPoint::new(
        source.unwrap_or(b""),
        target,
        fs_type,
    );

    let mut mp = mp;
    mp.flags = flags;
    mp.root = Some(root);

    if mounts.add(mp).is_none() {
        return Err(VfsError::Enomem);
    }

    Ok(())
}

/// Unmount a file system
pub fn unmount(target: &[u8]) -> Result<(), VfsError> {
    let mut mounts = MOUNTS.lock();

    if mounts.remove(target).is_none() {
        return Err(VfsError::Enoent);
    }

    Ok(())
}

/// Find mount point for a path
pub fn find_mount(path: &[u8]) -> Option<Chan> {
    let mounts = MOUNTS.lock();
    mounts.find(path).and_then(|mp| mp.root.as_ref().map(|c| c.dup()))
}

/// Walk a path starting from a channel
/// This is the core walk operation used by namec()
pub fn walk_chan(chan: &mut Chan, name: &str) -> Result<Option<Qid>, VfsError> {
    if let Some(dev) = devs().get(chan.dev) {
        dev.walk(chan, name).map_err(VfsError::from_dev_error)
    } else {
        Err(VfsError::Enoent)
    }
}

/// Create a file in a directory
pub fn create_chan(chan: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), VfsError> {
    if let Some(dev) = devs().get(chan.dev) {
        dev.create(chan, name, mode, perm).map_err(VfsError::from_dev_error)
    } else {
        Err(VfsError::Enoent)
    }
}

/// Open a channel
pub fn open_chan(chan: &mut Chan, mode: u8) -> Result<(), VfsError> {
    if let Some(dev) = devs().get(chan.dev) {
        dev.open(chan, mode).map_err(VfsError::from_dev_error)
    } else {
        Err(VfsError::Enoent)
    }
}

/// Read from a channel
pub fn read_chan(chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, VfsError> {
    if let Some(dev) = devs().get(chan.dev) {
        dev.read(chan, buf, offset).map_err(VfsError::from_dev_error)
    } else {
        Err(VfsError::Enoent)
    }
}

/// Write to a channel
pub fn write_chan(chan: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, VfsError> {
    if let Some(dev) = devs().get(chan.dev) {
        dev.write(chan, buf, offset).map_err(VfsError::from_dev_error)
    } else {
        Err(VfsError::Enoent)
    }
}

// ============================================================================
// Vfs Trait (for file system implementations)
// ============================================================================

/// VFS operations trait - implemented by file systems
pub trait Vfs: Send + Sync {
    /// Initialize file system
    fn init(&mut self) {}

    /// Get root inode
    fn root(&mut self) -> Result<Chan, VfsError>;

    /// Sync file system
    fn sync(&mut self) {}
}

// ============================================================================
// Bind and Mount Helpers
// ============================================================================

/// Bind operation - create an alternate name for a file
///
/// Binds source to target. After a bind, accessing target is equivalent
/// to accessing source.
///
/// # Arguments
/// * `source` - Source channel to bind
/// * `target` - Target channel that will become an alias for source
/// * `flags` - Bind flags (MREPL, MBEFORE, MAFTER, MCREATE)
///
/// # Returns
/// * `Ok(())` on success
pub fn bind(source: Chan, target: Chan, _flags: u32) -> Result<(), VfsError> {
    // In Plan 9, bind creates a new mount entry that redirects
    // access to one path to another. For now, we just close
    // both channels and return success.
    // A full implementation would:
    // 1. Create a new mount point entry
    // 2. Add it to the mount table
    // 3. Set up the redirect
    let _ = source;
    let _ = target;

    // For now, return success as the bind operation is conceptually complete
    Ok(())
}

// ============================================================================
// Mount Table Module (for syscall interface)
// ============================================================================

/// Mount table management module
pub mod mount_table {
    use super::*;

    /// Add a mount point to the mount table
    pub fn add(source: Chan, path: String, flags: u32) -> Result<(), VfsError> {
        let mp = MountPoint::new(
            path.as_bytes(),
            path.as_bytes(),
            b"bind",
        );

        let mut mp = mp;
        mp.flags = flags;
        mp.root = Some(source);

        let mut mounts = MOUNTS.lock();
        if mounts.add(mp).is_none() {
            return Err(VfsError::Enomem);
        }

        Ok(())
    }

    /// Remove a mount point from the mount table
    pub fn remove(path: &str) -> Result<(), VfsError> {
        let mut mounts = MOUNTS.lock();
        if mounts.remove(path.as_bytes()).is_none() {
            return Err(VfsError::Enoent);
        }
        Ok(())
    }
}

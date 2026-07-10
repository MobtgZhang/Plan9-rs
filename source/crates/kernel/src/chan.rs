//! Channel and VFS Core Structures
//!
//! Implements the core data structures for Plan 9's VFS layer:
//! - Ref: Reference counting with lock
//! - Path: Path tracking for channels
//! - Qid: Unique file identifier
//! - Mhead: Mount head for mount points
//! - Mount: Mount table entry
//! - Mnt: Mount multiplexer
//! - Mntcache: Mount cache
//! - Mntconn: Mount connection
//! - ChanFull: Extended channel structure
//!
//! Reference: sys/src/9/port/portdat.h

use alloc::vec::Vec;
use alloc::string::String;
use alloc::boxed::Box;
use crate::plan9_common::sync::{Spinlock, Mutex};

// Re-export Chan from dev module for convenience
pub use crate::dev::Chan;

// ============================================================================
// Qid - Unique File Identifier
// ============================================================================

/// Qid - unique file identifier
/// 
/// A Qid represents a file's identity across the file system.
/// The path is unique within a server, and the version changes
/// when the file is modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qid {
    /// Path (unique number within server)
    pub path: u64,
    /// Version (incremented on write)
    pub vers: u32,
    /// Type flags (directory, append-only, etc.)
    pub type_: u8,
}

impl Qid {
    /// Create new Qid
    pub fn new(path: u64, vers: u32, type_: u8) -> Self {
        Self { path, vers, type_ }
    }

    /// Empty Qid (zero values)
    pub fn empty() -> Self {
        Self { path: 0, vers: 0, type_: 0 }
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        (self.type_ & QID_TYPE_DIR) != 0
    }

    /// Check if this is a symlink
    pub fn is_link(&self) -> bool {
        (self.type_ & QID_TYPE_LINK) != 0
    }

    /// Check if this is an auth file
    pub fn is_auth(&self) -> bool {
        (self.type_ & QID_TYPE_AUTH) != 0
    }
}

/// Qid type flags
pub const QID_TYPE_NONE: u8 = 0;
pub const QID_TYPE_EXEC: u8 = 0x80;    // executable
pub const QID_TYPE_EXCL: u8 = 0x40;    // exclusive use
pub const QID_TYPE_APPEND: u8 = 0x20;  // append-only
pub const QID_TYPE_MOUNT: u8 = 0x10;   // mounted channel
pub const QID_TYPE_AUTH: u8 = 0x08;   // authentication file
pub const QID_TYPE_TMP: u8 = 0x04;     // temporary file
pub const QID_TYPE_LINK: u8 = 0x02;     // symbolic link
pub const QID_TYPE_FILE: u8 = 0x00;     // regular file
pub const QID_TYPE_DIR: u8 = 0x80;      // directory

// ============================================================================
// Ref - Reference Counting with Lock
// ============================================================================

/// Ref - Reference counting structure with embedded lock
/// 
/// In Plan 9, the Ref structure is used for reference counting with
/// an embedded lock. When ref reaches 0, the object can be freed.
/// The lock is also used to serialize access to the object itself.
#[derive(Debug)]
pub struct Ref {
    /// Reference count
    ref_: Mutex<i32>,
}

impl Ref {
    /// Create a new Ref with initial count of 1
    pub fn new() -> Self {
        Self {
            ref_: Mutex::new(1),
        }
    }

    /// Create a new Ref with specified initial count
    pub fn with_count(count: i32) -> Self {
        Self {
            ref_: Mutex::new(count),
        }
    }

    /// Increment reference count
    pub fn inc(&self) {
        *self.ref_.lock() += 1;
    }

    /// Decrement reference count, return new value
    pub fn dec(&self) -> i32 {
        let mut lock = self.ref_.lock();
        *lock -= 1;
        *lock
    }

    /// Get current reference count
    pub fn get(&self) -> i32 {
        *self.ref_.lock()
    }
}

impl Default for Ref {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Path - Path Tracking Structure
// ============================================================================

/// Maximum length for a path string
pub const PATH_MAXLEN: usize = 1024;

/// Maximum number of mount points in path history
pub const MAX_MTPT: usize = 16;

/// Path - Tracks path information for a channel
/// 
/// The Path structure maintains the full path string and a history
/// of mount points crossed to reach the current channel.
#[derive(Debug)]
pub struct Path {
    /// Reference count
    pub ref_: Ref,
    /// Path string (null-terminated)
    pub s: Vec<u8>,
    /// Length of path string (excluding null)
    pub len: usize,
    /// Allocated length of s
    pub alen: usize,
    /// Number of path elements
    pub mlen: usize,
    /// Number of allocated mtpt entries
    pub malen: usize,
    /// Mount point history (indices into mount table)
    pub mtpt: Vec<Option<usize>>,
}

impl Path {
    /// Create a new Path from a string
    pub fn new(s: &[u8]) -> Option<Self> {
        if s.len() >= PATH_MAXLEN {
            return None;
        }
        
        let len = s.len();
        let mut s_vec = s.to_vec();
        s_vec.push(0); // Null terminator
        
        let alen = s_vec.capacity();
        
        Some(Self {
            ref_: Ref::new(),
            s: s_vec,
            len,
            alen,
            mlen: 0,
            malen: MAX_MTPT,
            mtpt: Vec::with_capacity(MAX_MTPT),
        })
    }

    /// Create an empty path
    pub fn empty() -> Self {
        let mut s = Vec::new();
        s.push(0);
        Self {
            ref_: Ref::new(),
            s,
            len: 0,
            alen: 1,
            mlen: 0,
            malen: MAX_MTPT,
            mtpt: Vec::with_capacity(MAX_MTPT),
        }
    }

    /// Get the path as a string slice
    pub fn as_str(&self) -> &str {
        // Exclude null terminator
        core::str::from_utf8(&self.s[..self.len]).unwrap_or("")
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.ref_.inc();
    }

    /// Decrement reference count, return true if should be freed
    pub fn decref(&self) -> bool {
        self.ref_.dec() == 0
    }

    /// Add a mount point to the history
    pub fn add_mtpt(&mut self, mtpt_idx: Option<usize>) {
        if self.mlen < self.malen {
            while self.mtpt.len() <= self.mlen {
                self.mtpt.push(None);
            }
            self.mtpt[self.mlen] = mtpt_idx;
            self.mlen += 1;
        }
    }

    /// Get the last mount point index
    pub fn last_mtpt(&self) -> Option<usize> {
        if self.mlen > 0 {
            self.mtpt[self.mlen - 1]
        } else {
            None
        }
    }

    /// Concatenate path element
    pub fn append(&mut self, elem: &[u8]) -> bool {
        if self.len + elem.len() + 1 >= self.alen {
            return false; // Would exceed capacity
        }
        
        // Add '/' separator if not at root
        if self.len > 0 && self.s[0] != b'/' {
            self.s[self.len] = b'/';
            self.len += 1;
        }
        
        // Add element
        self.s[self.len..self.len + elem.len()].copy_from_slice(elem);
        self.len += elem.len();
        self.s[self.len] = b'\0';
        self.mlen += 1;
        
        true
    }

    /// Reset to empty path
    pub fn clear(&mut self) {
        self.len = 0;
        self.mlen = 0;
        if !self.s.is_empty() {
            self.s[0] = b'\0';
        }
    }
}

// ============================================================================
// Channel Flags
// ============================================================================

/// Channel flags
pub mod chanflag {
    /// Channel is open for I/O
    pub const COPEN: u32 = 0x0001;
    /// Message channel for a mount
    pub const CMSG: u32 = 0x0002;
    /// Close on exec
    pub const CCEXEC: u32 = 0x0008;
    /// Not in use (free)
    pub const CFREE: u32 = 0x0010;
    /// Remove on close
    pub const CRCLOSE: u32 = 0x0020;
    /// Client cache enabled
    pub const CCACHE: u32 = 0x0080;
    
    /// Check if channel is open
    pub fn is_open(flag: u32) -> bool {
        (flag & COPEN) != 0
    }
    
    /// Check if channel is free
    pub fn is_free(flag: u32) -> bool {
        (flag & CFREE) != 0
    }
}

// ============================================================================
// Access Types
// ============================================================================

/// Access types for namec()
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// As in stat, wstat
    Access,
    /// For left-hand-side of bind
    Bind,
    /// As in chdir
    Todir,
    /// For i/o
    Open,
    /// To be mounted or mounted upon
    Amount,
    /// Is to be created
    Acreate,
    /// Will be removed by caller
    Aremove,
}

impl AccessType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AccessType::Access,
            1 => AccessType::Bind,
            2 => AccessType::Todir,
            3 => AccessType::Open,
            4 => AccessType::Amount,
            5 => AccessType::Acreate,
            6 => AccessType::Aremove,
            _ => AccessType::Access,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            AccessType::Access => 0,
            AccessType::Bind => 1,
            AccessType::Todir => 2,
            AccessType::Open => 3,
            AccessType::Amount => 4,
            AccessType::Acreate => 5,
            AccessType::Aremove => 6,
        }
    }
}

// ============================================================================
// Mntcache - Mount Cache
// ============================================================================

/// Mount cache entry
/// 
/// Used to cache mount point lookups for improved performance.
#[derive(Debug)]
pub struct Mntcache {
    /// Mount ID
    pub mountid: u64,
    /// Mount point index
    pub mtpt: Option<usize>,
    /// Next in cache chain
    pub next: Option<Box<Mntcache>>,
}

impl Mntcache {
    /// Create a new Mntcache entry
    pub fn new(mountid: u64, mtpt: Option<usize>) -> Self {
        Self {
            mountid,
            mtpt,
            next: None,
        }
    }
}

/// Mount cache size
pub const NSCACHE: usize = 256;
/// Mount cache hash log
pub const NSLOG: usize = 7;

// ============================================================================
// Mntrpc - Mount RPC
// ============================================================================

/// Mntrpc - Mount RPC request
/// 
/// Represents a pending RPC request on a mount connection.
#[derive(Debug)]
pub struct Mntrpc {
    /// Request tag
    pub tag: u16,
    /// Request type
    pub rtype: u16,
    /// Request data
    pub data: Vec<u8>,
    /// Reply data
    pub reply: Vec<u8>,
    /// Error
    pub error: i32,
    /// Next in queue
    pub next: Option<Box<Mntrpc>>,
}

impl Mntrpc {
    /// Create a new Mntrpc
    pub fn new() -> Self {
        Self {
            tag: 0,
            rtype: 0,
            data: Vec::new(),
            reply: Vec::new(),
            error: 0,
            next: None,
        }
    }
}

// ============================================================================
// Mnt - Mount Multiplexer
// ============================================================================

/// Mnt - Mount multiplexer
/// 
/// The Mnt structure represents a mount connection, used for
/// 9P file service access. It maintains the RPC queue and
/// connection state.
#[derive(Debug)]
pub struct Mnt {
    /// Lock protecting this structure
    pub lock: Spinlock<()>,
    /// Mount ID
    pub id: u32,
    /// Reader in progress (process index)
    pub rip: Option<usize>,
    /// Queue of pending requests
    pub queue: Option<Box<Mntrpc>>,
    /// Cache flags
    pub flags: u32,
    /// Maximum message size
    pub msize: u32,
    /// 9P version string
    pub version: Vec<u8>,
}

impl Mnt {
    /// Create a new Mnt
    pub fn new(id: u32, msize: u32) -> Self {
        Self {
            lock: Spinlock::new(()),
            id,
            rip: None,
            queue: None,
            flags: 0,
            msize,
            version: b"9P2000".to_vec(),
        }
    }

    /// Add RPC to queue
    pub fn add_rpc(&mut self, mut rpc: Box<Mntrpc>) {
        rpc.next = self.queue.take();
        self.queue = Some(rpc);
    }

    /// Remove RPC from queue by tag
    pub fn remove_rpc(&mut self, tag: u16) -> Option<Box<Mntrpc>> {
        // First check if queue is empty
        if self.queue.is_none() {
            return None;
        }
        
        // Check if first element matches
        if let Some(ref first) = self.queue {
            if first.tag == tag {
                // Remove first element
                let first = self.queue.take().unwrap();
                let mut first = first; // Make mutable
                self.queue = first.next.take();
                return Some(first);
            }
        }
        
        // Search for the element
        let mut scan = &mut self.queue;
        while let Some(ref mut curr) = scan {
            if curr.next.as_ref().map(|n| n.tag == tag).unwrap_or(false) {
                // Found it - curr.next is the one to remove
                let next = curr.next.take().unwrap();
                let mut next = next; // Make mutable
                curr.next = next.next.take();
                return Some(next);
            }
            scan = &mut curr.next;
        }
        
        None
    }

    /// Check if there are pending RPCs
    pub fn has_pending(&self) -> bool {
        self.queue.is_some()
    }
}

// ============================================================================
// Mhead - Mount Head
// ============================================================================

/// Mount head - represents a mount point
/// 
/// Mhead is the "mount head" - the directory on which something
/// is mounted. Multiple mounts can share the same Mhead.
#[derive(Debug)]
pub struct Mhead {
    /// Reference count
    pub ref_: Ref,
    /// Lock for mount list
    pub lock: Spinlock<()>,
    /// Mount chain (indices into mount table)
    pub mount: Option<usize>,
    /// Hash chain for lookup
    pub hash: Option<usize>,
    /// Mount flags
    pub flags: u32,
}

impl Mhead {
    /// Create a new Mhead
    pub fn new() -> Self {
        Self {
            ref_: Ref::new(),
            lock: Spinlock::new(()),
            mount: None,
            hash: None,
            flags: 0,
        }
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.ref_.inc();
    }

    /// Decrement reference count
    pub fn decref(&self) -> i32 {
        self.ref_.dec()
    }
}

// ============================================================================
// Mount - Mount Table Entry
// ============================================================================

/// Mount flags
pub const MBEFORE: u32 = 0x01;   // Mount before existing
pub const MAFTER: u32 = 0x02;    // Mount after existing
pub const MCREATE: u32 = 0x04;   // Auto-create directory
pub const MCACHE: u32 = 0x08;    // Cache results
pub const MREPL: u32 = 0x10;     // Replace existing
pub const MBIND: u32 = 0x20;     // Bind mount (Plan 9 style)
pub const MUNION: u32 = 0x40;    // Union mount (layered)
pub const MCROSSMOUNT: u32 = 0x80; // Cross-mount (don't search further)

/// Mount - Mount table entry
/// 
/// Represents a single mount in the system. Each mount links
/// a source channel to a mount point (Mhead).
#[derive(Debug)]
pub struct Mount {
    /// Unique mount ID
    pub mountid: u64,
    /// Next mount in chain
    pub next: Option<usize>,
    /// Mount head index (mount point)
    pub head: Option<usize>,
    /// Copy of this mount
    pub copy: Option<usize>,
    /// Order for union mounts
    pub order: Option<usize>,
    /// Mount flags
    pub mflag: u32,
    /// Special specification
    pub spec: Vec<u8>,
}

impl Mount {
    /// Create a new Mount
    pub fn new(mflag: u32) -> Self {
        Self {
            mountid: 0, // Will be assigned by mount table
            next: None,
            head: None,
            copy: None,
            order: None,
            mflag,
            spec: Vec::new(),
        }
    }

    /// Check if this is a bind mount
    pub fn is_bind(&self) -> bool {
        (self.mflag & MBIND) != 0
    }

    /// Check if this is a union mount
    pub fn is_union(&self) -> bool {
        (self.mflag & MUNION) != 0
    }

    /// Check if this is a before mount
    pub fn is_before(&self) -> bool {
        (self.mflag & MBEFORE) != 0
    }

    /// Check if this is an after mount
    pub fn is_after(&self) -> bool {
        (self.mflag & MAFTER) != 0
    }
}

// ============================================================================
// Mntconn - Mount Connection (Client-side)
// ============================================================================

/// Mntconn - Mount connection (client-side representation)
/// 
/// Represents the client's view of a mount connection.
#[derive(Debug)]
pub struct Mntconn {
    /// Reference count
    pub ref_: Ref,
    /// The Mnt structure
    pub mnt: Option<Box<Mnt>>,
    /// Mount ID
    pub id: u32,
}

impl Mntconn {
    /// Create a new Mntconn
    pub fn new(mnt: Option<Box<Mnt>>, id: u32) -> Self {
        Self {
            ref_: Ref::new(),
            mnt,
            id,
        }
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.ref_.inc();
    }

    /// Decrement reference count
    pub fn decref(&self) -> i32 {
        self.ref_.dec()
    }
}

// ============================================================================
// Extended Chan - Full Plan 9 Channel Structure
// ============================================================================

/// Extended channel structure with all Plan 9 fields
/// 
/// This is the full Plan 9 Chan structure as defined in portdat.h.
/// It represents an open file or device.
pub struct ChanFull {
    /// Reference count (includes embedded lock)
    pub ref_: Ref,
    /// Lock protecting this channel
    pub lock: Spinlock<()>,
    /// Next channel in allocation list
    pub next: Option<Box<ChanFull>>,
    /// Link for various uses (walk clone, etc.)
    pub link: Option<Box<ChanFull>>,
    /// Offset in file
    pub offset: u64,
    /// Offset in underlying device
    pub devoffset: u64,
    /// Channel type (device-specific)
    pub chan_type: u16,
    /// Device number
    pub dev: u32,
    /// Open mode (read/write)
    pub mode: u16,
    /// Channel flags
    pub flag: u32,
    /// Unique file identifier
    pub qid: Qid,
    /// FID for devmnt
    pub fid: i32,
    /// I/O unit size (0 = default)
    pub iounit: u32,
    /// Union mount head index
    pub umh: Option<usize>,
    /// Union channel
    pub umc: Option<Box<ChanFull>>,
    /// Union read lock
    pub umqlock: Spinlock<()>,
    /// Union read index
    pub uri: i32,
    /// Devdirread index
    pub dri: i32,
    /// Directory entry rock for translations
    pub dirrock: Option<Vec<u8>>,
    /// Number of rock entries
    pub nrock: i32,
    /// Maximum rock entries
    pub mrock: i32,
    /// Lock for dirrock
    pub rockqlock: Spinlock<()>,
    /// Is this a mount point?
    pub ismtpt: bool,
    /// Mount cache pointer
    pub mcp: Option<Box<Mntcache>>,
    /// Multiplexer for clients
    pub mux: Option<Box<Mnt>>,
    /// Device-specific data
    pub aux: Option<Box<dyn Send + Sync>>,
    /// Mounted server channel
    pub mchan: Option<Box<ChanFull>>,
    /// Mount point root qid
    pub mqid: Qid,
    /// Path information
    pub path: Option<Box<Path>>,
}

impl ChanFull {
    /// Create a new ChanFull
    pub fn new(dev: u32, chan_type: u16, qid: Qid) -> Self {
        Self {
            ref_: Ref::new(),
            lock: Spinlock::new(()),
            next: None,
            link: None,
            offset: 0,
            devoffset: 0,
            chan_type,
            dev,
            mode: 0,
            flag: 0,
            qid,
            fid: 0,
            iounit: 0,
            umh: None,
            umc: None,
            umqlock: Spinlock::new(()),
            uri: 0,
            dri: 0,
            dirrock: None,
            nrock: 0,
            mrock: 0,
            rockqlock: Spinlock::new(()),
            ismtpt: false,
            mcp: None,
            mux: None,
            aux: None,
            mchan: None,
            mqid: Qid::empty(),
            path: None,
        }
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.ref_.inc();
    }

    /// Decrement reference count
    pub fn decref(&self) -> i32 {
        self.ref_.dec()
    }

    /// Check if channel is open
    pub fn is_open(&self) -> bool {
        chanflag::is_open(self.flag)
    }

    /// Check if channel is free
    pub fn is_free(&self) -> bool {
        chanflag::is_free(self.flag)
    }

    /// Set open flag
    pub fn set_open(&mut self, open: bool) {
        if open {
            self.flag |= chanflag::COPEN;
        } else {
            self.flag &= !chanflag::COPEN;
        }
    }

    /// Get the channel's path string
    pub fn path_string(&self) -> Option<String> {
        self.path.as_ref().map(|p| alloc::string::String::from(p.as_str()))
    }

    /// Set the path
    pub fn set_path(&mut self, path: Option<Box<Path>>) {
        self.path = path;
    }

    /// Lock the channel
    pub fn lock(&self) {
        let _ = self.lock.lock();
    }

    /// Unlock the channel
    pub fn unlock(&self) {
        // Spinlock unlocks automatically
    }
}

// ============================================================================
// Mount Table (Global)
// ============================================================================

/// Maximum number of mount points
pub const NMOUNT: usize = 256;

/// Mount table - manages all mount points
pub struct MountTable {
    /// Array of mount points
    mounts: [Option<Mount>; NMOUNT],
    /// Array of mount heads
    mheads: [Option<Mhead>; NMOUNT],
    /// Number of active mounts
    nmount: usize,
    /// Next mount ID
    next_mountid: u64,
}

impl MountTable {
    /// Create a new mount table
    pub fn new() -> Self {
        Self {
            mounts: [const { None }; NMOUNT],
            mheads: [const { None }; NMOUNT],
            nmount: 0,
            next_mountid: 1,
        }
    }

    /// Add a mount point
    pub fn add_mount(&mut self, m: Mount) -> Option<usize> {
        for (i, slot) in self.mounts.iter_mut().enumerate() {
            if slot.is_none() {
                let mut m = m;
                m.mountid = self.next_mountid;
                self.next_mountid += 1;
                *slot = Some(m);
                self.nmount += 1;
                return Some(i);
            }
        }
        None
    }

    /// Get a mount by index
    pub fn get_mount(&self, i: usize) -> Option<&Mount> {
        self.mounts.get(i).and_then(|m| m.as_ref())
    }

    /// Get a mount mutably by index
    pub fn get_mount_mut(&mut self, i: usize) -> Option<&mut Mount> {
        self.mounts.get_mut(i).and_then(|m| m.as_mut())
    }

    /// Add a mount head
    pub fn add_mhead(&mut self, m: Mhead) -> Option<usize> {
        for (i, slot) in self.mheads.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(m);
                return Some(i);
            }
        }
        None
    }

    /// Get a mount head by index
    pub fn get_mhead(&self, i: usize) -> Option<&Mhead> {
        self.mheads.get(i).and_then(|m| m.as_ref())
    }

    /// Get a mount head mutably by index
    pub fn get_mhead_mut(&mut self, i: usize) -> Option<&mut Mhead> {
        self.mheads.get_mut(i).and_then(|m| m.as_mut())
    }

    /// Get number of active mounts
    pub fn count(&self) -> usize {
        self.nmount
    }

    /// Find mount head by hash
    pub fn find_mhead_by_hash(&self, hash: usize) -> Option<&Mhead> {
        self.get_mhead(hash)
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Channel Pool (Allocation)
// ============================================================================

/// Channel allocation pool
pub struct ChanPool {
    /// Free list of channels
    free: Option<Box<ChanFull>>,
    /// Count of allocated channels
    allocated: usize,
}

impl ChanPool {
    /// Create a new channel pool
    pub fn new() -> Self {
        Self {
            free: None,
            allocated: 0,
        }
    }

    /// Allocate a new channel
    pub fn alloc(&mut self) -> Box<ChanFull> {
        if let Some(chan) = self.free.take() {
            return chan;
        }
        self.allocated += 1;
        Box::new(ChanFull::new(0, 0, Qid::empty()))
    }

    /// Free a channel
    pub fn free(&mut self, chan: Box<ChanFull>) {
        self.free = Some(chan);
    }

    /// Get number of allocated channels
    pub fn allocated(&self) -> usize {
        self.allocated
    }
}

impl Default for ChanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ChanFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanFull")
            .field("ref_", &self.ref_)
            .field("offset", &self.offset)
            .field("dev", &self.dev)
            .field("mode", &self.mode)
            .field("flag", &self.flag)
            .field("qid", &self.qid)
            .field("fid", &self.fid)
            .field("iounit", &self.iounit)
            .field("uri", &self.uri)
            .field("dri", &self.dri)
            .field("nrock", &self.nrock)
            .field("mrock", &self.mrock)
            .field("ismtpt", &self.ismtpt)
            .finish_non_exhaustive()
    }
}

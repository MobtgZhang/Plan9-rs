//! 9P Session Management
//!
//! Implements session management for 9P protocol including:
//! - FID pool management
//! - Tag table for pending requests
//! - Session state tracking

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::net::protocol::{P9Error, Stat, Qid};

// ============================================================================
// FID Pool
// ============================================================================

/// Maximum number of FIDs per session
const MAX_FIDS: usize = 4096;

/// Open mode for FID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    NotOpen,
    Read,
    Write,
    ReadWrite,
    Execute,
}

/// File information associated with a FID
#[derive(Debug, Clone)]
pub struct FidEntry {
    /// FID number
    pub fid: u32,
    /// QID of the file
    pub qid: Qid,
    /// Open mode
    pub mode: OpenMode,
    /// Current offset
    pub offset: u64,
    /// IO unit (maximum read/write without breaking into pieces)
    pub iounit: u32,
    /// Directory entries for walk results
    pub walk_qids: Vec<Qid>,
    /// Reference count
    pub refcount: u32,
    /// Accumulated path walked so far. Used to derive a stable Qid
    /// `path` field even without a real file-system backing store.
    pub path: String,
}

impl FidEntry {
    /// Create a new FID entry
    pub fn new(fid: u32, qid: Qid) -> Self {
        Self {
            fid,
            qid,
            mode: OpenMode::NotOpen,
            offset: 0,
            iounit: 0,
            walk_qids: Vec::new(),
            refcount: 1,
            path: String::new(),
        }
    }

    /// Clone with new FID
    pub fn clone_as(&self, new_fid: u32) -> Self {
        Self {
            fid: new_fid,
            qid: self.qid,
            mode: OpenMode::NotOpen,
            offset: 0,
            iounit: 0,
            walk_qids: self.walk_qids.clone(),
            refcount: 1,
            path: self.path.clone(),
        }
    }
}

/// FID pool - manages file identifiers
pub struct FidPool {
    /// FID entries
    entries: Vec<Option<FidEntry>>,
    /// Free FID list
    free_list: Vec<u32>,
    /// Next FID to allocate
    next_fid: u32,
}

impl FidPool {
    /// Create a new FID pool
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(MAX_FIDS);
        for _ in 0..MAX_FIDS {
            entries.push(None);
        }
        Self {
            entries,
            free_list: (0..MAX_FIDS as u32).collect(),
            next_fid: 0,
        }
    }

    /// Allocate a new FID
    pub fn alloc(&mut self, entry: FidEntry) -> Result<u32, P9Error> {
        let fid = self.free_list.pop()
            .ok_or(P9Error::new(24))? as usize; // ENFILE

        // Track high-water mark for diagnostics.
        if fid as u32 >= self.next_fid {
            self.next_fid = fid as u32 + 1;
        }

        if self.entries.len() <= fid {
            self.entries.resize(fid + 1, None);
        }

        self.entries[fid] = Some(entry);
        Ok(fid as u32)
    }

    /// Highest FID ever allocated (high-water mark).
    pub fn next_fid(&self) -> u32 {
        self.next_fid
    }

    /// Get FID entry
    pub fn get(&self, fid: u64) -> Option<&FidEntry> {
        let idx = fid as usize;
        if idx < self.entries.len() {
            self.entries[idx].as_ref()
        } else {
            None
        }
    }

    /// Get mutable FID entry
    pub fn get_mut(&mut self, fid: u64) -> Option<&mut FidEntry> {
        let idx = fid as usize;
        if idx < self.entries.len() {
            self.entries[idx].as_mut()
        } else {
            None
        }
    }

    /// Free a FID
    pub fn free(&mut self, fid: u32) {
        let idx = fid as usize;
        if idx < self.entries.len() {
            if self.entries[idx].is_some() {
                self.entries[idx] = None;
                self.free_list.push(fid);
            }
        }
    }

    /// Check if FID exists
    pub fn exists(&self, fid: u32) -> bool {
        let idx = fid as usize;
        idx < self.entries.len() && self.entries[idx].is_some()
    }

    /// Clone FID to new FID (for Twalk)
    pub fn clone_fid(&mut self, old_fid: u32, new_fid: u32) -> Result<(), P9Error> {
        let old_entry = self.get(old_fid as u64)
            .ok_or(P9Error::new(9))?; // EBADF
        
        let new_entry = old_entry.clone_as(new_fid);
        
        // Ensure entries array is large enough
        let idx = new_fid as usize;
        if self.entries.len() <= idx {
            self.entries.resize(idx + 1, None);
        }
        
        self.entries[idx] = Some(new_entry);
        Ok(())
    }
}

// ============================================================================
// Tag Table
// ============================================================================

/// Maximum number of tags
const MAX_TAGS: usize = 8192;

/// Pending request information
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Tag
    pub tag: u16,
    /// Message type
    pub msg_type: u8,
    /// FID (if applicable)
    pub fid: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
}

impl PendingRequest {
    pub fn new(tag: u16, msg_type: u8, fid: Option<u32>) -> Self {
        Self {
            tag,
            msg_type,
            fid,
            timestamp: 0,
        }
    }
}

/// Tag table for tracking pending requests
pub struct TagTable {
    /// Pending requests indexed by tag
    entries: Vec<Option<PendingRequest>>,
    /// Next tag to allocate
    next_tag: u16,
}

impl TagTable {
    /// Create a new tag table
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(MAX_TAGS);
        for _ in 0..MAX_TAGS {
            entries.push(None);
        }
        Self {
            entries,
            next_tag: 1, // Tag 0xFFFF is NO_TAG
        }
    }

    /// Allocate a tag for a pending request
    pub fn alloc(&mut self, request: PendingRequest) -> Result<u16, P9Error> {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        
        if self.next_tag == 0xFFFF {
            self.next_tag = 1;
        }
        
        let idx = tag as usize;
        if self.entries.len() <= idx {
            self.entries.resize(idx + 1, None);
        }
        
        self.entries[idx] = Some(request);
        Ok(tag)
    }

    /// Get pending request by tag
    pub fn get(&self, tag: u16) -> Option<&PendingRequest> {
        let idx = tag as usize;
        if idx < self.entries.len() {
            self.entries[idx].as_ref()
        } else {
            None
        }
    }

    /// Remove pending request
    pub fn remove(&mut self, tag: u16) {
        let idx = tag as usize;
        if idx < self.entries.len() {
            self.entries[idx] = None;
        }
    }

    /// Flush pending requests with tag >= oldtag
    pub fn flush(&mut self, oldtag: u16) {
        for entry in &mut self.entries {
            if let Some(req) = entry {
                if req.tag == oldtag {
                    *entry = None;
                }
            }
        }
    }
}

// ============================================================================
// Lock Manager (9P2000.e)
// ============================================================================

/// 9P2000.e lock types
pub const LOCK_TYPE_NONE: u8 = 0;
pub const LOCK_TYPE_READ: u8 = 1;
pub const LOCK_TYPE_WRITE: u8 = 2;
pub const LOCK_TYPE_RECLAIM: u8 = 3;

/// 9P2000.e lock flags
pub const LOCK_FLAGS_BLOCK: u32 = 1;
pub const LOCK_FLAGS_RECLAIM: u32 = 2;

/// Range covered by a single lock entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockRange {
    pub start: u64,
    pub length: u64,
}

impl LockRange {
    pub fn end(&self) -> u64 {
        if self.length == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.length)
        }
    }

    pub fn overlaps(&self, other: &LockRange) -> bool {
        let a_start = self.start;
        let a_end = self.end();
        let b_start = other.start;
        let b_end = other.end();
        a_start < b_end && b_start < a_end
    }
}

/// Single lock entry kept in the server lock table.
#[derive(Debug, Clone)]
pub struct LockEntry {
    pub lock_type: u8,
    pub range: LockRange,
    pub proc_id: Vec<u8>,
}

/// Maintains the per-FID lock table for 9P2000.e.
#[derive(Default)]
pub struct LockManager {
    locks: BTreeMap<u32, Vec<LockEntry>>,
}

impl LockManager {
    pub fn new() -> Self {
        Self { locks: BTreeMap::new() }
    }

    /// Attempt to acquire a lock on `fid`.
    ///
    /// Returns `Ok(true)` when the lock is granted (status 0 in the
    /// response), `Ok(false)` when a conflicting lock is held and the
    /// caller did not request blocking (status 1).
    pub fn acquire(
        &mut self,
        fid: u32,
        lock_type: u8,
        range: LockRange,
        proc_id: &[u8],
        flags: u32,
    ) -> bool {
        if lock_type == LOCK_TYPE_NONE {
            // LOCK_UN: drop all locks for this fid and return success.
            self.locks.remove(&fid);
            return true;
        }

        let existing = self.locks.entry(fid).or_default();

        // A reclaim takes precedence and replaces any existing locks for
        // the requested range.
        if flags & LOCK_FLAGS_RECLAIM != 0 || lock_type == LOCK_TYPE_RECLAIM {
            existing.retain(|e| !e.range.overlaps(&range));
            existing.push(LockEntry {
                lock_type,
                range,
                proc_id: proc_id.to_vec(),
            });
            return true;
        }

        // Check whether a conflicting write lock already covers the range.
        let conflict = existing.iter().any(|e| {
            e.range.overlaps(&range)
                && (e.lock_type == LOCK_TYPE_WRITE
                    || lock_type == LOCK_TYPE_WRITE)
        });
        if conflict {
            return false;
        }

        existing.push(LockEntry {
            lock_type,
            range,
            proc_id: proc_id.to_vec(),
        });
        true
    }

    /// Look up a lock that overlaps `range` for the given fid.
    pub fn get_lock(&self, fid: u32, lock_type: u8, range: LockRange) -> Option<LockEntry> {
        let entries = self.locks.get(&fid)?;
        entries
            .iter()
            .find(|e| e.range.overlaps(&range) && (lock_type == LOCK_TYPE_NONE || e.lock_type == lock_type))
            .cloned()
    }

    /// Drop all locks associated with `fid` (called from clunk).
    pub fn drop_fid(&mut self, fid: u32) {
        self.locks.remove(&fid);
    }
}

// ============================================================================
// QID Allocator
// ============================================================================

/// Thread-safe unique QID path generator. Replaces the previous
/// `static mut NEXT_PATH` pattern used inside the 9P server.
pub struct QidAllocator {
    next: AtomicU64,
}

impl QidAllocator {
    pub const fn new() -> Self {
        Self { next: AtomicU64::new(1) }
    }

    pub fn allocate(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Session State
// ============================================================================

/// 9P protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V9P2000,
    V9P2000L,
    V9P2000U,
    V9P2000E,
    V9P2000Sev,
    Unknown,
}

impl ProtocolVersion {
    pub fn from_str(s: &str) -> Self {
        match s {
            "9P2000" => Self::V9P2000,
            "9P2000.L" => Self::V9P2000L,
            "9P2000.U" | "9P2000.u" => Self::V9P2000U,
            "9P2000.E" | "9P2000.e" => Self::V9P2000E,
            "9P2000.Sev" => Self::V9P2000Sev,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V9P2000 => "9P2000",
            Self::V9P2000L => "9P2000.L",
            Self::V9P2000U => "9P2000.u",
            Self::V9P2000E => "9P2000.e",
            Self::V9P2000Sev => "9P2000.Sev",
            Self::Unknown => "unknown",
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    New,
    VersionNegotiated,
    Attached,
    Active,
    Error,
}

/// 9P session
pub struct P9Session {
    /// Session state
    pub state: SessionState,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Maximum message size
    pub msize: u32,
    /// FID pool
    pub fid_pool: FidPool,
    /// Tag table
    pub tag_table: TagTable,
    /// Lock manager (9P2000.e)
    pub lock_manager: LockManager,
    /// QID path allocator (replaces `static mut`)
    pub qid_alloc: QidAllocator,
    /// Authenticated user
    pub uname: Option<Vec<u8>>,
    /// Authenticated user's UID
    pub uid: Option<u32>,
    /// Root QID (after attach)
    pub root_qid: Option<Qid>,
    /// Current working QID
    pub dot_qid: Option<Qid>,
    /// Number of attached clients
    pub refcount: u32,
}

impl P9Session {
    /// Create a new session
    pub fn new(msize: u32) -> Self {
        Self {
            state: SessionState::New,
            version: ProtocolVersion::Unknown,
            msize,
            fid_pool: FidPool::new(),
            tag_table: TagTable::new(),
            lock_manager: LockManager::new(),
            qid_alloc: QidAllocator::new(),
            uname: None,
            uid: None,
            root_qid: None,
            dot_qid: None,
            refcount: 1,
        }
    }

    /// Negotiate protocol version
    pub fn negotiate_version(&mut self, version: &str, msize: u32) -> Result<(u32, String), P9Error> {
        let v = ProtocolVersion::from_str(version);
        if v == ProtocolVersion::Unknown {
            return Err(P9Error::new(22)); // EINVAL
        }
        
        // Use minimum of requested and supported msize
        let negotiated_msize = msize.min(self.msize);
        
        self.version = v;
        self.msize = negotiated_msize;
        self.state = SessionState::VersionNegotiated;
        
        // Return the negotiated version string
        Ok((negotiated_msize, v.as_str().to_string()))
    }

    /// Attach to file system
    pub fn attach(&mut self, fid: u32, uname: &str, _aname: &str) -> Result<Qid, P9Error> {
        // Create FID for root - type 0 for regular file
        let qid = Qid::new(0, 0, 0); // Root has qid 0,0,0
        let entry = FidEntry::new(fid, qid);
        
        self.fid_pool.alloc(entry)
            .map_err(|_| P9Error::new(24))?; // ENFILE
        
        self.uname = Some(uname.as_bytes().to_vec());
        self.root_qid = Some(qid);
        self.dot_qid = Some(qid);
        self.state = SessionState::Attached;
        
        Ok(qid)
    }

    /// Clone FID (for Twalk)
    pub fn clone_fid(&mut self, old_fid: u32, new_fid: u32) -> Result<(), P9Error> {
        self.fid_pool.clone_fid(old_fid, new_fid)
    }

    /// Get FID
    pub fn get_fid(&self, fid: u64) -> Option<&FidEntry> {
        self.fid_pool.get(fid)
    }

    /// Get mutable FID
    pub fn get_fid_mut(&mut self, fid: u64) -> Option<&mut FidEntry> {
        self.fid_pool.get_mut(fid)
    }

    /// Open FID
    pub fn open_fid(&mut self, fid: u32, mode: OpenMode, qid: Qid, iounit: u32) -> Result<(), P9Error> {
        let entry = self.fid_pool.get_mut(fid as u64)
            .ok_or(P9Error::new(9))?;
        
        entry.mode = mode;
        entry.qid = qid;
        entry.iounit = iounit;
        entry.offset = 0;
        
        Ok(())
    }

    /// Close FID (clunk)
    pub fn clunk_fid(&mut self, fid: u32) {
        // Drop any locks held on this FID before releasing it.
        self.lock_manager.drop_fid(fid);
        self.fid_pool.free(fid);
    }

    /// Walk FID (returns QIDs along path)
    ///
    /// Walks one path element at a time against a per-FID path string so
    /// that a subsequent `walk` resumes from where the previous one
    /// left off. Each component is converted to a Qid whose `path` is a
    /// small deterministic hash of the accumulated path. This is enough
    /// for testing the protocol's state machine; production code would
    /// forward the request to the file-tree layer.
    pub fn walk_fid(&mut self, fid: u32, names: &[String]) -> Result<Vec<Qid>, P9Error> {
        let mut qids = Vec::with_capacity(names.len());
        let fid_key = fid as u64;
        for name in names {
            // "." and "" are no-ops: the Qid matches the FID's current location.
            if name == "." || name.is_empty() {
                let entry = self.fid_pool.get(fid_key)
                    .ok_or_else(|| P9Error::new(9))?;
                qids.push(entry.qid);
                continue;
            }

            let entry = self.fid_pool.get_mut(fid_key)
                .ok_or_else(|| P9Error::new(9))?;

            // Append the component and hash to derive a stable path id.
            if !entry.path.is_empty() {
                entry.path.push('/');
            }
            entry.path.push_str(name);
            let path_id = stable_hash(&entry.path);
            entry.qid = Qid::new(path_id, 0, 0);
            qids.push(entry.qid);
        }
        Ok(qids)
    }

    /// Allocate a fresh Qid path id. Wraps `qid_alloc` so callers can stay
    /// independent of the allocator implementation.
    pub fn alloc_qid_path(&self) -> u64 {
        self.qid_alloc.allocate()
    }

    /// Acquire a 9P2000.e lock on `fid`. Returns `true` when the lock was
    /// granted (status 0), `false` when a conflicting lock is held and
    /// the caller did not request blocking.
    pub fn lock_fid(
        &mut self,
        fid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: &[u8],
        flags: u32,
    ) -> bool {
        self.lock_manager.acquire(
            fid,
            lock_type,
            LockRange { start, length },
            proc_id,
            flags,
        )
    }

    /// Look up an existing 9P2000.e lock for `fid`.
    pub fn get_lock_fid(
        &self,
        fid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
    ) -> Option<LockEntry> {
        self.lock_manager
            .get_lock(fid, lock_type, LockRange { start, length })
    }

    /// Read from FID
    pub fn read_fid(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, P9Error> {
        let entry = self.fid_pool.get_mut(fid as u64)
            .ok_or(P9Error::new(9))?;

        // Update offset
        entry.offset = offset;

        // Without a real backing store we cannot return data; report EOF
        // by returning an empty buffer (the caller treats this as 0 bytes
        // read).
        let _ = count;
        Ok(Vec::new())
    }

    /// Write to FID
    pub fn write_fid(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, P9Error> {
        let entry = self.fid_pool.get_mut(fid as u64)
            .ok_or(P9Error::new(9))?;

        // Update offset to reflect the write position.
        entry.offset = offset + data.len() as u64;
        Ok(data.len() as u32)
    }

    /// Stat FID
    ///
    /// Without a real file backing, returns a minimal Stat populated with
    /// the FID's accumulated path so clients can at least observe the
    /// name they walked to.
    pub fn stat_fid(&self, fid: u32) -> Result<Stat, P9Error> {
        let entry = self.fid_pool.get(fid as u64)
            .ok_or(P9Error::new(9))?;

        let mut stat = Stat::default();
        stat.name = entry.path.clone();
        stat.uid = "root".to_string();
        stat.gid = "root".to_string();
        Ok(stat)
    }

    /// Check if session is valid
    pub fn is_valid(&self) -> bool {
        self.state != SessionState::Error
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }
}

// ============================================================================
// QID Extension
// ============================================================================

/// Deterministic 64-bit FNV-1a hash used to derive Qid path identifiers
/// from accumulated walk paths. Stable across runs and platform-independent.
fn stable_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

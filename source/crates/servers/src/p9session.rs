//! 9P Session Management
//!
//! Implements session management for 9P protocol including:
//! - FID pool management
//! - Tag table for pending requests
//! - Session state tracking

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::plan9_common::types::Qid;
use crate::net::protocol::{P9Msg, P9Error, Stat};

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
        
        if self.entries.len() <= fid {
            self.entries.resize(fid + 1, None);
        }
        
        self.entries[fid] = Some(entry);
        Ok(fid as u32)
    }

    /// Get FID entry
    pub fn get(&self, fid: u32) -> Option<&FidEntry> {
        let idx = fid as usize;
        if idx < self.entries.len() {
            self.entries[idx].as_ref()
        } else {
            None
        }
    }

    /// Get mutable FID entry
    pub fn get_mut(&mut self, fid: u32) -> Option<&mut FidEntry> {
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
        let old_entry = self.get(old_fid)
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
// Session State
// ============================================================================

/// 9P protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V9P2000,
    V9P2000L,
    V9P2000U,
    V9P2000Sev,
    Unknown,
}

impl ProtocolVersion {
    pub fn from_str(s: &str) -> Self {
        match s {
            "9P2000" => Self::V9P2000,
            "9P2000.L" => Self::V9P2000L,
            "9P2000.U" => Self::V9P2000U,
            "9P2000.Sev" => Self::V9P2000Sev,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V9P2000 => "9P2000",
            Self::V9P2000L => "9P2000.L",
            Self::V9P2000U => "9P2000.U",
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
        // Create FID for root
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
    pub fn get_fid(&self, fid: u32) -> Option<&FidEntry> {
        self.fid_pool.get(fid)
    }

    /// Get mutable FID
    pub fn get_fid_mut(&mut self, fid: u32) -> Option<&mut FidEntry> {
        self.fid_pool.get_mut(fid)
    }

    /// Open FID
    pub fn open_fid(&mut self, fid: u32, mode: OpenMode, qid: Qid, iounit: u32) -> Result<(), P9Error> {
        let entry = self.fid_pool.get_mut(fid)
            .ok_or_else(|| P9Error::new(9))?;
        
        entry.mode = mode;
        entry.qid = qid;
        entry.iounit = iounit;
        entry.offset = 0;
        
        Ok(())
    }

    /// Close FID (clunk)
    pub fn clunk_fid(&mut self, fid: u32) {
        self.fid_pool.free(fid);
    }

    /// Walk FID (returns QIDs along path)
    pub fn walk_fid(&mut self, fid: u32, names: &[String]) -> Result<Vec<Qid>, P9Error> {
        // For a full implementation, this would walk the directory tree
        // For now, return empty QIDs
        let _ = fid;
        Ok(names.iter().map(|_| Qid::new(0, 0, 0)).collect())
    }

    /// Read from FID
    pub fn read_fid(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, P9Error> {
        let entry = self.fid_pool.get_mut(fid)
            .ok_or_else(|| P9Error::new(9))?;
        
        // Update offset
        entry.offset = offset;
        
        // For now, return empty data
        Ok(Vec::new())
    }

    /// Write to FID
    pub fn write_fid(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, P9Error> {
        let entry = self.fid_pool.get_mut(fid)
            .ok_or_else(|| P9Error::new(9))?;
        
        // Update offset
        entry.offset = offset;
        
        Ok(data.len() as u32)
    }

    /// Stat FID
    pub fn stat_fid(&self, fid: u32) -> Result<Stat, P9Error> {
        let _ = self.fid_pool.get(fid)
            .ok_or_else(|| P9Error::new(9))?;
        
        // Return default stat
        Ok(Stat::default())
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

impl Qid {
    /// Create a new QID for session
    pub fn new(path: u64, vers: u32, qtype: u8) -> Self {
        Self { qtype, vers, path }
    }
}

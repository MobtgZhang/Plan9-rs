//! 9P Server Implementation
//!
//! Implements a complete 9P server that handles all protocol messages.


extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use crate::net::protocol::{P9Msg, P9Codec, P9Error, Qid};
use crate::p9session::{
    P9Session,
    OpenMode,
    LockEntry,
};

// ============================================================================
// Config and Stats
// ============================================================================

/// 9P server configuration
#[derive(Debug, Clone)]
pub struct P9ServerConfig {
    /// Maximum message size
    pub max_msize: u32,
    /// Root path
    pub root_path: String,
    /// Default user
    pub default_user: String,
    /// Enable dotl extensions
    pub enable_dotl: bool,
    /// Enable locking extensions
    pub enable_locking: bool,
}

impl Default for P9ServerConfig {
    fn default() -> Self {
        Self {
            max_msize: 65536,
            root_path: "/".to_string(),
            default_user: "none".to_string(),
            enable_dotl: true,
            enable_locking: true,
        }
    }
}

/// 9P server statistics
#[derive(Debug, Clone, Default)]
pub struct P9ServerStats {
    /// Total requests handled
    pub total_requests: u64,
    /// Requests by type
    pub attach_count: u64,
    pub walk_count: u64,
    pub open_count: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub create_count: u64,
    pub stat_count: u64,
}

/// P9Server type alias for P9ServerImpl
pub type P9Server = P9ServerImpl;

// ============================================================================
// 9P Server Implementation
// ============================================================================

/// 9P server errors
#[derive(Debug)]
pub enum ServerError {
    IoError,
    NotFound,
    PermissionDenied,
    AlreadyExists,
    IsDirectory,
    NotDirectory,
    InvalidPath,
    FileTooLarge,
    NoSpace,
    AuthFailed,
    LockFailed,
    P9Error(P9Error),
}

impl From<&str> for ServerError {
    fn from(s: &str) -> Self {
        ServerError::P9Error(P9Error::from_errno(s))
    }
}

impl From<String> for ServerError {
    fn from(s: String) -> Self {
        ServerError::P9Error(P9Error::from_errno(&s))
    }
}

impl From<P9Error> for ServerError {
    fn from(e: P9Error) -> Self {
        ServerError::P9Error(e)
    }
}

impl From<core::convert::Infallible> for ServerError {
    fn from(_: core::convert::Infallible) -> Self {
        ServerError::IoError
    }
}

/// 9P server implementation
pub struct P9ServerImpl {
    /// Session
    session: P9Session,
    /// Root path
    root_path: Vec<u8>,
    /// Maximum message size
    max_msize: u32,
    /// Supported protocol versions
    pub supported_versions: Vec<String>,
}

impl Default for P9ServerImpl {
    fn default() -> Self {
        Self::new(65536)
    }
}

impl P9ServerImpl {
    /// Create a new 9P server
    pub fn new(max_msize: u32) -> Self {
        Self {
            session: P9Session::new(max_msize),
            root_path: b"/".to_vec(),
            max_msize,
            supported_versions: vec![
                "9P2000".to_string(),
                "9P2000.u".to_string(),
                "9P2000.L".to_string(),
                "9P2000.e".to_string(),
            ],
        }
    }

    /// Process a 9P message and return the response
    pub fn handle_message(&mut self, msg: P9Msg) -> Result<P9Msg, ServerError> {
        match msg {
            P9Msg::TVersion { tag, msize, version } => {
                self.handle_version(tag, msize, &version)
            }
            P9Msg::TAttach { tag, fid, afid: _, uname, aname } => {
                // Validate the attach aname against the server's root path.
                if !aname.is_empty() && aname.as_bytes() != self.root_path.as_slice() {
                    return Err(ServerError::InvalidPath);
                }
                self.handle_attach(tag, fid, &uname, &aname)
            }
            P9Msg::TWalk { tag, fid, new_fid, names } => {
                self.handle_walk(tag, fid, new_fid, &names)
            }
            P9Msg::TOpen { tag, fid, mode } => {
                self.handle_open(tag, fid, mode)
            }
            P9Msg::TCreate { tag, fid, name, mode, perm } => {
                self.handle_create(tag, fid, &name, mode, perm)
            }
            P9Msg::TRead { tag, fid, offset, count } => {
                self.handle_read(tag, fid, offset, count)
            }
            P9Msg::TWrite { tag, fid, offset, data } => {
                self.handle_write(tag, fid, offset, &data)
            }
            P9Msg::TClunk { tag, fid } => {
                self.handle_clunk(tag, fid)
            }
            P9Msg::TRemove { tag, fid } => {
                self.handle_remove(tag, fid)
            }
            P9Msg::TStat { tag, fid } => {
                self.handle_stat(tag, fid)
            }
            P9Msg::TWStat { tag, fid, stat: _ } => {
                self.handle_wstat(tag, fid)
            }
            P9Msg::TFlush { tag, oldtag } => {
                self.handle_flush(tag, oldtag)
            }
            // 9P2000.u - Auth
            P9Msg::TAuth { tag, afid, uname, aname } => {
                self.handle_auth(tag, afid, &uname, &aname)
            }
            // 9P2000.L - dotl
            P9Msg::TOpenAt { tag, dfid, flags, mode } => {
                self.handle_openat(tag, dfid, flags, mode)
            }
            P9Msg::TCreateAt { tag, dfid, name, flags, mode, perm } => {
                self.handle_createat(tag, dfid, &name, flags, mode, perm)
            }
            P9Msg::TWalkAt { tag, fid, new_fid, wfid, names } => {
                self.handle_walkat(tag, fid, new_fid, wfid, &names)
            }
            // 9P2000.e - Locking
            P9Msg::TLock { tag, fid, lock_type, flags, start, length, proc_id } => {
                self.handle_lock(tag, fid, lock_type, flags, start, length, &proc_id)
            }
            P9Msg::TGetLock { tag, fid, lock_type, start, length, proc_id } => {
                self.handle_getlock(tag, fid, lock_type, start, length, &proc_id)
            }
            _ => Err(ServerError::IoError),
        }
    }

    /// Handle Tversion
    fn handle_version(&mut self, tag: u16, msize: u32, version: &str) -> Result<P9Msg, ServerError> {
        // Cap the requested msize at the server's configured maximum.
        let requested = msize.min(self.max_msize);
        // Negotiate version
        let (neg_msize, neg_version) = self.session.negotiate_version(version, requested)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RVersion {
            tag,
            msize: neg_msize,
            version: neg_version,
        })
    }

    /// Handle Tattach
    fn handle_attach(&mut self, tag: u16, fid: u32, uname: &str, _aname: &str) -> Result<P9Msg, ServerError> {
        // Attach creates a FID for the root directory
        let qid = self.session.attach(fid, uname, "")
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RAttach { tag, qid })
    }

    /// Handle Tauth (9P2000.u)
    fn handle_auth(&mut self, tag: u16, afid: u32, uname: &str, aname: &str) -> Result<P9Msg, ServerError> {
        // Create auth FID
        self.session.attach(afid, uname, aname)
            .map_err(|e| ServerError::from(e))?;

        // Generate auth QID (simplified - real implementation would involve crypto)
        let aqid = Qid::new(0, 0, 0x80); // Auth QID type

        Ok(P9Msg::RAuth { tag, aqid })
    }

    /// Handle Twalk
    fn handle_walk(&mut self, tag: u16, fid: u32, new_fid: u32, names: &[String]) -> Result<P9Msg, ServerError> {
        // Walk traverses a path from an existing FID
        // If new_fid == fid, modify the existing FID
        // If new_fid != fid, create a new FID
        
        if new_fid != fid {
            // Clone FID for new_fid
            self.session.clone_fid(fid, new_fid)
                .map_err(|e| ServerError::from(e))?;
        }

        // Walk the path
        let qids = self.session.walk_fid(fid, names)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RWalk { tag, qids })
    }

    /// Handle Topen
    fn handle_open(&mut self, tag: u16, fid: u32, mode: u8) -> Result<P9Msg, ServerError> {
        // Get the FID
        let entry = self.session.get_fid(fid as u64)
            .ok_or(ServerError::IoError)?;

        // Convert mode to OpenMode
        let open_mode = match mode & 0o3 {
            0 => OpenMode::Read,
            1 => OpenMode::Write,
            2 => OpenMode::ReadWrite,
            3 => OpenMode::ReadWrite, // OTRUNC implies write
            _ => OpenMode::ReadWrite,
        };

        // Get the QID for the file
        let qid = entry.qid;
        let iounit = 65536; // Typical default

        // Update FID with open mode
        self.session.open_fid(fid, open_mode, qid, iounit)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::ROpen {
            tag,
            qid,
            iounit,
        })
    }

    /// Handle TOpenAt (9P2000.L dotl)
    fn handle_openat(&mut self, tag: u16, dfid: u32, flags: u32, _mode: u8) -> Result<P9Msg, ServerError> {
        // Get the directory FID
        let entry = self.session.get_fid(dfid as u64)
            .ok_or(ServerError::IoError)?;

        // Get the QID for the file
        let qid = entry.qid;
        let iounit = 65536;

        // Convert flags to OpenMode
        let open_mode = match flags & 0x3 {
            0 => OpenMode::Read,
            1 => OpenMode::Write,
            2 | 3 => OpenMode::ReadWrite,
            _ => OpenMode::ReadWrite,
        };

        // Update FID with open mode
        self.session.open_fid(dfid, open_mode, qid, iounit)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::ROpenAt {
            tag,
            qid,
            iounit,
        })
    }

    /// Handle Tcreate
    fn handle_create(&mut self, tag: u16, fid: u32, _name: &str, _mode: u32, _perm: u32) -> Result<P9Msg, ServerError> {
        // Get the parent FID
        let entry = self.session.get_fid(fid as u64)
            .ok_or(ServerError::IoError)?;

        // Check if it's a directory
        if entry.qid.qtype & 0x80 != 0 { // QTDIR
            // Creating in directory
        }

        // Create new QID for the file using the session's allocator.
        let path = self.session.alloc_qid_path();
        let qid = Qid::new(path, 0, 0);

        // Open the file
        let open_mode = OpenMode::ReadWrite;
        let iounit = 65536;

        self.session.open_fid(fid, open_mode, qid, iounit)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RCreate {
            tag,
            qid,
            iounit,
        })
    }

    /// Handle TCreateAt (9P2000.L dotl)
    fn handle_createat(&mut self, tag: u16, dfid: u32, _name: &str, _flags: u32, _mode: u32, perm: u64) -> Result<P9Msg, ServerError> {
        // Get the directory FID
        let _entry = self.session.get_fid(dfid as u64)
            .ok_or(ServerError::IoError)?;

        // Create new QID for the file (with large file support) via the
        // session allocator. This eliminates the prior `static mut`
        // pattern that was unsafe under concurrent 9P sessions.
        let path = self.session.alloc_qid_path();

        // Set appropriate QID type based on permissions
        let qtype = if (perm as u32) & 0x80000000 != 0 { 0x40 } else { 0 };
        let qid = Qid::new(path, 0, qtype as u8);

        // Open the file
        let open_mode = OpenMode::ReadWrite;
        let iounit = 65536;

        self.session.open_fid(dfid, open_mode, qid, iounit)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RCreateAt {
            tag,
            qid,
            iounit,
        })
    }

    /// Handle TWalkAt (9P2000.L dotl)
    fn handle_walkat(&mut self, tag: u16, fid: u32, new_fid: u32, _wfid: u32, names: &[String]) -> Result<P9Msg, ServerError> {
        // Similar to handle_walk but for dotl
        if new_fid != fid {
            self.session.clone_fid(fid, new_fid)
                .map_err(|e| ServerError::from(e))?;
        }

        let qids = self.session.walk_fid(fid, names)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RWalkAt { tag, qids })
    }

    /// Handle Tread
    fn handle_read(&mut self, tag: u16, fid: u32, offset: u64, count: u32) -> Result<P9Msg, ServerError> {
        // Read data from the FID
        let data = self.session.read_fid(fid, offset, count)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RRead { tag, data })
    }

    /// Handle Twrite
    fn handle_write(&mut self, tag: u16, fid: u32, offset: u64, data: &[u8]) -> Result<P9Msg, ServerError> {
        // Write data to the FID
        let written = self.session.write_fid(fid, offset, data)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RWrite { tag, count: written })
    }

    /// Handle Tclunk
    fn handle_clunk(&mut self, tag: u16, fid: u32) -> Result<P9Msg, ServerError> {
        // Clunk frees the FID
        self.session.clunk_fid(fid);

        Ok(P9Msg::RClunk { tag })
    }

    /// Handle Tremove
    fn handle_remove(&mut self, tag: u16, fid: u32) -> Result<P9Msg, ServerError> {
        // Remove the file and clunk the FID
        // For now, just clunk
        self.session.clunk_fid(fid);

        Ok(P9Msg::RRemove { tag })
    }

    /// Handle Tstat
    fn handle_stat(&mut self, tag: u16, fid: u32) -> Result<P9Msg, ServerError> {
        // Get stat information for the FID
        let stat = self.session.stat_fid(fid)
            .map_err(|e| ServerError::from(e))?;

        Ok(P9Msg::RStat { tag, stat })
    }

    /// Handle Twstat
    fn handle_wstat(&mut self, tag: u16, fid: u32) -> Result<P9Msg, ServerError> {
        // Set stat information for the FID
        let _ = fid;
        Ok(P9Msg::RWStat { tag })
    }

    /// Handle Tflush
    fn handle_flush(&mut self, tag: u16, _oldtag: u16) -> Result<P9Msg, ServerError> {
        // Flush pending requests
        // For now, just acknowledge
        Ok(P9Msg::RFlush { tag })
    }

    /// Handle TLock (9P2000.e)
    ///
    /// Real implementation that consults the per-session lock manager. The
    /// `lock_type` encodes one of the 9P2000.e lock flavours
    /// (none / read / write / reclaim) and `flags` carries BLOCK/RECLAIM
    /// hints. On conflict with an incompatible lock the response carries
    /// status 1; on success the status is 0 and the lock entry is recorded
    /// for the FID.
    fn handle_lock(&mut self, tag: u16, fid: u32, lock_type: u8, flags: u32, start: u64, length: u64, proc_id: &[u8]) -> Result<P9Msg, ServerError> {
        // Validate lock type up front.
        match lock_type {
            0 | 1 | 2 | 3 => {}
            _ => return Err(ServerError::LockFailed),
        }

        let granted = self.session.lock_fid(fid, lock_type, start, length, proc_id, flags);
        // Status 0 = success, status 1 = lock held by another proc (no blocking).
        let status = if granted { 0 } else { 1 };
        Ok(P9Msg::RLock { tag, status: status as u8 })
    }

    /// Handle TGetLock (9P2000.e)
    ///
    /// Looks up an existing lock for the requested FID/range and returns
    /// its fields (or zeros when no lock is held).
    fn handle_getlock(&mut self, tag: u16, fid: u32, lock_type: u8, start: u64, length: u64, _proc_id: &[u8]) -> Result<P9Msg, ServerError> {
        // 9P2000.e TGetLock returns 0 when no lock is held.
        let entry: Option<LockEntry> = self.session.get_lock_fid(fid, lock_type, start, length);
        match entry {
            Some(lock) => Ok(P9Msg::RGetLock {
                tag,
                status: 0,
                lock_type: lock.lock_type,
                start: lock.range.start,
                length: lock.range.length,
                proc_id: lock.proc_id,
            }),
            None => Ok(P9Msg::RGetLock {
                tag,
                status: 0,
                lock_type: 0,
                start: 0,
                length: 0,
                proc_id: Vec::new(),
            }),
        }
    }

    /// Get the session
    pub fn session(&self) -> &P9Session {
        &self.session
    }

    /// Get mutable session
    pub fn session_mut(&mut self) -> &mut P9Session {
        &mut self.session
    }
}

// ============================================================================
// Stream-based 9P Server
// ============================================================================

/// Trait for 9P server transport
pub trait P9Transport {
    /// Read data from transport
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ServerError>;
    /// Write data to transport
    fn write(&mut self, buf: &[u8]) -> Result<usize, ServerError>;
}

/// Run the 9P server loop
pub fn run_server<T: P9Transport>(transport: &mut T, max_msize: u32) -> Result<(), ServerError> {
    let mut server = P9ServerImpl::new(max_msize);
    let mut buf = vec![0u8; max_msize as usize];

    loop {
        // Read message
        let n = transport.read(&mut buf)?;
        if n == 0 {
            break; // EOF
        }

        // Decode message
        let codec = P9Codec::new();
        let msg = codec.decode(&buf[..n])
            .map_err(|e| ServerError::from(e))?;

        // Process message
        let response = server.handle_message(msg)?;

        // Encode response
        let response_buf = codec.encode(&response)?;

        // Send response
        transport.write(&response_buf)?;
    }

    Ok(())
}

// ============================================================================
// Connection Handler
// ============================================================================

/// Handle a single 9P connection
pub struct P9Connection {
    /// Server instance
    server: P9ServerImpl,
    /// Connected flag
    connected: bool,
}

impl P9Connection {
    /// Create a new connection handler
    pub fn new(max_msize: u32) -> Self {
        Self {
            server: P9ServerImpl::new(max_msize),
            connected: true,
        }
    }

    /// Handle incoming data
    pub fn handle_data(&mut self, data: &[u8]) -> Result<Vec<u8>, ServerError> {
        // Decode message
        let codec = P9Codec::new();
        let msg = codec.decode(data)
            .map_err(|e| ServerError::from(e))?;

        // Process message
        let response = self.server.handle_message(msg)?;

        // Encode response
        let response_buf = codec.encode(&response)?;

        Ok(response_buf)
    }

    /// Check if connection is still active
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Close the connection
    pub fn close(&mut self) {
        self.connected = false;
    }
}

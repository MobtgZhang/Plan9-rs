//! 9P Protocol Implementation
//!
//! Implements the Plan 9 9P protocol for file system communication.

#![no_std]

extern crate alloc;

use crate::common::{Qid, Result};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// 9P Constants
// ============================================================================

/// 9P protocol version
pub const P9_VERSION: u32 = 2;

/// 9P message types (following Plan 9 fcall.h specification)
pub mod msg_type {
    // T messages (requests)
    pub const TVERSION: u8 = 100;
    pub const TVERSION_TAG: u8 = 100;
    pub const TAUTH: u8 = 102;
    pub const TATTACH: u8 = 104;
    pub const TERROR: u8 = 106;
    pub const TFLUSH: u8 = 108;
    pub const TWALK: u8 = 110;
    pub const TOPEN: u8 = 112;
    pub const TCREATE: u8 = 114;
    pub const TREAD: u8 = 116;
    pub const TWRITE: u8 = 118;
    pub const TCLUNK: u8 = 120;
    pub const TREMOVE: u8 = 122;
    pub const TSTAT: u8 = 124;
    pub const TWSTAT: u8 = 126;

    // R messages (responses)
    pub const RVERSION: u8 = 101;
    pub const RAUTH: u8 = 103;
    pub const RATTACH: u8 = 105;
    pub const RERROR: u8 = 107;
    pub const RFLUSH: u8 = 109;
    pub const RWALK: u8 = 111;
    pub const ROPEN: u8 = 113;
    pub const RCREATE: u8 = 115;
    pub const RREAD: u8 = 117;
    pub const RWRITE: u8 = 119;
    pub const RCLUNK: u8 = 121;
    pub const RREMOVE: u8 = 123;
    pub const RSTAT: u8 = 125;
    pub const RWSTAT: u8 = 127;

    // Legacy aliases for compatibility
    pub const TFLUSH_LEGACY: u8 = 16;
    pub const RFLUSH_LEGACY: u8 = 17;
    pub const TWALK_LEGACY: u8 = 14;
    pub const RWALK_LEGACY: u8 = 15;
    pub const TCCLONE: u8 = 18;
    pub const RCCLONE: u8 = 19;
    pub const TWSTAT_LEGACY: u8 = 9;
    pub const RWSTAT_LEGACY: u8 = 25;

    // 9P2000.u - Auth extensions
    pub const TAUTH_U: u8 = 30;
    pub const RAUTH_U: u8 = 31;

    // 9P2000.L - Large file support (dotl)
    pub const TOPENAT: u8 = 80;
    pub const ROPENAT: u8 = 81;
    pub const TCCREATEAT: u8 = 82;
    pub const RCCREATEAT: u8 = 83;
    pub const TWALKAT: u8 = 84;
    pub const RWALKAT: u8 = 85;

    // 9P2000.e - Locking extensions
    pub const TLOCK: u8 = 90;
    pub const RLOCK: u8 = 91;
    pub const TGETLOCK: u8 = 92;
    pub const RGETLOCK: u8 = 93;

    // Version strings
    pub const VERSION_9P2000: &'static str = "9P2000";
    pub const VERSION_9P2000_U: &'static str = "9P2000.u";
    pub const VERSION_9P2000_L: &'static str = "9P2000.L";
    pub const VERSION_9P2000_E: &'static str = "9P2000.e";
}

/// File mode flags
pub mod mode {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const EXEC: u32 = 2;
    pub const EXCL: u32 = 0x20; // exclusive use
    pub const CEXEC: u32 = 0x40; // close on exec
    pub const RCLOSE: u32 = 0x80; // remove on close
    pub const APPEND: u32 = 0x10; // append only
    pub const DMDIR: u32 = 0x80000000;
    pub const DMAPPEND: u32 = 0x40000000;
    pub const DMEXCL: u32 = 0x20000000;
    pub const DMMOUNT: u32 = 0x10000000;
    pub const DMAUTH: u32 = 0x08000000;
    pub const DMTMP: u32 = 0x04000000;
    pub const DMREAD: u32 = 0x4;
    pub const DMWRITE: u32 = 0x2;
    pub const DMREADWRITE: u32 = 0x3;
    pub const DMEXEC: u32 = 0x1;
}

/// 9P stat structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Stat {
    pub size: u16,       // total byte count
    pub type_: u16,      // server type
    pub dev: u32,        // server subtype
    pub qid: StatQid,    // unique id from server
    pub mode: u32,       // permissions
    pub atime: u32,      // last access time
    pub mtime: u32,      // last modification time
    pub length: u64,     // file length
    pub name: [u8; 256], // file name
    pub uid: [u8; 128],  // owner name
    pub gid: [u8; 128],  // group name
    pub muid: [u8; 128], // last modifier name
}

impl Default for Stat {
    fn default() -> Self {
        Self {
            size: 0,
            type_: 0,
            dev: 0,
            qid: StatQid::new(),
            mode: 0,
            atime: 0,
            mtime: 0,
            length: 0,
            name: [0; 256],
            uid: [0; 128],
            gid: [0; 128],
            muid: [0; 128],
        }
    }
}

impl Stat {
    /// Create new stat
    pub fn new() -> Self {
        Self {
            size: 0,
            type_: 0,
            dev: 0,
            qid: StatQid::new(),
            mode: 0,
            atime: 0,
            mtime: 0,
            length: 0,
            name: [0; 256],
            uid: [0; 128],
            gid: [0; 128],
            muid: [0; 128],
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(255);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Set uid
    pub fn set_uid(&mut self, uid: &str) {
        let bytes = uid.as_bytes();
        let len = bytes.len().min(127);
        self.uid[..len].copy_from_slice(&bytes[..len]);
        self.uid[len] = 0;
    }

    /// Set gid
    pub fn set_gid(&mut self, gid: &str) {
        let bytes = gid.as_bytes();
        let len = bytes.len().min(127);
        self.gid[..len].copy_from_slice(&bytes[..len]);
        self.gid[len] = 0;
    }

    /// Calculate total size
    pub fn calc_size(&mut self) {
        let mut size: u16 = 0;
        size += 2 + 2 + 4; // size, type, dev
        size += 13; // qid
        size += 4 + 4 + 4 + 8; // mode, atime, mtime, length
                               // name
        let name_len = self.name.iter().position(|&c| c == 0).unwrap_or(256);
        size += 2 + name_len as u16;
        // uid
        let uid_len = self.uid.iter().position(|&c| c == 0).unwrap_or(128);
        size += 2 + uid_len as u16;
        // gid
        let gid_len = self.gid.iter().position(|&c| c == 0).unwrap_or(128);
        size += 2 + gid_len as u16;
        // muid
        let muid_len = self.muid.iter().position(|&c| c == 0).unwrap_or(128);
        size += 2 + muid_len as u16;

        self.size = size;
    }
}

/// Stat Qid (simplified version)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct StatQid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

impl StatQid {
    pub fn new() -> Self {
        Self {
            qtype: 0,
            version: 0,
            path: 0,
        }
    }

    pub fn from_qid(qid: Qid) -> Self {
        Self {
            qtype: qid.qtype,
            version: qid.vers,
            path: qid.path,
        }
    }
}

// ============================================================================
// 9P Message
// ============================================================================

/// 9P message types
#[derive(Debug, Clone)]
pub enum P9Msg {
    /// Version negotiation
    TVersion {
        tag: u16,
        msize: u32,
        version: String,
    },
    RVersion {
        tag: u16,
        msize: u32,
        version: String,
    },
    /// Attach
    TAttach {
        tag: u16,
        fid: u32,
        afid: u32,
        uname: String,
        aname: String,
    },
    RAttach {
        tag: u16,
        qid: Qid,
    },
    /// Walk
    TWalk {
        tag: u16,
        fid: u32,
        new_fid: u32,
        names: Vec<String>,
    },
    RWalk {
        tag: u16,
        qids: Vec<Qid>,
    },
    /// Open
    TOpen {
        tag: u16,
        fid: u32,
        mode: u8,
    },
    ROpen {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    /// Create
    TCreate {
        tag: u16,
        fid: u32,
        name: String,
        mode: u32,
        perm: u32,
    },
    RCreate {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    /// Read
    TRead {
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    },
    RRead {
        tag: u16,
        data: Vec<u8>,
    },
    /// Write
    TWrite {
        tag: u16,
        fid: u32,
        offset: u64,
        data: Vec<u8>,
    },
    RWrite {
        tag: u16,
        count: u32,
    },
    /// Clunk
    TClunk {
        tag: u16,
        fid: u32,
    },
    RClunk {
        tag: u16,
    },
    /// Remove
    TRemove {
        tag: u16,
        fid: u32,
    },
    RRemove {
        tag: u16,
    },
    /// Stat
    TStat {
        tag: u16,
        fid: u32,
    },
    RStat {
        tag: u16,
        stat: Stat,
    },
    /// WStat
    TWStat {
        tag: u16,
        fid: u32,
        stat: Stat,
    },
    RWStat {
        tag: u16,
    },
    /// Flush
    TFlush {
        tag: u16,
        oldtag: u16,
    },
    RFlush {
        tag: u16,
    },
    /// Error
    RError {
        tag: u16,
        ename: String,
    },
    // =========================================================================
    // 9P2000.u - Authentication Extensions
    // =========================================================================
    /// Auth - request authentication
    TAuth {
        tag: u16,
        afid: u32,
        uname: String,
        aname: String,
    },
    /// Auth response
    RAuth {
        tag: u16,
        aqid: Qid,
    },
    // =========================================================================
    // 9P2000.L - Large File Support (dotl)
    // =========================================================================
    /// Openat - open file relative to directory
    TOpenAt {
        tag: u16,
        dfid: u32,
        flags: u32,
        mode: u8,
    },
    /// OpenAt response
    ROpenAt {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    /// CreateAt - create file relative to directory
    TCreateAt {
        tag: u16,
        dfid: u32,
        name: String,
        flags: u32,
        mode: u32,
        perm: u64,
    },
    /// CreateAt response
    RCreateAt {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    /// WalkAt - walk relative to directory
    TWalkAt {
        tag: u16,
        fid: u32,
        new_fid: u32,
        wfid: u32,
        names: Vec<String>,
    },
    /// WalkAt response
    RWalkAt {
        tag: u16,
        qids: Vec<Qid>,
    },
    // =========================================================================
    // 9P2000.e - Locking Extensions
    // =========================================================================
    /// Lock - acquire file lock
    TLock {
        tag: u16,
        fid: u32,
        lock_type: u8,
        flags: u32,
        start: u64,
        length: u64,
        proc_id: Vec<u8>,
    },
    /// Lock response
    RLock {
        tag: u16,
        status: u8,
    },
    /// GetLock - check lock status
    TGetLock {
        tag: u16,
        fid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: Vec<u8>,
    },
    /// GetLock response
    RGetLock {
        tag: u16,
        status: u8,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: Vec<u8>,
    },
}

/// 9P protocol encoder/decoder
pub struct P9Codec;

impl P9Codec {
    /// Calculate message size
    pub fn msg_size(msg: &P9Msg) -> usize {
        match msg {
            P9Msg::TVersion {
                msize: _, version, ..
            } => 4 + 4 + 4 + version.len() + 1,
            P9Msg::RVersion {
                msize: _, version, ..
            } => 4 + 4 + 4 + version.len() + 1,
            P9Msg::TAttach { uname, aname, .. } => {
                4 + 4 + 4 + 4 + uname.len() + 1 + aname.len() + 1
            }
            P9Msg::RAttach { .. } => 4 + 13,
            P9Msg::TWalk { names, .. } => {
                4 + 4 + 4 + 4 + names.iter().map(|s| s.len() + 1).sum::<usize>()
            }
            P9Msg::RWalk { qids, .. } => 4 + 4 + qids.len() * 13,
            P9Msg::TOpen { .. } => 4 + 4 + 4 + 1,
            P9Msg::ROpen { .. } => 4 + 13 + 4,
            P9Msg::TCreate { name, .. } => 4 + 4 + 4 + name.len() + 1 + 4 + 4,
            P9Msg::RCreate { .. } => 4 + 13 + 4,
            P9Msg::TRead { .. } => 4 + 4 + 4 + 8 + 4,
            P9Msg::RRead { data, .. } => 4 + 4 + data.len(),
            P9Msg::TWrite { data, .. } => 4 + 4 + 4 + 8 + 4 + data.len(),
            P9Msg::RWrite { .. } => 4 + 4,
            P9Msg::TClunk { .. } => 4 + 4,
            P9Msg::RClunk { .. } => 4,
            P9Msg::TRemove { .. } => 4 + 4,
            P9Msg::RRemove { .. } => 4,
            P9Msg::TStat { .. } => 4 + 4,
            P9Msg::RStat { stat, .. } => 4 + stat.size as usize,
            P9Msg::TWStat { stat, .. } => 4 + 4 + stat.size as usize,
            P9Msg::RWStat { .. } => 4,
            P9Msg::TFlush { .. } => 4 + 4,
            P9Msg::RFlush { .. } => 4,
            P9Msg::RError { ename, .. } => 4 + 4 + ename.len() + 1,
            // 9P2000.u Auth
            P9Msg::TAuth { uname, aname, .. } => {
                4 + 4 + 4 + uname.len() + 1 + aname.len() + 1
            }
            P9Msg::RAuth { .. } => 4 + 13,
            // 9P2000.L dotl
            P9Msg::TOpenAt { .. } => 4 + 4 + 4 + 4 + 1,
            P9Msg::ROpenAt { .. } => 4 + 13 + 4,
            P9Msg::TCreateAt { name, .. } => 4 + 4 + 4 + 4 + name.len() + 1 + 4 + 4 + 8,
            P9Msg::RCreateAt { .. } => 4 + 13 + 4,
            P9Msg::TWalkAt { names, .. } => {
                4 + 4 + 4 + 4 + 4 + names.iter().map(|s| s.len() + 1).sum::<usize>()
            }
            P9Msg::RWalkAt { qids, .. } => 4 + 4 + qids.len() * 13,
            // 9P2000.e Locking
            P9Msg::TLock { proc_id, .. } => 4 + 4 + 1 + 4 + 8 + 8 + 4 + proc_id.len(),
            P9Msg::RLock { .. } => 4 + 1,
            P9Msg::TGetLock { proc_id, .. } => 4 + 4 + 1 + 8 + 8 + 4 + proc_id.len(),
            P9Msg::RGetLock { proc_id, .. } => 4 + 1 + 1 + 8 + 8 + 4 + proc_id.len(),
        }
    }

    /// Encode message to bytes
    pub fn encode(msg: &P9Msg, buf: &mut Vec<u8>) -> Result<()> {
        let size = Self::msg_size(msg) + 4; // +4 for size field

        match msg {
            P9Msg::TVersion {
                tag,
                msize,
                version,
            } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TVERSION);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&msize.to_le_bytes());
                buf.extend_from_slice(version.as_bytes());
                buf.push(0);
            }
            P9Msg::RVersion {
                tag,
                msize,
                version,
            } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RVERSION);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&msize.to_le_bytes());
                buf.extend_from_slice(version.as_bytes());
                buf.push(0);
            }
            P9Msg::TAttach {
                tag,
                fid,
                afid,
                uname,
                aname,
            } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TATTACH);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&afid.to_le_bytes());
                buf.extend_from_slice(uname.as_bytes());
                buf.push(0);
                buf.extend_from_slice(aname.as_bytes());
                buf.push(0);
            }
            P9Msg::RAttach { tag, qid } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RATTACH);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(qid.qtype);
                buf.extend_from_slice(&qid.vers.to_le_bytes());
                buf.extend_from_slice(&qid.path.to_le_bytes());
            }
            P9Msg::TWalk {
                tag,
                fid,
                new_fid,
                names,
            } => {
                let mut data = Vec::new();
                for name in names {
                    data.extend_from_slice(name.as_bytes());
                    data.push(0);
                }
                let size = 4 + 4 + 4 + 4 + 4 + data.len(); // recalculate
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TWALK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&new_fid.to_le_bytes());
                buf.extend_from_slice(&(names.len() as u32).to_le_bytes());
                buf.extend_from_slice(&data);
            }
            P9Msg::RWalk { tag, qids } => {
                let size = 4 + 4 + qids.len() * 13;
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RWALK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&(qids.len() as u32).to_le_bytes());
                for qid in qids {
                    buf.push(qid.qtype);
                    buf.extend_from_slice(&qid.vers.to_le_bytes());
                    buf.extend_from_slice(&qid.path.to_le_bytes());
                }
            }
            P9Msg::TOpen { tag, fid, mode } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TOPEN);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.push(*mode);
            }
            P9Msg::ROpen { tag, qid, iounit } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::ROPEN);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(qid.qtype);
                buf.extend_from_slice(&qid.vers.to_le_bytes());
                buf.extend_from_slice(&qid.path.to_le_bytes());
                buf.extend_from_slice(&iounit.to_le_bytes());
            }
            P9Msg::TRead {
                tag,
                fid,
                offset,
                count,
            } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TREAD);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&count.to_le_bytes());
            }
            P9Msg::RRead { tag, data } => {
                let size = 4 + 4 + 4 + data.len();
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RREAD);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                buf.extend_from_slice(data);
            }
            P9Msg::TWrite {
                tag,
                fid,
                offset,
                data,
            } => {
                let size = 4 + 4 + 4 + 8 + 4 + data.len();
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TWRITE);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                buf.extend_from_slice(data);
            }
            P9Msg::RWrite { tag, count } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RWRITE);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&count.to_le_bytes());
            }
            P9Msg::TClunk { tag, fid } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TCLUNK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
            }
            P9Msg::RClunk { tag } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RCLUNK);
                buf.extend_from_slice(&tag.to_le_bytes());
            }
            P9Msg::TRemove { tag, fid } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TREMOVE);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
            }
            P9Msg::RRemove { tag } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RREMOVE);
                buf.extend_from_slice(&tag.to_le_bytes());
            }
            P9Msg::TStat { tag, fid } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TSTAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
            }
            P9Msg::RStat { tag, stat } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RSTAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&stat.size.to_le_bytes());
                buf.extend_from_slice(&stat.type_.to_le_bytes());
                buf.extend_from_slice(&stat.dev.to_le_bytes());
                buf.push(stat.qid.qtype);
                buf.extend_from_slice(&stat.qid.version.to_le_bytes());
                buf.extend_from_slice(&stat.qid.path.to_le_bytes());
                buf.extend_from_slice(&stat.mode.to_le_bytes());
                buf.extend_from_slice(&stat.atime.to_le_bytes());
                buf.extend_from_slice(&stat.mtime.to_le_bytes());
                buf.extend_from_slice(&stat.length.to_le_bytes());
                // Names
                let name_len = stat.name.iter().position(|&c| c == 0).unwrap_or(256) as u16;
                buf.extend_from_slice(&name_len.to_le_bytes());
                buf.extend_from_slice(&stat.name[..name_len as usize]);
            }
            P9Msg::TWStat { tag, fid, stat } => {
                let size = 4 + 4 + 4 + stat.size as usize;
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TWSTAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&stat.size.to_le_bytes());
            }
            P9Msg::RWStat { tag } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RWSTAT);
                buf.extend_from_slice(&tag.to_le_bytes());
            }
            P9Msg::TFlush { tag, oldtag } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TFLUSH);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&oldtag.to_le_bytes());
            }
            P9Msg::RFlush { tag } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RFLUSH);
                buf.extend_from_slice(&tag.to_le_bytes());
            }
            P9Msg::RError { tag, ename } => {
                let len = ename.len() as u16 + 1;
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RERROR);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(ename.as_bytes());
                buf.push(0);
            }
            P9Msg::TCreate {
                tag,
                fid,
                name,
                mode,
                perm,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(name.as_bytes());
                data.push(0);
                let size = 4 + 4 + 4 + 4 + data.len() + 4 + 4;
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TCREATE);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&data);
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&perm.to_le_bytes());
            }
            P9Msg::RCreate { tag, qid, iounit } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RCREATE);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(qid.qtype);
                buf.extend_from_slice(&qid.vers.to_le_bytes());
                buf.extend_from_slice(&qid.path.to_le_bytes());
                buf.extend_from_slice(&iounit.to_le_bytes());
            }
            // 9P2000.u - Auth
            P9Msg::TAuth { tag, afid, uname, aname } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TAUTH);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&afid.to_le_bytes());
                buf.extend_from_slice(uname.as_bytes());
                buf.push(0);
                buf.extend_from_slice(aname.as_bytes());
                buf.push(0);
            }
            P9Msg::RAuth { tag, aqid } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RAUTH);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(aqid.qtype);
                buf.extend_from_slice(&aqid.vers.to_le_bytes());
                buf.extend_from_slice(&aqid.path.to_le_bytes());
            }
            // 9P2000.L - dotl OpenAt
            P9Msg::TOpenAt { tag, dfid, flags, mode } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::TOPENAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&dfid.to_le_bytes());
                buf.extend_from_slice(&flags.to_le_bytes());
                buf.push(*mode);
            }
            P9Msg::ROpenAt { tag, qid, iounit } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::ROPENAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(qid.qtype);
                buf.extend_from_slice(&qid.vers.to_le_bytes());
                buf.extend_from_slice(&qid.path.to_le_bytes());
                buf.extend_from_slice(&iounit.to_le_bytes());
            }
            // 9P2000.L - dotl CreateAt
            P9Msg::TCreateAt { tag, dfid, name, flags, mode, perm } => {
                let mut data = Vec::new();
                data.extend_from_slice(name.as_bytes());
                data.push(0);
                let msg_size = 4 + 4 + 4 + 4 + data.len() + 4 + 4 + 8;
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::TCCREATEAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&dfid.to_le_bytes());
                buf.extend_from_slice(&flags.to_le_bytes());
                buf.extend_from_slice(&data);
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&perm.to_le_bytes());
            }
            P9Msg::RCreateAt { tag, qid, iounit } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RCCREATEAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(qid.qtype);
                buf.extend_from_slice(&qid.vers.to_le_bytes());
                buf.extend_from_slice(&qid.path.to_le_bytes());
                buf.extend_from_slice(&iounit.to_le_bytes());
            }
            // 9P2000.L - dotl WalkAt
            P9Msg::TWalkAt { tag, fid, new_fid, wfid, names } => {
                let mut data = Vec::new();
                for name in names {
                    data.extend_from_slice(name.as_bytes());
                    data.push(0);
                }
                let msg_size = 4 + 4 + 4 + 4 + 4 + data.len();
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::TWALKAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.extend_from_slice(&new_fid.to_le_bytes());
                buf.extend_from_slice(&wfid.to_le_bytes());
                buf.extend_from_slice(&(names.len() as u32).to_le_bytes());
                buf.extend_from_slice(&data);
            }
            P9Msg::RWalkAt { tag, qids } => {
                let msg_size = 4 + 4 + qids.len() * 13;
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::RWALKAT);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&(qids.len() as u32).to_le_bytes());
                for qid in qids {
                    buf.push(qid.qtype);
                    buf.extend_from_slice(&qid.vers.to_le_bytes());
                    buf.extend_from_slice(&qid.path.to_le_bytes());
                }
            }
            // 9P2000.e - Locking
            P9Msg::TLock { tag, fid, lock_type, flags, start, length, proc_id } => {
                let msg_size = 4 + 4 + 1 + 4 + 8 + 8 + 4 + proc_id.len();
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::TLOCK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.push(*lock_type);
                buf.extend_from_slice(&flags.to_le_bytes());
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(&(proc_id.len() as u32).to_le_bytes());
                buf.extend_from_slice(proc_id);
            }
            P9Msg::RLock { tag, status } => {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
                buf.push(msg_type::RLOCK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(*status);
            }
            P9Msg::TGetLock { tag, fid, lock_type, start, length, proc_id } => {
                let msg_size = 4 + 4 + 1 + 8 + 8 + 4 + proc_id.len();
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::TGETLOCK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.extend_from_slice(&fid.to_le_bytes());
                buf.push(*lock_type);
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(&(proc_id.len() as u32).to_le_bytes());
                buf.extend_from_slice(proc_id);
            }
            P9Msg::RGetLock { tag, status, lock_type, start, length, proc_id } => {
                let msg_size = 4 + 1 + 1 + 8 + 8 + 4 + proc_id.len();
                buf.extend_from_slice(&(msg_size as u32).to_le_bytes());
                buf.push(msg_type::RGETLOCK);
                buf.extend_from_slice(&tag.to_le_bytes());
                buf.push(*status);
                buf.push(*lock_type);
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(&(proc_id.len() as u32).to_le_bytes());
                buf.extend_from_slice(proc_id);
            }
        }

        Ok(())
    }
}

// ============================================================================
// 9P Client
// ============================================================================

/// 9P client state
pub struct P9Client {
    /// Maximum message size
    msize: u32,
    /// Connected flag
    connected: bool,
    /// Next tag
    next_tag: u16,
}

impl P9Client {
    /// Create new client
    pub fn new(msize: u32) -> Self {
        Self {
            msize,
            connected: false,
            next_tag: 1,
        }
    }

    /// Get next tag
    fn next_tag(&mut self) -> u16 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == 0xFFFF {
            self.next_tag = 1;
        }
        tag
    }

    /// Start version negotiation
    pub fn version(&mut self, version: &str) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TVersion {
            tag,
            msize: self.msize,
            version: version.to_string(),
        }
    }

    /// Attach to file server
    pub fn attach(&mut self, fid: u32, uname: &str, aname: &str) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TAttach {
            tag,
            fid,
            afid: u32::MAX,
            uname: uname.to_string(),
            aname: aname.to_string(),
        }
    }

    /// Walk path
    pub fn walk(&mut self, fid: u32, new_fid: u32, names: &[&str]) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TWalk {
            tag,
            fid,
            new_fid,
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Open file
    pub fn open(&mut self, fid: u32, mode: u8) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TOpen { tag, fid, mode }
    }

    /// Create file
    pub fn create(&mut self, fid: u32, name: &str, mode: u32, perm: u32) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TCreate {
            tag,
            fid,
            name: name.to_string(),
            mode,
            perm,
        }
    }

    /// Read data
    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TRead {
            tag,
            fid,
            offset,
            count,
        }
    }

    /// Write data
    pub fn write(&mut self, fid: u32, offset: u64, data: Vec<u8>) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TWrite {
            tag,
            fid,
            offset,
            data,
        }
    }

    /// Clunk (close file)
    pub fn clunk(&mut self, fid: u32) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TClunk { tag, fid }
    }

    /// Remove file
    pub fn remove(&mut self, fid: u32) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TRemove { tag, fid }
    }

    /// Get stat
    pub fn stat(&mut self, fid: u32) -> P9Msg {
        let tag = self.next_tag();
        P9Msg::TStat { tag, fid }
    }

    /// Set connected state
    pub fn set_connected(&mut self, msize: u32) {
        self.msize = msize;
        self.connected = true;
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

// ============================================================================
// 9P Server
// ============================================================================

/// 9P server trait
pub trait P9Server {
    /// Handle version request
    fn version(&mut self, msize: u32, version: &str) -> (u32, String);
    /// Handle attach
    fn attach(&mut self, fid: u32, uname: &str, aname: &str) -> Result<Qid>;
    /// Handle walk
    fn walk(&mut self, fid: u32, new_fid: u32, names: &[String]) -> Result<Vec<Qid>>;
    /// Handle open
    fn open(&mut self, fid: u32, mode: u8) -> Result<(Qid, u32)>;
    /// Handle create
    fn create(&mut self, fid: u32, name: &str, mode: u32, perm: u32) -> Result<(Qid, u32)>;
    /// Handle read
    fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>>;
    /// Handle write
    fn write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32>;
    /// Handle clunk
    fn clunk(&mut self, fid: u32) -> Result<()>;
    /// Handle remove
    fn remove(&mut self, fid: u32) -> Result<()>;
    /// Handle stat
    fn stat(&mut self, fid: u32) -> Result<Stat>;
    /// Handle wstat
    fn wstat(&mut self, fid: u32, stat: &Stat) -> Result<()>;
}

// ============================================================================
// 9P Message Decoder
// ============================================================================

/// 9P protocol error
#[derive(Debug, Clone, Copy)]
pub struct P9Error {
    pub code: u32,
    pub message: &'static str,
}

impl P9Error {
    pub fn new(code: u32) -> Self {
        let message = match code {
            0 => "success",
            1 => "operation not permitted",
            2 => "no such file or directory",
            3 => "file not found",
            4 => "interrupted system call",
            5 => "input/output error",
            6 => "no such device or address",
            7 => "argument list too long",
            8 => "exec format error",
            9 => "bad file number",
            10 => "no child processes",
            11 => "resource temporarily unavailable",
            12 => "out of memory",
            13 => "permission denied",
            14 => "bad address",
            15 => "block device required",
            16 => "file exists",
            17 => "cross-device link",
            18 => "no such device",
            19 => "not a directory",
            20 => "is a directory",
            21 => "invalid argument",
            22 => "too many open files",
            23 => "text file busy",
            24 => "file too large",
            25 => "no space left on device",
            26 => "illegal seek",
            27 => "read-only file system",
            28 => "too many links",
            29 => "broken pipe",
            30 => "math argument out of domain",
            31 => "result too large",
            32 => "operation would block",
            33 => "operation now in progress",
            34 => "operation already in progress",
            35 => "socket operation on non-socket",
            36 => "destination address required",
            37 => "message too long",
            38 => "protocol wrong type",
            39 => "protocol not available",
            40 => "protocol not supported",
            41 => "operation not supported",
            42 => "protocol family not supported",
            43 => "address family not supported",
            44 => "address already in use",
            45 => "address not available",
            46 => "network is down",
            47 => "network unreachable",
            48 => "connection reset",
            49 => "connection aborted",
            50 => "connection reset by peer",
            51 => "no buffer space available",
            52 => "socket is connected",
            53 => "socket not connected",
            54 => "cannot send after socket shutdown",
            55 => "too many references",
            56 => "connection timed out",
            57 => "connection refused",
            58 => "host is down",
            59 => "host unreachable",
            60 => "operation already in progress",
            61 => "operation in progress",
            62 => "stale file handle",
            63 => "directory not empty",
            64 => "too many levels of symbolic links",
            65 => "identifier removed",
            66 => "no message of desired type",
            67 => "not a data message",
            68 => "value too large for data type",
            69 => "identifier removed",
            70 => "device not a stream",
            71 => "no data available",
            72 => "timer expired",
            73 => "stream ioctl not possible",
            74 => "out of streams resources",
            75 => "device not configured",
            76 => "advertise error",
            77 => "no such process",
            78 => "quota exceeded",
            79 => "unknown error",
            _ => "unknown error",
        };
        Self { code, message }
    }
}

/// Decoder for parsing 9P messages from wire format
pub struct P9Decoder;

impl P9Decoder {
    /// Decode a 9P message from bytes
    pub fn decode(buf: &[u8]) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35)); // EINVAL
        }

        // Read message size (4 bytes, little-endian)
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < size {
            return Err(P9Error::new(35));
        }

        // Read message type (1 byte)
        let msg_type = buf[4];

        // Read tag (2 bytes, little-endian)
        let tag = u16::from_le_bytes([buf[5], buf[6]]);

        // Parse based on message type
        match msg_type {
            msg_type::TVERSION => Self::decode_tversion(&buf[7..], tag),
            msg_type::RVERSION => Self::decode_rversion(&buf[7..], tag),
            msg_type::TATTACH => Self::decode_tattach(&buf[7..], tag),
            msg_type::RATTACH => Self::decode_rattach(&buf[7..], tag),
            msg_type::TWALK => Self::decode_twalk(&buf[7..], tag),
            msg_type::RWALK => Self::decode_rwalk(&buf[7..], tag),
            msg_type::TOPEN => Self::decode_topen(&buf[7..], tag),
            msg_type::ROPEN => Self::decode_ropen(&buf[7..], tag),
            msg_type::TCREATE => Self::decode_tcreate(&buf[7..], tag),
            msg_type::RCREATE => Self::decode_rcreate(&buf[7..], tag),
            msg_type::TREAD => Self::decode_tread(&buf[7..], tag),
            msg_type::RREAD => Self::decode_rread(&buf[7..], tag),
            msg_type::TWRITE => Self::decode_twrite(&buf[7..], tag),
            msg_type::RWRITE => Self::decode_rwrite(&buf[7..], tag),
            msg_type::TCLUNK => Self::decode_tclunk(&buf[7..], tag),
            msg_type::RCLUNK => Self::decode_rclunk(&buf[7..], tag),
            msg_type::TREMOVE => Self::decode_tremove(&buf[7..], tag),
            msg_type::RREMOVE => Self::decode_rremove(&buf[7..], tag),
            msg_type::TSTAT => Self::decode_tstat(&buf[7..], tag),
            msg_type::RSTAT => Self::decode_rstat(&buf[7..], tag),
            msg_type::TWSTAT => Self::decode_twstat(&buf[7..], tag),
            msg_type::RWSTAT => Self::decode_rwstat(&buf[7..], tag),
            msg_type::TFLUSH => Self::decode_tflush(&buf[7..], tag),
            msg_type::RFLUSH => Self::decode_rflush(&buf[7..], tag),
            // 9P2000.u - Auth
            msg_type::TAUTH_U => Self::decode_tauth(&buf[7..], tag),
            msg_type::RAUTH_U => Self::decode_rauth(&buf[7..], tag),
            // 9P2000.L - dotl
            msg_type::TOPENAT => Self::decode_topenat(&buf[7..], tag),
            msg_type::ROPENAT => Self::decode_ropenat(&buf[7..], tag),
            msg_type::TCCREATEAT => Self::decode_tcreateat(&buf[7..], tag),
            msg_type::RCCREATEAT => Self::decode_rcreateat(&buf[7..], tag),
            msg_type::TWALKAT => Self::decode_twalkat(&buf[7..], tag),
            msg_type::RWALKAT => Self::decode_rwalkat(&buf[7..], tag),
            // 9P2000.e - Locking
            msg_type::TLOCK => Self::decode_tlock(&buf[7..], tag),
            msg_type::RLOCK => Self::decode_rlock(&buf[7..], tag),
            msg_type::TGETLOCK => Self::decode_tgetlock(&buf[7..], tag),
            msg_type::RGETLOCK => Self::decode_rgetlock(&buf[7..], tag),
            _ => Err(P9Error::new(22)), // EINVAL
        }
    }

    /// Read a NUL-terminated string from buffer
    fn read_string(buf: &[u8]) -> Option<(&str, usize)> {
        let nul_pos = buf.iter().position(|&c| c == 0)?;
        let s = core::str::from_utf8(&buf[..nul_pos]).ok()?;
        Some((s, nul_pos + 1))
    }

    fn decode_tversion(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 5 {
            return Err(P9Error::new(35));
        }
        let msize = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let (version, _) = Self::read_string(&buf[4..]).ok_or_else(|| P9Error::new(35))?;
        Ok(P9Msg::TVersion {
            tag,
            msize,
            version: version.to_string(),
        })
    }

    fn decode_rversion(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 5 {
            return Err(P9Error::new(35));
        }
        let msize = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let (version, _) = Self::read_string(&buf[4..]).ok_or_else(|| P9Error::new(35))?;
        Ok(P9Msg::RVersion {
            tag,
            msize,
            version: version.to_string(),
        })
    }

    fn decode_tattach(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 12 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let afid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut offset = 8;

        let (uname, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
        offset += len;

        let (aname, _) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;

        Ok(P9Msg::TAttach {
            tag,
            fid,
            afid,
            uname: uname.to_string(),
            aname: aname.to_string(),
        })
    }

    fn decode_rattach(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 13 {
            return Err(P9Error::new(35));
        }
        let qid = Qid {
            qtype: buf[0],
            vers: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            path: u64::from_le_bytes([
                buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
            ]),
        };
        Ok(P9Msg::RAttach { tag, qid })
    }

    fn decode_twalk(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 12 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let new_fid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let nwname = u16::from_le_bytes([buf[8], buf[9]]) as usize;

        let mut offset = 10;
        let mut names = Vec::with_capacity(nwname);

        for _ in 0..nwname {
            let (name, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
            names.push(name.to_string());
            offset += len;
        }

        Ok(P9Msg::TWalk {
            tag,
            fid,
            new_fid,
            names,
        })
    }

    fn decode_rwalk(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let nwqid = u16::from_le_bytes([buf[0], buf[1]]) as usize;

        let mut offset = 2;
        let mut qids = Vec::with_capacity(nwqid);

        for _ in 0..nwqid {
            if buf.len() < offset + 13 {
                return Err(P9Error::new(35));
            }
            let qid = Qid {
                qtype: buf[offset],
                vers: u32::from_le_bytes([
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                    buf[offset + 4],
                ]),
                path: u64::from_le_bytes([
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                ]),
            };
            qids.push(qid);
            offset += 13;
        }

        Ok(P9Msg::RWalk { tag, qids })
    }

    fn decode_topen(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 5 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let mode = buf[4];
        Ok(P9Msg::TOpen { tag, fid, mode })
    }

    fn decode_ropen(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 17 {
            return Err(P9Error::new(35));
        }
        let qid = Qid {
            qtype: buf[0],
            vers: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            path: u64::from_le_bytes([
                buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
            ]),
        };
        let iounit = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        Ok(P9Msg::ROpen { tag, qid, iounit })
    }

    fn decode_tread(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 20 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let offset = u64::from_le_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(P9Msg::TRead {
            tag,
            fid,
            offset,
            count,
        })
    }

    fn decode_rread(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let data = buf[4..4 + count].to_vec();
        Ok(P9Msg::RRead { tag, data })
    }

    fn decode_twrite(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 20 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let offset = u64::from_le_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
        let data = buf[16..16 + count].to_vec();
        Ok(P9Msg::TWrite {
            tag,
            fid,
            offset,
            data,
        })
    }

    fn decode_rwrite(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(P9Msg::RWrite { tag, count })
    }

    fn decode_tclunk(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(P9Msg::TClunk { tag, fid })
    }

    fn decode_rclunk(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        let _ = buf;
        Ok(P9Msg::RClunk { tag })
    }

    fn decode_tremove(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(P9Msg::TRemove { tag, fid })
    }

    fn decode_rremove(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        let _ = buf;
        Ok(P9Msg::RRemove { tag })
    }

    fn decode_tstat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(P9Msg::TStat { tag, fid })
    }

    fn decode_rstat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        // Stat decoding is complex, return a default for now
        let _ = buf;
        Ok(P9Msg::RStat {
            tag,
            stat: Stat::default(),
        })
    }

    fn decode_twstat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 4 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(P9Msg::TWStat {
            tag,
            fid,
            stat: Stat::default(),
        })
    }

    fn decode_rwstat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        let _ = buf;
        Ok(P9Msg::RWStat { tag })
    }

    fn decode_tflush(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 2 {
            return Err(P9Error::new(35));
        }
        let oldtag = u16::from_le_bytes([buf[0], buf[1]]);
        Ok(P9Msg::TFlush { tag, oldtag })
    }

    fn decode_rflush(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        let _ = buf;
        Ok(P9Msg::RFlush { tag })
    }

    fn decode_tcreate(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 12 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let mut offset = 4;

        let (name, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
        offset += len;

        if buf.len() < offset + 8 {
            return Err(P9Error::new(35));
        }
        let perm = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let mode = buf[offset + 4];

        Ok(P9Msg::TCreate {
            tag,
            fid,
            name: name.to_string(),
            mode,
            perm,
        })
    }

    fn decode_rcreate(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 17 {
            return Err(P9Error::new(35));
        }
        let qid = Qid {
            qtype: buf[0],
            vers: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            path: u64::from_le_bytes([
                buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
            ]),
        };
        let iounit = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        Ok(P9Msg::RCreate { tag, qid, iounit })
    }

    // =========================================================================
    // 9P2000.u - Auth Extensions
    // =========================================================================
    fn decode_tauth(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 12 {
            return Err(P9Error::new(35));
        }
        let afid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let mut offset = 4;

        let (uname, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
        offset += len;

        let (aname, _) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;

        Ok(P9Msg::TAuth {
            tag,
            afid,
            uname: uname.to_string(),
            aname: aname.to_string(),
        })
    }

    fn decode_rauth(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 13 {
            return Err(P9Error::new(35));
        }
        let aqid = Qid {
            qtype: buf[0],
            vers: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            path: u64::from_le_bytes([
                buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
            ]),
        };
        Ok(P9Msg::RAuth { tag, aqid })
    }

    // =========================================================================
    // 9P2000.L - dotl Extensions
    // =========================================================================
    fn decode_topenat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 13 {
            return Err(P9Error::new(35));
        }
        let dfid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let flags = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mode = buf[8];
        Ok(P9Msg::TOpenAt { tag, dfid, flags, mode })
    }

    fn decode_ropenat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 17 {
            return Err(P9Error::new(35));
        }
        let qid = Qid {
            qtype: buf[0],
            vers: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            path: u64::from_le_bytes([
                buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
            ]),
        };
        let iounit = u32::from_le_bytes([buf[13], buf[14], buf[15], buf[16]]);
        Ok(P9Msg::ROpenAt { tag, qid, iounit })
    }

    fn decode_tcreateat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 16 {
            return Err(P9Error::new(35));
        }
        let dfid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let flags = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut offset = 8;

        let (name, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
        offset += len;

        if buf.len() < offset + 12 {
            return Err(P9Error::new(35));
        }
        let mode = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        offset += 4;
        let perm = u64::from_le_bytes([
            buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
            buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
        ]);

        Ok(P9Msg::TCreateAt {
            tag,
            dfid,
            name: name.to_string(),
            flags,
            mode,
            perm,
        })
    }

    fn decode_rcreateat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        Self::decode_ropenat(buf, tag)
    }

    fn decode_twalkat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 16 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let new_fid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let wfid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let nwname = u16::from_le_bytes([buf[12], buf[13]]) as usize;

        let mut offset = 14;
        let mut names = Vec::with_capacity(nwname);

        for _ in 0..nwname {
            let (name, len) = Self::read_string(&buf[offset..]).ok_or_else(|| P9Error::new(35))?;
            names.push(name.to_string());
            offset += len;
        }

        Ok(P9Msg::TWalkAt {
            tag,
            fid,
            new_fid,
            wfid,
            names,
        })
    }

    fn decode_rwalkat(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        Self::decode_rwalk(buf, tag).map(|msg| match msg {
            P9Msg::RWalk { tag, qids } => P9Msg::RWalkAt { tag, qids },
            _ => P9Msg::RWalkAt { tag, qids: Vec::new() },
        })
    }

    // =========================================================================
    // 9P2000.e - Locking Extensions
    // =========================================================================
    fn decode_tlock(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 25 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let lock_type = buf[4];
        let flags = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let start = u64::from_le_bytes([
            buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
        ]);
        let length = u64::from_le_bytes([
            buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24],
        ]);
        let proc_id_len = u32::from_le_bytes([buf[25], buf[26], buf[27], buf[28]]) as usize;

        if buf.len() < 29 + proc_id_len {
            return Err(P9Error::new(35));
        }
        let proc_id = buf[29..29 + proc_id_len].to_vec();

        Ok(P9Msg::TLock {
            tag,
            fid,
            lock_type,
            flags,
            start,
            length,
            proc_id,
        })
    }

    fn decode_rlock(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 1 {
            return Err(P9Error::new(35));
        }
        let status = buf[0];
        Ok(P9Msg::RLock { tag, status })
    }

    fn decode_tgetlock(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 33 {
            return Err(P9Error::new(35));
        }
        let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let lock_type = buf[4];
        let start = u64::from_le_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        let length = u64::from_le_bytes([
            buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20],
        ]);
        let proc_id_len = u32::from_le_bytes([buf[21], buf[22], buf[23], buf[24]]) as usize;

        if buf.len() < 25 + proc_id_len {
            return Err(P9Error::new(35));
        }
        let proc_id = buf[25..25 + proc_id_len].to_vec();

        Ok(P9Msg::TGetLock {
            tag,
            fid,
            lock_type,
            start,
            length,
            proc_id,
        })
    }

    fn decode_rgetlock(buf: &[u8], tag: u16) -> Result<P9Msg, P9Error> {
        if buf.len() < 26 {
            return Err(P9Error::new(35));
        }
        let status = buf[0];
        let lock_type = buf[1];
        let start = u64::from_le_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        let length = u64::from_le_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]);
        let proc_id_len = u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]) as usize;

        if buf.len() < 22 + proc_id_len {
            return Err(P9Error::new(35));
        }
        let proc_id = buf[22..22 + proc_id_len].to_vec();

        Ok(P9Msg::RGetLock {
            tag,
            status,
            lock_type,
            start,
            length,
            proc_id,
        })
    }
}

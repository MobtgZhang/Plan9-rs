//! Network protocol module for 9P servers.
//!
//! Provides the complete 9P protocol types (P9Msg, P9Error, Stat, P9Codec) used by
//! the server module. This implements the full 9P2000 protocol with extensions
//! for 9P2000.L (dotl) and 9P2000.e (locking).


pub mod protocol {
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    
    use core::convert::TryFrom;

    // ============================================================================
    // P9Error
    // ============================================================================

    /// 9P error code.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct P9Error(pub u32);

    impl P9Error {
        pub fn new(code: u32) -> Self {
            Self(code)
        }

        pub fn code(&self) -> u32 {
            self.0
        }

        pub fn from_errno(ename: &str) -> Self {
            match ename {
                "unknown" => Self(0),
                "eperm" => Self(1),
                "enoent" => Self(2),
                "esrch" => Self(3),
                "eintr" => Self(4),
                "eio" => Self(5),
                "enxio" => Self(6),
                "e2big" => Self(7),
                "enoexec" => Self(8),
                "ebadf" => Self(9),
                "echild" => Self(10),
                "enomem" => Self(12),
                "eacces" => Self(13),
                "efault" => Self(14),
                "enotblk" => Self(15),
                "ebusy" => Self(16),
                "eexist" => Self(17),
                "exdev" => Self(18),
                "enodev" => Self(19),
                "enotdir" => Self(20),
                "eisdir" => Self(21),
                "einval" => Self(22),
                "enfile" => Self(24),
                "emfile" => Self(25),
                "enotty" => Self(25),
                "etxtbsy" => Self(26),
                "efbig" => Self(27),
                "enospc" => Self(28),
                "espipe" => Self(29),
                "erofs" => Self(30),
                "emlink" => Self(31),
                "epipe" => Self(32),
                "edoms" => Self(33),
                "erange" => Self(34),
                _ => Self(0),
            }
        }
    }

    impl TryFrom<u32> for P9Error {
        type Error = ();
        fn try_from(v: u32) -> Result<Self, Self::Error> {
            Ok(Self(v))
        }
    }

    // ============================================================================
    // Stat Structure (9P Directory Entry)
    // ============================================================================

    /// Stat structure for Tstat/Rstat messages.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Stat {
        pub name: String,
        pub uid: String,
        pub gid: String,
        pub muid: String,
        pub mode: u32,
        pub atime: u32,
        pub mtime: u32,
        pub length: u64,
        pub n_uid: u32,
        pub n_gid: u32,
        pub n_muid: u32,
    }

    impl Stat {
        pub fn new(name: &str, length: u64) -> Self {
            Self {
                name: name.to_string(),
                uid: "none".to_string(),
                gid: "none".to_string(),
                muid: "none".to_string(),
                mode: 0o644,
                atime: 0,
                mtime: 0,
                length,
                n_uid: 0,
                n_gid: 0,
                n_muid: 0,
            }
        }
    }

    // ============================================================================
    // QID Structure
    // ============================================================================

    /// QID represents a file's unique identifier in 9P.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Qid {
        pub qtype: u8,
        pub vers: u32,
        pub path: u64,
    }

    impl Qid {
        pub fn new(path: u64, vers: u32, qtype: u8) -> Self {
            Self { qtype, vers, path }
        }

        pub fn to_bytes(&self) -> [u8; 13] {
            let mut b = [0u8; 13];
            b[0] = self.qtype;
            b[1..5].copy_from_slice(&self.vers.to_le_bytes());
            b[5..13].copy_from_slice(&self.path.to_le_bytes());
            b
        }

        pub fn from_bytes(b: &[u8; 13]) -> Self {
            Self {
                qtype: b[0],
                vers: u32::from_le_bytes([b[1], b[2], b[3], b[4]]),
                path: u64::from_le_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]),
            }
        }

        pub fn is_dir(&self) -> bool {
            (self.qtype & 0x80) != 0
        }
    }

    pub mod qidtype {
        pub const DIR: u8 = 0x80;
        pub const APPEND: u8 = 0x40;
        pub const EXCL: u8 = 0x20;
        pub const MOUNT: u8 = 0x10;
        pub const AUTH: u8 = 0x08;
        pub const TRUNCATE: u8 = 0x04;
        pub const RDONLY: u8 = 0x02;
        pub const PIPE: u8 = 0x01;
    }

    // ============================================================================
    // P9Msg
    // ============================================================================

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[repr(u8)]
    pub enum P9Msg {
        TVersion { tag: u16, msize: u32, version: String },
        RVersion { tag: u16, msize: u32, version: String },
        TAuth { tag: u16, afid: u32, uname: String, aname: String },
        RAuth { tag: u16, aqid: Qid },
        TAttach { tag: u16, fid: u32, afid: u32, uname: String, aname: String },
        RAttach { tag: u16, qid: Qid },
        TWalk { tag: u16, fid: u32, new_fid: u32, names: Vec<String> },
        RWalk { tag: u16, qids: Vec<Qid> },
        TOpen { tag: u16, fid: u32, mode: u8 },
        ROpen { tag: u16, qid: Qid, iounit: u32 },
        TCreate { tag: u16, fid: u32, name: String, mode: u32, perm: u32 },
        RCreate { tag: u16, qid: Qid, iounit: u32 },
        TRead { tag: u16, fid: u32, offset: u64, count: u32 },
        RRead { tag: u16, data: Vec<u8> },
        TWrite { tag: u16, fid: u32, offset: u64, data: Vec<u8> },
        RWrite { tag: u16, count: u32 },
        TClunk { tag: u16, fid: u32 },
        RClunk { tag: u16 },
        TRemove { tag: u16, fid: u32 },
        RRemove { tag: u16 },
        TStat { tag: u16, fid: u32 },
        RStat { tag: u16, stat: Stat },
        TWStat { tag: u16, fid: u32, stat: Stat },
        RWStat { tag: u16 },
        TFlush { tag: u16, oldtag: u16 },
        RFlush { tag: u16 },
        TOpenAt { tag: u16, dfid: u32, flags: u32, mode: u8 },
        ROpenAt { tag: u16, qid: Qid, iounit: u32 },
        TCreateAt { tag: u16, dfid: u32, name: String, flags: u32, mode: u32, perm: u64 },
        RCreateAt { tag: u16, qid: Qid, iounit: u32 },
        TWalkAt { tag: u16, fid: u32, new_fid: u32, wfid: u32, names: Vec<String> },
        RWalkAt { tag: u16, qids: Vec<Qid> },
        TLock { tag: u16, fid: u32, lock_type: u8, flags: u32, start: u64, length: u64, proc_id: Vec<u8> },
        RLock { tag: u16, status: u8 },
        TGetLock { tag: u16, fid: u32, lock_type: u8, start: u64, length: u64, proc_id: Vec<u8> },
        RGetLock { tag: u16, status: u8, lock_type: u8, start: u64, length: u64, proc_id: Vec<u8> },
        RError { tag: u16, ename: String },
    }

    // ============================================================================
    // P9Codec
    // ============================================================================

    #[derive(Debug, Clone, Default)]
    pub struct P9Codec;

    impl P9Codec {
        pub fn new() -> Self {
            Self
        }

        pub fn encode(&self, msg: &P9Msg) -> Result<Vec<u8>, &'static str> {
            let mut buf = Vec::new();
            let size_offset = buf.len();
            buf.extend_from_slice(&[0u8; 4]);
            self.write_message(msg, &mut buf)?;
            let total_size = (buf.len() as u32).to_le_bytes();
            buf[size_offset..size_offset + 4].copy_from_slice(&total_size);
            Ok(buf)
        }

        pub fn decode(&self, buf: &[u8]) -> Result<P9Msg, &'static str> {
            if buf.len() < 7 {
                return Err("message too short");
            }
            let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if size as usize != buf.len() {
                return Err("invalid message size");
            }
            let msg_type = buf[4];
            let tag = u16::from_le_bytes([buf[5], buf[6]]);
            self.read_message(msg_type, tag, &buf[7..])
        }

        fn write_message(&self, msg: &P9Msg, buf: &mut Vec<u8>) -> Result<(), &'static str> {
            match msg {
                P9Msg::TVersion { tag, msize, version } => {
                    buf.push(100);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&msize.to_le_bytes());
                    buf.extend_from_slice(version.as_bytes());
                    buf.push(0);
                }
                P9Msg::RVersion { tag, msize, version } => {
                    buf.push(101);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&msize.to_le_bytes());
                    buf.extend_from_slice(version.as_bytes());
                    buf.push(0);
                }
                P9Msg::TAuth { tag, afid, uname, aname } => {
                    buf.push(102);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&afid.to_le_bytes());
                    buf.extend_from_slice(uname.as_bytes());
                    buf.push(0);
                    buf.extend_from_slice(aname.as_bytes());
                    buf.push(0);
                }
                P9Msg::RAuth { tag, aqid } => {
                    buf.push(103);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&aqid.to_bytes());
                }
                P9Msg::TAttach { tag, fid, afid, uname, aname } => {
                    buf.push(104);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(&afid.to_le_bytes());
                    buf.extend_from_slice(uname.as_bytes());
                    buf.push(0);
                    buf.extend_from_slice(aname.as_bytes());
                    buf.push(0);
                }
                P9Msg::RAttach { tag, qid } => {
                    buf.push(105);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&qid.to_bytes());
                }
                P9Msg::TWalk { tag, fid, new_fid, names } => {
                    buf.push(110);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(&new_fid.to_le_bytes());
                    buf.extend_from_slice(&(names.len() as u16).to_le_bytes());
                    for name in names {
                        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
                P9Msg::RWalk { tag, qids } => {
                    buf.push(111);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&(qids.len() as u16).to_le_bytes());
                    for qid in qids {
                        buf.extend_from_slice(&qid.to_bytes());
                    }
                }
                P9Msg::TOpen { tag, fid, mode } => {
                    buf.push(112);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.push(*mode);
                }
                P9Msg::ROpen { tag, qid, iounit } => {
                    buf.push(113);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&qid.to_bytes());
                    buf.extend_from_slice(&iounit.to_le_bytes());
                }
                P9Msg::TCreate { tag, fid, name, mode, perm } => {
                    buf.push(114);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(name.as_bytes());
                    buf.push(0);
                    buf.extend_from_slice(&mode.to_le_bytes());
                    buf.extend_from_slice(&perm.to_le_bytes());
                }
                P9Msg::RCreate { tag, qid, iounit } => {
                    buf.push(115);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&qid.to_bytes());
                    buf.extend_from_slice(&iounit.to_le_bytes());
                }
                P9Msg::TRead { tag, fid, offset, count } => {
                    buf.push(116);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(&offset.to_le_bytes());
                    buf.extend_from_slice(&count.to_le_bytes());
                }
                P9Msg::RRead { tag, data } => {
                    buf.push(117);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    buf.extend_from_slice(data);
                }
                P9Msg::TWrite { tag, fid, offset, data } => {
                    buf.push(118);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(&offset.to_le_bytes());
                    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    buf.extend_from_slice(data);
                }
                P9Msg::RWrite { tag, count } => {
                    buf.push(119);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&count.to_le_bytes());
                }
                P9Msg::TClunk { tag, fid } => {
                    buf.push(120);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                }
                P9Msg::RClunk { tag } => {
                    buf.push(121);
                    buf.extend_from_slice(&tag.to_le_bytes());
                }
                P9Msg::TRemove { tag, fid } => {
                    buf.push(122);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                }
                P9Msg::RRemove { tag } => {
                    buf.push(123);
                    buf.extend_from_slice(&tag.to_le_bytes());
                }
                P9Msg::TStat { tag, fid } => {
                    buf.push(124);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                }
                P9Msg::RStat { tag, stat } => {
                    buf.push(125);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    self.write_stat(stat, buf);
                }
                P9Msg::TWStat { tag, fid, stat } => {
                    buf.push(126);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    self.write_stat(stat, buf);
                }
                P9Msg::RWStat { tag } => {
                    buf.push(127);
                    buf.extend_from_slice(&tag.to_le_bytes());
                }
                P9Msg::TFlush { tag, oldtag } => {
                    buf.push(108);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&oldtag.to_le_bytes());
                }
                P9Msg::RFlush { tag } => {
                    buf.push(109);
                    buf.extend_from_slice(&tag.to_le_bytes());
                }
                P9Msg::TOpenAt { tag, dfid, flags, mode } => {
                    buf.push(72);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&dfid.to_le_bytes());
                    buf.extend_from_slice(&flags.to_le_bytes());
                    buf.push(*mode);
                }
                P9Msg::ROpenAt { tag, qid, iounit } => {
                    buf.push(73);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&qid.to_bytes());
                    buf.extend_from_slice(&iounit.to_le_bytes());
                }
                P9Msg::TCreateAt { tag, dfid, name, flags, mode, perm } => {
                    buf.push(74);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&dfid.to_le_bytes());
                    buf.extend_from_slice(name.as_bytes());
                    buf.push(0);
                    buf.extend_from_slice(&flags.to_le_bytes());
                    buf.extend_from_slice(&mode.to_le_bytes());
                    buf.extend_from_slice(&perm.to_le_bytes());
                }
                P9Msg::RCreateAt { tag, qid, iounit } => {
                    buf.push(75);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&qid.to_bytes());
                    buf.extend_from_slice(&iounit.to_le_bytes());
                }
                P9Msg::TWalkAt { tag, fid, new_fid, wfid, names } => {
                    buf.push(76);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.extend_from_slice(&new_fid.to_le_bytes());
                    buf.extend_from_slice(&wfid.to_le_bytes());
                    buf.extend_from_slice(&(names.len() as u16).to_le_bytes());
                    for name in names {
                        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
                P9Msg::RWalkAt { tag, qids } => {
                    buf.push(77);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&(qids.len() as u16).to_le_bytes());
                    for qid in qids {
                        buf.extend_from_slice(&qid.to_bytes());
                    }
                }
                P9Msg::TLock { tag, fid, lock_type, flags, start, length, proc_id } => {
                    buf.push(52);
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
                    buf.push(53);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.push(*status);
                }
                P9Msg::TGetLock { tag, fid, lock_type, start, length, proc_id } => {
                    buf.push(54);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(&fid.to_le_bytes());
                    buf.push(*lock_type);
                    buf.extend_from_slice(&start.to_le_bytes());
                    buf.extend_from_slice(&length.to_le_bytes());
                    buf.extend_from_slice(&(proc_id.len() as u32).to_le_bytes());
                    buf.extend_from_slice(proc_id);
                }
                P9Msg::RGetLock { tag, status, lock_type, start, length, proc_id } => {
                    buf.push(55);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.push(*status);
                    buf.push(*lock_type);
                    buf.extend_from_slice(&start.to_le_bytes());
                    buf.extend_from_slice(&length.to_le_bytes());
                    buf.extend_from_slice(&(proc_id.len() as u32).to_le_bytes());
                    buf.extend_from_slice(proc_id);
                }
                P9Msg::RError { tag, ename } => {
                    buf.push(7);
                    buf.extend_from_slice(&tag.to_le_bytes());
                    buf.extend_from_slice(ename.as_bytes());
                    buf.push(0);
                }
            }
            Ok(())
        }

        fn write_stat(&self, stat: &Stat, buf: &mut Vec<u8>) {
            let name_len = stat.name.len();
            let uid_len = stat.uid.len();
            let gid_len = stat.gid.len();
            let muid_len = stat.muid.len();
            let stat_size = 2 + name_len + 2 + uid_len + 2 + gid_len + 2 + muid_len + 4 + 4 + 4 + 8 + 4 + 4 + 4;
            buf.extend_from_slice(&(stat_size as u16).to_le_bytes());
            buf.extend_from_slice(&(name_len as u16).to_le_bytes());
            buf.extend_from_slice(stat.name.as_bytes());
            buf.extend_from_slice(&(uid_len as u16).to_le_bytes());
            buf.extend_from_slice(stat.uid.as_bytes());
            buf.extend_from_slice(&(gid_len as u16).to_le_bytes());
            buf.extend_from_slice(stat.gid.as_bytes());
            buf.extend_from_slice(&(muid_len as u16).to_le_bytes());
            buf.extend_from_slice(stat.muid.as_bytes());
            buf.extend_from_slice(&stat.mode.to_le_bytes());
            buf.extend_from_slice(&stat.atime.to_le_bytes());
            buf.extend_from_slice(&stat.mtime.to_le_bytes());
            buf.extend_from_slice(&stat.length.to_le_bytes());
            buf.extend_from_slice(&stat.n_uid.to_le_bytes());
            buf.extend_from_slice(&stat.n_gid.to_le_bytes());
            buf.extend_from_slice(&stat.n_muid.to_le_bytes());
        }

        fn read_message(&self, msg_type: u8, tag: u16, data: &[u8]) -> Result<P9Msg, &'static str> {
            match msg_type {
                100 => {
                    if data.len() < 4 { return Err("Tversion: too short"); }
                    let msize = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let version = read_string(&data[4..]).unwrap_or_default();
                    Ok(P9Msg::TVersion { tag, msize, version })
                }
                101 => {
                    if data.len() < 4 { return Err("Rversion: too short"); }
                    let msize = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let version = read_string(&data[4..]).unwrap_or_default();
                    Ok(P9Msg::RVersion { tag, msize, version })
                }
                102 => {
                    if data.len() < 4 { return Err("Tauth: too short"); }
                    let afid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let (uname, rest) = read_string_pair(&data[4..]).unwrap_or((String::new(), &[]));
                    let aname = read_string(rest).unwrap_or_default();
                    Ok(P9Msg::TAuth { tag, afid, uname, aname })
                }
                103 => {
                    if data.len() < 13 { return Err("Rauth: too short"); }
                    let mut qid_buf = [0u8; 13];
                    qid_buf.copy_from_slice(&data[..13]);
                    let aqid = Qid::from_bytes(&qid_buf);
                    Ok(P9Msg::RAuth { tag, aqid })
                }
                104 => {
                    if data.len() < 12 { return Err("Tattach: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let afid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let (uname, rest) = read_string_pair(&data[8..]).unwrap_or((String::new(), &[]));
                    let aname = read_string(rest).unwrap_or_default();
                    Ok(P9Msg::TAttach { tag, fid, afid, uname, aname })
                }
                105 => {
                    if data.len() < 13 { return Err("Rattach: too short"); }
                    let mut qid_buf = [0u8; 13];
                    qid_buf.copy_from_slice(&data[..13]);
                    let qid = Qid::from_bytes(&qid_buf);
                    Ok(P9Msg::RAttach { tag, qid })
                }
                110 => {
                    if data.len() < 12 { return Err("Twalk: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let new_fid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let nwname = u16::from_le_bytes([data[8], data[9]]);
                    let mut names = Vec::new();
                    let mut pos = 11;
                    for _ in 0..nwname {
                        if pos + 2 > data.len() { break; }
                        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                        pos += 2;
                        if pos + name_len > data.len() { break; }
                        names.push(String::from_utf8_lossy(&data[pos..pos + name_len]).to_string());
                        pos += name_len;
                    }
                    Ok(P9Msg::TWalk { tag, fid, new_fid, names })
                }
                111 => {
                    if data.len() < 2 { return Err("Rwalk: too short"); }
                    let nwqid = u16::from_le_bytes([data[0], data[1]]);
                    let mut qids = Vec::new();
                    let mut pos = 3;
                    for _ in 0..nwqid {
                        if pos + 13 > data.len() { break; }
                        let mut qid_buf = [0u8; 13];
                        qid_buf.copy_from_slice(&data[pos..pos + 13]);
                        qids.push(Qid::from_bytes(&qid_buf));
                        pos += 13;
                    }
                    Ok(P9Msg::RWalk { tag, qids })
                }
                112 => {
                    if data.len() < 5 { return Err("Topen: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let mode = data[4];
                    Ok(P9Msg::TOpen { tag, fid, mode })
                }
                113 => {
                    if data.len() < 17 { return Err("Ropen: too short"); }
                    let mut qid_buf = [0u8; 13];
                    qid_buf.copy_from_slice(&data[..13]);
                    let qid = Qid::from_bytes(&qid_buf);
                    let iounit = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
                    Ok(P9Msg::ROpen { tag, qid, iounit })
                }
                114 => {
                    if data.len() < 9 { return Err("Tcreate: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let (name, rest) = read_string_pair(&data[4..]).unwrap_or((String::new(), &[]));
                    if rest.len() < 8 { return Err("Tcreate: too short for perm"); }
                    let mode = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
                    let perm = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);
                    Ok(P9Msg::TCreate { tag, fid, name, mode, perm })
                }
                115 => {
                    if data.len() < 17 { return Err("Rcreate: too short"); }
                    let mut qid_buf = [0u8; 13];
                    qid_buf.copy_from_slice(&data[..13]);
                    let qid = Qid::from_bytes(&qid_buf);
                    let iounit = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
                    Ok(P9Msg::RCreate { tag, qid, iounit })
                }
                116 => {
                    if data.len() < 20 { return Err("Tread: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let offset = u64::from_le_bytes([data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11]]);
                    let count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                    Ok(P9Msg::TRead { tag, fid, offset, count })
                }
                117 => {
                    if data.len() < 4 { return Err("Rread: too short"); }
                    let d = data[4..].to_vec();
                    Ok(P9Msg::RRead { tag, data: d })
                }
                118 => {
                    if data.len() < 20 { return Err("Twrite: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let offset = u64::from_le_bytes([data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11]]);
                    let _count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
                    let d = data[16..].to_vec();
                    Ok(P9Msg::TWrite { tag, fid, offset, data: d })
                }
                119 => {
                    if data.len() < 4 { return Err("Rwrite: too short"); }
                    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    Ok(P9Msg::RWrite { tag, count })
                }
                120 => {
                    if data.len() < 4 { return Err("Tclunk: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    Ok(P9Msg::TClunk { tag, fid })
                }
                121 => Ok(P9Msg::RClunk { tag }),
                122 => {
                    if data.len() < 4 { return Err("Tremove: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    Ok(P9Msg::TRemove { tag, fid })
                }
                123 => Ok(P9Msg::RRemove { tag }),
                124 => {
                    if data.len() < 4 { return Err("Tstat: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    Ok(P9Msg::TStat { tag, fid })
                }
                125 => {
                    let stat = self.read_stat(data).unwrap_or_default();
                    Ok(P9Msg::RStat { tag, stat })
                }
                126 => {
                    if data.len() < 4 { return Err("Twstat: too short"); }
                    let fid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let stat = self.read_stat(&data[4..]).unwrap_or_default();
                    Ok(P9Msg::TWStat { tag, fid, stat })
                }
                127 => Ok(P9Msg::RWStat { tag }),
                108 => {
                    if data.len() < 2 { return Err("Tflush: too short"); }
                    let oldtag = u16::from_le_bytes([data[0], data[1]]);
                    Ok(P9Msg::TFlush { tag, oldtag })
                }
                109 => Ok(P9Msg::RFlush { tag }),
                72 => {
                    if data.len() < 8 { return Err("Tlopen: too short"); }
                    let dfid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    let mode = if data.len() > 8 { data[8] } else { 0 };
                    Ok(P9Msg::TOpenAt { tag, dfid, flags, mode })
                }
                73 => {
                    if data.len() < 17 { return Err("Rlopen: too short"); }
                    let mut qid_buf = [0u8; 13];
                    qid_buf.copy_from_slice(&data[..13]);
                    let qid = Qid::from_bytes(&qid_buf);
                    let iounit = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
                    Ok(P9Msg::ROpenAt { tag, qid, iounit })
                }
                7 => {
                    let ename = read_string(data).unwrap_or_default();
                    Ok(P9Msg::RError { tag, ename })
                }
                _ => Err("unknown message type"),
            }
        }

        fn read_stat(&self, data: &[u8]) -> Result<Stat, &'static str> {
            if data.len() < 2 { return Err("stat: too short"); }
            let stat_len = u16::from_le_bytes([data[0], data[1]]) as usize;
            if data.len() < 2 + stat_len { return Err("stat: invalid length"); }
            let mut pos = 2;
            let name = read_string_at(data, pos)?;
            pos += 2 + name.len();
            let uid = read_string_at(data, pos)?;
            pos += 2 + uid.len();
            let gid = read_string_at(data, pos)?;
            pos += 2 + gid.len();
            let muid = read_string_at(data, pos)?;
            pos += 2 + muid.len();
            if pos + 28 > data.len() { return Err("stat: truncated"); }
            let mode = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
            let atime = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);
            let mtime = u32::from_le_bytes([data[pos+8], data[pos+9], data[pos+10], data[pos+11]]);
            let length = u64::from_le_bytes([data[pos+12], data[pos+13], data[pos+14], data[pos+15], data[pos+16], data[pos+17], data[pos+18], data[pos+19]]);
            let n_uid = u32::from_le_bytes([data[pos+20], data[pos+21], data[pos+22], data[pos+23]]);
            let n_gid = u32::from_le_bytes([data[pos+24], data[pos+25], data[pos+26], data[pos+27]]);
            let n_muid = u32::from_le_bytes([data[pos+28], data[pos+29], data[pos+30], data[pos+31]]);
            Ok(Stat { name, uid, gid, muid, mode, atime, mtime, length, n_uid, n_gid, n_muid })
        }
    }

    fn read_string(data: &[u8]) -> Option<String> {
        let mut len = 0;
        for (i, &b) in data.iter().enumerate() {
            if b == 0 {
                len = i;
                break;
            }
        }
        if len == 0 { return Some(String::new()); }
        Some(String::from_utf8_lossy(&data[..len]).to_string())
    }

    fn read_string_at(data: &[u8], pos: usize) -> Result<String, &'static str> {
        if pos + 2 > data.len() { return Err("read_string_at: out of bounds"); }
        let len = u16::from_le_bytes([data[pos], data[pos+1]]) as usize;
        if pos + 2 + len > data.len() { return Err("read_string_at: string too long"); }
        Ok(String::from_utf8_lossy(&data[pos+2..pos+2+len]).to_string())
    }

    fn read_string_pair(data: &[u8]) -> Option<(String, &[u8])> {
        let mut len = 0;
        for (i, &b) in data.iter().enumerate() {
            if b == 0 {
                len = i;
                break;
            }
        }
        let s = String::from_utf8_lossy(&data[..len]).to_string();
        Some((s, &data[len + 1..]))
    }

    // ============================================================================
    // P9Server Placeholder
    // ============================================================================

    #[derive(Debug, Clone, Default)]
    pub struct P9Server;

    impl P9Server {
        pub fn new() -> Self {
            Self
        }
    }
}

pub use protocol::{P9Codec, P9Error, P9Msg, P9Server, Stat, Qid};

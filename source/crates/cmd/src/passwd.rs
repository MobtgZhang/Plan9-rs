//! User-space access to `/etc/passwd` and `/etc/group`.
//!
//! Every command that needs to turn a login name into a uid (or back) uses
//! this module.  It re-reads the files on each call so that a `useradd`
//! performed moments earlier is immediately visible, with no daemon and no
//! cached state to invalidate.

/// One parsed `/etc/passwd` record.
#[derive(Clone, Copy)]
pub struct UserInfo {
    pub name: [u8; 32],
    pub name_len: usize,
    pub uid: u32,
    pub gid: u32,
    pub home: [u8; 128],
    pub home_len: usize,
    pub shell: [u8; 64],
    pub shell_len: usize,
    pub gecos: [u8; 64],
    pub gecos_len: usize,
}

impl UserInfo {
    const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            uid: 0,
            gid: 0,
            home: [0u8; 128],
            home_len: 0,
            shell: [0u8; 64],
            shell_len: 0,
            gecos: [0u8; 64],
            gecos_len: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn home_str(&self) -> &str {
        core::str::from_utf8(&self.home[..self.home_len]).unwrap_or("")
    }

    pub fn shell_str(&self) -> &str {
        core::str::from_utf8(&self.shell[..self.shell_len]).unwrap_or("")
    }

    pub fn gecos_str(&self) -> &str {
        core::str::from_utf8(&self.gecos[..self.gecos_len]).unwrap_or("")
    }
}

/// One parsed `/etc/group` record.
#[derive(Clone, Copy)]
pub struct GroupInfo {
    pub name: [u8; 32],
    pub name_len: usize,
    pub gid: u32,
}

impl GroupInfo {
    const fn empty() -> Self {
        Self { name: [0u8; 32], name_len: 0, gid: 0 }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

const MAX_RECORDS: usize = 64;

fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// Read the whole of `path` into `buf`, returning the number of bytes.
pub fn read_all(path: &str, buf: &mut [u8]) -> usize {
    let cs = crate::syscall::make_cstr(path);
    let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
    if fd < 0 {
        return 0;
    }
    let mut total = 0usize;
    while total < buf.len() {
        let n = crate::syscall::read(fd, unsafe { buf.as_mut_ptr().add(total) }, buf.len() - total);
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    crate::syscall::close(fd);
    total
}

fn split(line: &[u8]) -> [&[u8]; 7] {
    let mut out: [&[u8]; 7] = [b""; 7];
    let mut idx = 0usize;
    let mut start = 0usize;
    for i in 0..=line.len() {
        if i == line.len() || line[i] == b':' {
            if idx < 7 {
                out[idx] = &line[start..i];
                idx += 1;
            }
            start = i + 1;
        }
    }
    out
}

fn parse_u32(b: &[u8]) -> Option<u32> {
    if b.is_empty() {
        return None;
    }
    let mut v = 0u32;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(v)
}

/// Parse `/etc/passwd` into `out`, returning the number of records.
pub fn parse_users(text: &[u8], out: &mut [UserInfo; MAX_RECORDS]) -> usize {
    let mut n = 0usize;
    for line in text.split(|&b| b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let f = split(line);
        let uid = match parse_u32(f[2]) {
            Some(v) => v,
            None => continue,
        };
        let gid = parse_u32(f[3]).unwrap_or(0);
        if n >= MAX_RECORDS {
            break;
        }
        let mut u = UserInfo::empty();
        u.name_len = copy_into(&mut u.name, f[0]);
        u.uid = uid;
        u.gid = gid;
        u.gecos_len = copy_into(&mut u.gecos, f[4]);
        u.home_len = copy_into(&mut u.home, f[5]);
        u.shell_len = copy_into(&mut u.shell, f[6]);
        out[n] = u;
        n += 1;
    }
    n
}

/// Parse `/etc/group` into `out`, returning the number of records.
pub fn parse_groups(text: &[u8], out: &mut [GroupInfo; MAX_RECORDS]) -> usize {
    let mut n = 0usize;
    for line in text.split(|&b| b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let f = split(line);
        let gid = match parse_u32(f[2]) {
            Some(v) => v,
            None => continue,
        };
        if n >= MAX_RECORDS {
            break;
        }
        let mut g = GroupInfo::empty();
        g.name_len = copy_into(&mut g.name, f[0]);
        g.gid = gid;
        out[n] = g;
        n += 1;
    }
    n
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' || c == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = b.split_last() {
        if c == b' ' || c == b'\t' || c == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// Look a user up by login name.
pub fn lookup_name(name: &str) -> Option<UserInfo> {
    let mut text = [0u8; 4096];
    let n = read_all("/etc/passwd", &mut text);
    let mut users = [UserInfo::empty(); MAX_RECORDS];
    let count = parse_users(&text[..n], &mut users);
    users[..count].iter().copied().find(|u| u.name_str() == name)
}

/// Look a user up by uid.
pub fn lookup_uid(uid: u32) -> Option<UserInfo> {
    let mut text = [0u8; 4096];
    let n = read_all("/etc/passwd", &mut text);
    let mut users = [UserInfo::empty(); MAX_RECORDS];
    let count = parse_users(&text[..n], &mut users);
    users[..count].iter().copied().find(|u| u.uid == uid)
}

/// Look a group up by name.
pub fn lookup_group(name: &str) -> Option<GroupInfo> {
    let mut text = [0u8; 4096];
    let n = read_all("/etc/group", &mut text);
    let mut groups = [GroupInfo::empty(); MAX_RECORDS];
    let count = parse_groups(&text[..n], &mut groups);
    groups[..count].iter().copied().find(|g| g.name_str() == name)
}

/// Look a group up by gid.
pub fn lookup_gid(gid: u32) -> Option<GroupInfo> {
    let mut text = [0u8; 4096];
    let n = read_all("/etc/group", &mut text);
    let mut groups = [GroupInfo::empty(); MAX_RECORDS];
    let count = parse_groups(&text[..n], &mut groups);
    groups[..count].iter().copied().find(|g| g.gid == gid)
}

/// Render an integer as decimal into `buf`, returning the slice.
pub fn num(v: u32, buf: &mut [u8; 10]) -> &str {
    crate::utoa(v as u64, buf)
}

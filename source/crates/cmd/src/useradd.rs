//! `useradd` — create a user account.
//!
//! Usage:
//! ```text
//! useradd [-u uid] [-g group] [-c comment] [-d home] [-s shell] [-M] name
//! ```
//!
//! The account is written to `/etc/passwd`, a same-named group is created in
//! `/etc/group`, the home directory is created and populated with a starter
//! `lib/profile`, and an empty password is recorded so that `passwd` can set
//! one later.

use crate::passwd;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut comment: &str = "";
    let mut home_arg: Option<&str> = None;
    let mut shell = "/bin/rc";
    let mut name: Option<&str> = None;
    let mut create_home = true;
    let mut system = false;

    let mut i = 1usize;
    while i < argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => break,
        };
        match a {
            "-u" => {
                i += 1;
                uid = crate::arg(argc, argv, i)
                    .and_then(crate::parse_u64)
                    .map(|v| v as u32);
            }
            "-g" => {
                i += 1;
                if let Some(g) = crate::arg(argc, argv, i) {
                    gid = match crate::parse_u64(g) {
                        Some(v) => Some(v as u32),
                        None => passwd::lookup_group(g).map(|x| x.gid),
                    };
                }
            }
            "-c" => {
                i += 1;
                comment = crate::arg(argc, argv, i).unwrap_or("");
            }
            "-d" => {
                i += 1;
                home_arg = crate::arg(argc, argv, i);
            }
            "-s" => {
                i += 1;
                shell = crate::arg(argc, argv, i).unwrap_or("/bin/rc");
            }
            "-M" => create_home = false,
            "-m" => create_home = true,
            "-r" => system = true,
            other => {
                if other.starts_with('-') {
                    crate::out_str("useradd: unknown option ");
                    crate::outln(other);
                    return 1;
                }
                name = Some(other);
            }
        }
        i += 1;
    }

    let name = match name {
        Some(n) => n,
        None => {
            crate::outln("usage: useradd [-u uid] [-g group] [-c comment] [-d home] [-s shell] name");
            return 1;
        }
    };

    if crate::syscall::getuid() != 0 {
        crate::outln("useradd: permission denied (must be root)");
        return 1;
    }
    if !valid_name(name) {
        crate::out_str("useradd: invalid user name: ");
        crate::outln(name);
        return 1;
    }
    if passwd::lookup_name(name).is_some() {
        crate::out_str("useradd: user exists: ");
        crate::outln(name);
        return 1;
    }

    let uid = match uid {
        Some(u) => u,
        None => match free_uid(if system { 100 } else { 1000 }) {
            Some(u) => u,
            None => {
                crate::outln("useradd: no free uid");
                return 1;
            }
        },
    };
    if passwd::lookup_uid(uid).is_some() {
        crate::out_str("useradd: uid already in use: ");
        let mut b = [0u8; 10];
        crate::outln(crate::utoa(uid as u64, &mut b));
        return 1;
    }

    let gid = match gid {
        Some(g) => g,
        None => match passwd::lookup_group(name) {
            Some(g) => g.gid,
            None => free_gid(1000).unwrap_or(uid),
        },
    };

    // Default home directory: /usr/<name>.
    let mut home_buf = [0u8; 128];
    let home: &[u8] = match home_arg {
        Some(h) => {
            let n = h.len().min(127);
            home_buf[..n].copy_from_slice(&h.as_bytes()[..n]);
            &home_buf[..n]
        }
        None => {
            let mut n = 0usize;
            for &b in b"/usr/" {
                home_buf[n] = b;
                n += 1;
            }
            for &b in name.as_bytes() {
                if n < 127 {
                    home_buf[n] = b;
                    n += 1;
                }
            }
            &home_buf[..n]
        }
    };

    // --- /etc/passwd -------------------------------------------------------
    let mut passwd_buf = [0u8; 8192];
    let plen = passwd::read_all("/etc/passwd", &mut passwd_buf);
    let mut line = [0u8; 256];
    let ln = build_passwd_line(&mut line, name, uid, gid, comment, home, shell);
    if !rewrite_with("/etc/passwd", &passwd_buf[..plen], &line[..ln]) {
        crate::outln("useradd: cannot write /etc/passwd");
        return 1;
    }

    // --- /etc/group --------------------------------------------------------
    let mut group_buf = [0u8; 8192];
    let glen = passwd::read_all("/etc/group", &mut group_buf);
    let groups = &group_buf[..glen];
    if passwd::lookup_gid(gid).is_none() {
        // New private group with the user as its only member.
        let mut gline = [0u8; 128];
        let gn = build_group_line(&mut gline, name, gid, Some(name));
        if !rewrite_with("/etc/group", groups, &gline[..gn]) {
            crate::outln("useradd: cannot write /etc/group");
            return 1;
        }
    } else if !rewrite_group_add_member(groups, gid, name) {
        crate::outln("useradd: cannot update /etc/group");
        return 1;
    }

    // --- /etc/shadow -------------------------------------------------------
    let mut shadow_buf = [0u8; 4096];
    let slen = passwd::read_all("/etc/shadow", &mut shadow_buf);
    let mut sline = [0u8; 64];
    let sn = build_shadow_line(&mut sline, name);
    if !rewrite_with("/etc/shadow", &shadow_buf[..slen], &sline[..sn]) {
        crate::outln("useradd: warning: cannot write /etc/shadow");
    }

    // --- home directory ----------------------------------------------------
    if create_home {
        mkdir_all(home);
        let mut cpath = [0u8; 128];
        cpath[..home.len()].copy_from_slice(home);
        let _ = crate::syscall::chown(cpath.as_ptr(), uid, gid);
        write_profile(home);
    }

    crate::out_str("useradd: created ");
    crate::outln(name);
    0
}

// ---------------------------------------------------------------------------
// Validation and allocation
// ---------------------------------------------------------------------------

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 31 {
        return false;
    }
    let bytes = name.as_bytes();
    if bytes[0].is_ascii_digit() || bytes[0] == b'-' || bytes[0] == b'.' {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn free_uid(base: u32) -> Option<u32> {
    let mut candidate = base;
    while candidate < base + 2000 {
        if passwd::lookup_uid(candidate).is_none() {
            return Some(candidate);
        }
        candidate += 1;
    }
    None
}

fn free_gid(base: u32) -> Option<u32> {
    let mut candidate = base;
    while candidate < base + 2000 {
        if passwd::lookup_gid(candidate).is_none() {
            return Some(candidate);
        }
        candidate += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Line builders
// ---------------------------------------------------------------------------

fn build_passwd_line(
    out: &mut [u8],
    name: &str,
    uid: u32,
    gid: u32,
    comment: &str,
    home: &[u8],
    shell: &str,
) -> usize {
    let mut n = 0usize;
    let mut put = |s: &[u8]| {
        for &b in s {
            if n + 1 < out.len() {
                out[n] = b;
                n += 1;
            }
        }
    };
    put(name.as_bytes());
    put(b":x:");
    let mut b = [0u8; 10];
    put(crate::utoa(uid as u64, &mut b).as_bytes());
    put(b":");
    let mut b2 = [0u8; 10];
    put(crate::utoa(gid as u64, &mut b2).as_bytes());
    put(b":");
    put(comment.as_bytes());
    put(b":");
    put(home);
    put(b":");
    put(shell.as_bytes());
    put(b"\n");
    n
}

fn build_group_line(out: &mut [u8], name: &str, gid: u32, member: Option<&str>) -> usize {
    let mut n = 0usize;
    let mut put = |s: &[u8]| {
        for &b in s {
            if n + 1 < out.len() {
                out[n] = b;
                n += 1;
            }
        }
    };
    put(name.as_bytes());
    put(b":x:");
    let mut b = [0u8; 10];
    put(crate::utoa(gid as u64, &mut b).as_bytes());
    put(b":");
    if let Some(m) = member {
        put(m.as_bytes());
    }
    put(b"\n");
    n
}

fn build_shadow_line(out: &mut [u8], name: &str) -> usize {
    let mut n = 0usize;
    for &b in name.as_bytes() {
        if n + 2 < out.len() {
            out[n] = b;
            n += 1;
        }
    }
    out[n] = b':';
    n += 1;
    out[n] = b'\n';
    n += 1;
    n
}

// ---------------------------------------------------------------------------
// File rewriting helpers
// ---------------------------------------------------------------------------

/// Rewrite `path` as `existing` followed by `extra`.
fn rewrite_with(path: &str, existing: &[u8], extra: &[u8]) -> bool {
    let cs = crate::syscall::make_cstr(path);
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o600);
    if fd < 0 {
        return false;
    }
    // `create` truncates, so the whole file is rebuilt each time.
    let mut ok = true;
    if !existing.is_empty() {
        ok = crate::syscall::write(fd, existing.as_ptr(), existing.len()) > 0;
    }
    if ok {
        ok = crate::syscall::write(fd, extra.as_ptr(), extra.len()) > 0;
    }
    crate::syscall::close(fd);
    ok
}

/// Rewrite `/etc/group` adding `member` to the group whose gid is `gid`.
fn rewrite_group_add_member(existing: &[u8], gid: u32, member: &str) -> bool {
    let cs = crate::syscall::make_cstr("/etc/group");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return false;
    }

    let mut matched = false;
    for line in existing.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let line_gid = field_u32(line, 2);
        if line_gid == Some(gid) && !matched {
            matched = true;
            // Emit the first three fields, then the augmented member list.
            let mut colons = 0usize;
            let mut prefix_len = 0usize;
            for (i, &b) in line.iter().enumerate() {
                if b == b':' {
                    colons += 1;
                    if colons == 3 {
                        prefix_len = i + 1;
                        break;
                    }
                }
            }
            if prefix_len == 0 {
                prefix_len = line.len();
            }
            crate::syscall::write_all(fd, &line[..prefix_len]);
            let existing_members = &line[prefix_len..];
            if !existing_members.is_empty() {
                crate::syscall::write_all(fd, existing_members);
                crate::syscall::write_all(fd, b",");
            }
            crate::syscall::write_all(fd, member.as_bytes());
            crate::syscall::write_all(fd, b"\n");
        } else {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
        }
    }
    crate::syscall::close(fd);
    matched
}

/// The `idx`-th colon-separated field of `line` parsed as a decimal.
fn field_u32(line: &[u8], idx: usize) -> Option<u32> {
    let mut cur = 0usize;
    let mut start = 0usize;
    for i in 0..=line.len() {
        if i == line.len() || line[i] == b':' {
            if cur == idx {
                let field = &line[start..i];
                let s = core::str::from_utf8(field).ok()?;
                return s.parse::<u32>().ok();
            }
            cur += 1;
            start = i + 1;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Home directory
// ---------------------------------------------------------------------------

fn write_profile(home: &[u8]) {
    let mut lib = [0u8; 128];
    let n = home.len();
    lib[..n].copy_from_slice(home);
    lib[n..n + 4].copy_from_slice(b"/lib");
    make_dir(&lib[..n + 4]);

    let mut file = [0u8; 128];
    let m = n + 4;
    file[..m].copy_from_slice(&lib[..m]);
    file[m..m + 8].copy_from_slice(b"/profile");
    let fd = crate::syscall::create3(file.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd >= 0 {
        let text = b"path=(. /bin)\n";
        crate::syscall::write_all(fd, text);
        crate::syscall::close(fd);
    }
}

fn make_dir(path: &[u8]) {
    let mut buf = [0u8; 130];
    buf[..path.len()].copy_from_slice(path);
    let fd = crate::syscall::create3(
        buf.as_ptr(),
        crate::syscall::OREAD,
        crate::syscall::DMDIR | 0o755,
    );
    if fd >= 0 {
        crate::syscall::close(fd);
    }
}

/// Create `path` and every missing component.
fn mkdir_all(path: &[u8]) {
    let mut buf = [0u8; 130];
    let mut n = 0usize;
    for &b in path {
        if n >= 127 {
            break;
        }
        buf[n] = b;
        n += 1;
        if b == b'/' && n > 1 {
            make_dir(&buf[..n]);
        }
    }
    make_dir(&buf[..n]);
}

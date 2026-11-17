//! `usermod` — modify an existing account.
//!
//! Usage:
//! ```text
//! usermod [-l newname] [-u uid] [-g group] [-c comment] [-d home] [-s shell] name
//! usermod -aG group name      add the user to a group
//! usermod -rG group name      remove the user from a group
//! ```

use crate::passwd;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut new_name: Option<&str> = None;
    let mut new_uid: Option<u32> = None;
    let mut new_gid: Option<u32> = None;
    let mut new_comment: Option<&str> = None;
    let mut new_home: Option<&str> = None;
    let mut new_shell: Option<&str> = None;
    // `-G` with `-a` adds, `-G` with `-r` removes.
    let mut group_change: Option<(&str, bool)> = None;
    let mut remove_from_group = false;
    let mut name: Option<&str> = None;

    let mut i = 1usize;
    while i < argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => break,
        };
        match a {
            "-l" => {
                i += 1;
                new_name = crate::arg(argc, argv, i);
            }
            "-u" => {
                i += 1;
                new_uid = crate::arg(argc, argv, i)
                    .and_then(crate::parse_u64)
                    .map(|v| v as u32);
            }
            "-g" => {
                i += 1;
                if let Some(g) = crate::arg(argc, argv, i) {
                    new_gid = match crate::parse_u64(g) {
                        Some(v) => Some(v as u32),
                        None => passwd::lookup_group(g).map(|x| x.gid),
                    };
                }
            }
            "-c" => {
                i += 1;
                new_comment = crate::arg(argc, argv, i);
            }
            "-d" => {
                i += 1;
                new_home = crate::arg(argc, argv, i);
            }
            "-s" => {
                i += 1;
                new_shell = crate::arg(argc, argv, i);
            }
            "-G" => {
                i += 1;
                if let Some(g) = crate::arg(argc, argv, i) {
                    group_change = Some((g, true));
                }
            }
            "-aG" => {
                i += 1;
                if let Some(g) = crate::arg(argc, argv, i) {
                    group_change = Some((g, true));
                }
            }
            "-rG" => {
                i += 1;
                if let Some(g) = crate::arg(argc, argv, i) {
                    group_change = Some((g, false));
                }
            }
            "-r" => remove_from_group = true,
            "-a" => {}
            other => {
                if other.starts_with('-') {
                    crate::out_str("usermod: unknown option ");
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
            crate::outln("usage: usermod [-l newname] [-u uid] [-g group] [-c comment] [-d home] [-s shell] name");
            return 1;
        }
    };

    if crate::syscall::getuid() != 0 {
        crate::outln("usermod: permission denied (must be root)");
        return 1;
    }

    let user = match passwd::lookup_name(name) {
        Some(u) => u,
        None => {
            crate::out_str("usermod: no such user: ");
            crate::outln(name);
            return 1;
        }
    };

    // Group membership change is independent of the passwd record.
    if let Some((group, add)) = group_change {
        let add = add && !remove_from_group;
        return match modify_group_membership(group, name, add) {
            Ok(()) => {
                crate::out_str("usermod: ");
                crate::out_str(if add { "added " } else { "removed " });
                crate::out_str(name);
                crate::out_str(if add { " to " } else { " from " });
                crate::outln(group);
                0
            }
            Err(msg) => {
                crate::out_str("usermod: ");
                crate::outln(msg);
                1
            }
        };
    }

    // Validate a uid change against the existing database.
    if let Some(u) = new_uid {
        if let Some(other) = passwd::lookup_uid(u) {
            if other.name_str() != name {
                crate::outln("usermod: uid already in use");
                return 1;
            }
        }
    }

    if !rewrite_passwd(
        &user,
        new_name,
        new_uid,
        new_gid,
        new_comment,
        new_home,
        new_shell,
    ) {
        crate::outln("usermod: cannot write /etc/passwd");
        return 1;
    }

    // A rename must propagate into group member lists.
    if let Some(nn) = new_name {
        if nn != name {
            propagate_rename(name, nn);
        }
    }

    // A new home directory is created when it does not exist yet.
    let home_final: &str = match new_home {
        Some(h) => h,
        None => user.home_str(),
    };
    if new_home.is_some() && !home_final.is_empty() {
        let mut buf = [0u8; 130];
        let n = home_final.len().min(127);
        buf[..n].copy_from_slice(home_final.as_bytes());
        make_dir(&buf[..n]);
        let uid = new_uid.unwrap_or(user.uid);
        let gid = new_gid.unwrap_or(user.gid);
        let _ = crate::syscall::chown(buf.as_ptr(), uid, gid);
    }

    crate::out_str("usermod: updated ");
    crate::outln(name);
    0
}

// ---------------------------------------------------------------------------
// /etc/passwd rewriting
// ---------------------------------------------------------------------------

fn rewrite_passwd(
    user: &passwd::UserInfo,
    new_name: Option<&str>,
    new_uid: Option<u32>,
    new_gid: Option<u32>,
    new_comment: Option<&str>,
    new_home: Option<&str>,
    new_shell: Option<&str>,
) -> bool {
    let mut text = [0u8; 8192];
    let n = passwd::read_all("/etc/passwd", &mut text);

    let cs = crate::syscall::make_cstr("/etc/passwd");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o600);
    if fd < 0 {
        return false;
    }

    let old_name = user.name_str();
    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let this_name = field(line, 0);
        if this_name != old_name.as_bytes() {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
            continue;
        }
        // Rebuild the record field by field.
        let name = new_name.unwrap_or(old_name);
        let uid = new_uid.unwrap_or(user.uid);
        let gid = new_gid.unwrap_or(user.gid);
        let comment = new_comment.unwrap_or(user.gecos_str());
        let home = new_home.unwrap_or(user.home_str());
        let shell = new_shell.unwrap_or(user.shell_str());

        let mut buf = [0u8; 256];
        let m = assemble(&mut buf, name, uid, gid, comment, home, shell);
        crate::syscall::write_all(fd, &buf[..m]);
        crate::syscall::write_all(fd, b"\n");
    }
    crate::syscall::close(fd);
    true
}

fn assemble(
    out: &mut [u8],
    name: &str,
    uid: u32,
    gid: u32,
    comment: &str,
    home: &str,
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
    put(home.as_bytes());
    put(b":");
    put(shell.as_bytes());
    n
}

/// Colon-separated field `idx` of `line`.
fn field(line: &[u8], idx: usize) -> &[u8] {
    let mut cur = 0usize;
    let mut start = 0usize;
    for i in 0..=line.len() {
        if i == line.len() || line[i] == b':' {
            if cur == idx {
                return &line[start..i];
            }
            cur += 1;
            start = i + 1;
        }
    }
    b""
}

// ---------------------------------------------------------------------------
// /etc/group rewriting
// ---------------------------------------------------------------------------

fn propagate_rename(old: &str, new: &str) {
    let mut text = [0u8; 8192];
    let n = passwd::read_all("/etc/group", &mut text);
    if n == 0 {
        return;
    }
    let cs = crate::syscall::make_cstr("/etc/group");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return;
    }
    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        // Members live in field 3.
        let members = field(line, 3);
        if members.is_empty() {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
            continue;
        }
        let prefix_end = line.len() - members.len();
        crate::syscall::write_all(fd, &line[..prefix_end]);
        let mut first = true;
        for m in members.split(|&b| b == b',') {
            if !first {
                crate::syscall::write_all(fd, b",");
            }
            first = false;
            if m == old.as_bytes() {
                crate::syscall::write_all(fd, new.as_bytes());
            } else {
                crate::syscall::write_all(fd, m);
            }
        }
        crate::syscall::write_all(fd, b"\n");
    }
    crate::syscall::close(fd);
}

fn modify_group_membership(group: &str, member: &str, add: bool) -> Result<(), &'static str> {
    let target = match passwd::lookup_group(group) {
        Some(g) => g,
        None => return Err("no such group"),
    };

    let mut text = [0u8; 8192];
    let n = passwd::read_all("/etc/group", &mut text);

    let cs = crate::syscall::make_cstr("/etc/group");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return Err("cannot write /etc/group");
    }

    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let this_gid = field(line, 2);
        let is_target = core::str::from_utf8(this_gid)
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|g| g == target.gid)
            .unwrap_or(false);
        if !is_target {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
            continue;
        }

        let members = field(line, 3);
        let prefix_end = line.len() - members.len();
        crate::syscall::write_all(fd, &line[..prefix_end]);

        // Collect the surviving members into a scratch list.
        let mut kept = [0u8; 512];
        let mut kn = 0usize;
        let mut present = false;
        for m in members.split(|&b| b == b',') {
            if m.is_empty() {
                continue;
            }
            if m == member.as_bytes() {
                present = true;
                if !add {
                    continue;
                }
            }
            if kn > 0 && kn < kept.len() - 1 {
                kept[kn] = b',';
                kn += 1;
            }
            for &b in m {
                if kn < kept.len() - 1 {
                    kept[kn] = b;
                    kn += 1;
                }
            }
        }
        if add && !present {
            if kn > 0 && kn < kept.len() - 1 {
                kept[kn] = b',';
                kn += 1;
            }
            for &b in member.as_bytes() {
                if kn < kept.len() - 1 {
                    kept[kn] = b;
                    kn += 1;
                }
            }
        }
        crate::syscall::write_all(fd, &kept[..kn]);
        crate::syscall::write_all(fd, b"\n");
    }
    crate::syscall::close(fd);
    Ok(())
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

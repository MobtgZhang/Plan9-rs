//! `group` — create, delete and inspect groups.
//!
//! ```text
//! group                       list every group
//! group add [-g gid] name     create a group
//! group del name              delete a group
//! group add-user group user   add a member
//! group del-user group user   remove a member
//! group show name             show a group and its members
//! ```

use crate::passwd;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let sub = crate::arg(argc, argv, 1);
    match sub {
        None | Some("-l") | Some("list") => list(),
        Some("add") => add(argc, argv),
        Some("del") | Some("remove") | Some("rm") => del(argc, argv),
        Some("add-user") | Some("adduser") => member(argc, argv, true),
        Some("del-user") | Some("deluser") => member(argc, argv, false),
        Some("show") => show(argc, argv),
        Some("-h") | Some("--help") => {
            usage();
            0
        }
        Some(other) => {
            crate::out_str("group: unknown subcommand ");
            crate::outln(other);
            usage();
            1
        }
    }
}

fn usage() {
    crate::outln("usage: group                      list groups");
    crate::outln("       group add [-g gid] name     create a group");
    crate::outln("       group del name              delete a group");
    crate::outln("       group add-user group user   add a member");
    crate::outln("       group del-user group user   remove a member");
    crate::outln("       group show name             show a group");
}

fn require_root() -> bool {
    if crate::syscall::getuid() != 0 {
        crate::outln("group: permission denied (must be root)");
        return false;
    }
    true
}

fn list() -> i32 {
    let mut text = [0u8; 4096];
    let n = passwd::read_all("/etc/group", &mut text);
    if n == 0 {
        crate::outln("group: cannot read /etc/group");
        return 1;
    }
    crate::out(&text[..n]);
    0
}

fn show(argc: usize, argv: *const *const u8) -> i32 {
    let name = match crate::arg(argc, argv, 2) {
        Some(n) => n,
        None => {
            crate::outln("usage: group show name");
            return 1;
        }
    };
    let g = match passwd::lookup_group(name) {
        Some(g) => g,
        None => {
            crate::out_str("group: no such group: ");
            crate::outln(name);
            return 1;
        }
    };
    crate::out_str(g.name_str());
    crate::out_str(" (gid ");
    let mut b = [0u8; 10];
    crate::out_str(crate::utoa(g.gid as u64, &mut b));
    crate::outln(")");
    0
}

fn add(argc: usize, argv: *const *const u8) -> i32 {
    if !require_root() {
        return 1;
    }
    let mut gid: Option<u32> = None;
    let mut name: Option<&str> = None;
    let mut i = 2usize;
    while i < argc {
        match crate::arg(argc, argv, i) {
            Some("-g") => {
                i += 1;
                gid = crate::arg(argc, argv, i)
                    .and_then(crate::parse_u64)
                    .map(|v| v as u32);
            }
            Some(other) if !other.starts_with('-') => name = Some(other),
            _ => {}
        }
        i += 1;
    }
    let name = match name {
        Some(n) => n,
        None => {
            crate::outln("usage: group add [-g gid] name");
            return 1;
        }
    };
    if passwd::lookup_group(name).is_some() {
        crate::out_str("group: group exists: ");
        crate::outln(name);
        return 1;
    }
    let gid = match gid {
        Some(g) => g,
        None => match first_free_gid() {
            Some(g) => g,
            None => {
                crate::outln("group: no free gid");
                return 1;
            }
        },
    };
    if passwd::lookup_gid(gid).is_some() {
        crate::outln("group: gid already in use");
        return 1;
    }

    let mut line = [0u8; 128];
    let n = build_group_line(&mut line, name, gid, "");
    if !append_file("/etc/group", &line[..n]) {
        crate::outln("group: cannot write /etc/group");
        return 1;
    }
    crate::out_str("group: created ");
    crate::outln(name);
    0
}

fn del(argc: usize, argv: *const *const u8) -> i32 {
    if !require_root() {
        return 1;
    }
    let name = match crate::arg(argc, argv, 2) {
        Some(n) => n,
        None => {
            crate::outln("usage: group del name");
            return 1;
        }
    };
    let mut text = [0u8; 8192];
    let n = passwd::read_all("/etc/group", &mut text);
    let cs = crate::syscall::make_cstr("/etc/group");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        crate::outln("group: cannot write /etc/group");
        return 1;
    }
    let mut removed = false;
    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let this = first_field(line);
        if this == name.as_bytes() {
            removed = true;
            continue;
        }
        crate::syscall::write_all(fd, line);
        crate::syscall::write_all(fd, b"\n");
    }
    crate::syscall::close(fd);
    if !removed {
        crate::out_str("group: no such group: ");
        crate::outln(name);
        return 1;
    }
    crate::out_str("group: deleted ");
    crate::outln(name);
    0
}

fn member(argc: usize, argv: *const *const u8, add: bool) -> i32 {
    if !require_root() {
        return 1;
    }
    let (group, user) = match (
        crate::arg(argc, argv, 2),
        crate::arg(argc, argv, 3),
    ) {
        (Some(g), Some(u)) => (g, u),
        _ => {
            crate::outln("usage: group add-user group user | group del-user group user");
            return 1;
        }
    };
    if passwd::lookup_group(group).is_none() {
        crate::out_str("group: no such group: ");
        crate::outln(group);
        return 1;
    }
    if passwd::lookup_name(user).is_none() {
        crate::out_str("group: no such user: ");
        crate::outln(user);
        return 1;
    }
    if !rewrite_membership(group, user, add) {
        crate::outln("group: cannot write /etc/group");
        return 1;
    }
    crate::out_str(if add { "group: added " } else { "group: removed " });
    crate::out_str(user);
    crate::out_str(if add { " to " } else { " from " });
    crate::outln(group);
    0
}

// ---------------------------------------------------------------------------

fn first_free_gid() -> Option<u32> {
    let mut gid = 1000u32;
    while gid < 3000 {
        if passwd::lookup_gid(gid).is_none() {
            return Some(gid);
        }
        gid += 1;
    }
    None
}

fn first_field(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == b':') {
        Some(p) => &line[..p],
        None => line,
    }
}

fn build_group_line(out: &mut [u8], name: &str, gid: u32, members: &str) -> usize {
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
    put(members.as_bytes());
    put(b"\n");
    n
}

fn append_file(path: &str, data: &[u8]) -> bool {
    let mut old = [0u8; 8192];
    let n = passwd::read_all(path, &mut old);
    let cs = crate::syscall::make_cstr(path);
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return false;
    }
    if n > 0 {
        crate::syscall::write_all(fd, &old[..n]);
    }
    crate::syscall::write_all(fd, data);
    crate::syscall::close(fd);
    true
}

fn rewrite_membership(group: &str, user: &str, add: bool) -> bool {
    let target = match passwd::lookup_group(group) {
        Some(g) => g,
        None => return false,
    };
    let mut text = [0u8; 8192];
    let n = passwd::read_all("/etc/group", &mut text);
    let cs = crate::syscall::make_cstr("/etc/group");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return false;
    }

    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if field_u32(line, 2) != Some(target.gid) {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
            continue;
        }

        // Rebuild: prefix (through the third colon) + member list.
        let mut prefix_end = line.len();
        let mut colons = 0usize;
        for (i, &b) in line.iter().enumerate() {
            if b == b':' {
                colons += 1;
                if colons == 3 {
                    prefix_end = i + 1;
                    break;
                }
            }
        }
        crate::syscall::write_all(fd, &line[..prefix_end]);

        let existing = &line[prefix_end..];
        let mut scratch = [0u8; 512];
        let mut sn = 0usize;
        let mut present = false;
        for m in existing.split(|&b| b == b',') {
            if m.is_empty() {
                continue;
            }
            if m == user.as_bytes() {
                present = true;
                if !add {
                    continue;
                }
            }
            if sn > 0 && sn < scratch.len() - 1 {
                scratch[sn] = b',';
                sn += 1;
            }
            for &b in m {
                if sn < scratch.len() - 1 {
                    scratch[sn] = b;
                    sn += 1;
                }
            }
        }
        if add && !present {
            if sn > 0 && sn < scratch.len() - 1 {
                scratch[sn] = b',';
                sn += 1;
            }
            for &b in user.as_bytes() {
                if sn < scratch.len() - 1 {
                    scratch[sn] = b;
                    sn += 1;
                }
            }
        }
        crate::syscall::write_all(fd, &scratch[..sn]);
        crate::syscall::write_all(fd, b"\n");
    }
    crate::syscall::close(fd);
    true
}

fn field_u32(line: &[u8], idx: usize) -> Option<u32> {
    let mut cur = 0usize;
    let mut start = 0usize;
    for i in 0..=line.len() {
        if i == line.len() || line[i] == b':' {
            if cur == idx {
                let s = core::str::from_utf8(&line[start..i]).ok()?;
                return s.parse::<u32>().ok();
            }
            cur += 1;
            start = i + 1;
        }
    }
    None
}

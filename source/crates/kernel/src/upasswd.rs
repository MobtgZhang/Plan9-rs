//! User and group database.
//!
//! Plan 9 keeps identity in `/adm/users`; this prototype follows the more
//! familiar `/etc/passwd` and `/etc/group` layout so that `useradd`,
//! `usermod`, `groupadd` and friends have a natural place to store their
//! data.  The files live in the RAM root file system and are rewritten in
//! place whenever an entry changes.
//!
//! Two storage layers exist:
//!
//! * the on-disk text files (`/etc/passwd`, `/etc/group`, `/etc/shadow`),
//!   which are the authoritative source of truth, and
//! * nothing else: every lookup re-parses the file, so an edit made by one
//!   process is immediately visible to the next.
//!
//! Passwords are stored as a salted FNV-1a digest.  This is *not* a
//! cryptographically strong password hash — the kernel has no randomness
//! source and no heap-backed crypto in this prototype — but it keeps plain
//! text passwords out of the image and demonstrates the data flow.

use alloc::string::String;
use alloc::vec::Vec;

/// Where the identity files live.
pub const PASSWD_PATH: &str = "/etc/passwd";
pub const GROUP_PATH: &str = "/etc/group";
pub const SHADOW_PATH: &str = "/etc/shadow";

/// One `/etc/passwd` line.
#[derive(Clone, Debug)]
pub struct UserEntry {
    /// Login name.
    pub name: String,
    /// Numeric user id.
    pub uid: u32,
    /// Numeric primary group id.
    pub gid: u32,
    /// Real name / comment field.
    pub gecos: String,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

/// One `/etc/group` line.
#[derive(Clone, Debug)]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Numeric group id.
    pub gid: u32,
    /// Member login names.
    pub members: Vec<String>,
}

// ---------------------------------------------------------------------------
// File access helpers
// ---------------------------------------------------------------------------

/// Read a whole identity file into memory.  Returns an empty vector when the
/// file does not exist yet, which makes first-boot creation straightforward.
fn read_file(path: &str) -> Vec<u8> {
    let mut chan = match crate::vfs::namec(
        path.as_bytes(),
        crate::vfs::NamecMode::Walk,
        0,
        0,
    ) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    if let Some(dev) = crate::dev::devs_mut().get_mut(chan.dev) {
        let _ = dev.open(&mut chan, 0);
    }

    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    let mut offset = 0u64;
    loop {
        let n = match crate::dev::dev_read(&mut chan, &mut buf, offset) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        offset += n as u64;
    }
    let _ = crate::dev::dev_close(&mut chan);
    out
}

/// Create (truncating) an identity file and write `data`.
fn write_file(path: &str, data: &[u8]) -> bool {
    let perm = if matches!(path, PASSWD_PATH | GROUP_PATH) { 0o644 } else { 0o600 };
    let mut chan = match crate::vfs::namec(
        path.as_bytes(),
        crate::vfs::NamecMode::Create(1, perm),
        0,
        0,
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(dev) = crate::dev::devs_mut().get_mut(chan.dev) {
        let _ = dev.open(&mut chan, 1);
    }
    // Truncate any previous contents first: identity files are rewritten
    // wholesale and a shorter rendering must not leave stale tail bytes.
    let _ = crate::dev::dev_truncate(&mut chan);
    let ok = crate::dev::dev_write(&mut chan, data, 0).is_ok();
    let _ = crate::dev::dev_close(&mut chan);
    ok
}

// ---------------------------------------------------------------------------
// Parsing / serialising
// ---------------------------------------------------------------------------

fn split_colon(line: &str) -> Vec<&str> {
    line.split(':').collect()
}

/// Parse the textual passwd file.
pub fn parse_passwd(text: &[u8]) -> Vec<UserEntry> {
    let mut out = Vec::new();
    let s = core::str::from_utf8(text).unwrap_or("");
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f = split_colon(line);
        if f.len() < 7 {
            continue;
        }
        let (uid, gid) = match (f[2].parse::<u32>(), f[3].parse::<u32>()) {
            (Ok(u), Ok(g)) => (u, g),
            _ => continue,
        };
        out.push(UserEntry {
            name: String::from(f[0]),
            uid,
            gid,
            gecos: String::from(f[4]),
            home: String::from(f[5]),
            shell: String::from(f[6]),
        });
    }
    out
}

/// Parse the textual group file.
pub fn parse_group(text: &[u8]) -> Vec<GroupEntry> {
    let mut out = Vec::new();
    let s = core::str::from_utf8(text).unwrap_or("");
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f = split_colon(line);
        if f.len() < 3 {
            continue;
        }
        let gid = match f[2].parse::<u32>() {
            Ok(g) => g,
            Err(_) => continue,
        };
        let members = if f.len() > 3 && !f[3].is_empty() {
            f[3].split(',').map(String::from).collect()
        } else {
            Vec::new()
        };
        out.push(GroupEntry {
            name: String::from(f[0]),
            gid,
            members,
        });
    }
    out
}

fn render_passwd(users: &[UserEntry]) -> String {
    let mut s = String::new();
    for u in users {
        s.push_str(&u.name);
        s.push(':');
        s.push_str("x:");
        s.push_str(&u32_str(u.uid));
        s.push(':');
        s.push_str(&u32_str(u.gid));
        s.push(':');
        s.push_str(&u.gecos);
        s.push(':');
        s.push_str(&u.home);
        s.push(':');
        s.push_str(&u.shell);
        s.push('\n');
    }
    s
}

fn render_group(groups: &[GroupEntry]) -> String {
    let mut s = String::new();
    for g in groups {
        s.push_str(&g.name);
        s.push(':');
        s.push_str("x:");
        s.push_str(&u32_str(g.gid));
        s.push(':');
        for (i, m) in g.members.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(m);
        }
        s.push('\n');
    }
    s
}

/// Render a `u32` without pulling in `alloc::format!`.
pub fn u32_str(v: u32) -> String {
    let mut buf = [0u8; 10];
    let mut n = 0usize;
    let mut v = v;
    if v == 0 {
        return String::from("0");
    }
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut s = String::new();
    for i in (0..n).rev() {
        s.push(buf[i] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Public database API
// ---------------------------------------------------------------------------

/// All users from `/etc/passwd`.
pub fn users() -> Vec<UserEntry> {
    parse_passwd(&read_file(PASSWD_PATH))
}

/// All groups from `/etc/group`.
pub fn groups() -> Vec<GroupEntry> {
    parse_group(&read_file(GROUP_PATH))
}

/// Look a user up by name.
pub fn user_by_name(name: &str) -> Option<UserEntry> {
    users().into_iter().find(|u| u.name == name)
}

/// Look a user up by uid.
pub fn user_by_uid(uid: u32) -> Option<UserEntry> {
    users().into_iter().find(|u| u.uid == uid)
}

/// Look a group up by name.
pub fn group_by_name(name: &str) -> Option<GroupEntry> {
    groups().into_iter().find(|g| g.name == name)
}

/// Look a group up by gid.
pub fn group_by_gid(gid: u32) -> Option<GroupEntry> {
    groups().into_iter().find(|g| g.gid == gid)
}

/// Groups a user belongs to: the primary gid plus every group listing the
/// user as a member.
pub fn groups_of(user: &UserEntry) -> Vec<u32> {
    let mut out = Vec::new();
    out.push(user.gid);
    for g in groups() {
        if g.gid != user.gid && g.members.iter().any(|m| m == &user.name) {
            out.push(g.gid);
        }
    }
    out
}

/// Next free uid (>= 1000, the conventional first human account).
pub fn next_uid() -> u32 {
    let users = users();
    let mut candidate = 1000u32;
    loop {
        if !users.iter().any(|u| u.uid == candidate) {
            return candidate;
        }
        candidate += 1;
    }
}

/// Next free gid (>= 1000).
pub fn next_gid() -> u32 {
    let groups = groups();
    let mut candidate = 1000u32;
    loop {
        if !groups.iter().any(|g| g.gid == candidate) {
            return candidate;
        }
        candidate += 1;
    }
}

/// Add a user.  The uid/gid may be supplied explicitly (`Some`) or left to
/// `next_uid`/`next_gid`.  A matching private group is created when the gid
/// is new.
pub fn add_user(
    name: &str,
    uid: Option<u32>,
    gid: Option<u32>,
    gecos: &str,
    home: &str,
    shell: &str,
    password: &str,
) -> Result<UserEntry, &'static str> {
    if name.is_empty() || name.contains(':') || name.contains('/') {
        return Err("invalid user name");
    }
    let mut users = users();
    if users.iter().any(|u| u.name == name) {
        return Err("user already exists");
    }
    let uid = uid.unwrap_or_else(next_uid);
    if users.iter().any(|u| u.uid == uid) {
        return Err("uid already in use");
    }
    let gid = gid.unwrap_or_else(|| {
        // Reuse a group with the same name, else allocate.
        match group_by_name(name) {
            Some(g) => g.gid,
            None => next_gid(),
        }
    });

    let entry = UserEntry {
        name: String::from(name),
        uid,
        gid,
        gecos: String::from(gecos),
        home: String::from(home),
        shell: String::from(shell),
    };
    users.push(entry.clone());
    write_file(PASSWD_PATH, render_passwd(&users).as_bytes());

    // Ensure the primary group exists.
    let mut groups = groups();
    if !groups.iter().any(|g| g.gid == gid) {
        groups.push(GroupEntry {
            name: String::from(name),
            gid,
            members: Vec::new(),
        });
        write_file(GROUP_PATH, render_group(&groups).as_bytes());
    } else if let Some(g) = groups.iter_mut().find(|g| g.gid == gid) {
        if !g.members.iter().any(|m| m == name) {
            g.members.push(String::from(name));
            write_file(GROUP_PATH, render_group(&groups).as_bytes());
        }
    }

    // Record the password digest.
    set_password(name, password);

    // Create the home directory tree.
    mkdir_all(home);
    Ok(entry)
}

/// Remove a user and their private group membership.
pub fn remove_user(name: &str) -> Result<(), &'static str> {
    let mut users = users();
    let before = users.len();
    users.retain(|u| u.name != name);
    if users.len() == before {
        return Err("no such user");
    }
    write_file(PASSWD_PATH, render_passwd(&users).as_bytes());

    let mut groups = groups();
    for g in groups.iter_mut() {
        g.members.retain(|m| m != name);
    }
    write_file(GROUP_PATH, render_group(&groups).as_bytes());
    Ok(())
}

/// Modify fields of an existing user.  `None` leaves a field unchanged.
pub fn modify_user(
    name: &str,
    new_name: Option<&str>,
    new_uid: Option<u32>,
    new_gid: Option<u32>,
    new_gecos: Option<&str>,
    new_home: Option<&str>,
    new_shell: Option<&str>,
) -> Result<(), &'static str> {
    let mut users = users();
    let idx = match users.iter().position(|u| u.name == name) {
        Some(i) => i,
        None => return Err("no such user"),
    };
    if let Some(u) = new_uid {
        if users.iter().enumerate().any(|(i, e)| i != idx && e.uid == u) {
            return Err("uid already in use");
        }
    }
    let old_name = users[idx].name.clone();
    if let Some(n) = new_name {
        if n.is_empty() || users.iter().any(|u| u.name == n) {
            return Err("invalid or duplicate new name");
        }
        users[idx].name = String::from(n);
    }
    if let Some(u) = new_uid {
        users[idx].uid = u;
    }
    if let Some(g) = new_gid {
        users[idx].gid = g;
    }
    if let Some(g) = new_gecos {
        users[idx].gecos = String::from(g);
    }
    if let Some(h) = new_home {
        users[idx].home = String::from(h);
        mkdir_all(h);
    }
    if let Some(s) = new_shell {
        users[idx].shell = String::from(s);
    }
    write_file(PASSWD_PATH, render_passwd(&users).as_bytes());

    // Keep group membership in sync when the login name changed.
    if let Some(n) = new_name {
        let mut groups = groups();
        for g in groups.iter_mut() {
            for m in g.members.iter_mut() {
                if m == &old_name {
                    *m = String::from(n);
                }
            }
        }
        write_file(GROUP_PATH, render_group(&groups).as_bytes());
    }
    Ok(())
}

/// Create a group.
pub fn add_group(name: &str, gid: Option<u32>) -> Result<GroupEntry, &'static str> {
    if name.is_empty() || name.contains(':') {
        return Err("invalid group name");
    }
    let mut groups = groups();
    if groups.iter().any(|g| g.name == name) {
        return Err("group already exists");
    }
    let gid = gid.unwrap_or_else(next_gid);
    if groups.iter().any(|g| g.gid == gid) {
        return Err("gid already in use");
    }
    let entry = GroupEntry {
        name: String::from(name),
        gid,
        members: Vec::new(),
    };
    groups.push(entry.clone());
    write_file(GROUP_PATH, render_group(&groups).as_bytes());
    Ok(entry)
}

/// Delete a group.
pub fn remove_group(name: &str) -> Result<(), &'static str> {
    let mut groups = groups();
    let before = groups.len();
    groups.retain(|g| g.name != name);
    if groups.len() == before {
        return Err("no such group");
    }
    write_file(GROUP_PATH, render_group(&groups).as_bytes());
    Ok(())
}

/// Add (`add == true`) or remove a member from a group.
pub fn set_membership(group: &str, member: &str, add: bool) -> Result<(), &'static str> {
    let mut groups = groups();
    let idx = match groups.iter().position(|g| g.name == group) {
        Some(i) => i,
        None => return Err("no such group"),
    };
    let present = groups[idx].members.iter().any(|m| m == member);
    if add && !present {
        groups[idx].members.push(String::from(member));
    } else if !add && present {
        groups[idx].members.retain(|m| m != member);
    }
    write_file(GROUP_PATH, render_group(&groups).as_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// Shadow passwords
// ---------------------------------------------------------------------------

/// FNV-1a based salted digest used for stored passwords.
///
/// A kernel with no entropy source cannot do better than a deterministic
/// digest; the salt still prevents trivial "same password => same hash"
/// comparisons across users.  The digest is rendered as 16 hex digits:
/// `$p9$<salt>$<digest>`.
fn hash_password(salt: u32, password: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in salt.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for b in password.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn hex64(v: u64) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::new();
    for i in (0..16).rev() {
        s.push(HEX[((v >> (i * 4)) & 0xF) as usize] as char);
    }
    s
}

/// Salt derived from the login name (stable across reboots).
fn salt_for(name: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Set (or clear, with an empty password) a user's password digest.
pub fn set_password(name: &str, password: &str) -> bool {
    let mut lines: Vec<String> = Vec::new();
    let text = read_file(SHADOW_PATH);
    let s = core::str::from_utf8(&text).unwrap_or("");
    let mut found = false;
    for line in s.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let user = line.split(':').next().unwrap_or("");
        if user == name {
            found = true;
            lines.push(render_shadow_line(name, password));
        } else {
            lines.push(String::from(line));
        }
    }
    if !found {
        lines.push(render_shadow_line(name, password));
    }
    let mut out = String::new();
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    write_file(SHADOW_PATH, out.as_bytes())
}

fn render_shadow_line(name: &str, password: &str) -> String {
    let mut s = String::from(name);
    s.push(':');
    if password.is_empty() {
        // Empty field = passwordless account.
    } else {
        let salt = salt_for(name);
        s.push_str("$p9$");
        s.push_str(&hex64(salt as u64));
        s.push('$');
        s.push_str(&hex64(hash_password(salt, password)));
    }
    s
}

/// Verify `password` against the stored digest for `name`.
///
/// Accounts with no shadow entry (or an empty digest) are passwordless and
/// accept any input, which keeps the freshly built system usable.
pub fn verify_password(name: &str, password: &str) -> bool {
    let text = read_file(SHADOW_PATH);
    let s = core::str::from_utf8(&text).unwrap_or("");
    for line in s.lines() {
        let mut it = line.split(':');
        let user = it.next().unwrap_or("");
        if user != name {
            continue;
        }
        let digest = it.next().unwrap_or("");
        if digest.is_empty() {
            return true;
        }
        // `$p9$<hex salt>$<hex digest>`
        let rest = match digest.strip_prefix("$p9$") {
            Some(r) => r,
            None => return false,
        };
        let mut parts = rest.split('$');
        let salt_hex = parts.next().unwrap_or("");
        let want_hex = parts.next().unwrap_or("");
        let salt = match u32::from_str_radix(salt_hex, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        return hex64(hash_password(salt, password)) == want_hex;
    }
    // No shadow entry at all: treat as passwordless.
    true
}

/// Create `path` and every missing parent directory.
pub fn mkdir_all(path: &str) {
    if path.is_empty() || path == "/" {
        return;
    }
    let mut prefix = String::new();
    for comp in path.split('/').filter(|s| !s.is_empty()) {
        prefix.push('/');
        prefix.push_str(comp);
        let mut chan = match crate::vfs::namec(
            prefix.as_bytes(),
            crate::vfs::NamecMode::Create(0, 0x8000_0000u32 | 0o755),
            0,
            0x8000_0000u32 | 0o755,
        ) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let _ = crate::dev::dev_close(&mut chan);
    }
}

/// Populate the initial identity files on first boot.
///
/// The layout mirrors a conventional Unix system: `root` is uid 0, the
/// regular user `glenda` (Plan 9's mascot) is uid 1000, and the usual
/// groups exist so that `ls -l` output is meaningful from the start.
pub fn bootstrap() {
    // Only seed an empty database.
    if !users().is_empty() {
        return;
    }

    let initial_users = "root:x:0:0:root:/usr/root:/bin/rc\n\
glenda:x:1000:1000:Glenda the Plan 9 Bunny:/usr/glenda:/bin/rc\n";
    let initial_groups = "root:x:0:\n\
wheel:x:10:root\n\
users:x:100:glenda\n\
glenda:x:1000:glenda\n";
    write_file(PASSWD_PATH, initial_users.as_bytes());
    write_file(GROUP_PATH, initial_groups.as_bytes());
    write_file(SHADOW_PATH, b"root:\nglenda:\n");

    mkdir_all("/usr/root");
    mkdir_all("/usr/glenda");
    let devices = crate::dev::devs();
    if let Some(fs) = devices.find_by_char('/')
        .and_then(|index| devices.get(index))
        .and_then(|dev| dev.as_any().downcast_ref::<crate::rootfs::RootFsDev>())
    {
        for path in ["/usr/glenda", "/usr/glenda/lib", "/usr/glenda/lib/profile"] {
            if let Some(id) = fs.lookup_path(path) {
                fs.set_owner(id, 1000, 1000);
            }
        }
    }
}

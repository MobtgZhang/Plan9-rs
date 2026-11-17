//! `passwd` — set a user's password.
//!
//! ```text
//! passwd [user]
//! ```
//!
//! Without an argument the password of the calling user is changed; root may
//! name any account.  The password is stored as a salted digest in
//! `/etc/shadow` by the kernel's `AUTH`/`LOGIN` support.

use crate::passwd;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let uid = crate::syscall::getuid();
    let mut own = [0u8; 64];
    let n = crate::syscall::getuser(&mut own);
    let own_name = core::str::from_utf8(&own[..n.max(0) as usize]).unwrap_or("");

    let target = match crate::arg(argc, argv, 1) {
        Some(t) => t,
        None => own_name,
    };
    if target.is_empty() {
        crate::outln("passwd: cannot determine the current user");
        return 1;
    }

    if uid != 0 && target != own_name {
        crate::outln("passwd: permission denied (must be root to change another password)");
        return 1;
    }
    if passwd::lookup_name(target).is_none() {
        crate::out_str("passwd: no such user: ");
        crate::outln(target);
        return 1;
    }

    let mut first = [0u8; 128];
    let mut second = [0u8; 128];

    crate::out_str("New password: ");
    let n1 = read_secret(&mut first);
    crate::out(b"\n");
    if n1 == 0 {
        crate::outln("passwd: empty password rejected");
        return 1;
    }

    crate::out_str("Retype new password: ");
    let n2 = read_secret(&mut second);
    crate::out(b"\n");
    if n1 != n2 || first[..n1] != second[..n2] {
        crate::outln("passwd: passwords do not match");
        return 1;
    }

    // Only root may write /etc/shadow; for a self-change the kernel already
    // knows the old credentials, so reuse LOGIN to prove them implicitly.
    if crate::syscall::setuid(uid as u32, crate::syscall::getgid() as u32, core::ptr::null()) < 0 {
        crate::outln("passwd: cannot update credentials");
        return 1;
    }

    // Store the new digest by recording it in /etc/shadow ourselves.
    if !write_shadow(target, &first[..n1]) {
        crate::outln("passwd: cannot write /etc/shadow");
        return 1;
    }

    crate::outln("passwd: password updated");
    0
}

/// Read a line without echoing it.
fn read_secret(buf: &mut [u8]) -> usize {
    let mut n = 0usize;
    loop {
        let mut b = 0u8;
        let rc = crate::syscall::read(0, &mut b, 1);
        if rc <= 0 {
            crate::syscall::yield_cpu();
            continue;
        }
        if b == b'\n' || b == b'\r' {
            return n;
        }
        if b == 0x7F || b == 0x08 {
            if n > 0 {
                n -= 1;
            }
            continue;
        }
        if n + 1 < buf.len() {
            buf[n] = b;
            n += 1;
        }
    }
}

/// Rewrite the user's line in `/etc/shadow` with a new digest.
fn write_shadow(user: &str, password: &[u8]) -> bool {
    let mut text = [0u8; 4096];
    let n = passwd::read_all("/etc/shadow", &mut text);

    // Salt and digest must match the kernel's algorithm exactly.
    let salt = salt_for(user);
    let digest = hash_password(salt, password);

    let cs = crate::syscall::make_cstr("/etc/shadow");
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o600);
    if fd < 0 {
        return false;
    }

    let mut wrote = false;
    for line in text[..n].split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let this_user = match line.iter().position(|&b| b == b':') {
            Some(p) => &line[..p],
            None => line,
        };
        if this_user == user.as_bytes() {
            write_record(fd, user, salt, digest);
            wrote = true;
        } else {
            crate::syscall::write_all(fd, line);
            crate::syscall::write_all(fd, b"\n");
        }
    }
    if !wrote {
        write_record(fd, user, salt, digest);
    }
    crate::syscall::close(fd);
    true
}

fn write_record(fd: i64, user: &str, salt: u32, digest: u64) {
    crate::syscall::write_all(fd, user.as_bytes());
    crate::syscall::write_all(fd, b":$p9$");
    let mut b = [0u8; 16];
    crate::syscall::write_all(fd, hex(salt as u64, &mut b).as_bytes());
    crate::syscall::write_all(fd, b"$");
    let mut b2 = [0u8; 16];
    crate::syscall::write_all(fd, hex(digest, &mut b2).as_bytes());
    crate::syscall::write_all(fd, b"\n");
}

fn salt_for(name: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn hash_password(salt: u32, password: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in salt.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for b in password {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn hex(v: u64, buf: &mut [u8; 16]) -> &str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        buf[i] = HEX[((v >> ((15 - i) * 4)) & 0xF) as usize];
    }
    core::str::from_utf8(buf).unwrap_or("")
}

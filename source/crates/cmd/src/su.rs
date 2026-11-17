//! `su` — run a shell as another user.
//!
//! ```text
//! su [user]           switch to `user` (default: root)
//! su -c "cmd" user    not supported yet; the shell is always interactive
//! ```
//!
//! The password is read from the console with echo disabled (the line editor
//! is not used here, so characters are simply not echoed).

use crate::passwd;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut target = "root";
    for i in 1..argc {
        if let Some(a) = crate::arg(argc, argv, i) {
            if !a.starts_with('-') {
                target = a;
            }
        }
    }

    let user = match passwd::lookup_name(target) {
        Some(u) => u,
        None => {
            crate::out_str("su: no such user: ");
            crate::outln(target);
            return 1;
        }
    };

    let current = crate::syscall::getuid();
    // Root switching to another account needs no password.
    let needs_password = current != 0 && (current as u32) != user.uid;

    let mut pass = [0u8; 128];
    let pass_ptr = if needs_password {
        crate::out_str("password: ");
        let n = read_secret(&mut pass);
        crate::out(b"\n");
        if n == 0 {
            crate::outln("su: cancelled");
            return 1;
        }
        pass[n] = 0;
        pass.as_ptr()
    } else {
        core::ptr::null()
    };

    let name_c = crate::syscall::make_cstr(target);
    if crate::syscall::login(name_c.as_ptr(), pass_ptr) < 0 {
        crate::outln("su: authentication failed");
        return 1;
    }

    // Replace this process with a fresh shell so the previous identity is
    // gone for good.
    let rc = crate::syscall::make_cstr("/rc/bin/rc");
    let argv: [*const u8; 2] = [rc.as_ptr(), core::ptr::null()];
    let _ = crate::syscall::exec(rc.as_ptr(), argv.as_ptr());
    crate::outln("su: cannot start shell");
    1
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

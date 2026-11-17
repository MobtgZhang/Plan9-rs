//! `whoami` — print the effective login name.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let mut buf = [0u8; 64];
    let n = crate::syscall::getuser(&mut buf);
    if n <= 0 {
        crate::outln("whoami: no user name");
        return 1;
    }
    crate::out(&buf[..n as usize]);
    crate::out(b"\n");
    0
}

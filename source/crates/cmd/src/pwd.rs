//! `pwd` — print the working directory (kernel-tracked, Plan 9 `getwd`).

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let mut buf = [0u8; 256];
    let n = crate::syscall::getcwd(&mut buf);
    if n < 0 {
        crate::outln("pwd: cannot get working directory");
        return 1;
    }
    crate::out(&buf[..n as usize]);
    crate::out(b"\n");
    0
}

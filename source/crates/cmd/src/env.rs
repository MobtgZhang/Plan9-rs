//! `env` — print the environment (Plan 9 keeps this in /env).

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // The RAM root has no environment device wired to variables yet;
    // report the identity variables the kernel does maintain.
    let mut user = [0u8; 32];
    let un = crate::syscall::getuser(&mut user);
    let user: &[u8] = if un > 0 { &user[..un as usize] } else { b"glenda" };
    crate::out(b"user=");
    crate::out(user);
    crate::out(b"\n");

    let mut cwd = [0u8; 256];
    let cn = crate::syscall::getcwd(&mut cwd);
    crate::out(b"cwd=");
    if cn > 0 {
        crate::out(&cwd[..cn as usize]);
    } else {
        crate::out(b"/");
    }
    crate::out(b"\n");

    crate::out(b"sysname=plan9\n");
    0
}

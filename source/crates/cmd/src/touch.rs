//! `touch` — create files if missing (timestamp updates need WSTAT and
//! are not kept by the RAM root).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: touch file...");
        return 1;
    }
    let mut status = 0;
    for i in 1..argc {
        if let Some(path) = crate::arg(argc, argv, i) {
            let cs = crate::syscall::make_cstr(path);
            // Existing files are only touched (opened), never truncated.
            let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OWRITE);
            if fd >= 0 {
                crate::syscall::close(fd);
                continue;
            }
            let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
            if fd < 0 {
                crate::out_str("touch: can't create ");
                crate::out_str(path);
                crate::out(b"\n");
                status = 1;
            } else {
                crate::syscall::close(fd);
            }
        }
    }
    status
}

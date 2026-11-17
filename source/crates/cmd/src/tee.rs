//! `tee` — copy standard input to a file and standard output.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: tee file");
        return 1;
    }
    let path = crate::arg(argc, argv, 1).unwrap_or("");
    let cs = crate::syscall::make_cstr(path);
    let out_fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if out_fd < 0 {
        crate::out_str("tee: can't create ");
        crate::out_str(path);
        crate::out(b"\n");
        return 1;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = crate::syscall::read(0, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        crate::syscall::write(1, buf.as_ptr(), n as usize);
        crate::syscall::write(out_fd, buf.as_ptr(), n as usize);
    }
    crate::syscall::close(out_fd);
    0
}

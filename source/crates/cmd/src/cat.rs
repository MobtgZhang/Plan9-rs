//! `cat` — concatenate files to standard output.

use crate::syscall;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut status = 0;
    if argc <= 1 {
        crate::copy_fd(0, 1);
        return 0;
    }
    for i in 1..argc {
        let name = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        if name == "-" {
            crate::copy_fd(0, 1);
            continue;
        }
        let cs = syscall::make_cstr(name);
        let fd = syscall::open(cs.as_ptr(), syscall::OREAD);
        if fd < 0 {
            crate::out_str("cat: can't open ");
            crate::out_str(name);
            crate::out(b"\n");
            status = 1;
            continue;
        }
        crate::copy_fd(fd, 1);
        syscall::close(fd);
    }
    status
}

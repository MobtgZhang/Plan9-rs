//! `mv` — move files: copy then remove the source.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: mv source destination");
        return 1;
    }
    let src = crate::arg(argc, argv, 1).unwrap_or("");
    let dst = crate::arg(argc, argv, 2).unwrap_or("");
    if crate::copy_path(src, dst) {
        let cs = crate::syscall::make_cstr(src);
        if crate::syscall::remove(cs.as_ptr()) < 0 {
            crate::out_str("mv: can't remove ");
            crate::out_str(src);
            crate::out(b"\n");
            return 1;
        }
        0
    } else {
        crate::out_str("mv: can't move ");
        crate::out_str(src);
        crate::out(b"\n");
        1
    }
}

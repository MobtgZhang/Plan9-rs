//! `rm` — remove files; `-r`/`-rf` removes directory trees by listing
//! and removing entries bottom-up (the RAM root removes directories
//! recursively, so a plain directory remove also works).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: rm [-r] file...");
        return 1;
    }
    let mut status = 0;
    for i in 1..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) if p != "-r" && p != "-f" && p != "-rf" && p != "-fr" => p,
            Some(_) => continue,
            None => continue,
        };
        let cs = crate::syscall::make_cstr(path);
        if crate::syscall::remove(cs.as_ptr()) < 0 {
            crate::out_str("rm: can't remove ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
        }
    }
    status
}

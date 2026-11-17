//! `rmdir` — remove empty directories.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: rmdir dir...");
        return 1;
    }
    let mut status = 0;
    for i in 1..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) => p,
            None => continue,
        };
        // Only remove when it is a directory; `remove` on a directory
        // already refuses non-empty ones.
        let mut sb = [0u8; 256];
        let is_dir = match crate::stat_text(path, &mut sb) {
            Some(n) => {
                // "name mode length qid\n"
                let text = &sb[..n];
                let mut it = text.split(|&b| b == b' ');
                let _name = it.next();
                let mode = it
                    .next()
                    .and_then(|f| core::str::from_utf8(f).ok())
                    .and_then(crate::parse_u64)
                    .unwrap_or(0);
                mode & 0x4000_0000 != 0
            }
            None => false,
        };
        if !is_dir {
            crate::out_str("rmdir: not a directory: ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
            continue;
        }
        let cs = crate::syscall::make_cstr(path);
        if crate::syscall::remove(cs.as_ptr()) < 0 {
            crate::out_str("rmdir: can't remove ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
        }
    }
    status
}

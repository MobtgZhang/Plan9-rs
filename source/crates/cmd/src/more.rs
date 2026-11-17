//! `more` — page through a file, N lines at a time, waiting for Enter.

const PAGE: usize = 20;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut status = 0;
    if argc < 2 {
        // Read stdin in pages.
        return page_fd(0, "<stdin>");
    }
    for i in 1..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) => p,
            None => continue,
        };
        let fd = crate::open_read(path);
        if fd < 0 {
            crate::out_str("more: can't open ");
            crate::outln(path);
            status = 1;
            continue;
        }
        status |= page_fd(fd, path);
        crate::syscall::close(fd);
    }
    status
}

fn page_fd(fd: i64, name: &str) -> i32 {
    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 512];
    let mut shown = 0usize;
    while let Some(n) = lr.next_line(&mut line) {
        crate::out(&line[..n]);
        crate::out(b"\n");
        shown += 1;
        if shown >= PAGE {
            shown = 0;
            crate::out_str("-- more: ");
            crate::out_str(name);
            crate::out_str(" -- (Enter = continue, q = quit) ");
            let mut key = [0u8; 1];
            let got = crate::syscall::read(0, key.as_mut_ptr(), 1);
            crate::out(b"\r\x1b[K");
            if got > 0 && (key[0] == b'q' || key[0] == b'Q') {
                return 0;
            }
        }
    }
    0
}

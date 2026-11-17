//! `head` — copy the first N lines (default 10) of a file to stdout.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut nlines = 10u64;
    let mut file = "";
    let mut i = 1usize;
    while i < argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => break,
        };
        if a == "-n" {
            i += 1;
            nlines = crate::arg(argc, argv, i).and_then(crate::parse_u64).unwrap_or(10);
        } else if let Some(rest) = a.strip_prefix("-n") {
            // Attached form: -n20
            nlines = crate::parse_u64(rest).unwrap_or(10);
        } else if a.len() > 1 && a.starts_with('-') {
            if let Some(v) = crate::parse_u64(&a[1..]) {
                // Plan 9 allows `head -5 file`.
                nlines = v;
            }
        } else {
            file = a;
        }
        i += 1;
    }

    let fd = if file.is_empty() {
        0
    } else {
        let cs = crate::syscall::make_cstr(file);
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
        if fd < 0 {
            crate::out_str("head: can't open ");
            crate::out_str(file);
            crate::out(b"\n");
            return 1;
        }
        fd
    };

    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 1024];
    let mut left = nlines;
    while left > 0 {
        match lr.next_line(&mut line) {
            Some(n) => {
                crate::out(&line[..n]);
                crate::out(b"\n");
                left -= 1;
            }
            None => break,
        }
    }
    if fd != 0 {
        crate::syscall::close(fd);
    }
    0
}

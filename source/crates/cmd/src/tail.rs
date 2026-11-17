//! `tail` — copy the last N lines (default 10) of a file to stdout.
//!
//! The input is scanned twice: once to count lines, once to copy the
//! trailing window (the kernel has no seekable pipes, so a ring buffer
//! pass is only used for non-seekable inputs; for files we use seek).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut nlines = 10i64;
    let mut file = "";
    let mut i = 1usize;
    while i < argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => break,
        };
        if a == "-n" {
            i += 1;
            nlines = crate::arg(argc, argv, i).and_then(crate::parse_i64).unwrap_or(10);
        } else if let Some(rest) = a.strip_prefix("-n") {
            nlines = crate::parse_i64(rest).unwrap_or(10);
        } else if a.len() > 1 && a.starts_with('-') {
            if let Some(v) = crate::parse_i64(&a[1..]) {
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
            crate::out_str("tail: can't open ");
            crate::out_str(file);
            crate::out(b"\n");
            return 1;
        }
        fd
    };

    // Count lines and remember the start of the last `nlines` window.
    let mut ring: [[u8; 1024]; 24] = [[0u8; 1024]; 24];
    let mut ring_len: [usize; 24] = [0; 24];
    let cap = ring.len() as i64;
    let keep = if nlines > cap { cap } else { nlines.max(1) };

    let mut lr = crate::LineReader::new(fd);
    let mut count = 0i64;
    loop {
        let idx = (count % keep) as usize;
        match lr.next_line(&mut ring[idx]) {
            Some(n) => {
                ring_len[idx] = n;
                count += 1;
            }
            None => break,
        }
    }

    let start = if count <= keep { 0 } else { count - keep };
    let mut status = 0;
    for k in start..count {
        let idx = (k % keep) as usize;
        crate::out(&ring[idx][..ring_len[idx]]);
        crate::out(b"\n");
    }
    if count == 0 {
        // Plan 9 `tail -0` prints nothing; other cases already handled.
        if nlines == 0 {
            status = 0;
        }
    }
    if fd != 0 {
        crate::syscall::close(fd);
    }
    status
}

//! `nl` — number the lines of a file (`nl -v start` honoured).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut start: u64 = 1;
    let mut width = 6usize;
    let mut files: [&str; 4] = [""; 4];
    let mut nf = 0usize;
    let mut i = 1usize;
    while i < argc {
        match crate::arg(argc, argv, i) {
            Some("-v") => {
                i += 1;
                start = crate::arg(argc, argv, i).and_then(crate::parse_u64).unwrap_or(1);
            }
            Some("-w") => {
                i += 1;
                width = crate::arg(argc, argv, i)
                    .and_then(crate::parse_u64)
                    .unwrap_or(6) as usize;
            }
            Some(a) => {
                if nf < 4 {
                    files[nf] = a;
                    nf += 1;
                }
            }
            None => {}
        }
        i += 1;
    }

    let mut status = 0;
    let mut num = start;
    for f in files.iter().take(nf) {
        let fd = crate::open_read(f);
        if fd < 0 {
            crate::out_str("nl: can't open ");
            crate::outln(f);
            status = 1;
            continue;
        }
        let mut lr = crate::LineReader::new(fd);
        let mut line = [0u8; 512];
        while let Some(n) = lr.next_line(&mut line) {
            let mut nb = [0u8; 20];
            let text = crate::utoa(num, &mut nb);
            for _ in text.len()..width.saturating_sub(1) {
                crate::out(b" ");
            }
            crate::out_str(text);
            crate::out(b"\t");
            crate::out(&line[..n]);
            crate::out(b"\n");
            num += 1;
        }
        crate::syscall::close(fd);
    }
    status
}

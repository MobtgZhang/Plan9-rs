//! `uniq` — drop or report adjacent repeated lines.
//!
//! Plan 9 usage: `uniq [-c | -d | -u] [-n] [fields] [file]`.  This port
//! supports -c (prefix count), -d (only duplicates), -u (only uniques)
//! and a leading field-skip count.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut mode_count = false;
    let mut mode_dup = false;
    let mut mode_uniq = false;
    let mut skip_fields = 0usize;
    let mut file = "";

    for i in 1..argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        match a {
            "-c" => mode_count = true,
            "-d" => mode_dup = true,
            "-u" => mode_uniq = true,
            _ => {
                if let Some(n) = crate::parse_u64(a) {
                    skip_fields = n as usize;
                } else {
                    file = a;
                }
            }
        }
    }

    let fd = if file.is_empty() {
        0
    } else {
        let cs = crate::syscall::make_cstr(file);
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
        if fd < 0 {
            crate::out_str("uniq: can't open ");
            crate::out_str(file);
            crate::out(b"\n");
            return 1;
        }
        fd
    };

    fn key<'a>(line: &'a [u8], skip: usize) -> &'a [u8] {
        let mut f = 0usize;
        let mut i = 0usize;
        while f < skip && i < line.len() {
            if line[i] == b' ' || line[i] == b'\t' {
                while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                    i += 1;
                }
                f += 1;
            } else {
                i += 1;
            }
        }
        &line[i.min(line.len())..]
    };

    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 1024];
    let mut have_prev = false;
    let mut prev: [u8; 1024] = [0u8; 1024];
    let mut prev_len = 0usize;
    let mut run = 0u64;

    while let Some(n) = lr.next_line(&mut line) {
        let cur = &line[..n];
        if have_prev && key(cur, skip_fields) == key(&prev[..prev_len], skip_fields) {
            run += 1;
            continue;
        }
        if have_prev {
            let show = if mode_dup { run > 1 } else if mode_uniq { run == 1 } else { true };
            if show && !mode_count {
                crate::out(&prev[..prev_len]);
                crate::out(b"\n");
            }
            if show && mode_count {
                let mut b = [0u8; 20];
                crate::out_str(crate::utoa(run, &mut b));
                crate::out(b" ");
                crate::out(&prev[..prev_len]);
                crate::out(b"\n");
            }
        }
        prev_len = n;
        prev[..n].copy_from_slice(cur);
        have_prev = true;
        run = 1;
    }
    if have_prev {
        let show = if mode_dup { run > 1 } else if mode_uniq { run == 1 } else { true };
        if show {
            if mode_count {
                let mut b = [0u8; 20];
                crate::out_str(crate::utoa(run, &mut b));
                crate::out(b" ");
            }
            crate::out(&prev[..prev_len]);
            crate::out(b"\n");
        }
    }

    if fd != 0 {
        crate::syscall::close(fd);
    }
    0
}

//! `wc` — count lines, words and bytes (Plan 9 order: lines words chars).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut files: [&str; 16] = [""; 16];
    let mut nfiles = 0usize;
    let mut opt_l = false;
    let mut opt_w = false;
    let mut opt_c = false;

    for i in 1..argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        match a {
            "-l" => opt_l = true,
            "-w" => opt_w = true,
            "-c" | "-m" => opt_c = true,
            other => {
                if nfiles < files.len() {
                    files[nfiles] = other;
                    nfiles += 1;
                }
            }
        }
    }
    if !opt_l && !opt_w && !opt_c {
        opt_l = true;
        opt_w = true;
        opt_c = true;
    }

    let mut status = 0;
    let mut tl = 0u64;
    let mut tw = 0u64;
    let mut tc = 0u64;
    if nfiles == 0 {
        // No file arguments: read standard input.
        let (l, w, c) = count("").unwrap_or((0, 0, 0));
        print_counts(l, w, c, opt_l, opt_w, opt_c, None);
        return status;
    }
    for f in files.iter().take(nfiles) {
        let (l, w, c) = match count(f) {
            Some(v) => v,
            None => {
                crate::out_str("wc: can't open ");
                crate::out_str(f);
                crate::out(b"\n");
                status = 1;
                continue;
            }
        };
        print_counts(l, w, c, opt_l, opt_w, opt_c, Some(f));
        tl += l;
        tw += w;
        tc += c;
    }
    if nfiles > 1 {
        print_counts(tl, tw, tc, opt_l, opt_w, opt_c, None);
    }
    status
}

fn count(path: &str) -> Option<(u64, u64, u64)> {
    let fd = if path.is_empty() {
        0
    } else {
        let cs = crate::syscall::make_cstr(path);
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
        if fd < 0 {
            return None;
        }
        fd
    };

    let mut lines = 0u64;
    let mut words = 0u64;
    let mut bytes = 0u64;
    let mut in_word = false;
    let mut buf = [0u8; 1024];
    loop {
        let n = crate::syscall::read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        bytes += n as u64;
        for &b in buf[..n as usize].iter() {
            if b == b'\n' {
                lines += 1;
            }
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                in_word = false;
            } else if !in_word {
                in_word = true;
                words += 1;
            }
        }
    }
    if fd != 0 {
        crate::syscall::close(fd);
    }
    Some((lines, words, bytes))
}

fn print_counts(l: u64, w: u64, c: u64, ol: bool, ow: bool, oc: bool, name: Option<&str>) {
    let mut b = [0u8; 24];
    let mut first = true;
    let mut put = |s: &str| {
        if !first {
            crate::out(b" ");
        }
        first = false;
        crate::out_str(s);
    };
    if ol {
        put(crate::utoa(l, &mut b));
    }
    if ow {
        let mut b2 = [0u8; 24];
        put(crate::utoa(w, &mut b2));
    }
    if oc {
        let mut b3 = [0u8; 24];
        put(crate::utoa(c, &mut b3));
    }
    if let Some(n) = name {
        crate::out(b" ");
        crate::out_str(n);
    }
    crate::out(b"\n");
}

//! `cut` — extract fields or columns from each line.
//!
//! `cut -f list [-d char]` fields; `cut -c list` character ranges.
//! List entries are `N`, `N-`, `-M`, `N-M`, comma separated.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut fields_mode = false;
    let mut delim = b'\t';
    let mut list = "";
    let mut file = "";

    let mut i = 1usize;
    while i < argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => break,
        };
        if a == "-f" {
            i += 1;
            list = crate::arg(argc, argv, i).unwrap_or("");
            fields_mode = true;
        } else if a == "-c" {
            i += 1;
            list = crate::arg(argc, argv, i).unwrap_or("");
            fields_mode = false;
        } else if a == "-d" {
            i += 1;
            if let Some(d) = crate::arg(argc, argv, i) {
                if let Some(c) = d.as_bytes().first() {
                    delim = *c;
                }
            }
        } else {
            file = a;
        }
        i += 1;
    }
    if list.is_empty() {
        crate::outln("usage: cut -f list [-d char] | -c list [file]");
        return 1;
    }

    let ranges = parse_list(list);
    let fd = if file.is_empty() {
        0
    } else {
        let cs = crate::syscall::make_cstr(file);
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
        if fd < 0 {
            crate::out_str("cut: can't open ");
            crate::out_str(file);
            crate::out(b"\n");
            return 1;
        }
        fd
    };

    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 1024];
    while let Some(n) = lr.next_line(&mut line) {
        if fields_mode {
            emit_fields(&line[..n], delim, &ranges);
        } else {
            emit_chars(&line[..n], &ranges);
        }
    }
    if fd != 0 {
        crate::syscall::close(fd);
    }
    0
}

#[derive(Clone, Copy)]
struct Range {
    from: usize, // 1-based; from=0 means "to end of line"
    to: usize,   // inclusive; to=0 means "to end of line"
}

fn parse_list(list: &str) -> [Range; 16] {
    let mut out = [Range { from: 0, to: 0 }; 16];
    let mut n = 0usize;
    for part in list.split(',') {
        if n >= out.len() {
            break;
        }
        let mut it = part.splitn(2, '-');
        let a = it.next().unwrap_or("");
        let b = it.next();
        let from = crate::parse_u64(a).unwrap_or(0) as usize;
        let to = match b {
            Some(b) => crate::parse_u64(b).unwrap_or(0) as usize,
            None => {
                if a.ends_with('-') {
                    0
                } else {
                    from
                }
            }
        };
        out[n] = Range { from: from.max(1), to };
        n += 1;
    }
    out
}

fn emit_fields(line: &[u8], delim: u8, ranges: &[Range; 16]) {
    // Split by delim into fields (1-based).
    let mut idx = 0usize;
    let mut start = 0usize;
    let mut first = true;
    for r in ranges.iter() {
        if r.from == 0 && r.to == 0 {
            break;
        }
        // find the r.from-th field
        let mut want = r.from;
        let mut fs = 0usize;
        let mut fe = line.len();
        let mut i = start;
        // walk from beginning for simplicity
        i = 0;
        let mut fno = 1usize;
        fs = 0;
        while fno < want && i < line.len() {
            if line[i] == delim {
                fno += 1;
                fs = i + 1;
            }
            i += 1;
        }
        if want > 0 && fs >= line.len() {
            continue; // no such field
        }
        fe = fs;
        while fe < line.len() && line[fe] != delim {
            fe += 1;
        }
        let _ = idx;
        idx += 1;
        if !first {
            crate::out(&[delim]);
        }
        first = false;
        crate::out(&line[fs..fe]);
    }
    crate::out(b"\n");
}

fn emit_chars(line: &[u8], ranges: &[Range; 16]) {
    let mut first = true;
    for r in ranges.iter() {
        if r.from == 0 && r.to == 0 {
            break;
        }
        let to = if r.to == 0 || r.to > line.len() { line.len() } else { r.to };
        let from = (r.from - 1).min(line.len());
        if from >= to {
            continue;
        }
        if !first {
            crate::out(b" ");
        }
        first = false;
        crate::out(&line[from..to]);
    }
    crate::out(b"\n");
}

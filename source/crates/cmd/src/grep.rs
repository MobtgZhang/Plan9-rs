//! `grep` — print lines matching a pattern.
//!
//! Supported options: `-v` (invert), `-n` (line numbers), `-i` (ignore
//! case), `-c` (count only), `-l` (list files with matches).  Patterns
//! are literal text; full regular expressions are provided by the host
//! `sed`/`awk` ports and the `libregexp` crate.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut invert = false;
    let mut numbers = false;
    let mut icase = false;
    let mut count_only = false;
    let mut list_files = false;
    let mut pattern = "";
    let mut files: [&str; 16] = [""; 16];
    let mut nfiles = 0usize;

    for i in 1..argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        match a {
            "-v" => invert = true,
            "-n" => numbers = true,
            "-i" => icase = true,
            "-c" => count_only = true,
            "-l" => list_files = true,
            _ => {
                if pattern.is_empty() {
                    pattern = a;
                } else if nfiles < files.len() {
                    files[nfiles] = a;
                    nfiles += 1;
                }
            }
        }
    }

    if pattern.is_empty() {
        crate::outln("usage: grep [-vilnc] pattern [file ...]");
        return 2;
    }

    let mut status = 1;
    for f in files.iter().take(nfiles) {
        if grep_file(f, pattern, invert, numbers, icase, count_only, list_files) {
            status = 0;
        }
    }
    if nfiles == 0 {
        if grep_fd(0, "", pattern, invert, numbers, icase, count_only, list_files) {
            status = 0;
        }
    }
    status
}

fn match_line(line: &[u8], pat: &[u8], icase: bool) -> bool {
    if pat.is_empty() {
        return true;
    }
    if pat.len() > line.len() {
        return false;
    }
    for i in 0..=(line.len() - pat.len()) {
        let mut ok = true;
        for (j, &n) in pat.iter().enumerate() {
            let h = line[i + j];
            if icase {
                if h.to_ascii_lowercase() != n.to_ascii_lowercase() {
                    ok = false;
                    break;
                }
            } else if h != n {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

const MAXLINE: usize = 1024;

fn grep_file(
    path: &str,
    pattern: &str,
    invert: bool,
    numbers: bool,
    icase: bool,
    count_only: bool,
    list_files: bool,
) -> bool {
    let cs = crate::syscall::make_cstr(path);
    let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
    if fd < 0 {
        crate::out_str("grep: can't open ");
        crate::out_str(path);
        crate::out(b"\n");
        return false;
    }
    grep_fd(fd, path, pattern, invert, numbers, icase, count_only, list_files)
}

fn grep_fd(
    fd: i64,
    path: &str,
    pattern: &str,
    invert: bool,
    numbers: bool,
    icase: bool,
    count_only: bool,
    list_files: bool,
) -> bool {
    let pat = pattern.as_bytes();
    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; MAXLINE];
    let mut lineno = 0u64;
    let mut matches = 0u64;
    let mut found = false;
    while let Some(n) = lr.next_line(&mut line) {
        lineno += 1;
        let m = match_line(&line[..n], pat, icase);
        if m != invert {
            found = true;
            matches += 1;
            if count_only || list_files {
                continue;
            }
            if numbers {
                let mut b = [0u8; 20];
                crate::out_str(crate::utoa(lineno, &mut b));
                crate::out(b":");
            }
            if list_files {
                crate::out_str(path);
                crate::out(b"\n");
                break;
            } else {
                crate::out(&line[..n]);
                crate::out(b"\n");
            }
        }
    }
    if count_only {
        let mut b = [0u8; 20];
        crate::out_str(crate::utoa(matches, &mut b));
        if !path.is_empty() {
            crate::out(b" ");
            crate::out_str(path);
        }
        crate::out(b"\n");
    }
    found
}

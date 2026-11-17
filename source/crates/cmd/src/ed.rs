//! `ed` — a minimal line editor in the spirit of Plan 9 `ed`:
//! `a` append, `i` insert, `d` delete, `p` print, `n` numbered print,
//! `w file` write, `q` quit, `$`, `=`.
//!
//! The text buffer lives in a static, not on the stack: the user stack is
//! 64 KiB and a 256-line buffer is already ~51 KiB.

const MAX_LINES: usize = 256;
const MAX_LINE: usize = 200;

static mut LINES: [[u8; MAX_LINE]; MAX_LINES] = [[0; MAX_LINE]; MAX_LINES];
static mut LENS: [usize; MAX_LINES] = [0; MAX_LINES];
static mut NLINES: usize = 0;
static mut DIRTY: bool = false;

/// Shift lines `[at, n)` down one slot and write `text` at `at`.
unsafe fn insert(at: usize, text: &[u8]) {
    if NLINES >= MAX_LINES {
        crate::outln("ed: buffer full");
        return;
    }
    let at = at.min(NLINES);
    let mut i = NLINES;
    while i > at {
        LINES[i] = LINES[i - 1];
        LENS[i] = LENS[i - 1];
        i -= 1;
    }
    let m = text.len().min(MAX_LINE);
    LINES[at][..m].copy_from_slice(&text[..m]);
    LENS[at] = m;
    NLINES += 1;
    DIRTY = true;
}

unsafe fn delete(at: usize) {
    if at >= NLINES {
        return;
    }
    let mut i = at;
    while i + 1 < NLINES {
        LINES[i] = LINES[i + 1];
        LENS[i] = LENS[i + 1];
        i += 1;
    }
    NLINES -= 1;
    DIRTY = true;
}

unsafe fn print(at: usize, numbered: bool) {
    if at >= NLINES {
        crate::outln("ed: address out of range");
        return;
    }
    let mut b = [0u8; 20];
    if numbered {
        crate::out_str(crate::utoa((at + 1) as u64, &mut b));
        crate::out(b"\t");
    }
    crate::out(&LINES[at][..LENS[at]]);
    crate::out(b"\n");
}

/// Parse an address: a number, `.` (current) or `$` (last).  0 = bad.
fn parse_addr(s: &str, n: usize, cur: usize) -> usize {
    match s {
        "" | "." => {
            if n == 0 {
                0
            } else {
                cur.max(1).min(n)
            }
        }
        "$" => n,
        other => other
            .parse::<usize>()
            .ok()
            .filter(|&v| v >= 1 && v <= n)
            .unwrap_or(0),
    }
}

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut cur = 0usize; // current line (0-based; 0 == empty)
    let mut filename: Option<&str> = None;

    unsafe {
        NLINES = 0;
        DIRTY = false;
    }

    if argc > 1 {
        filename = crate::arg(argc, argv, 1);
        if let Some(f) = filename {
            load_file(f);
        }
    }

    let mut lr = crate::LineReader::new(0);
    let mut cmd = [0u8; 256];
    crate::outln("ed: minimal line editor (a i d p n w q)");

    while let Some(n) = lr.next_line(&mut cmd) {
        let text = core::str::from_utf8(&cmd[..n]).unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let mut it = text.splitn(2, char::is_whitespace);
        let verb = it.next().unwrap_or("");
        let rest = it.next().unwrap_or("").trim();

        match verb {
            "a" | "i" => {
                unsafe {
                    cur = NLINES;
                }
                cur = read_append(&mut lr, cur);
            }
            "d" => {
                let (nlines, _) = unsafe { (NLINES, DIRTY) };
                let addr = parse_addr(rest, nlines, cur);
                if addr > 0 {
                    unsafe { delete(addr - 1) };
                    cur = addr.saturating_sub(1);
                } else {
                    crate::outln("ed: bad address");
                }
            }
            "p" | "n" => {
                let numbered = verb == "n";
                let nlines = unsafe { NLINES };
                let addr = parse_addr(rest, nlines, cur);
                if addr > 0 {
                    cur = addr;
                    unsafe { print(addr - 1, numbered) };
                } else {
                    crate::outln("ed: bad address");
                }
            }
            "=" => {
                let nlines = unsafe { NLINES };
                let mut b = [0u8; 20];
                crate::out_str(crate::utoa(nlines as u64, &mut b));
                crate::out(b"\n");
            }
            "w" => {
                let f = if rest.is_empty() {
                    filename.unwrap_or("untitled")
                } else {
                    rest
                };
                if write_file(f) {
                    crate::outln("ed: written");
                } else {
                    crate::outln("ed: write failed");
                }
            }
            "q" => {
                let dirty = unsafe { DIRTY };
                if dirty {
                    crate::outln("ed: changes not written (w or Q)");
                    unsafe { DIRTY = false }; // second q quits
                } else {
                    return 0;
                }
            }
            "Q" => return 0,
            _ => crate::outln("ed: unknown command"),
        }
    }
    0
}

fn read_append(lr: &mut crate::LineReader, mut cur: usize) -> usize {
    let mut line = [0u8; 512];
    while let Some(n) = lr.next_line(&mut line) {
        let text = core::str::from_utf8(&line[..n]).unwrap_or("");
        if text == "." {
            break;
        }
        unsafe { insert(cur, &line[..n]) };
        cur += 1;
        let nlines = unsafe { NLINES };
        cur = cur.min(nlines);
    }
    cur
}

fn load_file(name: &str) {
    let fd = crate::open_read(name);
    if fd < 0 {
        return;
    }
    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 512];
    while let Some(n) = lr.next_line(&mut line) {
        unsafe {
            let at = NLINES;
            insert(at, &line[..n]);
        }
    }
    crate::syscall::close(fd);
}

fn write_file(name: &str) -> bool {
    let cs = crate::syscall::make_cstr(name);
    let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OWRITE, 0o644);
    if fd < 0 {
        return false;
    }
    let mut ok = true;
    unsafe {
        for i in 0..NLINES {
            let l = &LINES[i][..LENS[i]];
            if crate::syscall::write(fd, l.as_ptr(), l.len()) < 0
                || crate::syscall::write(fd, b"\n".as_ptr(), 1) < 0
            {
                ok = false;
                break;
            }
        }
    }
    crate::syscall::close(fd);
    if ok {
        unsafe { DIRTY = false };
    }
    ok
}

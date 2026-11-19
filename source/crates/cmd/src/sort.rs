//! `sort` — sort input lines (Plan 9 options: -u unique, -r reverse,
//! -n numeric).  Input is limited by the arena (4096 lines).

use core::cmp::Ordering;
use core::sync::atomic::AtomicBool;
use crate::workspace::WorkspaceLease;

const MAX_LINES: usize = 4096;
const ARENA_SIZE: usize = 65536;

struct Sorter<'a> {
    arena: &'a mut [u8; ARENA_SIZE],
    starts: &'a mut [u32; MAX_LINES],
    lens: &'a mut [u16; MAX_LINES],
    count: usize,
    arena_len: usize,
    numeric: bool,
    reverse: bool,
    unique: bool,
}

impl Sorter<'_> {
    fn append(&mut self, line: &[u8]) -> bool {
        if self.count >= MAX_LINES || self.arena_len + line.len() + 1 > ARENA_SIZE {
            return false;
        }
        self.starts[self.count] = self.arena_len as u32;
        self.lens[self.count] = line.len() as u16;
        self.arena[self.arena_len..self.arena_len + line.len()].copy_from_slice(line);
        self.arena_len += line.len() + 1;
        self.count += 1;
        true
    }

    fn line(&self, i: usize) -> &[u8] {
        let s = self.starts[i] as usize;
        let l = self.lens[i] as usize;
        &self.arena[s..s + l]
    }

    fn less(&self, a: usize, b: usize) -> bool {
        let (x, y) = (self.line(a), self.line(b));
        let ord = if self.numeric {
            num_key(x).partial_cmp(&num_key(y)).unwrap_or(Ordering::Equal).then(x.cmp(y))
        } else {
            x.cmp(y)
        };
        ord == Ordering::Less
    }

    fn sort(&mut self) {
        for i in 1..self.count {
            let mut j = i;
            while j > 0 && self.less(j, j - 1) {
                let (t0, t1) = (self.starts[j - 1], self.lens[j - 1]);
                self.starts[j - 1] = self.starts[j];
                self.lens[j - 1] = self.lens[j];
                self.starts[j] = t0;
                self.lens[j] = t1;
                j -= 1;
            }
        }
    }

    fn emit(&mut self) {
        let mut prev_len = 0usize;
        let mut prev = [0u8; 1024];
        for idx in 0..self.count {
            // Reverse order walks the sorted table backwards.
            let i = if self.reverse { self.count - 1 - idx } else { idx };
            let cur = self.line(i);
            if self.unique && prev_len > 0 && cur.len() == prev_len && cur == &prev[..prev_len] {
                continue;
            }
            if self.unique {
                prev_len = cur.len().min(prev.len());
                prev[..prev_len].copy_from_slice(&cur[..prev_len]);
            }
            crate::out(cur);
            crate::out(b"\n");
        }
    }
}

/// Leading numeric prefix, Plan 9 `sort -n` style.
fn num_key(b: &[u8]) -> f64 {
    let mut v: f64 = 0.0;
    let mut neg = false;
    let mut i = 0usize;
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    if i < b.len() && b[i] == b'-' {
        neg = true;
        i += 1;
    }
    while i < b.len() && b[i].is_ascii_digit() {
        v = v * 10.0 + (b[i] - b'0') as f64;
        i += 1;
    }
    if neg {
        v = -v;
    }
    v
}

/// Feed every line of `fd` into `emit` (no allocation).
fn collect_fd(fd: i64, mut emit: impl FnMut(&[u8])) {
    let mut lr = crate::LineReader::new(fd);
    let mut line = [0u8; 1024];
    while let Some(n) = lr.next_line(&mut line) {
        emit(&line[..n]);
    }
}

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut unique = false;
    let mut reverse = false;
    let mut numeric = false;
    let mut files: [&str; 8] = [""; 8];
    let mut nfiles = 0usize;

    for i in 1..argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        match a {
            "-u" => unique = true,
            "-r" => reverse = true,
            "-n" => numeric = true,
            other => {
                if nfiles < files.len() {
                    files[nfiles] = other;
                    nfiles += 1;
                }
            }
        }
    }

    // Command state lives in .bss; the exec loader zero-fills those pages.
    static mut ARENA: [u8; ARENA_SIZE] = [0u8; ARENA_SIZE];
    static mut STARTS: [u32; MAX_LINES] = [0; MAX_LINES];
    static mut LENS: [u16; MAX_LINES] = [0; MAX_LINES];
    static BUSY: AtomicBool = AtomicBool::new(false);

    let Some(_lease) = WorkspaceLease::claim(&BUSY) else {
        crate::outln("sort: workspace is busy");
        return 1;
    };
    let mut s = unsafe {
        Sorter {
            arena: &mut *(&raw mut ARENA),
            starts: &mut *(&raw mut STARTS),
            lens: &mut *(&raw mut LENS),
            count: 0,
            arena_len: 0,
            numeric,
            reverse,
            unique,
        }
    };

    if nfiles == 0 {
        collect_fd(0, |line| {
            s.append(line);
        });
    } else {
        for f in files.iter().take(nfiles) {
            let cs = crate::syscall::make_cstr(f);
            let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OREAD);
            if fd < 0 {
                crate::out_str("sort: can't open ");
                crate::out_str(f);
                crate::out(b"\n");
                return 1;
            }
            collect_fd(fd, |line| {
                s.append(line);
            });
            crate::syscall::close(fd);
        }
    }

    s.sort();
    s.emit();
    0
}

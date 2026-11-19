//! `ls` — list directory contents.
//!
//! Plan 9 `ls` lists one file per line by default; this port supports
//! `-l` (long form with mode, length and name) and `-d` (directory
//! itself, not its contents).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut long = false;
    let mut dir_only = false;
    let mut paths: [&str; 32] = [""; 32];
    let mut npaths = 0usize;

    for i in 1..argc {
        let a = match crate::arg(argc, argv, i) {
            Some(a) => a,
            None => continue,
        };
        match a {
            "-l" => long = true,
            "-1" => {}
            "-d" => dir_only = true,
            other => {
                if npaths < paths.len() {
                    paths[npaths] = other;
                    npaths += 1;
                }
            }
        }
    }
    if npaths == 0 {
        paths[0] = ".";
        npaths = 1;
    }

    let mut status = 0;
    let multi = npaths > 1;
    for i in 0..npaths {
        let path = paths[i];
        if multi {
            // Plan 9 prints a blank line and a header between arguments.
            if i > 0 {
                crate::out(b"\n");
            }
            crate::out_str(path);
            crate::out(b":\n");
        }
        if dir_only {
            print_entry(path, long);
            continue;
        }
        if !list_one(path, long) {
            status = 1;
        }
    }
    status
}

/// List the contents of directory `path`; a plain file prints itself.
fn list_one(path: &str, long: bool) -> bool {
    let mut sb = [0u8; 256];
    let st = crate::stat_text(path, &mut sb);
    let is_dir = match &st {
        Some(n) => {
            let parts = split4(&sb[..*n]);
            u64_bytes(parts[1]).unwrap_or(0) & 0x4000_0000 != 0
        }
        None => false,
    };
    if st.is_none() {
        crate::out_str("ls: can't open ");
        crate::out_str(path);
        crate::out(b"\n");
        return false;
    }
    if !is_dir {
        print_entry(path, long);
        return true;
    }
    let mut buf = [0u8; 4096];
    let n = crate::list_dir(path, &mut buf);
    if n < 0 {
        return false;
    }
    let text = &buf[..n as usize];
    let mut start = 0usize;
    while start < text.len() {
        let end = text[start..].iter().position(|&b| b == b'\n').map(|p| start + p).unwrap_or(text.len());
        let name_bytes = &text[start..end];
        start = end + 1;
        if name_bytes.is_empty() {
            continue;
        }
        let name = unsafe { core::str::from_utf8_unchecked(name_bytes) };
        let joined = join(path, name);
        print_entry(joined.as_str(), long);
    }
    true
}

/// Join directory path and entry name into a display path.
fn join(dir: &str, name: &str) -> String8 {
    let mut s = String8::new();
    s.push_str(dir);
    if !dir.ends_with('/') {
        s.push(b'/');
    }
    s.push_str(name);
    s
}

/// Small fixed-size string to build joined paths without allocation.
pub struct String8 {
    buf: [u8; 256],
    len: usize,
}

impl String8 {
    pub fn new() -> Self {
        Self { buf: [0u8; 256], len: 0 }
    }
    /// Join `dir` and `name` with a slash.
    pub fn from_two(dir: &str, name: &str) -> Self {
        let mut s = Self::new();
        s.push_str(dir);
        if !dir.ends_with('/') {
            s.push(b'/');
        }
        s.push_str(name);
        s
    }
    pub fn push_str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if self.len < 255 {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }
    pub fn push(&mut self, c: u8) {
        if self.len < 255 {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }
    pub fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

/// Render one entry, optionally in long form.
fn print_entry(path: &str, long: bool) {
    if !long {
        crate::out_str(path);
        crate::out(b"\n");
        return;
    }
    let mut sb = [0u8; 256];
    let n = crate::stat_text(path, &mut sb);
    if n.is_none() {
        crate::out_str("?");
        crate::out(b"\n");
        return;
    }
    let text = &sb[..n.unwrap()];
    // Fields: name mode length qid
    let parts: [&[u8]; 4] = split4(text);
    let mode = u64_bytes(parts[1]).unwrap_or(0);
    let length = u64_bytes(parts[2]).unwrap_or(0);
    let is_dir = mode & 0x4000_0000 != 0;

    let mut out = String8::new();
    out.push(if is_dir { b'd' } else { b'-' });
    let perm = (mode & 0o777) as u32;
    let mut pb = [0u8; 8];
    let perms = octal(perm, &mut pb);
    // zero-pad to three digits
    for _ in perms.len()..3 {
        out.push(b'0');
    }
    out.push_str(perms);
    out.push(b' ');
    let mut lb = [0u8; 20];
    out.push_str(crate::utoa(length, &mut lb));
    out.push(b' ');
    out.push_str(path);
    crate::out_str(out.as_str());
    crate::out(b"\n");
}

/// Render `v` in base 8 into `buf`.
fn octal(v: u32, buf: &mut [u8; 8]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut n = 0usize;
    let mut v = v;
    while v > 0 && n < buf.len() {
        buf[n] = b'0' + (v & 0o7) as u8;
        v >>= 3;
        n += 1;
    }
    buf[..n].reverse();
    core::str::from_utf8(&buf[..n]).unwrap_or("0")
}

/// Split "a b c d\n" into the four fields.
fn split4(text: &[u8]) -> [&[u8]; 4] {
    let mut out: [&[u8]; 4] = [b"", b"", b"", b""];
    let mut idx = 0;
    let mut it = text.split(|&b| b == b' ' || b == b'\n');
    while idx < 4 {
        if let Some(f) = it.next() {
            out[idx] = f;
            idx += 1;
        } else {
            break;
        }
    }
    out
}

fn u64_bytes(b: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(b).ok()?;
    crate::parse_u64(s)
}

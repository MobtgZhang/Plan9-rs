//! Plan 9 / Bash-compatible user shell.
//!
//! This is a small no_std shell built on the Plan 9 syscall interface.  It
//! provides Bash-style builtins, `|` pipelines and `<`/`>`/`>>` redirection,
//! and dispatches unknown commands through fork + exec, so a command runs
//! as `/bin/<name>` without replacing the shell.

#![no_std]
#![no_main]

mod syscall;

use core::arch::asm;
use syscall::{
    chdir, close, create3, dup2, exec, exit, fork, getpid, list, open, pipe, read, remove, wait,
    write, yield_cpu, DMDIR,
};

const O_RDONLY: u32 = 0;
const OWRITE: u32 = 2;

const MAX_TOK: usize = 32;
const MAX_STAGE: usize = 8;
const MAX_WORDS: usize = 16;

// ---------------------------------------------------------------------------
// Output helpers: everything the shell prints goes through fd 1 so that
// pipelines and redirection behave uniformly.
// ---------------------------------------------------------------------------

fn out(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    write(1, buf.as_ptr(), buf.len());
}

fn out_str(s: &str) {
    out(s.as_bytes());
}

fn outln(s: &str) {
    out(s.as_bytes());
    out(b"\n");
}

fn cstr(s: &str) -> (usize, [u8; 256]) {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 256];
    let n = if bytes.len() < 255 { bytes.len() } else { 255 };
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
    (n, buf)
}

/// Null-terminate the byte range `line[a..b]` into a fresh buffer.
fn range_cstr(line: &[u8], a: usize, b: usize) -> [u8; 256] {
    let mut buf = [0u8; 256];
    let n = core::cmp::min(b - a, 255);
    buf[..n].copy_from_slice(&line[a..a + n]);
    buf
}

fn range_str<'a>(line: &'a [u8], a: usize, b: usize) -> &'a str {
    unsafe { core::str::from_utf8_unchecked(&line[a..b]) }
}

// ---------------------------------------------------------------------------
// Working-directory tracking for `pwd`.
// ---------------------------------------------------------------------------

static mut CWD: [u8; 256] = {
    let mut a = [0u8; 256];
    a[0] = b'/';
    a
};
static mut CWD_LEN: usize = 1;

fn cwd_snapshot() -> ([u8; 256], usize) {
    unsafe {
        let mut b = [0u8; 256];
        b[..CWD_LEN].copy_from_slice(&CWD[..CWD_LEN]);
        (b, CWD_LEN)
    }
}

fn cwd_store(line: &[u8], a: usize, b: usize) {
    unsafe {
        let n = core::cmp::min(b - a, 255);
        CWD[..n].copy_from_slice(&line[a..a + n]);
        CWD[n] = 0;
        CWD_LEN = n;
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

fn read_line(buf: &mut [u8]) -> usize {
    let mut idx = 0usize;
    loop {
        let n = read(0, &mut buf[idx], 1);
        if n <= 0 {
            yield_cpu();
            continue;
        }
        let b = buf[idx];
        if b == b'\n' || b == b'\r' {
            out(b"\r\n");
            break;
        }
        // Local echo so interactive typing is visible.
        if b == 0x7f || b == 0x08 {
            if idx > 0 {
                idx -= 1;
                out(b"\x08 \x08");
            }
            continue;
        }
        if idx + 1 < buf.len() {
            out(&[b]);
            idx += 1;
        }
    }
    idx
}

// ---------------------------------------------------------------------------
// Tokenizer + stage parsing (pipelines and redirection)
// ---------------------------------------------------------------------------

/// Split `line` into whitespace-separated tokens, returning token ranges.
fn tokenize(line: &[u8], toks: &mut [(usize, usize); MAX_TOK]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < line.len() {
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        let start = i;
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
            i += 1;
        }
        if n < toks.len() {
            toks[n] = (start, i);
            n += 1;
        }
    }
    n
}

struct Stage {
    /// Word ranges (redirections stripped).
    words: [(usize, usize); MAX_WORDS],
    nwords: usize,
    in_file: (usize, usize),
    in_ok: bool,
    out_file: (usize, usize),
    out_ok: bool,
    append: bool,
}

impl Stage {
    fn empty() -> Self {
        Self {
            words: [(0, 0); MAX_WORDS],
            nwords: 0,
            in_file: (0, 0),
            in_ok: false,
            out_file: (0, 0),
            out_ok: false,
            append: false,
        }
    }

    fn word(&self, i: usize) -> (usize, usize) {
        self.words[i]
    }

    fn word_count(&self) -> usize {
        self.nwords
    }
}

/// Parse one pipeline stage (tokens `s..e`) into words + redirections.
/// Returns None on a syntax error (dangling redirect).
fn parse_stage(line: &[u8], toks: &[(usize, usize); MAX_TOK], s: usize, e: usize) -> Option<Stage> {
    let mut st = Stage::empty();
    let mut i = s;
    while i < e {
        let (a, b) = toks[i];
        let tok = &line[a..b];
        if tok == b"<" || tok == b">" || tok == b">>" {
            if i + 1 >= e {
                return None; // dangling redirection
            }
            let f = toks[i + 1];
            if tok == b"<" {
                st.in_file = f;
                st.in_ok = true;
            } else {
                st.out_file = f;
                st.out_ok = true;
                st.append = tok == b">>";
            }
            i += 2;
            continue;
        }
        // Handle attached forms: `>file` / `>>file` / `<file`.
        if tok.len() > 1 && tok[0] == b'<' {
            st.in_file = (a + 1, b);
            st.in_ok = true;
            i += 1;
            continue;
        }
        if tok.len() > 1 && tok[0] == b'>'
            && &line[a..core::cmp::min(a + 2, b)] == b">>"
        {
            st.out_file = (a + 2, b);
            st.out_ok = true;
            st.append = true;
            i += 1;
            continue;
        }
        if tok.len() > 1 && tok[0] == b'>' {
            st.out_file = (a + 1, b);
            st.out_ok = true;
            i += 1;
            continue;
        }
        if st.nwords < MAX_WORDS {
            st.words[st.nwords] = (a, b);
            st.nwords += 1;
        }
        i += 1;
    }
    Some(st)
}

// ---------------------------------------------------------------------------
// Builtin dispatch.  Returns true when the command was a builtin.
// `in_child` is set when running inside a forked pipeline stage, where
// `exit`/`cd` must behave differently.
// ---------------------------------------------------------------------------

fn word_at<'a>(line: &'a [u8], st: &Stage, i: usize) -> &'a str {
    let (a, b) = st.word(i);
    range_str(line, a, b)
}

fn dispatch(line: &[u8], st: &Stage, in_child: bool) -> bool {
    if st.word_count() == 0 {
        return true;
    }
    let cmd = word_at(line, st, 0);
    let arg1 = if st.word_count() > 1 {
        word_at(line, st, 1)
    } else {
        ""
    };
    let arg2 = if st.word_count() > 2 {
        word_at(line, st, 2)
    } else {
        ""
    };

    match cmd {
        "help" => {
            outln("builtins: help echo pwd cd ls cat ps stat getpid rm mkdir touch cp mv wc head grep true false export unset which type printf fork exec exit");
            outln("syntax: cmd [args] | cmd2 ...   < in   > out   >> append");
            outln("other commands run as /bin/<command> in a child process");
        }
        "exit" => {
            if in_child {
                exit(0);
            }
            outln("goodbye");
            exit(0);
        }
        "echo" => {
            let mut buf = [0u8; 512];
            let mut len = 0usize;
            let start = 1usize;
            for wi in start..st.word_count() {
                if wi > start && len < buf.len() {
                    buf[len] = b' ';
                    len += 1;
                }
                let (a, b) = st.word(wi);
                let n = core::cmp::min(b - a, buf.len() - len);
                buf[len..len + n].copy_from_slice(&line[a..a + n]);
                len += n;
            }
            out(&buf[..len]);
            out(b"\n");
        }
        "pwd" => {
            let (b, n) = cwd_snapshot();
            out(&b[..n]);
            out(b"\n");
        }
        "cd" => {
            if arg1.is_empty() {
                outln("/");
            } else {
                let (_, p) = cstr(arg1);
                if chdir(p.as_ptr()) < 0 {
                    outln("cd: failed");
                } else {
                    cwd_store(line, st.word(1).0, st.word(1).1);
                }
            }
        }
        "ls" => {
            let path = if arg1.is_empty() { "/" } else { arg1 };
            list_dir(path);
        }
        "cat" => {
            if st.word_count() > 1 {
                for wi in 1..st.word_count() {
                    cat_file(word_at(line, st, wi));
                }
            } else {
                copy_fd(0, 1);
            }
        }
        "ps" => {
            list_dir("/proc");
        }
        "getpid" => {
            let pid = getpid();
            let mut b = [0u8; 16];
            let txt = format_u64(pid as u64, &mut b);
            outln(txt);
        }
        "stat" => {
            stat_file(arg1);
        }
        "true" => {}
        "false" => {
            if in_child {
                exit(1);
            }
        }
        "export" => outln("export: accepted"),
        "unset" => outln("unset: accepted"),
        "which" | "type" => outln(arg1),
        "printf" => printf_simple(arg1),
        "rm" => {
            if arg1.is_empty() {
                outln("rm: usage: rm path");
            } else {
                let (_, p) = cstr(arg1);
                if remove(p.as_ptr()) < 0 {
                    outln("rm: failed");
                }
            }
        }
        "mkdir" => {
            if arg1.is_empty() {
                outln("mkdir: usage: mkdir path");
            } else {
                let (_, p) = cstr(arg1);
                let fd = create3(p.as_ptr(), O_RDONLY, DMDIR | 0o755);
                if fd < 0 {
                    outln("mkdir: failed");
                } else {
                    close(fd);
                }
            }
        }
        "touch" => {
            if arg1.is_empty() {
                outln("touch: usage: touch path");
            } else {
                let (_, p) = cstr(arg1);
                let fd = create3(p.as_ptr(), OWRITE, 0o644);
                if fd >= 0 {
                    close(fd);
                }
                // Existing files are left untouched (no timestamp support).
            }
        }
        "cp" => {
            if arg1.is_empty() || arg2.is_empty() {
                outln("cp: usage: cp src dst");
            } else if !copy_path(arg1, arg2) {
                outln("cp: failed");
            }
        }
        "mv" => {
            if arg1.is_empty() || arg2.is_empty() {
                outln("mv: usage: mv src dst");
            } else {
                if !copy_path(arg1, arg2) {
                    outln("mv: copy failed");
                } else {
                    let (_, p) = cstr(arg1);
                    if remove(p.as_ptr()) < 0 {
                        outln("mv: remove failed");
                    }
                }
            }
        }
        "wc" => wc_cmd(arg1),
        "head" => head_cmd(line, st),
        "grep" => grep_cmd(line, st, arg1, arg2),
        "fork" => {
            let pid = fork();
            if pid > 0 {
                let mut b = [0u8; 16];
                let p = format_u64(pid as u64, &mut b);
                outln(p);
                wait(pid as i32);
            } else if pid == 0 {
                outln("[bash] child");
                exit(0);
            } else {
                outln("fork: failed");
            }
        }
        "exec" => {
            // Replace the shell with the named program.
            if st.word_count() < 2 {
                outln("exec: usage: exec program [arg]");
            } else {
                exec_binary(line, st.word(1), if st.word_count() > 2 { Some(st.word(2)) } else { None });
                outln("exec: command not found");
                exit(1);
            }
        }
        _ => return false,
    }
    true
}

fn list_dir(path: &str) {
    let (_, p) = cstr(path);
    let mut buf = [0u8; 2048];
    let n = list(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if n < 0 {
        outln("ls: failed");
        return;
    }
    out(&buf[..n as usize]);
}

fn cat_file(path: &str) {
    let (_, p) = cstr(path);
    let fd = open(p.as_ptr(), O_RDONLY);
    if fd < 0 {
        outln("cat: open failed");
        return;
    }
    copy_fd(fd, 1);
    close(fd);
}

/// Copy everything from `src` to `dst` in chunks.
fn copy_fd(src: i64, dst: i64) {
    let mut buf = [0u8; 512];
    loop {
        let n = read(src, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        write(dst, buf.as_ptr(), n as usize);
    }
}

fn copy_path(src: &str, dst: &str) -> bool {
    let (_, s) = cstr(src);
    let fd1 = open(s.as_ptr(), O_RDONLY);
    if fd1 < 0 {
        return false;
    }
    let (_, d) = cstr(dst);
    let fd2 = create3(d.as_ptr(), OWRITE, 0o644);
    if fd2 < 0 {
        close(fd1);
        return false;
    }
    copy_fd(fd1, fd2);
    close(fd1);
    close(fd2);
    true
}

fn stat_file(path: &str) {
    if path.is_empty() {
        outln("stat: usage: stat path");
        return;
    }
    let (_, p) = cstr(path);
    let mut buf = [0u8; 256];
    let rc = syscall::stat(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if rc < 0 {
        outln("stat: failed");
    } else {
        out(&buf[..rc as usize]);
        out(b"\n");
    }
}

fn printf_simple(fmt: &str) {
    // Print the format, allowing a single `%s` replaced by the second word
    // if present.  (The caller only gives one argument in this prototype.)
    let mut outb = [0u8; 256];
    let mut n = 0usize;
    for &b in fmt.as_bytes() {
        if n < outb.len() {
            outb[n] = b;
            n += 1;
        }
    }
    out(&outb[..n]);
    out(b"\n");
}

/// `wc [file]` — counts lines, words, bytes (stdin when no file given).
fn wc_cmd(arg1: &str) {
    let mut fd = 0i64;
    if !arg1.is_empty() {
        let (_, p) = cstr(arg1);
        fd = open(p.as_ptr(), O_RDONLY);
        if fd < 0 {
            outln("wc: open failed");
            return;
        }
    }
    let mut lines = 0u64;
    let mut words = 0u64;
    let mut bytes = 0u64;
    let mut in_word = false;
    let mut buf = [0u8; 512];
    loop {
        let n = read(fd, buf.as_mut_ptr(), buf.len());
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
        close(fd);
    }
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    let mut b3 = [0u8; 20];
    let mut outb = [0u8; 80];
    let mut k = 0usize;
    for txt in [
        format_u64(lines, &mut b1),
        format_u64(words, &mut b2),
        format_u64(bytes, &mut b3),
    ] {
        for &c in txt.as_bytes() {
            outb[k] = c;
            k += 1;
        }
        outb[k] = b' ';
        k += 1;
    }
    outb[k - 1] = b'\n';
    out(&outb[..k]);
}

/// `head [-n N] [file]` — first N lines (default 10).
fn head_cmd(line: &[u8], st: &Stage) {
    let mut nlines = 10u64;
    let mut file = "";
    let mut wi = 1usize;
    while wi < st.word_count() {
        let w = word_at(line, st, wi);
        if w == "-n" && wi + 1 < st.word_count() {
            nlines = parse_u64(word_at(line, st, wi + 1)).unwrap_or(10);
            wi += 2;
        } else {
            file = w;
            wi += 1;
        }
    }
    let mut fd = 0i64;
    if !file.is_empty() {
        let (_, p) = cstr(file);
        fd = open(p.as_ptr(), O_RDONLY);
        if fd < 0 {
            outln("head: open failed");
            return;
        }
    }
    let mut left = nlines;
    let mut buf = [0u8; 512];
    let mut partial = [0u8; 512];
    let mut plen = 0usize;
    let mut done = false;
    while !done {
        let n = read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let mut i = 0usize;
        while i < n as usize {
            let b = buf[i];
            i += 1;
            if b == b'\n' {
                if left == 0 {
                    done = true;
                    break;
                }
                left -= 1;
                partial[plen] = b'\n';
                plen += 1;
                out(&partial[..plen]);
                plen = 0;
            } else if plen < partial.len() {
                partial[plen] = b;
                plen += 1;
            }
        }
    }
    if plen > 0 && left > 0 {
        out(&partial[..plen]);
        out(b"\n");
    }
    if fd != 0 {
        close(fd);
    }
}

/// `grep pattern [file]` — print lines containing the pattern (stdin when
/// no file given).
fn grep_cmd(_line: &[u8], _st: &Stage, pat: &str, file: &str) {
    if pat.is_empty() {
        outln("grep: usage: grep pattern [file]");
        return;
    }
    let mut fd = 0i64;
    if !file.is_empty() {
        let (_, p) = cstr(file);
        fd = open(p.as_ptr(), O_RDONLY);
        if fd < 0 {
            outln("grep: open failed");
            return;
        }
    }
    let patb = pat.as_bytes();
    let mut buf = [0u8; 512];
    let mut cur = [0u8; 512];
    let mut clen = 0usize;
    loop {
        let n = read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        for &b in buf[..n as usize].iter() {
            if b == b'\n' {
                if contains(&cur[..clen], patb) {
                    out(&cur[..clen]);
                    out(b"\n");
                }
                clen = 0;
            } else if clen < cur.len() {
                cur[clen] = b;
                clen += 1;
            }
        }
    }
    if clen > 0 && contains(&cur[..clen], patb) {
        out(&cur[..clen]);
        out(b"\n");
    }
    if fd != 0 {
        close(fd);
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - needle.len()) {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

fn parse_u64(s: &str) -> Option<u64> {
    let mut v = 0u64;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some(v)
}

fn exec_binary(line: &[u8], prog: (usize, usize), arg: Option<(usize, usize)>) {
    let name = range_str(line, prog.0, prog.1);
    let mut path = [0u8; 256];
    let prefix = b"/bin/";
    path[..prefix.len()].copy_from_slice(prefix);
    let nameb = name.as_bytes();
    let n = core::cmp::min(nameb.len(), 255 - prefix.len());
    path[prefix.len()..prefix.len() + n].copy_from_slice(&nameb[..n]);
    path[prefix.len() + n] = 0;

    let mut arg_buf = [0u8; 256];
    let arg_ptr = if let Some((a, b)) = arg {
        let ab = range_cstr(line, a, b);
        arg_buf.copy_from_slice(&ab);
        arg_buf.as_ptr()
    } else {
        core::ptr::null()
    };

    let argv: [*const u8; 3] = [
        path.as_ptr(),
        arg_ptr,
        core::ptr::null(),
    ];

    let _rc = exec(path.as_ptr(), argv.as_ptr(), 0);
}

fn format_u64(mut v: u64, buf: &mut [u8]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut n = 0usize;
    let mut tmp = [0u8; 20];
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
    }
    unsafe { core::str::from_utf8_unchecked(&buf[..n]) }
}

// ---------------------------------------------------------------------------
// Line execution: pipelines + redirection
// ---------------------------------------------------------------------------

fn is_known_builtin(line: &[u8], st: &Stage) -> bool {
    if st.word_count() == 0 {
        return true;
    }
    match word_at(line, st, 0) {
        "help" | "exit" | "echo" | "pwd" | "cd" | "ls" | "cat" | "ps" | "getpid" | "stat"
        | "true" | "false" | "export" | "unset" | "which" | "type" | "printf" | "rm"
        | "mkdir" | "touch" | "cp" | "mv" | "wc" | "head" | "grep" | "fork" | "exec" => true,
        _ => false,
    }
}

/// Apply a stage's redirections to the current process (must run in the
/// forked child).
fn apply_redirs(line: &[u8], st: &Stage) {
    if st.in_ok {
        let f = range_cstr(line, st.in_file.0, st.in_file.1);
        let fd = open(f.as_ptr(), O_RDONLY);
        if fd < 0 {
            outln("sh: input open failed");
            exit(1);
        }
        if fd != 0 {
            dup2(fd, 0);
            close(fd);
        }
    }
    if st.out_ok {
        let f = range_cstr(line, st.out_file.0, st.out_file.1);
        let mode = if st.append { O_RDONLY } else { OWRITE };
        let fd = if st.append {
            // Append: open (or create) then seek to end.
            let mut fd = create3(f.as_ptr(), O_RDONLY, 0o644);
            if fd < 0 {
                fd = open(f.as_ptr(), O_RDONLY);
            }
            fd
        } else {
            create3(f.as_ptr(), OWRITE, 0o644)
        };
        if fd < 0 {
            outln("sh: output open failed");
            exit(1);
        }
        if st.append {
            syscall::seek(fd, 0, 2);
        }
        if fd != 1 {
            dup2(fd, 1);
            close(fd);
        }
    }
}

/// Run one stage inside an already-forked child; never returns.
fn run_stage_child(line: &[u8], st: &Stage) -> ! {
    if dispatch(line, st, true) {
        exit(0);
    }
    exec_binary(line, st.word(0), if st.word_count() > 1 { Some(st.word(1)) } else { None });
    out_str("sh: command not found: ");
    out_str(word_at(line, st, 0));
    out(b"\n");
    exit(1);
}

fn run_line(line: &[u8]) {
    let mut toks = [(0usize, 0usize); MAX_TOK];
    let ntok = tokenize(line, &mut toks);
    if ntok == 0 {
        return;
    }

    // Split into pipeline stages on '|'.
    let mut stages: [(usize, usize); MAX_STAGE] = [(0, 0); MAX_STAGE];
    let mut nstages = 0usize;
    let mut s = 0usize;
    for t in 0..ntok {
        let (a, b) = toks[t];
        if &line[a..b] == b"|" {
            if t == s {
                outln("sh: syntax error near |");
                return;
            }
            stages[nstages] = (s, t);
            nstages += 1;
            s = t + 1;
        }
    }
    if s == ntok {
        outln("sh: syntax error near |");
        return;
    }
    stages[nstages] = (s, ntok);
    nstages += 1;
    if nstages > MAX_STAGE {
        outln("sh: too many pipeline stages");
        return;
    }

    // Parse each stage.
    let mut parsed: [Stage; MAX_STAGE] = [Stage::empty(), Stage::empty(), Stage::empty(), Stage::empty(),
        Stage::empty(), Stage::empty(), Stage::empty(), Stage::empty()];
    for i in 0..nstages {
        match parse_stage(line, &toks, stages[i].0, stages[i].1) {
            Some(st) => parsed[i] = st,
            None => {
                outln("sh: syntax error in redirection");
                return;
            }
        }
    }

    // Fast path: single stage, no redirection.
    if nstages == 1 && !parsed[0].in_ok && !parsed[0].out_ok {
        if parsed[0].word_count() == 0 {
            return;
        }
        if is_known_builtin(line, &parsed[0]) {
            dispatch(line, &parsed[0], false);
            return;
        }
        // External command: fork + exec + wait so the shell survives.
        let pid = fork();
        if pid == 0 {
            run_stage_child(line, &parsed[0]);
        } else if pid > 0 {
            wait(pid as i32);
        } else {
            outln("fork: failed");
        }
        return;
    }

    // General path: every stage runs in a forked child.
    let mut prev_read: i64 = -1;
    let mut pids = [0i64; MAX_STAGE];
    for i in 0..nstages {
        let has_next = i + 1 < nstages;
        let mut pfd = [0i64; 2];
        if has_next {
            if pipe(&mut pfd) < 0 {
                outln("pipe: failed");
                return;
            }
        }
        let pid = fork();
        if pid == 0 {
            // Child: wire up stdin/stdout then run the stage.
            if prev_read >= 0 {
                dup2(prev_read, 0);
                close(prev_read);
            }
            if has_next {
                close(pfd[0]);
                dup2(pfd[1], 1);
                close(pfd[1]);
            }
            apply_redirs(line, &parsed[i]);
            run_stage_child(line, &parsed[i]);
        } else if pid < 0 {
            outln("fork: failed");
            return;
        }
        // Parent: close our ends of the pipes and record the pid.
        if prev_read >= 0 {
            close(prev_read);
        }
        if has_next {
            close(pfd[1]);
            prev_read = pfd[0];
        }
        pids[i] = pid as i64;
    }
    for i in 0..nstages {
        wait(pids[i] as i32);
    }
}

// ---------------------------------------------------------------------------
// Shell main loop
// ---------------------------------------------------------------------------

fn main() -> ! {
    out_str("\n[bash] Plan 9 from Outer Space — Rust shell\n");
    out_str("[bash] pid=");
    let mut pid_buf = [0u8; 16];
    let s = format_u64(getpid() as u64, &mut pid_buf);
    outln(s);

    let mut line = [0u8; 256];
    loop {
        out_str("bash$ ");
        let len = read_line(&mut line);
        if len == 0 {
            continue;
        }
        run_line(&line[..len]);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)) }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfi", options(nostack, preserves_flags)) }
    }
}

/// Binary entry point (the kernel jumps here in ring 3).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

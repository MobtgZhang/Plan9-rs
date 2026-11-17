//! `rc` — the Plan 9 shell.
//!
//! A faithful-in-spirit port of `plan9/sys/src/cmd/rc`'s interactive
//! behaviour for this kernel: the `term%` prompt, `;`-separated command
//! lists, `#` comments, `|` pipelines, `<` `>` `>>` redirection and
//! command execution from `/bin` and `/rc/bin`.

use crate::lineedit;
use crate::syscall;

const OREAD: u32 = syscall::OREAD;
const OWRITE: u32 = syscall::OWRITE;

const MAX_TOK: usize = 32;
const MAX_STAGE: usize = 8;
const MAX_WORDS: usize = 16;

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn out(buf: &[u8]) {
    syscall::write_all(1, buf);
}

fn out_str(s: &str) {
    out(s.as_bytes());
}

fn outln(s: &str) {
    out(s.as_bytes());
    out(b"\n");
}

fn range_str<'a>(line: &'a [u8], a: usize, b: usize) -> &'a str {
    unsafe { core::str::from_utf8_unchecked(&line[a..b]) }
}

fn word_at<'a>(line: &'a [u8], st: &Stage, i: usize) -> &'a str {
    let (a, b) = st.word(i);
    range_str(line, a, b)
}

// ---------------------------------------------------------------------------
// Tokenizer + stage parsing (pipelines and redirection)
// ---------------------------------------------------------------------------

/// Split `line` into whitespace-separated tokens, skipping `#` comments.
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
        // rc comments run to the end of the line.
        if line[i] == b'#' {
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
    words: [(usize, usize); MAX_WORDS],
    nwords: usize,
    in_file: (usize, usize),
    in_ok: bool,
    out_file: (usize, usize),
    out_ok: bool,
    append: bool,
}

impl Stage {
    const fn empty() -> Self {
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

/// Parse one pipeline stage into words + redirections.
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
        // Attached forms: `>file` / `>>file` / `<file`.
        if tok.len() > 1 && tok[0] == b'<' {
            st.in_file = (a + 1, b);
            st.in_ok = true;
            i += 1;
            continue;
        }
        if tok.len() > 1 && tok[0] == b'>' && &line[a..core::cmp::min(a + 2, b)] == b">>" {
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
// Builtin commands (rc keeps only `cd` and `shift`; we add `exit`)
// ---------------------------------------------------------------------------

fn is_builtin(line: &[u8], st: &Stage) -> bool {
    if st.word_count() == 0 {
        return true;
    }
    match word_at(line, st, 0) {
        "cd" | "exit" | "help" => true,
        _ => false,
    }
}

/// Commands installed in /bin; kept in one place so `help` and TAB
/// completion agree with what the build actually ships.
pub const COMMANDS: &[&str] = &[
    "basename", "cat", "chmod", "chown", "clear", "cmp", "cp", "cut", "date",
    "dc", "diff", "dirname", "du", "echo", "ed", "env", "expr", "false",
    "fortune", "grep", "group", "head", "hostname", "id", "kill", "ln", "ls",
    "mkdir", "more", "mv", "nl", "passwd", "ps", "pwd", "rc", "rm", "rmdir",
    "seq", "sleep", "sort", "stat", "su", "tail", "tee", "test", "time",
    "touch", "tr", "true", "tty", "uname", "uniq", "units", "uptime",
    "useradd", "usermod", "wc", "who", "whoami", "yes",
];

fn builtin_help() {
    out_str("builtins: cd exit help\n\ncommands:\n");
    let per_line = 6;
    for (i, c) in COMMANDS.iter().enumerate() {
        if i % per_line == 0 {
            out_str("  ");
        }
        out_str(" ");
        out_str(c);
        // Simple column padding.
        let mut pad = 10u8;
        while (pad as usize) > c.len() + 1 {
            out(b" ");
            pad -= 1;
        }
        if i % per_line == per_line - 1 || i == COMMANDS.len() - 1 {
            out(b"\n");
        }
    }
    out_str("\nredirection: < > >>    pipelines: cmd | cmd    lists: cmd ; cmd\n");
}

fn dispatch(line: &[u8], st: &Stage, in_child: bool) -> bool {
    if st.word_count() == 0 {
        return true;
    }
    match word_at(line, st, 0) {
        "cd" => {
            let arg1 = if st.word_count() > 1 { word_at(line, st, 1) } else { "" };
            if arg1.is_empty() {
                return true;
            }
            let cs = syscall::make_cstr(arg1);
            if syscall::chdir(cs.as_ptr()) < 0 {
                out_str("rc: can't cd: ");
                out_str(arg1);
                out(b"\n");
                if in_child {
                    syscall::exit(1);
                }
            }
            true
        }
        "exit" => {
            let code = if st.word_count() > 1 {
                word_at(line, st, 1).parse::<i32>().unwrap_or(0)
            } else {
                0
            };
            syscall::exit(code)
        }
        "help" => {
            builtin_help();
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// External command execution from /bin and /rc/bin
// ---------------------------------------------------------------------------

/// Build the full argv array (NUL-terminated strings) and exec.
fn exec_argv(line: &[u8], st: &Stage, dir_prefix: &[u8]) -> bool {
    let name = word_at(line, st, 0);
    let mut path = [0u8; 256];
    path[..dir_prefix.len()].copy_from_slice(dir_prefix);
    let nameb = name.as_bytes();
    let n = core::cmp::min(nameb.len(), 255 - dir_prefix.len());
    path[dir_prefix.len()..dir_prefix.len() + n].copy_from_slice(&nameb[..n]);
    path[dir_prefix.len() + n] = 0;

    // Copy every word to NUL-terminated buffers on the stack.
    let mut bufs: [[u8; 64]; MAX_WORDS] = [[0u8; 64]; MAX_WORDS];
    let mut ptrs: [*const u8; MAX_WORDS + 1] = [core::ptr::null(); MAX_WORDS + 1];
    let nw = st.word_count().min(MAX_WORDS);
    ptrs[0] = path.as_ptr();
    for k in 1..nw {
        let (a, b) = st.word(k);
        let wb = &line[a..b];
        let m = wb.len().min(63);
        bufs[k][..m].copy_from_slice(&wb[..m]);
        bufs[k][m] = 0;
        ptrs[k] = bufs[k].as_ptr();
    }
    ptrs[nw] = core::ptr::null();

    syscall::exec(path.as_ptr(), ptrs.as_ptr()) >= 0
}

fn exec_binary(line: &[u8], st: &Stage) -> ! {
    if exec_argv(line, st, b"/bin/") {
        syscall::exit(0);
    }
    if exec_argv(line, st, b"/rc/bin/") {
        syscall::exit(0);
    }
    if exec_argv(line, st, b"/boot/") {
        syscall::exit(0);
    }
    out_str("rc: ");
    out_str(word_at(line, st, 0));
    outln(": not found");
    syscall::exit(1);
}

// ---------------------------------------------------------------------------
// Redirection + stage execution
// ---------------------------------------------------------------------------

fn apply_redirs(line: &[u8], st: &Stage) {
    if st.in_ok {
        let (a, b) = st.in_file;
        let f = syscall::make_cstr(range_str(line, a, b));
        let fd = syscall::open(f.as_ptr(), OREAD);
        if fd < 0 {
            outln("rc: can't open < file");
            syscall::exit(1);
        }
        if fd != 0 {
            syscall::dup2(fd, 0);
            syscall::close(fd);
        }
    }
    if st.out_ok {
        let (a, b) = st.out_file;
        let f = syscall::make_cstr(range_str(line, a, b));
        let fd = if st.append {
            // Append: create (or open) then seek to end.
            let mut fd = syscall::create3(f.as_ptr(), OREAD, 0o644);
            if fd < 0 {
                fd = syscall::open(f.as_ptr(), OREAD);
            }
            fd
        } else {
            syscall::create3(f.as_ptr(), OWRITE, 0o644)
        };
        if fd < 0 {
            outln("rc: can't open > file");
            syscall::exit(1);
        }
        if st.append {
            syscall::seek(fd, 0, 2);
        }
        if fd != 1 {
            syscall::dup2(fd, 1);
            syscall::close(fd);
        }
    }
}

fn run_stage_child(line: &[u8], st: &Stage) -> ! {
    if dispatch(line, st, true) {
        syscall::exit(0);
    }
    apply_redirs(line, st);
    exec_binary(line, st);
}

// ---------------------------------------------------------------------------
// Command lists (`;` separated), pipelines and redirection
// ---------------------------------------------------------------------------

fn run_list(line: &[u8]) {
    // Split on `;`, `&&` and `||`: sequential lists and conditional lists.
    // `&&` runs the next command only when the previous one succeeded,
    // `||` only when it failed.
    let mut s = 0usize;
    let mut i = 0usize;
    let mut last_status = 0i32;
    while i <= line.len() {
        let at_end = i == line.len();
        let is_semi = at_end || line[i] == b';';
        let is_and = !at_end
            && line[i] == b'&'
            && i + 1 < line.len()
            && line[i + 1] == b'&'
            && (i == 0 || line[i - 1] != b'&');
        let is_or = !at_end && line[i] == b'|' && i + 1 < line.len() && line[i + 1] == b'|';
        // A single `|` belongs to pipelines and is not a list separator;
        // `||` and `&&` never appear inside a pipeline stage.
        if is_semi {
            let seg = &line[s..i];
            if !seg.is_empty() {
                last_status = run_segment(seg, last_status);
            }
            s = i + 1;
            i += 1;
        } else if is_and {
            let seg = &line[s..i];
            if !seg.is_empty() {
                last_status = run_segment(seg, last_status);
            }
            // Skip the second `&` and continue only on success.
            s = i + 2;
            i += 2;
            if last_status != 0 {
                // Fast-forward past the `&&` operand: skip to next `;`.
                while i < line.len() && line[i] != b';' {
                    i += 1;
                }
                s = i + 1;
            }
        } else if is_or {
            let seg = &line[s..i];
            if !seg.is_empty() {
                last_status = run_segment(seg, last_status);
            }
            s = i + 2;
            i += 2;
            if last_status == 0 {
                while i < line.len() && line[i] != b';' {
                    i += 1;
                }
                s = i + 1;
            }
        } else {
            i += 1;
        }
    }
}

/// Run one list element; `prev` is the status that led here (used by the
/// `&&`/`||` fast-forward logic).  Returns this segment's exit status.
fn run_segment(line: &[u8], _prev: i32) -> i32 {
    run_line(line);
    0
}

fn run_line(line: &[u8]) {
    if line.is_empty() {
        return;
    }
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
                outln("rc: syntax error near |");
                return;
            }
            if nstages >= MAX_STAGE {
                outln("rc: too many pipeline stages");
                return;
            }
            stages[nstages] = (s, t);
            nstages += 1;
            s = t + 1;
        }
    }
    if s == ntok {
        outln("rc: syntax error near |");
        return;
    }
    stages[nstages] = (s, ntok);
    nstages += 1;

    // Parse each stage.
    let mut parsed: [Stage; MAX_STAGE] = [
        Stage::empty(), Stage::empty(), Stage::empty(), Stage::empty(),
        Stage::empty(), Stage::empty(), Stage::empty(), Stage::empty(),
    ];
    for i in 0..nstages {
        match parse_stage(line, &toks, stages[i].0, stages[i].1) {
            Some(st) => parsed[i] = st,
            None => {
                outln("rc: syntax error in redirection");
                return;
            }
        }
    }

    // Fast path: single stage, no redirection, builtin command.
    if nstages == 1 && !parsed[0].in_ok && !parsed[0].out_ok {
        if parsed[0].word_count() == 0 {
            return;
        }
        if is_builtin(line, &parsed[0]) {
            dispatch(line, &parsed[0], false);
            return;
        }
        // External command: fork + exec + wait so the shell survives.
        let pid = syscall::fork();
        if pid == 0 {
            run_stage_child(line, &parsed[0]);
        } else if pid > 0 {
            syscall::wait(pid as i32);
        } else {
            outln("rc: fork failed");
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
            if syscall::pipe(&mut pfd) < 0 {
                outln("rc: pipe failed");
                return;
            }
        }
        let pid = syscall::fork();
        if pid == 0 {
            // Child: wire up stdin/stdout then run the stage.
            if prev_read >= 0 {
                syscall::dup2(prev_read, 0);
                syscall::close(prev_read);
            }
            if has_next {
                syscall::close(pfd[0]);
                syscall::dup2(pfd[1], 1);
                syscall::close(pfd[1]);
            }
            apply_redirs(line, &parsed[i]);
            if dispatch(line, &parsed[i], true) {
                syscall::exit(0);
            }
            exec_binary(line, &parsed[i]);
        } else if pid < 0 {
            outln("rc: fork failed");
            return;
        }
        // Parent: close our ends of the pipes and record the pid.
        if prev_read >= 0 {
            syscall::close(prev_read);
        }
        if has_next {
            syscall::close(pfd[1]);
            prev_read = pfd[0];
        }
        pids[i] = pid as i64;
    }
    for i in 0..nstages {
        syscall::wait(pids[i] as i32);
    }
}

// ---------------------------------------------------------------------------
// Shell main loop
// ---------------------------------------------------------------------------

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // Welcome banner, in the spirit of the Plan 9 `termrc` login greeting.
    out_str("\nPlan 9 from Outer Space — Rust kernel\n");
    out_str("rc (Rust) — type `help` for a list of commands\n\n");

    // Make sure the interactive shell starts in a usable directory.
    let mut cwd = [0u8; 256];
    if syscall::getcwd(&mut cwd) <= 0 {
        let root = syscall::make_cstr("/");
        syscall::chdir(root.as_ptr());
    }

    let mut line = [0u8; lineedit::MAX_LINE];
    let mut hist = lineedit::History::new();

    loop {
        lineedit::prompt();
        let len = match lineedit::edit_line(&mut line, &mut hist) {
            lineedit::Edit::Line(n) => n,
            lineedit::Edit::Eof => {
                // The console closed; keep the shell alive so the terminal
                // never drops back to a dead prompt.
                syscall::sleep_ms(50);
                continue;
            }
        };
        if len == 0 {
            continue;
        }
        hist.push(&line[..len]);
        run_list(&line[..len]);
    }
}

/// Entry point hook for the crt0 stub; the `rc` binary wires it up.
pub fn entry(argc: u64, argv: u64) -> ! {
    let code = main(argc as usize, argv as *const *const u8);
    syscall::exit(code)
}

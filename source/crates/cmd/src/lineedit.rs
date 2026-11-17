//! Interactive line editor for `rc`.
//!
//! The kernel deliberately has no terminal line discipline: `/dev/console`
//! hands the shell raw bytes, exactly like Plan 9's `cons` device.  All of
//! the interactive behaviour therefore lives here, in the user-space shell:
//!
//! * echo of typed characters,
//! * `DEL`/`BS` erase one character,
//! * `TAB` completes command names from `/bin` and `/rc/bin`,
//! * `UP`/`DOWN` walk the command history, and
//! * `Ctrl-A/E/U/K/W/L` provide the usual line-editing shortcuts.
//!
//! Escape sequences use the ANSI/VT100 forms (`ESC [ A` …), which is what
//! QEMU's serial console and the PS/2 keyboard driver both produce.

use crate::syscall;

/// Maximum length of one edited line.
pub const MAX_LINE: usize = 512;
/// Number of remembered history entries.
const HIST_MAX: usize = 32;

/// Fixed-capacity history ring (no allocator in user space).
pub struct History {
    entries: [[u8; MAX_LINE]; HIST_MAX],
    lens: [usize; HIST_MAX],
    /// Index of the oldest entry.
    head: usize,
    /// Number of valid entries.
    len: usize,
    /// Position while browsing; `== len` means "the line being edited".
    cursor: usize,
}

impl History {
    pub const fn new() -> Self {
        Self {
            entries: [[0u8; MAX_LINE]; HIST_MAX],
            lens: [0usize; HIST_MAX],
            head: 0,
            len: 0,
            cursor: 0,
        }
    }

    /// Append a line, ignoring empty lines and immediate duplicates.
    pub fn push(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        if self.len > 0 {
            let last = (self.head + self.len - 1) % HIST_MAX;
            if &self.entries[last][..self.lens[last]] == line {
                return;
            }
        }
        let slot = (self.head + self.len) % HIST_MAX;
        let n = line.len().min(MAX_LINE);
        self.entries[slot][..n].copy_from_slice(&line[..n]);
        self.lens[slot] = n;
        if self.len == HIST_MAX {
            self.head = (self.head + 1) % HIST_MAX;
        } else {
            self.len += 1;
        }
        self.cursor = self.len;
    }

    /// Entry `i`, oldest first.
    pub fn at(&self, i: usize) -> Option<&[u8]> {
        if i >= self.len {
            return None;
        }
        let slot = (self.head + i) % HIST_MAX;
        Some(&self.entries[slot][..self.lens[slot]])
    }

    /// Move back in time; returns the entry to display.
    pub fn older(&mut self) -> Option<&[u8]> {
        if self.len == 0 || self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        let slot = (self.head + self.cursor) % HIST_MAX;
        Some(&self.entries[slot][..self.lens[slot]])
    }

    /// Move forward in time; returns `Some(&[])` for the edited line.
    pub fn newer(&mut self) -> Option<&[u8]> {
        if self.len == 0 || self.cursor >= self.len {
            return None;
        }
        self.cursor += 1;
        if self.cursor == self.len {
            return Some(&[]);
        }
        let slot = (self.head + self.cursor) % HIST_MAX;
        Some(&self.entries[slot][..self.lens[slot]])
    }
}

// ---------------------------------------------------------------------------
// Console output helpers
// ---------------------------------------------------------------------------

fn put(b: &[u8]) {
    syscall::write_all(1, b);
}

/// Erase `n` characters to the left of the cursor.
fn erase_left(n: usize) {
    for _ in 0..n {
        put(b"\x08 \x08");
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Read one byte from the console, blocking until it arrives.
fn read_byte() -> Option<u8> {
    let mut b = 0u8;
    loop {
        let n = syscall::read(0, &mut b, 1);
        if n == 1 {
            return Some(b);
        }
        if n < 0 {
            return None;
        }
        syscall::yield_cpu();
    }
}

/// Try to read a byte without blocking for long, returning `None` when the
/// console has nothing queued.  A short spin covers the case where the bytes
/// of an escape sequence arrive a few cycles apart.
fn read_byte_now() -> Option<u8> {
    let mut b = 0u8;
    for _ in 0..200_000 {
        let n = syscall::read(0, &mut b, 1);
        if n == 1 {
            return Some(b);
        }
        if n < 0 {
            return None;
        }
        syscall::yield_cpu();
    }
    None
}

// ---------------------------------------------------------------------------
// TAB completion
// ---------------------------------------------------------------------------

/// Candidate buffer size: enough for every command plus separators.
const CAND_BUF: usize = 1024;

/// Collect command names from `/bin` and `/rc/bin` into `out`.
///
/// The names are returned NUL-terminated so that a caller can iterate over
/// them without counting.
fn collect_commands(out: &mut [u8]) -> usize {
    let mut n = 0usize;
    for dir in ["/bin", "/rc/bin"] {
        let mut cpath = [0u8; 64];
        let dlen = dir.len().min(63);
        cpath[..dlen].copy_from_slice(dir.as_bytes());

        let mut buf = [0u8; 2048];
        let rc = syscall::list(cpath.as_ptr(), buf.as_mut_ptr(), buf.len());
        if rc <= 0 {
            continue;
        }
        for name in buf[..rc as usize].split(|&b| b == b'\n') {
            if name.is_empty() {
                continue;
            }
            if n + name.len() + 1 > out.len() {
                return n;
            }
            out[n..n + name.len()].copy_from_slice(name);
            n += name.len();
            out[n] = 0;
            n += 1;
        }
    }
    n
}

/// Longest common prefix of two byte strings.
fn common_prefix<'a>(a: &'a [u8], b: &[u8]) -> &'a [u8] {
    let mut i = 0usize;
    while i < a.len() && i < b.len() && a[i] == b[i] {
        i += 1;
    }
    &a[..i]
}

/// Attempt command completion for `line[..len]` at the cursor.
///
/// Returns the number of bytes appended to the line.  When several
/// candidates share a prefix, that prefix is inserted and the list is
/// printed; a unique candidate is completed with a trailing space.
fn complete(line: &mut [u8], len: usize, prompt: &[u8]) -> usize {
    // Only complete the first word as a command name; other words are
    // completed as filesystem paths.
    let word_start = line[..len]
        .iter()
        .rposition(|&b| b == b' ' || b == b'\t')
        .map(|p| p + 1)
        .unwrap_or(0);
    if word_start >= len {
        return 0;
    }
    // Copy the word out so the line can be mutated below.
    let mut prefix_buf = [0u8; MAX_LINE];
    let plen = len - word_start;
    prefix_buf[..plen].copy_from_slice(&line[word_start..len]);
    let prefix = &prefix_buf[..plen];
    let is_command = word_start == 0;

    let mut cands = [0u8; CAND_BUF];
    let cand_len = if is_command {
        collect_commands(&mut cands)
    } else {
        complete_path(prefix, &mut cands)
    };
    if cand_len == 0 {
        return 0;
    }

    // Count the matches and their longest common prefix.
    let mut matches = 0usize;
    let mut lcp = [0u8; MAX_LINE];
    let mut lcp_len = 0usize;
    for name in cands[..cand_len].split(|&b| b == 0) {
        if name.is_empty() || !name.starts_with(prefix) || name == prefix {
            continue;
        }
        matches += 1;
        if matches == 1 {
            lcp_len = name.len().min(MAX_LINE);
            lcp[..lcp_len].copy_from_slice(&name[..lcp_len]);
        } else {
            let common = common_prefix(&lcp[..lcp_len], name);
            let n = common.len();
            lcp_len = n;
        }
    }

    if matches == 0 {
        return 0;
    }

    let mut appended = 0usize;
    if lcp_len > prefix.len() {
        let extension = &lcp[prefix.len()..lcp_len];
        let room = MAX_LINE - len;
        let n = extension.len().min(room);
        line[len..len + n].copy_from_slice(&extension[..n]);
        put(&extension[..n]);
        appended += n;
    }
    if matches == 1 && len + appended < MAX_LINE {
        line[len + appended] = b' ';
        put(b" ");
        appended += 1;
    } else if matches > 1 && lcp_len == prefix.len() {
        // Nothing new to insert and several possibilities: show them.
        put(b"\r\n");
        for name in cands[..cand_len].split(|&b| b == 0) {
            if name.is_empty() || !name.starts_with(prefix) || name == prefix {
                continue;
            }
            put(name);
            put(b"  ");
        }
        put(b"\r\n");
        put(prompt);
        put(&line[..len]);
    }
    appended
}

/// `prefix` may name a directory: list it and return entries as candidates.
fn complete_path(prefix: &[u8], out: &mut [u8]) -> usize {
    let (dir, base): (&[u8], &[u8]) = match prefix.iter().rposition(|&b| b == b'/') {
        Some(pos) => (&prefix[..=pos], &prefix[pos + 1..]),
        None => (b"." as &[u8], prefix),
    };

    let mut cpath = [0u8; 256];
    let dlen = dir.len().min(255);
    cpath[..dlen].copy_from_slice(&dir[..dlen]);
    // Trailing slash is harmless for LIST but an empty name is not.
    if dlen == 0 {
        cpath[0] = b'.';
    }

    let mut buf = [0u8; 2048];
    let rc = syscall::list(cpath.as_ptr(), buf.as_mut_ptr(), buf.len());
    if rc <= 0 {
        return 0;
    }

    let mut n = 0usize;
    for name in buf[..rc as usize].split(|&b| b == b'\n') {
        if name.is_empty() || !name.starts_with(base) {
            continue;
        }
        // Candidates are full prefixes again so the LCP logic works.
        let total = dir.len() + name.len() + 1;
        if n + total > out.len() {
            break;
        }
        n += dir.len();
        out[n - dir.len()..n].copy_from_slice(dir);
        out[n..n + name.len()].copy_from_slice(name);
        n += name.len();
        out[n] = 0;
        n += 1;
    }
    n
}


// ---------------------------------------------------------------------------
// Line editing
// ---------------------------------------------------------------------------

/// Outcome of one editing pass.
pub enum Edit {
    /// A complete line was entered (length in bytes).
    Line(usize),
    /// End of input: the console will deliver nothing more.
    Eof,
}

/// Edit one line interactively.
///
/// Characters are echoed as they are typed; the returned length excludes
/// the terminating newline.
pub fn edit_line(line: &mut [u8], hist: &mut History) -> Edit {
    let mut len = 0usize;
    let mut hist_pos = hist.len;

    loop {
        let b = match read_byte() {
            Some(b) => b,
            None => return Edit::Eof,
        };

        match b {
            b'\n' | b'\r' => {
                put(b"\r\n");
                return Edit::Line(len);
            }
            // Backspace: both DEL (0x7F, what most terminals send) and BS.
            0x7F | 0x08 => {
                if len > 0 {
                    len -= 1;
                    erase_left(1);
                }
            }
            b'\t' => {
                let (prompt, plen) = current_prompt();
                len += complete(line, len, &prompt[..plen]);
            }
            // Ctrl-C: abandon the line.
            0x03 => {
                put(b"^C\r\n");
                hist.cursor = hist.len;
                return Edit::Line(0);
            }
            // Ctrl-D: end of input on an empty line.
            0x04 => {
                if len == 0 {
                    put(b"\r\n");
                    return Edit::Eof;
                }
            }
            // Ctrl-A: beginning of line.  The cursor is tracked implicitly
            // at the end, so this simply erases what was typed.
            0x01 => {
                erase_left(len);
                len = 0;
            }
            // Ctrl-E: end of line (already there).
            0x05 => {}
            // Ctrl-U: erase the whole line.
            0x15 => {
                erase_left(len);
                len = 0;
            }
            // Ctrl-K: erase to end of line (already there).
            0x0B => {}
            // Ctrl-W: erase the previous word.
            0x17 => {
                let mut n = len;
                while n > 0 && line[n - 1] == b' ' {
                    n -= 1;
                }
                while n > 0 && line[n - 1] != b' ' {
                    n -= 1;
                }
                erase_left(len - n);
                len = n;
            }
            // Ctrl-L: clear the screen, keep the line.
            0x0C => {
                put(b"\x1b[2J\x1b[H");
                let (p, pn) = current_prompt();
                put(&p[..pn]);
                put(&line[..len]);
            }
            // Escape sequences: history and cursor keys.
            0x1b => match read_escape() {
                Esc::Up => {
                    if hist_pos > 0 {
                        hist_pos -= 1;
                        if let Some(entry) = hist.at(hist_pos) {
                            erase_left(len);
                            let n = entry.len().min(line.len());
                            let mut tmp = [0u8; MAX_LINE];
                            tmp[..n].copy_from_slice(&entry[..n]);
                            line[..n].copy_from_slice(&tmp[..n]);
                            len = n;
                            put(&line[..len]);
                        }
                    }
                }
                Esc::Down => {
                    if hist_pos < hist.len {
                        hist_pos += 1;
                        erase_left(len);
                        if hist_pos == hist.len {
                            len = 0;
                        } else if let Some(entry) = hist.at(hist_pos) {
                            let n = entry.len().min(line.len());
                            line[..n].copy_from_slice(&entry[..n]);
                            len = n;
                            put(&line[..len]);
                        }
                    }
                }
                Esc::Left | Esc::Right | Esc::Ignore => {}
            },
            // Printable ASCII (and UTF-8 continuation bytes, echoed raw).
            _ => {
                if len < line.len() {
                    line[len] = b;
                    len += 1;
                    put(&[b]);
                }
            }
        }
    }
}

enum Esc {
    Up,
    Down,
    Left,
    Right,
    Ignore,
}

/// Decode a VT100 escape sequence after the leading ESC.
fn read_escape() -> Esc {
    match read_byte_now() {
        Some(b'[') => {}
        // Lone ESC: treat as a no-op.
        _ => return Esc::Ignore,
    }
    match read_byte_now() {
        Some(b'A') => Esc::Up,
        Some(b'B') => Esc::Down,
        Some(b'C') => Esc::Right,
        Some(b'D') => Esc::Left,
        Some(_) | None => Esc::Ignore,
    }
}

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

/// Render `user@host:/cwd>` into a stack buffer, returning the buffer and
/// the number of bytes that belong to the prompt.
fn current_prompt() -> ([u8; 320], usize) {
    let mut out = [0u8; 320];
    let mut n = 0usize;

    // Login name from the kernel.
    let mut user = [0u8; 32];
    let ulen = syscall::getuser(&mut user);
    let user: &[u8] = if ulen > 0 { &user[..ulen as usize] } else { b"glenda" };

    // Working directory.
    let mut cwd = [0u8; 256];
    let clen = syscall::getcwd(&mut cwd);
    let cwd: &[u8] = if clen > 0 { &cwd[..clen as usize] } else { b"/" };

    for part in [user, b"@" as &[u8], hostname(), b":", cwd, b"> "] {
        for &b in part {
            if n < out.len() {
                out[n] = b;
                n += 1;
            }
        }
    }
    (out, n)
}

/// Print the interactive prompt: `user@host:/cwd>`.
pub fn prompt() {
    let (buf, n) = current_prompt();
    put(&buf[..n]);
}

/// Short system name, in the spirit of Plan 9's `/dev/sysname`.
pub fn hostname() -> &'static [u8] {
    b"plan9"
}

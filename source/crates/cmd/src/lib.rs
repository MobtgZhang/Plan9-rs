//! Plan 9 user commands — shared `no_std` runtime.
//!
//! Every command in this crate is a standalone bare-metal program linked
//! against the kernel's `int 0x80` syscall gate.  The runtime provides:
//!
//! - the `_start` crt0 stub (the kernel enters user mode with the System V
//!   argument stack: `[rsp] = argc`, `[rsp+8] = argv`)
//! - syscall wrappers (see `syscall`)
//! - panic handling, small formatting helpers and line/pipe I/O
//!
//! Command semantics follow the Plan 9 originals from
//! `plan9/sys/src/cmd/*` as closely as the kernel allows.

#![no_std]
use core::arch::global_asm;

pub mod syscall;

// ---------------------------------------------------------------------------
// Command modules
// ---------------------------------------------------------------------------

pub mod cat;
pub mod chmod;
pub mod chown;
pub mod cp;
pub mod cut;
pub mod date;
pub mod du;
pub mod echo;
pub mod grep;
pub mod group;
pub mod head;
pub mod hostname;
pub mod id;
pub mod kill;
pub mod lineedit;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod passwd;
pub mod passwd_cmd;
pub mod printf;
pub mod ps;
pub mod pwd;
pub mod rc;
pub mod rm;
pub mod seq;
pub mod sleep;
pub mod sort;
pub mod stat;
pub mod su;
pub mod tail;
pub mod tee;
pub mod test;
pub mod time;
pub mod touch;
pub mod tr;
pub mod uniq;
pub mod useradd;
pub mod usermod;
pub mod wc;
pub mod whoami;
pub mod tty;
pub mod uname;
pub mod basename;
pub mod clear;
pub mod cmp;
pub mod dc;
pub mod diff;
pub mod dirname;
pub mod ed;
pub mod env;
pub mod expr;
pub mod false_cmd;
pub mod fortune;
pub mod ln;
pub mod more;
pub mod nl;
pub mod rmdir;
pub mod true_cmd;
pub mod units;
pub mod uptime;
pub mod who;
pub mod yes;

// ---------------------------------------------------------------------------
// crt0: the kernel jumps to `_start` with the SysV argument stack.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .section .text.start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    mov     rdi, qword ptr [rsp]        # argc
    lea     rsi, [rsp + 8]              # argv
    call    cmd_main
    # cmd_main returned an exit status in eax -> exits(status)
    mov     rdi, rax
    mov     rax, 2                      # SYS_EXITS
    int     0x80
.halt:
    hlt
    jmp     .halt
    .size _start, . - _start
"#
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
    .section .text.start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    ldr     x0, [sp]                    /* argc */
    add     x1, sp, #8                  /* argv */
    bl      cmd_main
    /* exit status in x0 -> exits(status) */
    mov     x19, x0
    mov     x8, #2                      /* SYS_EXITS */
    svc     #0
.halt_a64:
    wfi
    b       .halt_a64
    .size _start, . - _start
"#
);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    out_str("panic: user program aborted\n");
    syscall::exit(1)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

pub fn out(bytes: &[u8]) {
    syscall::write_all(1, bytes);
}

pub fn out_str(s: &str) {
    out(s.as_bytes());
}

pub fn outln(s: &str) {
    out(s.as_bytes());
    out(b"\n");
}

// ---------------------------------------------------------------------------
// argv helpers
// ---------------------------------------------------------------------------

/// NUL-terminated C string starting at `p`, as a `&str`.
///
/// # Safety
/// `p` must point to a NUL-terminated UTF-8 string valid for the process
/// lifetime (the kernel places argv on the user stack).
pub unsafe fn cstr_to_str<'a>(p: *const u8) -> &'a str {
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 && len < 256 {
            len += 1;
        }
        let bytes = core::slice::from_raw_parts(p, len);
        core::str::from_utf8_unchecked(bytes)
    }
}

/// Argument `i` as a `&str`, or `None` past the end.
pub fn arg<'a>(argc: usize, argv: *const *const u8, i: usize) -> Option<&'a str> {
    if i >= argc {
        return None;
    }
    unsafe {
        let p = *argv.add(i);
        if p.is_null() {
            return None;
        }
        Some(cstr_to_str(p))
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Format `v` into `buf`, returning the rendered slice.
pub fn utoa(mut v: u64, buf: &mut [u8]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
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

/// Format a signed value into `buf`.
pub fn itoa(v: i64, buf: &mut [u8]) -> &str {
    if v < 0 {
        buf[0] = b'-';
        let s = utoa(v.unsigned_abs(), &mut buf[1..]);
        let n = s.len() + 1;
        return unsafe { core::str::from_utf8_unchecked(&buf[..n]) };
    }
    utoa(v as u64, buf)
}

/// Parse a non-negative decimal integer.
pub fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// Parse a (possibly negative) decimal integer.
pub fn parse_i64(s: &str) -> Option<i64> {
    if let Some(rest) = s.strip_prefix('-') {
        Some(-(parse_u64(rest)? as i64))
    } else {
        Some(parse_u64(s)? as i64)
    }
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

/// Open `path` for reading (OREAD); returns the fd or a negative error.
pub fn open_read(path: &str) -> i64 {
    let mut buf = [0u8; 256];
    let n = path.len().min(255);
    buf[..n].copy_from_slice(path.as_bytes());
    syscall::open(buf.as_ptr(), syscall::OREAD)
}

/// Create (or truncate) `path` for writing (OWRITE).
pub fn create_write(path: &str) -> i64 {
    let mut buf = [0u8; 256];
    let n = path.len().min(255);
    buf[..n].copy_from_slice(path.as_bytes());
    syscall::create3(buf.as_ptr(), syscall::OWRITE, 0o644)
}

/// Copy everything from fd `src` to fd `dst`; returns total bytes or -1.
pub fn copy_fd(src: i64, dst: i64) -> i64 {
    let mut total: i64 = 0;
    let mut buf = [0u8; 1024];
    loop {
        let n = syscall::read(src, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        if syscall::write(dst, buf.as_ptr(), n as usize) < 0 {
            return -1;
        }
        total += n;
    }
    total
}

/// Copy a file `src` -> `dst` (create/truncate semantics).
pub fn copy_path(src: &str, dst: &str) -> bool {
    let fd1 = open_read(src);
    if fd1 < 0 {
        return false;
    }
    let fd2 = create_write(dst);
    if fd2 < 0 {
        syscall::close(fd1);
        return false;
    }
    copy_fd(fd1, fd2);
    syscall::close(fd1);
    syscall::close(fd2);
    true
}

/// Directory listing: read the newline-separated name stream into a
/// caller buffer.  Returns the number of bytes read or a negative error.
pub fn list_dir(path: &str, buf: &mut [u8]) -> i64 {
    let mut p = [0u8; 256];
    let n = path.len().min(255);
    p[..n].copy_from_slice(path.as_bytes());
    syscall::list(p.as_ptr(), buf.as_mut_ptr(), buf.len())
}

/// `stat` text for `path`: "name mode length qid\n".
pub fn stat_text(path: &str, buf: &mut [u8]) -> Option<usize> {
    let mut p = [0u8; 256];
    let n = path.len().min(255);
    p[..n].copy_from_slice(path.as_bytes());
    let rc = syscall::stat(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if rc < 0 {
        None
    } else {
        Some(rc as usize)
    }
}

// ---------------------------------------------------------------------------
// Line input
// ---------------------------------------------------------------------------

/// Buffered line reader over a file descriptor (no allocation).
pub struct LineReader {
    fd: i64,
    buf: [u8; 1024],
    len: usize,
    pos: usize,
    eof: bool,
}

impl LineReader {
    pub fn new(fd: i64) -> Self {
        Self {
            fd,
            buf: [0u8; 1024],
            len: 0,
            pos: 0,
            eof: false,
        }
    }

    fn fill(&mut self) -> bool {
        if self.eof {
            return false;
        }
        self.pos = 0;
        let n = syscall::read(self.fd, self.buf.as_mut_ptr(), self.buf.len());
        if n <= 0 {
            self.eof = true;
            self.len = 0;
            return false;
        }
        self.len = n as usize;
        true
    }

    /// Read the next line (without '\n') into `out`.
    /// Returns the line length, or `None` at end of input.
    pub fn next_line(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0usize;
        loop {
            // Scan for a newline in the unconsumed window.
            while self.pos < self.len {
                let b = self.buf[self.pos];
                self.pos += 1;
                if b == b'\n' {
                    return Some(n);
                }
                if b != b'\r' && n < out.len() {
                    out[n] = b;
                    n += 1;
                }
            }
            if !self.fill() {
                // Final line without trailing newline.
                if n > 0 {
                    return Some(n);
                }
                return None;
            }
        }
    }
}

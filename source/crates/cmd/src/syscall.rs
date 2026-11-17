//! Direct Plan 9 syscall interface to the Rust kernel.
//!
//! The kernel's syscall gate is `int 0x80`; the ABI follows the Plan 9
//! `syscall.h` numbers:
//!
//!     rax = syscall number
//!     rdi, rsi, rdx, r10, r8, r9 = arg0..arg5
//!
//! Prototype extensions (LIST/PUTS/GETPID/WAIT/TIME/GETCWD) occupy
//! numbers 48-53.

use core::arch::asm;

pub const SYS_EXITS: usize = 2;
pub const SYS_OPEN: usize = 3;
pub const SYS_CREATE: usize = 4;
pub const SYS_READ: usize = 5;
pub const SYS_WRITE: usize = 6;
pub const SYS_CLOSE: usize = 7;
pub const SYS_SEEK: usize = 8;
pub const SYS_DUP: usize = 9;
pub const SYS_PIPE: usize = 10;
pub const SYS_PREAD: usize = 11;
pub const SYS_PWRITE: usize = 12;
pub const SYS_REMOVE: usize = 13;
pub const SYS_STAT: usize = 18;
pub const SYS_CHDIR: usize = 37;
pub const SYS_BRK: usize = 38;
pub const SYS_FORK: usize = 40;
pub const SYS_EXEC: usize = 1;
pub const SYS_YIELD: usize = 33;
pub const SYS_SLEEP: usize = 29;

pub const SYS_LIST: usize = 48;
pub const SYS_PUTS: usize = 49;
pub const SYS_GETPID: usize = 50;
pub const SYS_WAIT: usize = 51;
pub const SYS_TIME: usize = 52;
pub const SYS_GETCWD: usize = 53;
pub const SYS_GETUID: usize = 54;
pub const SYS_SETUID: usize = 55;
pub const SYS_GETGID: usize = 56;
pub const SYS_GETUSER: usize = 57;
pub const SYS_GETGROUPS: usize = 58;
pub const SYS_CHMOD: usize = 59;
pub const SYS_CHOWN: usize = 60;
pub const SYS_ACL: usize = 61;
pub const SYS_AUTH: usize = 62;
pub const SYS_LOGIN: usize = 63;

/// Open mode bits (Plan 9): OREAD=0, OWRITE=1, ORDWR=2, OEXEC=3.
pub const OREAD: u32 = 0;
pub const OWRITE: u32 = 1;
pub const ORDWR: u32 = 2;
pub const OEXEC: u32 = 3;

/// Plan 9 create-permission bit: create a directory instead of a file.
pub const DMDIR: u32 = 0x8000_0000;

/// "Leave this field unchanged" marker for `chown`.
pub const NO_CHANGE: u32 = u32::MAX;

#[inline(always)]
pub unsafe fn syscall0(n: usize) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let n64 = n as u64;
        let r: u64;
        asm!(
            "int 0x80",
            inout("rax") n64 => r,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
        r as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r: u64;
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") 0u64 => r,
            options(nostack, preserves_flags),
        );
        r as i64
    }
}

#[inline(always)]
pub unsafe fn syscall1(n: usize, a0: u64) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let n64 = n as u64;
        let r: u64;
        asm!(
            "int 0x80",
            inout("rax") n64 => r,
            in("rdi") a0,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
        r as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r: u64;
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") a0 => r,
            options(nostack, preserves_flags),
        );
        r as i64
    }
}

#[inline(always)]
pub unsafe fn syscall2(n: usize, a0: u64, a1: u64) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let n64 = n as u64;
        let r: u64;
        asm!(
            "int 0x80",
            inout("rax") n64 => r,
            in("rdi") a0,
            in("rsi") a1,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
        r as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r: u64;
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") a0 => r,
            in("x1") a1,
            options(nostack, preserves_flags),
        );
        r as i64
    }
}

#[inline(always)]
pub unsafe fn syscall3(n: usize, a0: u64, a1: u64, a2: u64) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let n64 = n as u64;
        let r: u64;
        asm!(
            "int 0x80",
            inout("rax") n64 => r,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
        r as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r: u64;
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") a0 => r,
            in("x1") a1,
            in("x2") a2,
            options(nostack, preserves_flags),
        );
        r as i64
    }
}

#[inline(always)]
pub unsafe fn syscall4(n: usize, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        let n64 = n as u64;
        let r: u64;
        asm!(
            "int 0x80",
            inout("rax") n64 => r,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
        r as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r: u64;
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") a0 => r,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nostack, preserves_flags),
        );
        r as i64
    }
}

/// Terminate the process with `code`.
pub fn exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXITS, code as u64);
    }
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { asm!("hlt", options(nostack, preserves_flags)) }
        #[cfg(target_arch = "aarch64")]
        unsafe { asm!("wfi", options(nostack, preserves_flags)) }
    }
}

/// Write `len` bytes at `buf` to fd `fd`.
pub fn write(fd: i64, buf: *const u8, len: usize) -> i64 {
    unsafe { syscall3(SYS_WRITE, fd as u64, buf as u64, len as u64) }
}

/// Write the whole slice, retrying on short writes.
pub fn write_all(fd: i64, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = write(fd, bytes[off..].as_ptr(), bytes.len() - off);
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

pub fn read(fd: i64, buf: *mut u8, len: usize) -> i64 {
    unsafe { syscall3(SYS_READ, fd as u64, buf as u64, len as u64) }
}

pub fn open(path: *const u8, flags: u32) -> i64 {
    unsafe { syscall2(SYS_OPEN, path as u64, flags as u64) }
}

/// Full Plan 9 create: `create(name, omode, perm)`.
pub fn create3(path: *const u8, omode: u32, perm: u32) -> i64 {
    unsafe { syscall3(SYS_CREATE, path as u64, omode as u64, perm as u64) }
}

/// Remove a file (Plan 9 `remove`).
pub fn remove(path: *const u8) -> i64 {
    unsafe { syscall1(SYS_REMOVE, path as u64) }
}

/// Create a pipe; `fds` receives [read_fd, write_fd].
pub fn pipe(fds: &mut [i64; 2]) -> i64 {
    unsafe { syscall1(SYS_PIPE, fds.as_mut_ptr() as u64) }
}

/// Plan 9 `dup(oldfd, newfd)`: install the duplicate at `newfd`.
pub fn dup2(oldfd: i64, newfd: i64) -> i64 {
    unsafe { syscall2(SYS_DUP, oldfd as u64, newfd as u64) }
}

pub fn close(fd: i64) -> i64 {
    unsafe { syscall1(SYS_CLOSE, fd as u64) }
}

pub fn fork() -> i64 {
    unsafe { syscall0(SYS_FORK) }
}

pub fn wait(pid: i32) -> i64 {
    unsafe { syscall1(SYS_WAIT, pid as u64) }
}

pub fn getpid() -> i64 {
    unsafe { syscall0(SYS_GETPID) }
}

pub fn yield_cpu() -> i64 {
    unsafe { syscall0(SYS_YIELD) }
}

/// Sleep for `ms` milliseconds.
pub fn sleep_ms(ms: u64) -> i64 {
    unsafe { syscall1(SYS_SLEEP, ms) }
}

/// Read directory names: newline-separated stream into `buf`.
pub fn list(path: *const u8, buf: *mut u8, cap: usize) -> i64 {
    unsafe { syscall3(SYS_LIST, path as u64, buf as u64, cap as u64) }
}

/// stat text into `buf`: "name mode length qid\n".
pub fn stat(path: *const u8, buf: *mut u8, cap: usize) -> i64 {
    unsafe { syscall3(SYS_STAT, path as u64, buf as u64, cap as u64) }
}

pub fn brk(addr: usize) -> i64 {
    unsafe { syscall1(SYS_BRK, addr as u64) }
}

pub fn exec(path: *const u8, argv: *const *const u8) -> i64 {
    unsafe { syscall3(SYS_EXEC, path as u64, argv as u64, 0) }
}

pub fn dup(fd: i64) -> i64 {
    unsafe { syscall1(SYS_DUP, fd as u64) }
}

pub fn chdir(path: *const u8) -> i64 {
    unsafe { syscall1(SYS_CHDIR, path as u64) }
}

pub fn seek(fd: i64, offset: i64, whence: u8) -> i64 {
    unsafe { syscall3(SYS_SEEK, fd as u64, offset as u64, whence as u64) }
}

/// Kernel time: `mode` 0 = Unix seconds, 1 = uptime ms, 2 = boot time.
pub fn time(mode: u64) -> i64 {
    unsafe { syscall1(SYS_TIME, mode) }
}

/// Working directory path copied into `buf`; returns the path length.
pub fn getcwd(buf: &mut [u8]) -> i64 {
    unsafe { syscall2(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Current user id (0 = root).
pub fn getuid() -> i64 {
    unsafe { syscall0(SYS_GETUID) }
}

/// Current group id.
pub fn getgid() -> i64 {
    unsafe { syscall0(SYS_GETGID) }
}

/// Login name copied into `buf`; returns the name length.
pub fn getuser(buf: &mut [u8]) -> i64 {
    unsafe { syscall2(SYS_GETUSER, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Supplementary group ids copied into `buf`; returns the group count.
pub fn getgroups(buf: &mut [u32]) -> i64 {
    unsafe { syscall2(SYS_GETGROUPS, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Change the caller's uid/gid. Root only, except for a no-op self-change.
pub fn setuid(uid: u32, gid: u32, name: *const u8) -> i64 {
    unsafe { syscall3(SYS_SETUID, uid as u64, gid as u64, name as u64) }
}

/// Change a file's permission bits.
pub fn chmod(path: *const u8, mode: u32) -> i64 {
    unsafe { syscall2(SYS_CHMOD, path as u64, mode as u64) }
}

/// Change a file's owner/group; `u32::MAX` leaves a field unchanged.
pub fn chown(path: *const u8, uid: u32, gid: u32) -> i64 {
    unsafe { syscall3(SYS_CHOWN, path as u64, uid as u64, gid as u64) }
}

/// Set (bits != 0) or remove (bits == 0) an ACL entry, or query it.
pub fn acl(path: *const u8, uid: u32, bits: u32, query: bool) -> i64 {
    unsafe {
        syscall4(
            SYS_ACL,
            path as u64,
            uid as u64,
            bits as u64,
            query as u64,
        )
    }
}

/// Verify a login name and password without changing credentials.
pub fn auth(name: *const u8, password: *const u8) -> i64 {
    unsafe { syscall2(SYS_AUTH, name as u64, password as u64) }
}

/// Switch to another user, verifying `password` unless the caller is root.
pub fn login(name: *const u8, password: *const u8) -> i64 {
    unsafe { syscall2(SYS_LOGIN, name as u64, password as u64) }
}

/// Copy `s` NUL-terminated into a 256-byte buffer.
pub fn make_cstr(s: &str) -> [u8; 256] {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 256];
    let n = if bytes.len() < 255 { bytes.len() } else { 255 };
    buf[..n].copy_from_slice(&bytes[..n]);
    buf
}

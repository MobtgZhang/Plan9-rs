//! Direct Plan 9 syscall interface to the Rust kernel.
//!
//! The kernel's syscall gate is `int 0x80`; the ABI follows the Plan 9
//! `syscall.h` numbers:
//!
//!     rax = syscall number
//!     rdi, rsi, rdx, r10, r8, r9 = arg0..arg5
//!
//! Extra prototype syscalls (LIST/PUTS/GETPID/WAIT) occupy numbers 48-51.

use core::arch::asm;

pub const SYS_EXITS: usize = 2;
pub const SYS_OPEN: usize = 3;
pub const SYS_CREATE: usize = 4;
pub const SYS_READ: usize = 5;
pub const SYS_WRITE: usize = 6;
pub const SYS_CLOSE: usize = 7;
pub const SYS_SEEK: usize = 8;
pub const SYS_DUP: usize = 9;
pub const SYS_STAT: usize = 18;
pub const SYS_CHDIR: usize = 37;
pub const SYS_BRK: usize = 38;
pub const SYS_FORK: usize = 40;
pub const SYS_EXEC: usize = 1;
pub const SYS_YIELD: usize = 33;

pub const SYS_LIST: usize = 48;
pub const SYS_PUTS: usize = 49;
pub const SYS_GETPID: usize = 50;
pub const SYS_WAIT: usize = 51;

#[inline(always)]
pub unsafe fn syscall0(n: usize) -> i64 {
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

#[inline(always)]
pub unsafe fn syscall1(n: usize, a0: u64) -> i64 {
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

#[inline(always)]
pub unsafe fn syscall2(n: usize, a0: u64, a1: u64) -> i64 {
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

#[inline(always)]
pub unsafe fn syscall3(n: usize, a0: u64, a1: u64, a2: u64) -> i64 {
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

pub fn exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXITS, code as u64);
    }
    loop {
        unsafe { asm!("hlt", options(nostack, preserves_flags)) }
    }
}

pub fn write(fd: i64, buf: *const u8, len: usize) -> i64 {
    unsafe { syscall3(SYS_WRITE, fd as u64, buf as u64, len as u64) }
}

pub fn read(fd: i64, buf: *mut u8, len: usize) -> i64 {
    unsafe { syscall3(SYS_READ, fd as u64, buf as u64, len as u64) }
}

pub fn open(path: *const u8, flags: u32) -> i64 {
    unsafe { syscall2(SYS_OPEN, path as u64, flags as u64) }
}

pub fn create(path: *const u8, perm: u32) -> i64 {
    unsafe { syscall2(SYS_CREATE, path as u64, perm as u64) }
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

pub fn list(path: *const u8, buf: *mut u8, cap: usize) -> i64 {
    unsafe { syscall3(SYS_LIST, path as u64, buf as u64, cap as u64) }
}

pub fn puts(buf: *const u8) -> i64 {
    unsafe { syscall1(SYS_PUTS, buf as u64) }
}

pub fn stat(path: *const u8, buf: *mut u8, cap: usize) -> i64 {
    unsafe { syscall3(SYS_STAT, path as u64, buf as u64, cap as u64) }
}

pub fn brk(addr: usize) -> i64 {
    unsafe { syscall1(SYS_BRK, addr as u64) }
}

pub fn exec(path: *const u8, argv: *const *const u8, _argc: usize) -> i64 {
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

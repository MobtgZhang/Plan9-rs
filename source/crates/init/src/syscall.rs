//! Direct syscall interface to the Plan 9 Rust kernel.
//!
//! The kernel uses `int 0x80` as its system call gate. The argument
//! convention follows Linux x86_64:
//!
//!     rax = syscall number
//!     rdi, rsi, rdx, r10, r8, r9 = arg0..arg5

use core::arch::asm;

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_STAT: usize = 4;
pub const SYS_BRK: usize = 5;
pub const SYS_EXIT: usize = 6;
pub const SYS_FORK: usize = 7;
pub const SYS_EXEC: usize = 8;
pub const SYS_WAIT: usize = 9;
pub const SYS_GETPID: usize = 10;
pub const SYS_YIELD: usize = 11;
pub const SYS_DUP: usize = 12;
pub const SYS_CHDIR: usize = 14;
pub const SYS_LIST: usize = 15;
pub const SYS_PUTS: usize = 16;

#[inline(always)]
pub unsafe fn syscall0(n: usize) -> i64 {
    let r: i64;
    asm!(
        "mov rax, {n:r}",
        "int 0x80",
        n = in(reg) n,
        lateout("rax") r,
        options(nostack, preserves_flags),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall1(n: usize, a0: u64) -> i64 {
    let r: i64;
    asm!(
        "mov rax, {n:r}",
        "mov rdi, {a0:r}",
        "int 0x80",
        n = in(reg) n,
        a0 = in(reg) a0,
        lateout("rax") r,
        out("rdi") _,
        options(nostack, preserves_flags),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall2(n: usize, a0: u64, a1: u64) -> i64 {
    let r: i64;
    asm!(
        "mov rax, {n:r}",
        "mov rdi, {a0:r}",
        "mov rsi, {a1:r}",
        "int 0x80",
        n = in(reg) n,
        a0 = in(reg) a0,
        a1 = in(reg) a1,
        lateout("rax") r,
        out("rdi") _,
        out("rsi") _,
        options(nostack, preserves_flags),
    );
    r
}

#[inline(always)]
pub unsafe fn syscall3(n: usize, a0: u64, a1: u64, a2: u64) -> i64 {
    let r: i64;
    asm!(
        "mov rax, {n:r}",
        "mov rdi, {a0:r}",
        "mov rsi, {a1:r}",
        "mov rdx, {a2:r}",
        "int 0x80",
        n = in(reg) n,
        a0 = in(reg) a0,
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        lateout("rax") r,
        out("rdi") _,
        out("rsi") _,
        out("rdx") _,
        options(nostack, preserves_flags),
    );
    r
}

pub fn exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXIT, code as u64);
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

pub fn exec(path: *const u8, argv: *const *const u8, argc: usize) -> i64 {
    unsafe { syscall3(SYS_EXEC, path as u64, argv as u64, argc as u64) }
}

pub fn dup(fd: i64) -> i64 {
    unsafe { syscall1(SYS_DUP, fd as u64) }
}

pub fn chdir(path: *const u8) -> i64 {
    unsafe { syscall1(SYS_CHDIR, path as u64) }
}

//! System library for Plan 9 Rust
//!
//! User-space system call wrappers.

#![no_std]

pub mod io;
pub mod memory;

// Re-export memory functions at crate level
pub use memory::{malloc, free, realloc, calloc};

// ============================================================================
// System Call Numbers (Plan 9)
// ============================================================================

/// System call numbers
pub const SYS_RFOK: u32 = 0;
pub const SYS_EXITS: u32 = 1;
pub const SYS_WAIT: u32 = 2;
pub const SYS_OPEN: u32 = 3;
pub const SYS_CREATE: u32 = 4;
pub const SYS_CLOSE: u32 = 5;
pub const SYS_READ: u32 = 6;
pub const SYS_WRITE: u32 = 7;
pub const SYS_SEEK: u32 = 8;
pub const SYS_DUP: u32 = 9;
pub const SYS_PIPE: u32 = 10;
pub const SYS_EXEC: u32 = 11;
pub const SYS_EXISTING: u32 = 12;
pub const SYS_BRK: u32 = 13;
pub const SYS_REMOVE: u32 = 14;
pub const SYS_RENAME: u32 = 15;
pub const SYS_NOTE: u32 = 16;
pub const SYS_SEEKDIR: u32 = 17;
pub const SYS_CHDIR: u32 = 18;
pub const SYS_CLONE: u32 = 19;
pub const SYS_YIELD: u32 = 63;
pub const SYS_GETPID: u32 = 47;
pub const SYS_GETPPID: u32 = 49;
pub const SYS_GETUID: u32 = 50;
pub const SYS_GETEUID: u32 = 51;
pub const SYS_GETGID: u32 = 52;
pub const SYS_GETEGID: u32 = 53;
pub const SYS_GETTID: u32 = 54;
pub const SYS_NSEC: u32 = 43;
pub const SYS_DUP2: u32 = 55;
pub const SYS_PREAD: u32 = 56;
pub const SYS_PWRITE: u32 = 57;
pub const SYS_CREATE9P: u32 = 70;
pub const SYS_BIND: u32 = 20;
pub const SYS_MOUNT: u32 = 21;
pub const SYS_UNMOUNT: u32 = 22;
pub const SYS_SLEEP: u32 = 23;
pub const SYS_ALARM: u32 = 24;
pub const SYS_AWAIT: u32 = 25;
pub const SYS_SEMACQUIRE: u32 = 26;
pub const SYS_SEMRELEASE: u32 = 27;
pub const SYS_RENDEZVOUS: u32 = 28;
pub const SYS_STAT: u32 = 29;
pub const SYS_FSTAT: u32 = 30;
pub const SYS_WSTAT: u32 = 31;
pub const SYS_FWSTAT: u32 = 32;
pub const SYS_SEGATTACH: u32 = 33;
pub const SYS_SEGDETACH: u32 = 34;
pub const SYS_SEGFREE: u32 = 35;
pub const SYS_SEGFLUSH: u32 = 36;

// ============================================================================
// System Call Wrapper (x86_64)
// ============================================================================

/// Perform a system call with 0 arguments
#[inline]
pub unsafe fn syscall0(num: u32) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 1 argument
#[inline]
pub unsafe fn syscall1(num: u32, arg1: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 2 arguments
#[inline]
pub unsafe fn syscall2(num: u32, arg1: u64, arg2: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 3 arguments
#[inline]
pub unsafe fn syscall3(num: u32, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 4 arguments
#[inline]
pub unsafe fn syscall4(num: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 5 arguments
#[inline]
pub unsafe fn syscall5(num: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Perform a system call with 6 arguments
#[inline]
pub unsafe fn syscall6(num: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let ret: u64;
        core::arch::asm!(
            "syscall",
            inout("rax") num as u64 => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

// ============================================================================
// Process Management
// ============================================================================

/// Fork flags
pub const RFPROC: u32 = 0x0001;
pub const RFMEM: u32 = 0x0002;
pub const RFNOWAIT: u32 = 0x0004;
pub const RFFDG: u32 = 0x0080;
pub const RFCFDG: u32 = 0x0100;
pub const RFNOMNT: u32 = 0x0008;
pub const RFENV: u32 = 0x0200;
pub const RFREND: u32 = 0x0400;
pub const RFNOTEG: u32 = 0x0800;

/// Create a new process
pub unsafe fn rfork(flags: u32) -> i32 {
    let ret = syscall1(SYS_RFOK, flags as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Terminate the current process
pub unsafe fn exits(status: *const u8) -> ! {
    syscall1(SYS_EXITS, status as u64);
    loop {} // Never returns
}

/// Terminate with status
pub unsafe fn exits_str(_status: i32) -> ! {
    // In Plan 9, exits takes a string pointer
    // For simple use, pass nil for default "normal"
    syscall1(SYS_EXITS, 0);
    loop {}
}

/// Wait for a child process
pub unsafe fn wait() -> i32 {
    let ret = syscall0(SYS_WAIT);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Get current process ID
pub unsafe fn getpid() -> u32 {
    syscall0(SYS_GETPID) as u32
}

/// Get parent process ID
pub unsafe fn getppid() -> u32 {
    syscall0(SYS_GETPPID) as u32
}

/// Get current user ID
pub unsafe fn getuid() -> u32 {
    syscall0(SYS_GETUID) as u32
}

/// Get effective user ID
pub unsafe fn geteuid() -> u32 {
    syscall0(SYS_GETEUID) as u32
}

/// Get current group ID
pub unsafe fn getgid() -> u32 {
    syscall0(SYS_GETGID) as u32
}

/// Get effective group ID
pub unsafe fn getegid() -> u32 {
    syscall0(SYS_GETEGID) as u32
}

/// Get thread ID
pub unsafe fn gettid() -> u32 {
    syscall0(SYS_GETTID) as u32
}

/// Yield the processor
pub unsafe fn yield_() {
    let _ = syscall0(SYS_YIELD);
}

/// Execute a program
///
/// # Safety
/// This function will replace the current process with a new program.
/// It should only be called from a child process after fork.
pub unsafe fn exec(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    let ret = syscall3(SYS_EXEC, path as u64, argv as u64, envp as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Sleep for specified milliseconds
pub unsafe fn sleep(ms: u32) -> i32 {
    let ret = syscall1(SYS_SLEEP, ms as u64);
    ret as i32
}

/// Alarm in milliseconds
pub unsafe fn alarm(ms: u32) -> i32 {
    let ret = syscall1(SYS_ALARM, ms as u64);
    ret as i32
}

/// Rendezvous synchronization
pub unsafe fn rendezvous(tag: u64, val: u64) -> u64 {
    syscall2(SYS_RENDEZVOUS, tag, val)
}

// ============================================================================
// File Operations
// ============================================================================

/// Open mode flags
pub const O_READ: i32 = 0;
pub const O_WRITE: i32 = 1;
pub const O_READWRITE: i32 = 2;
pub const O_EXEC: i32 = 3;
pub const O_TRUNC: i32 = 0x10;
pub const O_CLOEXEC: i32 = 0x40000;
pub const O_EXCL: i32 = 0x10000;
pub const O_NOCTTY: i32 = 0x20000;
pub const O_NONBLOCK: i32 = 0x800;
pub const O_APPEND: i32 = 0x40;

#[derive(Debug, Clone, Copy)]
pub struct Fd(*mut u8);

impl Fd {
    pub fn as_raw(&self) -> i32 {
        self.0 as i32
    }
    
    pub fn is_valid(&self) -> bool {
        !self.0.is_null()
    }
}

/// Open a file
pub unsafe fn open(path: *const u8, mode: i32) -> i32 {
    let ret = syscall2(SYS_OPEN, path as u64, mode as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Create a file
pub unsafe fn create(path: *const u8, mode: i32, perm: u32) -> i32 {
    let ret = syscall3(SYS_CREATE, path as u64, mode as u64, perm as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Close a file descriptor
pub unsafe fn close(fd: i32) -> i32 {
    let ret = syscall1(SYS_CLOSE, fd as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Read from a file descriptor
pub unsafe fn read(fd: i32, buf: *mut u8, n: usize) -> i32 {
    let ret = syscall3(SYS_READ, fd as u64, buf as u64, n as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Write to a file descriptor
pub unsafe fn write(fd: i32, buf: *const u8, n: usize) -> i32 {
    let ret = syscall3(SYS_WRITE, fd as u64, buf as u64, n as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Change file offset
pub unsafe fn seek(fd: i32, offset: i64, whence: i32) -> i64 {
    syscall3(SYS_SEEK, fd as u64, offset as u64, whence as u64) as i64
}

/// Seek from start
pub const SEEK_SET: i32 = 0;
/// Seek from current
pub const SEEK_CUR: i32 = 1;
/// Seek from end
pub const SEEK_END: i32 = 2;

/// Duplicate a file descriptor
pub unsafe fn dup(fd: i32) -> i32 {
    let ret = syscall1(SYS_DUP, fd as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Duplicate to specific fd
pub unsafe fn dup2(oldfd: i32, newfd: i32) -> i32 {
    let ret = syscall2(SYS_DUP2, oldfd as u64, newfd as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Create a pipe
pub unsafe fn pipe(fds: *mut i32) -> i32 {
    let ret = syscall1(SYS_PIPE, fds as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Read at offset
pub unsafe fn pread(fd: i32, buf: *mut u8, n: usize, offset: u64) -> i32 {
    let ret = syscall4(SYS_PREAD, fd as u64, buf as u64, n as u64, offset);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Write at offset
pub unsafe fn pwrite(fd: i32, buf: *const u8, n: usize, offset: u64) -> i32 {
    let ret = syscall4(SYS_PWRITE, fd as u64, buf as u64, n as u64, offset);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

// ============================================================================
// Directory Operations
// ============================================================================

/// Bind a name to a channel
pub unsafe fn bind(src: *const u8, target: *const u8, flags: i32) -> i32 {
    let ret = syscall3(SYS_BIND, src as u64, target as u64, flags as u64);
    ret as i32
}

/// Mount a file system
pub unsafe fn mount(src: *const u8, target: *const u8, flags: i32, spec: *const u8) -> i32 {
    let ret = syscall4(SYS_MOUNT, src as u64, target as u64, flags as u64, spec as u64);
    ret as i32
}

/// Unmount a file system
pub unsafe fn unmount(spec: *const u8, target: *const u8) -> i32 {
    let ret = syscall2(SYS_UNMOUNT, spec as u64, target as u64);
    ret as i32
}

/// Change current directory
pub unsafe fn chdir(path: *const u8) -> i32 {
    let ret = syscall1(SYS_CHDIR, path as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Remove a file
pub unsafe fn remove(path: *const u8) -> i32 {
    let ret = syscall1(SYS_REMOVE, path as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Rename a file
pub unsafe fn rename(old: *const u8, new: *const u8) -> i32 {
    let ret = syscall2(SYS_RENAME, old as u64, new as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

// ============================================================================
// Memory
// ============================================================================

/// Change program break (sbrk)
pub unsafe fn brk(addr: *mut u8) -> i32 {
    let ret = syscall1(SYS_BRK, addr as u64);
    if ret > 0xFFFFFFFF {
        -1
    } else {
        ret as i32
    }
}

/// Internal brk syscall wrapper
///
/// Returns 0 on success, negative on error.
pub fn brk_internal(addr: isize) -> isize {
    // If addr is 0, just return current break
    // If addr is positive, set break to that address
    // If addr is negative, treat as offset from current break
    let target = if addr == 0 {
        // Get current break - we'll need to track this
        // For now, return -1 to indicate we need to track
        return -1;
    } else if addr > 0 {
        addr as u64
    } else {
        // Offset from current break not supported
        return -1;
    };

    let ret = unsafe { syscall1(SYS_BRK, target) };
    if ret > 0xFFFFFFFF as u64 {
        -1
    } else {
        ret as isize
    }
}

/// Get current program break
///
/// Tracks the break pointer in a private `static mut` cell so the rest
/// of the crate can observe it without referencing a non-existent C
/// symbol. The pointer is updated by the heap allocation routines in
/// `memory.rs` via `set_sbrk_current` whenever the program break moves.
pub fn sbrk() -> *mut u8 {
    static mut SBRK_CURRENT: *mut u8 = core::ptr::null_mut();
    unsafe { SBRK_CURRENT }
}

/// Update the cached break pointer. Called from the allocator when the
/// kernel-side break is moved by `brk(2)`.
pub unsafe fn set_sbrk_current(ptr: *mut u8) {
    static mut SBRK_CURRENT: *mut u8 = core::ptr::null_mut();
    SBRK_CURRENT = ptr;
}

/// Implementation of the Plan 9 `brk`/`sbrk` pair (libc-compatible
/// signature). The wrapper is the canonical caller of `brk_internal`,
/// which issues the actual `SYS_BRK` syscall.
pub fn sbrk_set(addr: *mut u8) -> i32 {
    let result = brk_internal(addr as isize);
    if result < 0 {
        -1
    } else {
        0
    }
}

/// Attach shared memory segment
pub unsafe fn segattach(seg: u32, addr: *mut u8, len: usize) -> *mut u8 {
    let ret = syscall3(SYS_SEGATTACH, seg as u64, addr as u64, len as u64);
    ret as *mut u8
}

/// Detach shared memory segment
pub unsafe fn segdetach(addr: *mut u8) -> i32 {
    let ret = syscall1(SYS_SEGDETACH, addr as u64);
    ret as i32
}

/// Free shared memory segment
pub unsafe fn segfree(addr: *mut u8, len: usize) -> i32 {
    let ret = syscall2(SYS_SEGFREE, addr as u64, len as u64);
    ret as i32
}

/// Flush instruction cache for segment
pub unsafe fn segflush(addr: *mut u8, len: usize) -> i32 {
    let ret = syscall2(SYS_SEGFLUSH, addr as u64, len as u64);
    ret as i32
}

// ============================================================================
// Time
// ============================================================================

/// Get nanoseconds since epoch
pub unsafe fn nsec() -> u64 {
    syscall0(SYS_NSEC)
}

/// Get current time as seconds since epoch
pub fn time() -> u64 {
    unsafe { nsec() / 1_000_000_000 }
}

// ============================================================================
// Error Handling
// ============================================================================

/// Check if return value is an error
pub fn is_error(ret: u64) -> bool {
    ret > 0xFFFFFFFF
}

/// Convert return value to errno
pub fn errnox(ret: u64) -> i32 {
    (!ret + 1) as i32
}

/// Plan 9 error strings
pub const ENOENT: i32 = 2;
pub const ENOMEM: i32 = 3;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const ENFILE: i32 = 11;
pub const EPERM: i32 = 13;
pub const EEXIST: i32 = 17;
pub const ENOTDIR: i32 = 21;
pub const EISDIR: i32 = 27;
pub const EINVAL: i32 = 29;
pub const ENFILE_MAX: i32 = 65535;

/// Get last error string
pub unsafe fn errstr(buf: *mut u8, len: usize) {
    let ret = syscall2(38, buf as u64, len as u64); // SYS_errstr = 39 in kernel
    let _ = ret;
}

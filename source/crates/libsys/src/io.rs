//! IO operations
pub const STDIN_FILENO: i32 = 0;
pub const STDOUT_FILENO: i32 = 1;
pub const STDERR_FILENO: i32 = 2;

// Open flags
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0x40;
pub const O_EXCL: i32 = 0x80;
pub const O_TRUNC: i32 = 0x200;
pub const O_APPEND: i32 = 0x400;

// Seek whence
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// Low-level syscalls for raw I/O. These are normally resolved by the
// kernel's libc shim; in a freestanding binary they would be linked
// against the kernel's syscall stubs.
extern "C" {
    pub fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    pub fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    pub fn open(path: *const u8, flags: i32) -> i32;
    pub fn close(fd: i32) -> i32;
}

/// Safe wrapper around the raw `read` syscall.
pub unsafe fn sys_read(fd: i32, buf: &mut [u8]) -> isize {
    read(fd, buf.as_mut_ptr(), buf.len())
}

/// Safe wrapper around the raw `write` syscall.
pub unsafe fn sys_write(fd: i32, buf: &[u8]) -> isize {
    write(fd, buf.as_ptr(), buf.len())
}

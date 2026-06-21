//! Error types for Plan 9 Rust

use core::fmt;

/// Plan 9 error codes (matching traditional Unix/Plan9 error semantics)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    // Success
    None = 0,
    
    // Standard errors
    Eperm = 1,        // Operation not permitted
    Enoent = 2,       // No such file or directory
    Esrch = 3,        // No such process
    Eintr = 4,        // Interrupted system call
    Eio = 5,           // I/O error
    Enxio = 6,         // No such device or address
    E2big = 7,        // Argument list too long
    Enoexec = 8,      // Exec format error
    Ebadf = 9,        // Bad file number
    Echild = 10,       // No child processes
    Eagain = 11,       // Try again
    Enomem = 12,       // Out of memory / cannot allocate
    Eacces = 13,       // Permission denied
    Efault = 14,       // Bad address
    Enotblk = 15,      // Block device required
    Ebusy = 16,        // Device or resource busy
    Eexist = 17,       // File exists
    Exdev = 18,        // Cross-device link
    Enodev = 19,       // No such device
    Enotdir = 20,      // Not a directory
    Eisdir = 21,       // Is a directory
    Einval = 22,       // Invalid argument
    Enfile = 23,       // File table overflow
    Emfile = 24,       // Too many open files
    Etxtbsy = 26,      // Text file busy
    Efbig = 27,        // File too large
    Enospc = 28,       // No space left on device
    Espipe = 29,       // Illegal seek
    Erofs = 30,        // Read-only file system
    Emlink = 31,       // Too many links
    Epipe = 32,        // Broken pipe
    Edoms = 33,        // Math argument out of domain
    Erange = 34,       // Math result not representable
    Eproclim = 36,     // Too many processes
    Eusers = 40,       // Too many users
    Edquot = 42,       // Quota exceeded
    Estale = 44,       // Stale NFS file handle
    Eremote = 46,      // Too many levels of remote in path
    Enolink = 47,      // Link has been severed
    Eadv = 48,         // Advertise error
    Esrmnt = 49,       // Srmount error
    
    // Plan 9 specific errors
    Ebadfd = 50,       // Bad file descriptor
    Egreg = 51,        // Protocol error
    Ebadsys = 52,      // Bad system call
    Ebadarg = 53,      // Bad argument
    Eintrstr = 54,     // Interrupted
    Ebadexec = 55,     // Bad exec format
    Ebaduid = 56,      // Bad user id
    Ebadenv = 57,      // Bad environment
    Enovmem = 58,      // Out of kernel memory
    Eprotonosupport = 59, // Protocol not supported
    Etoomanyrefs = 60, // Too many references
    Eipv4only = 61,    // Address family not supported by protocol
    Ereject = 62,      // Reject
    Enocache = 63,     // No cache
    Eshutdown = 64,     // Shutdown
    Ealready = 65,     // Already
    Enotempty = 66,    // Directory not empty
}

impl Error {
    /// Get error message string
    pub fn strerror(&self) -> &'static str {
        match self {
            Error::None => "no error",
            Error::Eperm => "permission denied",
            Error::Enoent => "file not found",
            Error::Esrch => "process not found",
            Error::Eintr => "interrupted system call",
            Error::Eio => "I/O error",
            Error::Enxio => "no such device or address",
            Error::E2big => "argument list too long",
            Error::Enoexec => "exec format error",
            Error::Ebadf => "bad file descriptor",
            Error::Echild => "no child processes",
            Error::Eagain => "try again",
            Error::Enomem => "out of memory",
            Error::Eacces => "access denied",
            Error::Efault => "bad address",
            Error::Enotblk => "block device required",
            Error::Ebusy => "device busy",
            Error::Eexist => "file exists",
            Error::Exdev => "cross-device link",
            Error::Enodev => "no such device",
            Error::Enotdir => "not a directory",
            Error::Eisdir => "is a directory",
            Error::Einval => "invalid argument",
            Error::Enfile => "file table overflow",
            Error::Emfile => "too many open files",
            Error::Etxtbsy => "text file busy",
            Error::Efbig => "file too large",
            Error::Enospc => "no space left on device",
            Error::Espipe => "illegal seek",
            Error::Erofs => "read-only file system",
            Error::Emlink => "too many links",
            Error::Epipe => "broken pipe",
            Error::Edoms => "math argument out of domain",
            Error::Erange => "math result not representable",
            Error::Eproclim => "too many processes",
            Error::Eusers => "too many users",
            Error::Edquot => "quota exceeded",
            Error::Estale => "stale NFS file handle",
            Error::Eremote => "too many levels of remote in path",
            Error::Enolink => "link has been severed",
            Error::Eadv => "advertise error",
            Error::Esrmnt => "srmount error",
            Error::Ebadfd => "bad file descriptor",
            Error::Egreg => "protocol error",
            Error::Ebadsys => "bad system call",
            Error::Ebadarg => "bad argument",
            Error::Eintrstr => "interrupted",
            Error::Ebadexec => "bad exec format",
            Error::Ebaduid => "bad user id",
            Error::Ebadenv => "bad environment",
            Error::Enovmem => "out of kernel memory",
            Error::Eprotonosupport => "protocol not supported",
            Error::Etoomanyrefs => "too many references",
            Error::Eipv4only => "address family not supported",
            Error::Ereject => "reject",
            Error::Enocache => "no cache",
            Error::Eshutdown => "shutdown",
            Error::Ealready => "already",
            Error::Enotempty => "directory not empty",
        }
    }
    
    /// Convert to errno value (negative)
    pub fn as_isize(&self) -> isize {
        -(self.clone() as isize)
    }
    
    /// Get errno code
    pub fn errno(&self) -> u32 {
        *self as i32 as u32
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.strerror())
    }
}

impl From<i32> for Error {
    fn from(code: i32) -> Self {
        match code {
            0 => Error::None,
            1 => Error::Eperm,
            2 => Error::Enoent,
            3 => Error::Esrch,
            4 => Error::Eintr,
            5 => Error::Eio,
            6 => Error::Enxio,
            7 => Error::E2big,
            8 => Error::Enoexec,
            9 => Error::Ebadf,
            10 => Error::Echild,
            11 => Error::Eagain,
            12 => Error::Enomem,
            13 => Error::Eacces,
            14 => Error::Efault,
            15 => Error::Enotblk,
            16 => Error::Ebusy,
            17 => Error::Eexist,
            18 => Error::Exdev,
            19 => Error::Enodev,
            20 => Error::Enotdir,
            21 => Error::Eisdir,
            22 => Error::Einval,
            23 => Error::Enfile,
            24 => Error::Emfile,
            26 => Error::Etxtbsy,
            27 => Error::Efbig,
            28 => Error::Enospc,
            29 => Error::Espipe,
            30 => Error::Erofs,
            31 => Error::Emlink,
            32 => Error::Epipe,
            33 => Error::Edoms,
            34 => Error::Erange,
            36 => Error::Eproclim,
            40 => Error::Eusers,
            42 => Error::Edquot,
            44 => Error::Estale,
            46 => Error::Eremote,
            47 => Error::Enolink,
            48 => Error::Eadv,
            49 => Error::Esrmnt,
            50 => Error::Ebadfd,
            51 => Error::Egreg,
            52 => Error::Ebadsys,
            53 => Error::Ebadarg,
            54 => Error::Eintrstr,
            55 => Error::Ebadexec,
            56 => Error::Ebaduid,
            57 => Error::Ebadenv,
            58 => Error::Enovmem,
            59 => Error::Eprotonosupport,
            60 => Error::Etoomanyrefs,
            61 => Error::Eipv4only,
            62 => Error::Ereject,
            63 => Error::Enocache,
            64 => Error::Eshutdown,
            65 => Error::Ealready,
            66 => Error::Enotempty,
            _ => Error::Einval,
        }
    }
}

impl From<Error> for i32 {
    fn from(err: Error) -> Self {
        err as i32
    }
}

/// Result type using Plan 9 errors
pub type Result<T> = core::result::Result<T, Error>;

/// Kernel panic with error message
#[macro_export]
macro_rules! panic {
    ($($arg:tt)*) => {
        loop {
            crate::common::error::_panic(file!(), line!(), format_args!($($arg)*));
        }
    }
}

/// Kernel assertion
#[macro_export]
macro_rules! assert {
    ($cond:expr) => {
        if !$cond {
            $crate::panic!("assertion failed: {}", stringify!($cond));
        }
    };
    ($cond:expr, $msg:expr) => {
        if !$cond {
            $crate::panic!("assertion failed: {}", $msg);
        }
    };
}

/// Unwrap with error propagation
#[macro_export]
macro_rules! try_or_return {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => return core::result::Result::Err(err),
        }
    };
}

/// Internal panic function
#[doc(hidden)]
pub fn _panic(_file: &str, _line: u32, _args: core::fmt::Arguments<'_>) {
    // Will be implemented with serial output later
}

/// Set error string for user
#[allow(dead_code)]
pub fn seterrstr(_err: &mut [u8], _msg: &str) {
    // TODO: Implement
}

/// Get current error string
#[allow(dead_code)]
pub fn geterrstr() -> &'static str {
    "unknown error"
}

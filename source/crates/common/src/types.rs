//! Common type definitions for Plan 9 Rust

// ============================================================================
// Address Types
// ============================================================================

/// Physical address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn null() -> Self { Self(0) }
    pub const fn as_u64(self) -> u64 { self.0 }
    pub const fn is_null(self) -> bool { self.0 == 0 }
    pub const fn page_align(self) -> Self { Self((self.0 + 4095) & !4095) }
    pub const fn align_to(self, align: u64) -> Self { Self((self.0 + align - 1) & !(align - 1)) }
    pub const fn is_aligned(self) -> bool { self.0 & 0xFFF == 0 }
}

impl From<u64> for PhysAddr {
    fn from(addr: u64) -> Self { Self(addr) }
}

impl From<PhysAddr> for u64 {
    fn from(addr: PhysAddr) -> Self { addr.0 }
}

/// Virtual address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct VirtAddr(u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn null() -> Self { Self(0) }
    pub const fn as_u64(self) -> u64 { self.0 }
    pub const fn is_null(self) -> bool { self.0 == 0 }
    pub const fn page_align(self) -> Self { Self((self.0 + 4095) & !4095) }
    pub const fn align_to(self, align: u64) -> Self { Self((self.0 + align - 1) & !(align - 1)) }
    pub const fn is_kernel(self) -> bool { self.0 >= 0xFFFF_8000_0000_0000 }
    pub const fn is_user(self) -> bool { !self.is_kernel() }
    
    /// Convert to pointer
    pub const fn as_ptr<T>(self) -> *const T { self.0 as *const T }
    pub const fn as_mut_ptr<T>(self) -> *mut T { self.0 as *mut T }
}

impl From<u64> for VirtAddr {
    fn from(addr: u64) -> Self { Self(addr) }
}

impl From<VirtAddr> for u64 {
    fn from(addr: VirtAddr) -> Self { addr.0 }
}

// ============================================================================
// Page and Memory
// ============================================================================

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Page shift (12 bits for 4KB pages)
pub const PAGE_SHIFT: u32 = 12;

/// Page mask
pub const PAGE_MASK: u64 = 0xFFF;

/// A memory page
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Page {
    pub base: VirtAddr,
}

impl Page {
    pub fn new(addr: VirtAddr) -> Self {
        Self { base: addr.page_align() }
    }
    pub fn number(self) -> usize {
        (self.base.as_u64() / PAGE_SIZE as u64) as usize
    }
    pub fn address(self) -> VirtAddr { self.base }
    pub fn physical(self) -> PhysAddr { PhysAddr::new(self.base.as_u64()) }
}

/// A physical page frame
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageFrame {
    pub paddr: PhysAddr,
    pub refcount: u32,
}

impl PageFrame {
    pub const fn new(paddr: PhysAddr) -> Self {
        Self { paddr, refcount: 1 }
    }
}

// ============================================================================
// Plan 9 Qid (File Identifier)
// ============================================================================

/// Plan 9 Qid - unique file identifier across sessions
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Qid {
    pub path: u64,      // unique file id
    pub vers: u32,      // version number
    pub qtype: u8,      // file type (QTFILE, QTDIR, etc.)
}

impl Qid {
    pub const fn new(path: u64, vers: u32, qtype: u8) -> Self {
        Self { path, vers, qtype }
    }
    pub const fn nil() -> Self {
        Self { path: 0, vers: 0, qtype: 0 }
    }
}

/// Qid types
pub const QTFILE: u8 = 0;
pub const QTDIR: u8 = 1;
pub const QTSYMLINK: u8 = 2;
pub const QTMOUNT: u8 = 4;
pub const QTAUTH: u8 = 8;
pub const QTAPPEND: u8 = 16;
pub const QTEXCLUSIVE: u8 = 32;

// ============================================================================
// File Mode
// ============================================================================

/// File mode flags
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Mode(u32);

impl Mode {
    pub const DIR: Self = Self(0o40000);
    pub const APPEND: Self = Self(0o20000);
    pub const EXCLUSIVE: Self = Self(0o10000);
    pub const TMP: Self = Self(0o1000);

    // Permission bits
    pub const R: Self = Self(0o400);
    pub const W: Self = Self(0o200);
    pub const X: Self = Self(0o100);

    pub fn from_bits(bits: u32) -> Self { Self(bits) }
    pub fn bits(self) -> u32 { self.0 }
    pub fn is_dir(self) -> bool { self.0 & 0o170000 == 0o40000 }
    pub fn is_file(self) -> bool { self.0 & 0o170000 == 0o100000 }
    pub fn is_symlink(self) -> bool { self.0 & 0o170000 == 0o120000 }
    
    pub fn readable(self) -> bool { self.0 & 0o400 != 0 }
    pub fn writable(self) -> bool { self.0 & 0o200 != 0 }
    pub fn executable(self) -> bool { self.0 & 0o100 != 0 }
}

/// Open mode flags
#[derive(Debug, Clone, Copy, Default)]
#[repr(u8)]
pub enum OpenMode {
    #[default]
    Read = 0,
    Write = 1,
    ReadWrite = 2,
    Exec = 3,
}

/// Channel flags
pub const COPEN: i32 = 0x0001;      // opened for i/o
pub const CMSG: i32 = 0x0002;        // message channel for mount
pub const CCEXEC: i32 = 0x0008;     // close on exec
pub const CFREE: i32 = 0x0010;       // not in use
pub const CRCLOSE: i32 = 0x0020;     // remove on close
pub const CCACHE: i32 = 0x0080;      // client cache

// ============================================================================
// User Registers
// ============================================================================

/// User register state (saved on trap/interrupt)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Ureg {
    pub ax: u64,
    pub bx: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub bp: u64,
    pub sp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub ip: u64,          // instruction pointer
    pub cs: u64,          // code segment
    pub flags: u64,       // rflags
    pub sp2: u64,         // kernel stack pointer
    pub ss: u64,          // stack segment
}

impl Ureg {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn syscall_result(&mut self, result: u64) {
        self.ax = result;
    }
    
    pub fn syscall_error(&mut self, errno: u64) {
        self.ax = !0u64.wrapping_sub(errno as i32 as u64).wrapping_add(1);
    }
    
    pub fn ip(&self) -> u64 { self.ip }
    pub fn sp(&self) -> u64 { self.sp }
    pub fn flags(&self) -> u64 { self.flags }
}

// ============================================================================
// Time Types
// ============================================================================

/// Clock ticks (system time unit)
pub type Ticks = u64;

/// Nanoseconds
#[derive(Debug, Clone, Copy)]
pub struct NSec(pub u64);

impl NSec {
    pub const fn as_ticks(self, freq: u64) -> Ticks {
        self.0 * freq / 1_000_000_000
    }
}

/// Milliseconds
#[derive(Debug, Clone, Copy)]
pub struct MSec(pub u64);

impl MSec {
    pub const fn as_ticks(self, freq: u64) -> Ticks {
        self.0 * freq / 1000
    }
    pub const fn as_us(self) -> u64 { self.0 * 1000 }
}

// ============================================================================
// Process ID
// ============================================================================

pub type Pid = u32;
pub type Uid = u32;
pub type Gid = u32;

pub const NO_PID: Pid = 0;
pub const INIT_PID: Pid = 1;

// ============================================================================
// Device Types
// ============================================================================

/// Device characters (first letter of device name)
pub const DEVROOT: u8 = b'/';       // root
pub const DEVCONS: u8 = b'c';       // console
pub const DEVDISK: u8 = b'd';       // data (disk)
pub const DEVENV: u8 = b'e';        // env
pub const DEVFILE: u8 = b'f';        // file
pub const DEVIP: u8 = b'i';         // ip
pub const DEVLOG: u8 = b'l';        // log
pub const DEVMOUNT: u8 = b'm';      // mount
pub const DEVNET: u8 = b'n';        // network
pub const DEVPROC_OLD: u8 = b'o';   // proc (old)
pub const DEVPROC: u8 = b'p';       // proc
pub const DEVRAW: u8 = b'r';        // raw (disk)
pub const DEVSERIAL: u8 = b's';     // serial
pub const DEVTERM: u8 = b't';       // terminal
pub const DEVUSER: u8 = b'u';       // user
pub const DEV_VGA: u8 = b'v';       // vga
pub const DEV_DRAW: u8 = b'w';      // draw (window)
pub const DEV_EXEC: u8 = b'x';      // exec

// ============================================================================
// Segment Types
// ============================================================================

/// Segment type flags
pub const SG_TEXT: u8 = 0;         // text segment
pub const SG_DATA: u8 = 1;         // data segment
pub const SG_BSS: u8 = 2;         // bss segment
pub const SG_STACK: u8 = 3;        // stack segment
pub const SG_SHARED: u8 = 4;       // shared segment
pub const SG_PHYSICAL: u8 = 5;     // physical segment
pub const SG_CEXEC: u8 = 6;        // clone on exec
pub const SG_RONLY: u8 = 7;        // read-only

// ============================================================================
// Constants
// ============================================================================

/// Maximum segments per process
pub const NSEG: usize = 10;

/// Maximum open files per process
pub const NOFILE: usize = 100;

/// Maximum path length
pub const MAXPATH: usize = 256;

/// Maximum name length
pub const MAXNAME: usize = 28;

/// Maximum string length
pub const MAXSTRING: usize = 256;

/// Error message max length
pub const ERRMAX: usize = 256;

/// Number of CPU cores (max)
pub const NCPU: usize = 16;

// ============================================================================
// Labels (for setjmp/longjmp)
// ============================================================================

/// Jump buffer for context switching
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Label {
    pub sp: u64,
    pub pc: u64,
}

impl Label {
    pub const fn new() -> Self {
        Self { sp: 0, pc: 0 }
    }
    
    pub fn is_valid(&self) -> bool {
        self.sp != 0 || self.pc != 0
    }
}

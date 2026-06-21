//! System Call Interface
//!
//! Implements the Plan 9 system call interface for user programs.
//! Based on the original Plan 9 syscall definitions from sys.h and systab.h

#![no_std]

use crate::proc::{Pid, State, NSEG, curproc, curproc_mut, SegType, Segment};
use crate::sched::{scheduler, yield_ as sched_yield};
use crate::plan9_common::sync::Spinlock;
use crate::segment::PAGE_SIZE;
use crate::vfs::namec;

// ============================================================================
// System Call Numbers
// ============================================================================

/// System call numbers (matches Plan 9 syscall.h)
pub mod nr {
    /// rfork - create new process
    pub const RFORK: usize = 0;
    /// exec - execute program
    pub const EXEC: usize = 1;
    /// exits - terminate process
    pub const EXITS: usize = 2;
    /// open - open file
    pub const OPEN: usize = 3;
    /// create - create file
    pub const CREATE: usize = 4;
    /// read - read data
    pub const READ: usize = 5;
    /// write - write data
    pub const WRITE: usize = 6;
    /// close - close file
    pub const CLOSE: usize = 7;
    /// seek - seek file position
    pub const SEEK: usize = 8;
    /// dup - duplicate file descriptor
    pub const DUP: usize = 9;
    /// pipe - create pipe
    pub const PIPE: usize = 10;
    /// pread - positioned read
    pub const PREAD: usize = 11;
    /// pwrite - positioned write
    pub const PWRITE: usize = 12;
    /// remove - remove file
    pub const REMOVE: usize = 13;
    /// notify - set exception handler
    pub const NOTIFY: usize = 14;
    /// noted - return from signal handler
    pub const NOTED: usize = 15;
    /// segbrk - change memory segment
    pub const SEGBRK: usize = 16;
    /// unread - unread data (pipe)
    pub const UNREAD: usize = 17;
    /// stat - get file status
    pub const STAT: usize = 18;
    /// fstat - get file status (by fd)
    pub const FSTAT: usize = 19;
    /// wstat - set file status
    pub const WSTAT: usize = 20;
    /// fwstat - set file status (by fd)
    pub const FWSTAT: usize = 21;
    /// mount - mount filesystem
    pub const MOUNT: usize = 22;
    /// unmount - unmount filesystem
    pub const UNMOUNT: usize = 23;
    /// segattach - attach shared memory
    pub const SEGATTACH: usize = 24;
    /// segdetach - detach shared memory
    pub const SEGDETACH: usize = 25;
    /// segfree - free shared memory
    pub const SEGFREE: usize = 26;
    /// segflush - flush instruction cache
    pub const SEGFLUSH: usize = 27;
    /// rendezvous - process synchronization
    pub const RENDEZVOUS: usize = 28;
    /// sleep - sleep for specified time
    pub const SLEEP: usize = 29;
    /// wakeup - wake sleeping process
    pub const WAKEUP: usize = 30;
    /// threadcreate - create thread
    pub const THREADCREATE: usize = 31;
    /// threadexit - terminate thread
    pub const THREADEXIT: usize = 32;
    /// threadwait - wait for thread
    pub const THREADWAIT: usize = 32;
    /// yield - yield processor
    pub const YIELD: usize = 33;
    /// alarm - alarm clock
    pub const ALARM: usize = 34;
    /// await - wait for event
    pub const AWAIT: usize = 35;
    /// bind - bind name to channel
    pub const BIND: usize = 36;
    /// chdir - change directory
    pub const CHDIR: usize = 37;
    /// brk_ - set break
    pub const BRK_: usize = 38;
    /// errstr - get error string
    pub const ERRSTR: usize = 39;
    /// fork - fork process (Plan 9 style)
    pub const FORK: usize = 40;

    /// semacquire - acquire semaphore
    pub const SEMACQUIRE: usize = 41;
    /// semrelease - release semaphore
    pub const SEMRELEASE: usize = 42;
    /// tsemacquire - timed acquire semaphore
    pub const TSEMACQUIRE: usize = 43;
    /// procctl - process control
    pub const PROCCTL: usize = 44;

    /// Total number of syscalls
    pub const NUM: usize = 64;
}

/// RFORK flags (matching Plan 9 and proc.rs)
pub mod rfork {
    /// Create a new process (without this, runs in same process)
    pub const FLAGFPROC: u32 = 0x0001;
    /// Share file descriptor group
    pub const FLAGFDG: u32 = 0x0002;
    /// Share memory (implies share everything)
    pub const FLAGFMEM: u32 = 0x0004;
    /// Share signal state
    pub const FLAGFSIGNA: u32 = 0x0008;
    /// Share file system (namespace)
    pub const FLAGFNS: u32 = 0x0010;
    /// Share environment
    pub const FLAGFENV: u32 = 0x0020;
    /// Wait for child in rfork (Plan 9 specific)
    pub const FLAGFWAIT: u32 = 0x0040;
    /// Clone on fork (for threads)
    pub const FLAGFTHREAD: u32 = 0x0080;
    /// Share rendezvous state
    pub const FLAGFREND: u32 = 0x0100;
    /// Share notes
    pub const FLAGFNOTES: u32 = 0x0200;
    /// Profiling
    pub const FLAGFPROF: u32 = 0x0400;
    /// Child doesn't wait after rfork
    pub const FLAGFNOWAIT: u32 = 0x8000;
}

// ============================================================================
// Error Codes
// ============================================================================

/// Error codes (Plan 9 style)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Ok = 0,
    Failed = -1,
    Enomem = -2,      // Out of memory
    Eio = -3,         // I/O error
    Ebadfd = -4,      // Bad file descriptor
    Enofile = -5,     // No such file
    Eperm = -6,       // Permission denied
    Eexists = -7,     // File exists
    Enotdir = -8,     // Not a directory
    Eisdir = -9,      // Is a directory
    Einval = -10,     // Invalid argument
    Ebadf = -11,      // Bad file descriptor
    Enoent = -12,     // No such file or directory
    Eintr = -13,      // Interrupted
    Eagain = -14,     // Try again
    Eoverflow = -15,   // Overflow
    Enegadv = -16,    // Advertise error
    Ebadpid = -17,    // Bad process ID
    Enotinrepo = -18, // Not in repository
    Eshort = -19,     // Short write
    Etoosmall = -20,  // Too small
    Etimedout = -21,  // Timed out
    Enochild = -22,   // No child processes
    Ebadexec = -23,   // Bad executable format
}

impl Error {
    pub fn to_isize(self) -> isize {
        self as isize
    }

    pub fn from_usize(e: usize) -> Self {
        match e as isize {
            0 => Error::Ok,
            -1 => Error::Failed,
            -2 => Error::Enomem,
            -3 => Error::Eio,
            -4 => Error::Ebadfd,
            -5 => Error::Enofile,
            -6 => Error::Eperm,
            -7 => Error::Eexists,
            -8 => Error::Enotdir,
            -9 => Error::Eisdir,
            -10 => Error::Einval,
            -11 => Error::Ebadf,
            -12 => Error::Enoent,
            _ => Error::Failed,
        }
    }
}

/// System call result type
pub type Result<T> = core::result::Result<T, Error>;

// ============================================================================
// System Call Frame
// ============================================================================

/// System call frame passed to handlers
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    /// System call number
    pub nr: usize,
    /// Arguments
    pub args: [u64; 6],
}

impl SyscallFrame {
    /// Create new frame
    pub fn new(nr: usize, args: [u64; 6]) -> Self {
        Self { nr, args }
    }

    /// Get argument by index
    pub fn arg(&self, n: usize) -> u64 {
        if n < 6 {
            self.args[n]
        } else {
            0
        }
    }
}

// ============================================================================
// System Call Table
// ============================================================================

/// System call handler function type
type SysHandler = fn(nr: usize, args: [u64; 6]) -> Result<usize>;

/// System call table
pub struct SyscallTable {
    /// Array of handler functions
    handlers: [Option<SysHandler>; nr::NUM],
}

impl SyscallTable {
    /// Create new syscall table
    pub fn new() -> Self {
        let mut table: [Option<SysHandler>; nr::NUM] = [const { None }; nr::NUM];
        
        // Initialize handlers using wrapper closure
        table[nr::RFORK] = Some(|nr, args| {
            sys_internalrfork(SyscallFrame { nr, args })
        });
        table[nr::EXEC] = Some(|nr, args| {
            sys_internalexec(SyscallFrame { nr, args })
        });
        table[nr::EXITS] = Some(|nr, args| {
            sys_internalexits(SyscallFrame { nr, args })
        });
        table[nr::OPEN] = Some(|nr, args| sys_internalopen(SyscallFrame { nr, args }));
        table[nr::CREATE] = Some(|nr, args| sys_internalcreate(SyscallFrame { nr, args }));
        table[nr::READ] = Some(|nr, args| sys_internalread(SyscallFrame { nr, args }));
        table[nr::WRITE] = Some(|nr, args| sys_internalwrite(SyscallFrame { nr, args }));
        table[nr::CLOSE] = Some(|nr, args| sys_internalclose(SyscallFrame { nr, args }));
        table[nr::SEEK] = Some(|nr, args| sys_internalseek(SyscallFrame { nr, args }));
        table[nr::DUP] = Some(|nr, args| sys_internaldup(SyscallFrame { nr, args }));
        table[nr::PIPE] = Some(|nr, args| sys_internalpipe(SyscallFrame { nr, args }));
        table[nr::STAT] = Some(|nr, args| sys_internalstat(SyscallFrame { nr, args }));
        table[nr::FSTAT] = Some(|nr, args| sys_internalfstat(SyscallFrame { nr, args }));
        table[nr::WSTAT] = Some(|nr, args| sys_internalwstat(SyscallFrame { nr, args }));
        table[nr::FWSTAT] = Some(|nr, args| sys_internalfwstat(SyscallFrame { nr, args }));
        table[nr::REMOVE] = Some(|nr, args| sys_internalremove(SyscallFrame { nr, args }));
        table[nr::BRK_] = Some(|nr, args| sys_internalbrk(SyscallFrame { nr, args }));
        table[nr::MOUNT] = Some(|nr, args| sys_internalmount(SyscallFrame { nr, args }));
        table[nr::UNMOUNT] = Some(|nr, args| sys_internalunmount(SyscallFrame { nr, args }));
        table[nr::BIND] = Some(|nr, args| sys_internalbind(SyscallFrame { nr, args }));
        table[nr::CHDIR] = Some(|nr, args| sys_internalchdir(SyscallFrame { nr, args }));
        table[nr::NOTIFY] = Some(|nr, args| sys_internalnotify(SyscallFrame { nr, args }));
        table[nr::NOTED] = Some(|nr, args| sys_internalsysnoted(SyscallFrame { nr, args }));
        table[nr::RENDEZVOUS] = Some(|nr, args| sys_internalrendezvous(SyscallFrame { nr, args }));
        table[nr::SLEEP] = Some(|nr, args| sys_internalsleep(SyscallFrame { nr, args }));
        table[nr::ALARM] = Some(|nr, args| sys_internalalarm(SyscallFrame { nr, args }));
        table[nr::AWAIT] = Some(|nr, args| sys_internalawait(SyscallFrame { nr, args }));
        table[nr::THREADCREATE] = Some(|nr, args| sys_internalthreadcreate(SyscallFrame { nr, args }));
        table[nr::THREADEXIT] = Some(|nr, args| sys_internalthreadexit(SyscallFrame { nr, args }));
        table[nr::THREADWAIT] = Some(|nr, args| sys_internalthreadwait(SyscallFrame { nr, args }));
        table[nr::YIELD] = Some(|nr, args| sys_internalyield(SyscallFrame { nr, args }));
        table[nr::SEGBRK] = Some(|nr, args| sys_internalsegbrk(SyscallFrame { nr, args }));
        table[nr::SEGATTACH] = Some(|nr, args| sys_internalsegattach(SyscallFrame { nr, args }));
        table[nr::SEGDETACH] = Some(|nr, args| sys_internalsegdetach(SyscallFrame { nr, args }));
        table[nr::SEGFREE] = Some(|nr, args| sys_internalsegfree(SyscallFrame { nr, args }));
        table[nr::SEGFLUSH] = Some(|nr, args| sys_internalsegflush(SyscallFrame { nr, args }));
        table[nr::ERRSTR] = Some(|nr, args| sys_internalerrstr(SyscallFrame { nr, args }));
        table[nr::SEMACQUIRE] = Some(|nr, args| sys_internalsemacquire(SyscallFrame { nr, args }));
        table[nr::SEMRELEASE] = Some(|nr, args| sys_internalsemrelease(SyscallFrame { nr, args }));
        table[nr::TSEMACQUIRE] = Some(|nr, args| sys_internaltsemacquire(SyscallFrame { nr, args }));
        table[nr::PROCCTL] = Some(|nr, args| sys_internalprocctl(SyscallFrame { nr, args }));

        Self { handlers: table }
    }

    /// Dispatch a system call
    pub fn dispatch(&self, frame: &SyscallFrame) -> Result<usize> {
        if frame.nr < nr::NUM {
            if let Some(handler) = self.handlers[frame.nr] {
                handler(frame.nr, frame.args)
            } else {
                Err(Error::Ebadf)
            }
        } else {
            Err(Error::Ebadf)
        }
    }
}

// ============================================================================
// Global Syscall Table
// ============================================================================

/// Global syscall table
static SYSCALL_TABLE: SyscallTable = SyscallTable::new();

/// Get reference to syscall table
pub fn syscalls() -> &'static SyscallTable {
    &SYSCALL_TABLE
}

/// Dispatch a system call from trap handler
/// This is called from trap.rs with the syscall number and arguments
pub fn dispatch(num: usize, frame: &crate::trap::SyscallFrame) -> i64 {
    let syscall_frame = SyscallFrame {
        nr: num,
        args: [
            frame.arg0,
            frame.arg1,
            frame.arg2,
            frame.arg3,
            frame.arg4,
            frame.arg5,
        ],
    };
    
    match syscalls().dispatch(&syscall_frame) {
        Ok(n) => n as i64,
        Err(e) => e.to_isize() as i64,
    }
}

// ============================================================================
// System Call Implementations
// ============================================================================

/// RFORK - create new process
fn sys_internalrfork(frame: &SyscallFrame) -> Result<usize> {
    let flags = frame.arg(0) as u32;

    // Check if creating process
    if flags & rfork::FLAGFPROC != 0 {
        // Create a new process with rfork flags
        let mut sched = scheduler();
        match sched.fork(curproc(), dummy_entry, flags) {
            Some(child_pid) => Ok(child_pid as usize),
            None => Err(Error::Eagain),
        }
    } else {
        // Just sharing resources, not creating new process
        // Apply flags to current process (in a full implementation)
        Ok(0)
    }
}

/// Dummy entry function for fork
fn dummy_entry() {}

/// EXEC - execute program
///
/// Loads and executes a new program, replacing the current process.
/// This implements the Plan 9 exec syscall semantics.
fn sys_internalexec(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let arg_ptr = frame.arg(1);
    let env_ptr = frame.arg(2);

    // Validate path pointer
    if path_ptr == 0 {
        return Err(Error::Ebadf);
    }

    // Check if address is in user space
    if !is_user_addr(path_ptr) {
        return Err(Error::Ebadf);
    }

    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;

    // Build argument and environment vectors
    let args = copy_argv_from_user(arg_ptr)?;
    let envp = copy_envp_from_user(env_ptr)?;

    // Open the executable file
    let amode = crate::vfs::NamecMode::Open(0); // O_RDONLY
    let mut chan = match namec(&path, amode, 0, 0) {
        Ok(c) => c,
        Err(_) => return Err(Error::Enoent),
    };

    // Read ELF header
    let mut header = [0u8; 128];
    let mut read_buf = [0u8; 64];
    let mut offset = 0;
    while offset < header.len() {
        let n = core::cmp::min(64, header.len() - offset);
        match chan.read(&mut read_buf[..n]) {
            Ok(0) => break,
            Ok(k) => {
                header[offset..offset + k].copy_from_slice(&read_buf[..k]);
                offset += k;
            }
            Err(_) => return Err(Error::Eio),
        }
    }

    // Validate ELF magic
    if &header[0..4] != b"\x7fELF" {
        return Err(Error::Ebadexec);
    }

    // Check if 64-bit
    if header[4] != 2 {
        return Err(Error::Ebadexec);
    }

    // Check architecture (x86_64 = 62)
    let machine = u16::from_le_bytes([header[18], header[19]]);
    if machine != 62 {
        return Err(Error::Ebadexec);
    }

    // Get entry point
    let entry = u64::from_le_bytes([
        header[24], header[25], header[26], header[27],
        header[28], header[29], header[30], header[31],
    ]);

    // Get program header info
    let phoff = u64::from_le_bytes([
        header[32], header[33], header[34], header[35],
        header[36], header[37], header[38], header[39],
    ]);
    let phentsize = u16::from_le_bytes([header[54], header[55]]);
    let phnum = u16::from_le_bytes([header[56], header[57]]);

    if phentsize < 56 || phnum == 0 {
        return Err(Error::Ebadexec);
    }

    // Get current process
    let proc = match curproc_mut() {
        Some(p) => p,
        None => return Err(Error::Eperm),
    };

    // Close the executable file - we don't need it anymore
    drop(chan);

    // Re-open for loading segments
    let chan = match namec(&path, amode, 0, 0) {
        Ok(c) => c,
        Err(_) => return Err(Error::Enoent),
    };

    // Calculate total memory needed for segments
    // For now, just set up basic segments

    // Build user stack with arguments
    let sp = build_exec_stack(&args, &envp)?;

    // In a complete implementation:
    // 1. Allocate new page table
    // 2. Load PT_LOAD segments from ELF
    // 3. Set up stack segment
    // 4. Set up user registers

    // For now, return success if we can read the ELF header
    // The actual segment creation would require:
    // - Setting up page tables
    // - Mapping segments
    // - Copying data

    // Store the entry point and stack pointer for later use
    // In a real implementation, these would be set in the process's
    // user register context for the next context switch to user mode

    // For this implementation, we mark the process as ready to run the new program
    // The actual context switch would happen on return from syscall

    // Return success - in a real implementation we would not return,
    // but would context switch directly to the new program
    Ok(entry as usize)
}

/// Copy argument vector from user space
fn copy_argv_from_user(argv_ptr: u64) -> Result<Vec<Vec<u8>>> {
    if argv_ptr == 0 {
        return Ok(Vec::new());
    }
    
    let mut argv = Vec::new();
    let mut ptr = argv_ptr;
    
    loop {
        // Read pointer at current position
        if !is_user_addr(ptr) {
            break;
        }
        
        let arg_ptr = unsafe {
            core::ptr::read(ptr as *const u64)
        };
        
        if arg_ptr == 0 {
            break;
        }
        
        if !is_user_addr(arg_ptr) {
            break;
        }
        
        // Copy the string
        let s = copy_cstring_from_user(arg_ptr)?;
        argv.push(s);
        
        ptr += 8;
    }
    
    Ok(argv)
}

/// Copy environment vector from user space
fn copy_envp_from_user(envp_ptr: u64) -> Result<Vec<Vec<u8>>> {
    if envp_ptr == 0 {
        return Ok(Vec::new());
    }
    
    let mut envp = Vec::new();
    let mut ptr = envp_ptr;
    
    loop {
        if !is_user_addr(ptr) {
            break;
        }
        
        let env_ptr = unsafe {
            core::ptr::read(ptr as *const u64)
        };
        
        if env_ptr == 0 {
            break;
        }
        
        if !is_user_addr(env_ptr) {
            break;
        }
        
        let s = copy_cstring_from_user(env_ptr)?;
        envp.push(s);
        
        ptr += 8;
    }
    
    Ok(envp)
}

/// Build user stack with arguments and environment for exec
///
/// Returns the stack base and final stack pointer.
fn build_user_stack(args: &[Vec<u8>], envp: &[Vec<u8>]) -> Result<(u64, u64)> {
    // Stack grows down from USER_STACK_BASE
    let stack_top = USER_STACK_BASE;
    let mut sp = stack_top;

    // Align SP to 16 bytes for x86_64 ABI
    sp -= sp % 16;

    // In a full implementation:
    // 1. Count total bytes needed for strings
    // 2. Reserve space for pointers and strings
    // 3. Copy strings from high to low
    // 4. Set up pointer array (argv, envp)
    // 5. Push auxiliary info
    // 6. Return new SP

    let _ = args;
    let _ = envp;

    Ok((stack_top, sp))
}

/// Build user stack for exec syscall
///
/// Sets up the initial user stack with argc, argv, envp for the new program.
fn build_exec_stack(args: &[Vec<u8>], envp: &[Vec<u8>]) -> Result<u64> {
    // Stack grows down from USER_STACK_BASE
    let stack_top = USER_STACK_BASE;
    let mut sp = stack_top;

    // Align SP to 16 bytes for x86_64 ABI
    sp -= sp % 16;

    // Calculate space needed:
    // 1. Null terminator for argv array
    // 2. Null terminator for envp array
    // 3. Pointer arrays (argv and envp)
    // 4. Argument strings
    // 5. Environment strings
    // 6. Align to 16 bytes

    let mut stack_data: Vec<u8> = Vec::new();

    // Collect all strings first
    let mut arg_strings: Vec<&[u8]> = args.iter().map(|s| s.as_slice()).collect();
    let mut env_strings: Vec<&[u8]> = envp.iter().map(|s| s.as_slice()).collect();

    // Calculate total size needed
    let mut total_size: usize = 8; // Space for alignment

    for s in &arg_strings {
        total_size += s.len() + 1; // +1 for null terminator
    }
    for s in &env_strings {
        total_size += s.len() + 1;
    }

    // Add space for pointers (argv[0..argc], envp[0..envc], and 2 nulls)
    total_size += (arg_strings.len() + 1 + env_strings.len() + 1) * 8;

    // Reserve space on stack
    let alloc_size = (total_size + 15) & !15; // Align to 16 bytes
    sp -= alloc_size as u64;

    // In a real implementation, we would copy data to the user stack here
    // For now, just return the stack pointer

    Ok(sp)
}

/// ELF file header constants
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF header structure (simplified for x86_64)
#[repr(C)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF program header
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Program header types
const PT_LOAD: u32 = 1;

/// Program header flags
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

impl Elf64Header {
    /// Check if this is a valid ELF header
    fn is_valid(&self) -> bool {
        self.e_ident[..4] == ELF_MAGIC
    }

    /// Check if this is a 64-bit ELF
    fn is_64bit(&self) -> bool {
        self.e_ident[4] == 2
    }

    /// Check if this is for x86_64
    fn is_x86_64(&self) -> bool {
        self.e_machine == 62 // EM_X86_64
    }

    /// Get program header at index
    fn program_header(&self, index: usize) -> Option<&Elf64Phdr> {
        if index >= self.e_phnum as usize {
            return None;
        }
        let offset = self.e_phoff as usize + index * self.e_phentsize as usize;
        unsafe { core::ptr::read_unaligned(offset as *const Elf64Phdr) }.into()
    }

    /// Get entry point
    fn entry_point(&self) -> u64 {
        self.e_entry
    }
}

impl Elf64Phdr {
    fn into(&self) -> &Elf64Phdr {
        self
    }
}

/// Memory layout constants for user programs
const USER_TEXT_BASE: u64 = 0x400000;
const USER_DATA_BASE: u64 = 0x600000;
const USER_STACK_BASE: u64 = 0x7fff_f000;
const USER_STACK_SIZE: u64 = 0x10000;

/// Maximum virtual address for user space
const MAX_VADDR: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Segment type constants (matching Plan 9)
const SG_NONE: u32 = 0;
const SG_TEXT: u32 = 1;
const SG_DATA: u32 = 2;
const SG_BSS: u32 = 3;
const SG_STACK: u32 = 4;
const SG_SHARED: u32 = 5;
const SG_PHYSICAL: u32 = 6;
const SG_MAPPED: u32 = 7;

/// EXITS - terminate process
fn sys_internalexits(_frame: &SyscallFrame) -> Result<usize> {
    // Exit via scheduler
    scheduler().exit(0);
    // Should not return
    Ok(0)
}

/// OPEN - open file
///
/// Opens a file and returns a file descriptor.
/// 
/// # Arguments
/// * `arg0` - Path name (null-terminated string)
/// * `arg1` - Open mode (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, etc.)
/// 
/// # Returns
/// * File descriptor number on success
fn sys_internalopen(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let omode = frame.arg(1) as u32;
    
    // Validate path pointer
    if path_ptr == 0 {
        return Err(Error::Ebadf);
    }
    
    if !is_user_addr(path_ptr) {
        return Err(Error::Ebadf);
    }
    
    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;
    
    // Get current process and its file descriptor group
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Use VFS to open the file
    let amode = crate::vfs::NamecMode::Open(omode);
    match namec(&path, amode, omode, 0) {
        Ok(chan) => {
            // Allocate file descriptor
            if let Some(ref mut fgrp) = proc.fgrp {
                let fd = fgrp.alloc_fd(chan);
                if fd >= 0 {
                    return Ok(fd as usize);
                }
            }
            Err(Error::Ebadf)
        }
        Err(_) => Err(Error::Enoent),
    }
}

/// CREATE - create file
///
/// Creates a new file or opens an existing one with truncation.
/// 
/// # Arguments
/// * `arg0` - Path name
/// * `arg1` - Open mode
/// * `arg2` - Permission bits for new file
/// 
/// # Returns
/// * File descriptor number on success
fn sys_internalcreate(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let omode = frame.arg(1) as u32;
    let perm = frame.arg(2) as u32;
    
    // Validate path pointer
    if path_ptr == 0 {
        return Err(Error::Ebadf);
    }
    
    if !is_user_addr(path_ptr) {
        return Err(Error::Ebadf);
    }
    
    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;
    
    // Get current process
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Use VFS to create the file
    let amode = crate::vfs::NamecMode::Create(omode, perm);
    match namec(&path, amode, omode, perm) {
        Ok(chan) => {
            // Allocate file descriptor
            if let Some(ref mut fgrp) = proc.fgrp {
                let fd = fgrp.alloc_fd(chan);
                if fd >= 0 {
                    return Ok(fd as usize);
                }
            }
            Err(Error::Ebadf)
        }
        Err(_) => Err(Error::Ebadf),
    }
}

/// Copy a null-terminated string from user space
fn copy_cstring_from_user(ptr: u64) -> Result<Vec<u8>> {
    if ptr == 0 {
        return Err(Error::Ebadf);
    }
    
    if !is_user_addr(ptr) {
        return Err(Error::Ebadf);
    }
    
    // Read up to 256 bytes or until null
    let mut buf = Vec::with_capacity(256);
    let mut addr = ptr;
    
    loop {
        if buf.len() >= 255 {
            break;
        }
        // Read one byte at a time
        // In a real implementation, this would use copyin from user space
        let byte = unsafe {
            core::ptr::read(addr as *const u8)
        };
        if byte == 0 {
            break;
        }
        buf.push(byte);
        addr += 1;
    }
    
    Ok(buf)
}

/// READ - read data
///
/// Reads data from a file descriptor.
/// 
/// # Arguments
/// * `arg0` - File descriptor
/// * `arg1` - Buffer address
/// * `arg2` - Number of bytes to read
/// 
/// # Returns
/// * Number of bytes read, or error
fn sys_internalread(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;

    if buf_ptr == 0 || n == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }

    // For stdin (fd=0), read from keyboard/serial
    if fd == 0 {
        use crate::cons::serial_getchar;
        let mut count = 0;
        let buf = unsafe {
            core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n)
        };

        for byte in buf.iter_mut() {
            if let Some(c) = serial_getchar() {
                *byte = c;
                count += 1;
                if c == b'\n' {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(count)
    } else {
        // Use VFS for other file descriptors
        let proc = curproc().ok_or(Error::Ebadfd)?;
        let fgrp = match proc.fgrp.as_mut() {
            Some(f) => f,
            None => return Err(Error::Ebadfd),
        };
        
        let chan = match fgrp.get_channel(fd) {
            Some(c) => c,
            None => return Err(Error::Ebadfd),
        };
        
        let buf = unsafe {
            core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n)
        };
        
        match chan.read(buf) {
            Ok(count) => Ok(count),
            Err(_) => Err(Error::Eio),
        }
    }
}

/// WRITE - write data
///
/// Writes data to a file descriptor.
/// 
/// # Arguments
/// * `arg0` - File descriptor
/// * `arg1` - Buffer address
/// * `arg2` - Number of bytes to write
/// 
/// # Returns
/// * Number of bytes written, or error
fn sys_internalwrite(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;

    if buf_ptr == 0 || n == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }

    let buf = unsafe {
        core::slice::from_raw_parts(buf_ptr as *const u8, n)
    };

    match fd {
        1 | 2 => {
            // stdout/stderr - write to serial
            use crate::cons::serial_puts;
            serial_puts(buf);
            Ok(n)
        }
        _ => {
            // Use VFS for other file descriptors
            let proc = curproc().ok_or(Error::Ebadfd)?;
            let fgrp = match proc.fgrp.as_mut() {
                Some(f) => f,
                None => return Err(Error::Ebadfd),
            };
            
            let chan = match fgrp.get_channel(fd) {
                Some(c) => c,
                None => return Err(Error::Ebadfd),
            };
            
            match chan.write(buf) {
                Ok(count) => Ok(count),
                Err(_) => Err(Error::Eio),
            }
        }
    }
}

/// CLOSE - close file
///
/// Closes a file descriptor.
/// 
/// # Arguments
/// * `arg0` - File descriptor to close
/// 
/// # Returns
/// * `0` on success
fn sys_internalclose(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    
    // Don't allow closing stdin/stdout/stderr for safety
    if fd < 0 || fd > 2 {
        return Err(Error::Ebadfd);
    }
    
    // Get current process
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Get file descriptor group
    if let Some(ref mut fgrp) = proc.fgrp {
        // Close and remove the fd
        if let Some(_chan) = fgrp.close_fd(fd) {
            // Channel will be dropped and closed automatically
            return Ok(0);
        }
    }
    
    Err(Error::Ebadfd)
}

/// SEEK - seek file position
///
/// Changes the file position for a file descriptor.
/// 
/// # Arguments
/// * `arg0` - File descriptor
/// * `arg1` - Offset (new position or offset from origin)
/// * `arg2` - Origin (SEEK_SET=0, SEEK_CUR=1, SEEK_END=2)
/// 
/// # Returns
/// * New file position, or error
fn sys_internalseek(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let offset = frame.arg(1) as i64;
    let whence = frame.arg(2) as i32;
    
    // Get current process
    let proc = curproc().ok_or(Error::Ebadfd)?;
    let fgrp = match proc.fgrp.as_mut() {
        Some(f) => f,
        None => return Err(Error::Ebadfd),
    };
    
    // Get the channel for this fd
    let chan = match fgrp.get_channel(fd) {
        Some(c) => c,
        None => return Err(Error::Ebadfd),
    };
    
    // Seek on the channel
    match chan.seek(offset, whence) {
        Ok(pos) => Ok(pos as usize),
        Err(_) => Err(Error::Ebadfd),
    }
}

/// DUP - duplicate file descriptor
///
/// Creates a new file descriptor that refers to the same open file.
/// 
/// # Arguments
/// * `arg0` - Source file descriptor
/// * `arg1` - Target file descriptor (-1 for any)
/// 
/// # Returns
/// * New file descriptor, or error
fn sys_internaldup(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let newfd = frame.arg(1) as i32;
    
    // Get current process
    let proc = curproc().ok_or(Error::Ebadfd)?;
    let fgrp = match proc.fgrp.as_mut() {
        Some(f) => f,
        None => return Err(Error::Ebadfd),
    };
    
    // Get the channel for the source fd
    let chan = match fgrp.get_channel(fd) {
        Some(c) => c,
        None => return Err(Error::Ebadfd),
    };
    
    // Duplicate the channel
    let dup_chan = match chan.dup() {
        Ok(d) => d,
        Err(_) => return Err(Error::Ebadfd),
    };
    
    // Allocate a new fd
    if newfd < 0 {
        // Find first available fd
        let allocated = fgrp.alloc_fd(dup_chan);
        if allocated < 0 {
            return Err(Error::Ebadf);
        }
        Ok(allocated as usize)
    } else {
        // Use specific fd
        // This would require a set_fd method
        let allocated = fgrp.alloc_fd(dup_chan);
        if allocated < 0 {
            return Err(Error::Ebadf);
        }
        Ok(allocated as usize)
    }
}

// ============================================================================
// Pipe Implementation
// ============================================================================

/// Simple in-memory pipe buffer
pub struct PipeBuffer {
    /// Circular buffer for data
    data: [u8; 4096],
    /// Read index
    read_idx: usize,
    /// Write index
    write_idx: usize,
    /// Number of bytes available to read
    available: usize,
    /// Maximum capacity
    capacity: usize,
    /// Lock for synchronization
    lock: Spinlock,
    /// Reader waiting flag
    reader_waiting: bool,
    /// Writer waiting flag
    writer_waiting: bool,
}

impl PipeBuffer {
    /// Create a new pipe buffer
    pub fn new() -> Self {
        Self {
            data: [0u8; 4096],
            read_idx: 0,
            write_idx: 0,
            available: 0,
            capacity: 4096,
            lock: Spinlock::new(),
            reader_waiting: false,
            writer_waiting: false,
        }
    }

    /// Write data to the pipe
    /// Returns the number of bytes written
    pub fn write(&mut self, buf: &[u8]) -> usize {
        let mut guard = self.lock.lock();
        let mut written = 0;

        for &byte in buf {
            if self.available >= self.capacity {
                // Buffer full
                break;
            }

            self.data[self.write_idx] = byte;
            self.write_idx = (self.write_idx + 1) % self.capacity;
            self.available += 1;
            written += 1;
        }

        // Wake up reader if there's data
        if self.available > 0 {
            self.reader_waiting = false;
        }

        written
    }

    /// Read data from the pipe
    /// Returns the number of bytes read
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut guard = self.lock.lock();
        let mut read = 0;

        for byte in buf.iter_mut() {
            if self.available == 0 {
                // Buffer empty
                break;
            }

            *byte = self.data[self.read_idx];
            self.read_idx = (self.read_idx + 1) % self.capacity;
            self.available -= 1;
            read += 1;
        }

        // Wake up writer if there's space
        if self.available < self.capacity {
            self.writer_waiting = false;
        }

        read
    }

    /// Get the number of bytes available to read
    pub fn available(&self) -> usize {
        let guard = self.lock.lock();
        self.available
    }

    /// Get the number of bytes available for writing
    pub fn writable(&self) -> usize {
        let guard = self.lock.lock();
        self.capacity - self.available
    }
}

impl Default for PipeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Pipe structure - pair of read/write channels
pub struct Pipe {
    /// The shared buffer
    buffer: PipeBuffer,
}

impl Pipe {
    /// Create a new pipe
    pub fn new() -> Self {
        Self {
            buffer: PipeBuffer::new(),
        }
    }
}

impl Default for Pipe {
    fn default() -> Self {
        Self::new()
    }
}

/// PIPE - create pipe
///
/// Creates a pair of connected file descriptors.
///
/// # Arguments
/// * `arg0` - Pointer to array of 2 ints for the fds
///
/// # Returns
/// * `0` on success
fn sys_internalpipe(frame: &SyscallFrame) -> Result<usize> {
    let fds_ptr = frame.arg(0);

    if fds_ptr == 0 {
        return Err(Error::Ebadf);
    }

    // Verify we can write to the user pointer
    if !is_user_addr(fds_ptr) || !is_user_addr(fds_ptr + 7) {
        return Err(Error::Ebadf);
    }

    // Get current process
    let proc = curproc().ok_or(Error::Eperm)?;

    // Get file descriptor group
    let fgrp = match proc.fgrp.as_mut() {
        Some(f) => f,
        None => return Err(Error::Ebadf),
    };

    // Create pipe channels
    // In a full implementation, we would create actual channel objects
    // For now, we just create dummy file descriptors

    // Allocate read fd
    let read_fd = fgrp.alloc_fd(Box::new(DummyChan::new(true, false)));
    if read_fd < 0 {
        return Err(Error::Enomem);
    }

    // Allocate write fd
    let write_fd = fgrp.alloc_fd(Box::new(DummyChan::new(false, true)));
    if write_fd < 0 {
        // Close read fd
        let _ = fgrp.close_fd(read_fd);
        return Err(Error::Enomem);
    }

    // Write the file descriptors to user memory
    // Note: In real implementation, we would use copyout
    unsafe {
        core::ptr::write(fds_ptr as *mut i32, read_fd);
        core::ptr::write((fds_ptr as *mut i32).add(1), write_fd);
    }

    Ok(0)
}

/// Dummy channel for pipe implementation
/// In a full implementation, this would be replaced with real pipe channels
pub struct DummyChan {
    readable: bool,
    writable: bool,
}

impl DummyChan {
    pub fn new(readable: bool, writable: bool) -> Self {
        Self { readable, writable }
    }
}

impl crate::proc::Chan for DummyChan {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.readable {
            return Err(crate::proc::Error {});
        }
        // In a real implementation, read from pipe buffer
        Ok(0)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(crate::proc::Error {});
        }
        // In a real implementation, write to pipe buffer
        Ok(buf.len())
    }

    fn close(&mut self) {
        // Cleanup
    }

    fn dev(&self) -> usize {
        0 // pipe device number
    }

    fn offset(&self) -> u64 {
        0
    }

    fn set_offset(&mut self, _offset: u64) {
        // No-op for pipes
    }
}

/// STAT - get file status
///
/// Gets file metadata for a path.
/// 
/// # Arguments
/// * `arg0` - Path name
/// * `arg1` - Buffer for stat data
/// * `arg2` - Buffer size
/// 
/// # Returns
/// * Bytes written, or error
fn sys_internalstat(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;
    
    if path_ptr == 0 || buf_ptr == 0 {
        return Err(Error::Ebadf);
    }
    
    if !is_user_addr(path_ptr) || !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }
    
    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;
    
    // Use VFS to stat the file
    let amode = crate::vfs::NamecMode::Walk;
    match namec(&path, amode, 0, 0) {
        Ok(chan) => {
            // Get stat data from channel
            // In a full implementation, this would call chan.stat()
            // For now, just return the channel and close it
            let _ = chan;
            Err(Error::Eio) // Stat not implemented yet
        }
        Err(_) => Err(Error::Enoent),
    }
}

/// FSTAT - get file status by fd
///
/// Gets file metadata for an open file descriptor.
/// 
/// # Arguments
/// * `arg0` - File descriptor
/// * `arg1` - Buffer for stat data
/// * `arg2` - Buffer size
/// 
/// # Returns
/// * Bytes written, or error
fn sys_internalfstat(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;
    
    if buf_ptr == 0 {
        return Err(Error::Ebadf);
    }
    
    if !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }
    
    // Get current process
    let proc = curproc().ok_or(Error::Ebadfd)?;
    let fgrp = match proc.fgrp.as_mut() {
        Some(f) => f,
        None => return Err(Error::Ebadfd),
    };
    
    // Get the channel for this fd
    let chan = match fgrp.get_channel(fd) {
        Some(c) => c,
        None => return Err(Error::Ebadfd),
    };
    
    // Get stat data from channel
    // In a full implementation, this would call chan.stat()
    let _ = chan;
    Err(Error::Eio) // Not implemented yet
}

/// FSTAT - get file status by fd
fn sys_internalfstat(_frame: &SyscallFrame) -> Result<usize> {
    Err(Error::Ebadfd)
}

/// WSTAT - set file status by path
///
/// Sets file metadata (permissions, owner, timestamps, etc.) for a path.
/// Only fields with corresponding "set" permissions in Dir are modified.
///
/// # Arguments
/// * `arg0` - Path name
/// * `arg1` - Buffer containing stat data with changes
/// * `arg2` - Buffer size
///
/// # Returns
/// * `0` on success
fn sys_internalwstat(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;

    if path_ptr == 0 || buf_ptr == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(path_ptr) || !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }

    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;

    // Use VFS to walk to the file
    let amode = crate::vfs::NamecMode::Walk;
    let chan = namec(&path, amode, 0, 0)?;

    // Copy stat data from user space
    // In a full implementation, this would parse and apply the stat changes
    let mut stat_buf = vec![0u8; n];
    copy_from_user(buf_ptr, &mut stat_buf)?;

    // For now, just close the channel
    // A full implementation would call chan.wstat(&stat_buf)?;
    chan.close()?;

    Ok(0)
}

/// FWSTAT - set file status by fd
///
/// Sets file metadata for an open file descriptor.
///
/// # Arguments
/// * `arg0` - File descriptor
/// * `arg1` - Buffer containing stat data with changes
/// * `arg2` - Buffer size
///
/// # Returns
/// * `0` on success
fn sys_internalfwstat(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let buf_ptr = frame.arg(1);
    let n = frame.arg(2) as usize;

    if buf_ptr == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(buf_ptr) {
        return Err(Error::Ebadf);
    }

    // Get current process
    let proc = curproc().ok_or(Error::Ebadfd)?;
    let fgrp = match proc.fgrp.as_mut() {
        Some(f) => f,
        None => return Err(Error::Ebadfd),
    };

    // Get the channel for this fd
    let mut chan = match fgrp.get_channel(fd) {
        Some(c) => c,
        None => return Err(Error::Ebadfd),
    };

    // Copy stat data from user space
    let mut stat_buf = vec![0u8; n];
    copy_from_user(buf_ptr, &mut stat_buf)?;

    // For now, just return success
    // A full implementation would call chan.wstat(&stat_buf)?;
    Ok(0)
}

/// REMOVE - remove file or directory
///
/// Removes a file or empty directory. The name is removed from its parent
/// directory. If the file has multiple links, only the specified name is removed.
///
/// # Arguments
/// * `arg0` - Path name
///
/// # Returns
/// * `0` on success
fn sys_internalremove(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);

    if path_ptr == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(path_ptr) {
        return Err(Error::Ebadf);
    }

    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;

    // Use VFS to remove the file
    let amode = crate::vfs::NamecMode::Remove;
    let chan = namec(&path, amode, 0, 0)?;

    // Close the channel (remove is completed by namec)
    chan.close()?;

    Ok(0)
}

/// BRK - set break
fn sys_internalbrk(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0);
    // TODO: Set program break
    Ok(addr as usize)
}

/// MOUNT - mount filesystem
///
/// Mounts a file system over a directory.
///
/// # Arguments
/// * `arg0` - Source file descriptor (-1 for no source)
/// * `arg1` - Mount point file descriptor
/// * `arg2` - Flags (MBEFORE, MAFTER, MCREATE)
///
/// # Returns
/// * `0` on success
fn sys_internalmount(frame: &SyscallFrame) -> Result<usize> {
    let fd = frame.arg(0) as i32;
    let mntfd = frame.arg(1) as i32;
    let flags = frame.arg(2) as u32;

    // Get current process
    let proc = curproc().ok_or(Error::Eperm)?;

    // Get the mount point channel
    let mntpt = if mntfd >= 0 {
        let fgrp = match proc.fgrp.as_mut() {
            Some(f) => f,
            None => return Err(Error::Ebadfd),
        };
        match fgrp.get_channel(mntfd) {
            Some(c) => c,
            None => return Err(Error::Ebadfd),
        }
    } else {
        return Err(Error::Einval);
    };

    // Get the source channel if provided
    let source = if fd >= 0 {
        let fgrp = match proc.fgrp.as_mut() {
            Some(f) => f,
            None => return Err(Error::Ebadfd),
        };
        match fgrp.get_channel(fd) {
            Some(c) => c,
            None => return Err(Error::Ebadfd),
        }
    } else {
        // No source - return error for now
        return Err(Error::Einval);
    };

    // Use VFS to mount
    // The mount table manages all mounts
    let mount_point_path = format!("fd:{}", mntfd);
    match crate::vfs::mount_table::add(source, mount_point_path, flags) {
        Ok(_) => Ok(0),
        Err(_) => Err(Error::Eio),
    }
}

/// UNMOUNT - unmount filesystem
///
/// Unmounts a file system.
///
/// # Arguments
/// * `arg0` - Mount point name (or null for any)
/// * `arg1` - Mount point to unmount
///
/// # Returns
/// * `0` on success
fn sys_internalunmount(frame: &SyscallFrame) -> Result<usize> {
    let name_ptr = frame.arg(0);
    let old_ptr = frame.arg(1);

    // Copy names from user space
    let _name = if name_ptr != 0 {
        Some(copy_cstring_from_user(name_ptr)?)
    } else {
        None
    };

    let old = if old_ptr != 0 {
        copy_cstring_from_user(old_ptr)?
    } else {
        return Err(Error::Einval);
    };

    // Use VFS to unmount
    match crate::vfs::mount_table::remove(&old) {
        Ok(_) => Ok(0),
        Err(_) => Err(Error::Eio),
    }
}

/// BIND - bind name to channel
///
/// Creates a bind mount or directory entry.
///
/// # Arguments
/// * `arg0` - Path name to bind
/// * `arg1` - Mount point path
/// * `arg2` - Flags (MBEFORE, MAFTER, MCREATE)
///
/// # Returns
/// * `0` on success
fn sys_internalbind(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);
    let mntpt_ptr = frame.arg(1);
    let flags = frame.arg(2) as u32;

    if path_ptr == 0 || mntpt_ptr == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(path_ptr) || !is_user_addr(mntpt_ptr) {
        return Err(Error::Ebadf);
    }

    // Copy paths from user space
    let source_path = copy_cstring_from_user(path_ptr)?;
    let target_path = copy_cstring_from_user(mntpt_ptr)?;

    // Walk to the source path
    let amode = crate::vfs::NamecMode::Walk;
    let source_chan = namec(&source_path, amode, 0, 0)?;

    // Walk to the target path
    let target_chan = namec(&target_path, amode, 0, 0)?;

    // Perform the bind mount via VFS
    match crate::vfs::bind(source_chan, target_chan, flags) {
        Ok(_) => Ok(0),
        Err(_) => Err(Error::Eio),
    }
}

/// CHDIR - change directory
///
/// Changes the current working directory.
///
/// # Arguments
/// * `arg0` - Path name
///
/// # Returns
/// * `0` on success
fn sys_internalchdir(frame: &SyscallFrame) -> Result<usize> {
    let path_ptr = frame.arg(0);

    if path_ptr == 0 {
        return Err(Error::Ebadf);
    }

    if !is_user_addr(path_ptr) {
        return Err(Error::Ebadf);
    }

    // Copy path from user space
    let path = copy_cstring_from_user(path_ptr)?;

    // Use VFS to walk to the directory
    let amode = crate::vfs::NamecMode::Walk;
    let chan = namec(&path, amode, 0, 0)?;

    // Verify it's a directory
    // In a full implementation, we would check chan.is_directory()

    // Get current process
    let proc = curproc().ok_or(Error::Ebadfd)?;

    // Close old current directory if set
    if let Some(old_dot) = proc.dot.take() {
        old_dot.close();
    }

    // Set new current directory
    proc.dot = Some(chan);

    Ok(0)
}

/// NOTIFY - set exception handler
///
/// Sets the function that will be called when a note (signal) is posted to the process.
fn sys_internalnotify(frame: &SyscallFrame) -> Result<usize> {
    let fn_ptr = frame.arg(0);

    if fn_ptr == 0 {
        // Disable notify
        if let Some(proc) = crate::proc::curproc_mut() {
            proc.set_notify(None);
        }
    } else {
        // Set the notify function
        // SAFETY: The function pointer is trusted as it comes from user space
        let handler = unsafe { core::mem::transmute::<u64, Option<unsafe fn(*mut u8, *const u8) -> i32>>(fn_ptr) };
        if let Some(proc) = crate::proc::curproc_mut() {
            proc.set_notify(handler);
        }
    }

    Ok(0)
}

/// NOTED - return from signal handler
///
/// This is called by the signal handler when it has finished processing.
/// It restores the user register state saved when the signal was delivered.
fn sys_internalsysnoted(frame: &SyscallFrame) -> Result<usize> {
    let _frame = frame; // unused

    let proc = crate::proc::curproc_mut().ok_or(Error::Eperm)?;

    // Check if there are saved registers to restore
    if proc.has_ureg() {
        // Restore the saved user registers
        // This would typically use iretq to return to user space
        // For now, just discard the saved state
        let _ = proc.restore_ureg();
    }

    Ok(0)
}

/// RENDEZVOUS - process synchronization
///
/// Plan 9's rendezvous is a simple synchronization primitive.
/// Two processes meet at a rendezvous point with a tag, and one waits
/// until both have arrived. They exchange values.
fn sys_internalrendezvous(frame: &SyscallFrame) -> Result<usize> {
    let tag = frame.arg(0) as usize;
    let val = frame.arg(1) as usize;
    
    // Get current process
    let proc = curproc().ok_or(Error::Eperm)?;
    let proc = unsafe { &mut *(proc as *const Proc as *mut Proc) };
    
    // Try to perform the rendezvous
    // This will either:
    // - Return immediately if a partner is found
    // - Return Err if we need to sleep
    match proc.rendezvous(tag, val) {
        Ok(exchanged_val) => Ok(exchanged_val),
        Err(()) => {
            // We need to sleep until a partner arrives
            // The caller should have stored our info and will sleep
            
            // For now, just return an error and let the caller handle it
            // In a full implementation, we would:
            // 1. Store our entry in the hash table
            // 2. Set state to Rendezvous
            // 3. Call schedule() to sleep
            // 4. When woken, return the exchanged value
            
            Err(Error::Eagain)
        }
    }
}

/// Rendezvous operation for current process
/// 
/// This is a helper that performs the rendezvous syscall logic.
impl Proc {
    /// Perform rendezvous with another process
    /// 
    /// # Arguments
    /// * `tag` - Rendezvous tag
    /// * `val` - Value to exchange
    /// 
    /// # Returns
    /// * `Ok(exchanged_val)` - Value from the other process
    /// * `Err(())` - Should sleep waiting for partner
    pub fn rendezvous(&mut self, tag: usize, val: usize) -> Result<usize, ()> {
        // Get the global rendezvous table
        // This would be a global static in a full implementation
        let _ = tag;
        let _ = val;
        
        // For now, return an error
        // The actual implementation needs a global rendezvous table
        Err(())
    }
}

/// SLEEP - sleep for specified milliseconds
///
/// Suspends the current process until the specified time has elapsed.
fn sys_internalsleep(frame: &SyscallFrame) -> Result<usize> {
    let ms = frame.arg(0) as u64;

    // Create a timer for the sleep
    let mut timer = crate::user_regs::Timer::relative(ms);

    // Add timer to queue
    // SAFETY: Timer is newly created and not in any queue
    unsafe {
        crate::user_regs::timerset(&mut timer);
    }

    // Sleep until timer expires or we're woken up
    let _guard = crate::plan9_common::sync::Spinlock::new(());

    // In a full implementation, this would:
    // 1. Set process state to Wakeme
    // 2. Call scheduler to switch to another process
    // 3. Return when woken up

    Ok(0)
}

/// ALARM - alarm clock
///
/// Sets a timer that will post a note to the process after the specified
/// number of milliseconds.
///
/// # Arguments
/// * `arg0` - Milliseconds until alarm (0 to cancel)
/// 
/// # Returns
/// * Previous alarm time in milliseconds
fn sys_internalalarm(frame: &SyscallFrame) -> Result<usize> {
    let ms = frame.arg(0) as u64;
    
    let proc = crate::proc::curproc_mut().ok_or(Error::Eperm)?;
    
    // Get current ticks (would need to be provided by architecture-specific code)
    // For now, use a placeholder
    let current_ticks = crate::proc::get_ticks();
    
    // Set the alarm and get the previous alarm time
    let old_alarm = proc.alarm.set(AlarmReq::new(ms), current_ticks);
    
    // If alarm is being set (not cancelled), also set up a timer
    if ms > 0 {
        // Create a timer for this alarm
        let mut timer = crate::user_regs::Timer::relative(ms);
        timer.arg = proc.pid as u64; // Store PID in arg
        
        // Add timer to queue
        // SAFETY: Timer is newly created and not in any queue
        unsafe {
            crate::user_regs::timerset(&mut timer);
        }
    }
    
    // Return previous alarm time in ms
    Ok(old_alarm as usize)
}

/// Get current system ticks
/// 
/// This should be provided by the architecture-specific code.
/// Returns the number of clock ticks since system start.
fn get_ticks() -> u64 {
    // In a real implementation, this would read the clock
    // For now, return a placeholder
    0
}

/// AWAIT - wait for event
///
/// Waits for child process to exit and returns the exit status.
/// This is Plan 9's await() equivalent.
///
/// The wait message format is:
///     "pid status time[3] message\0"
/// 
/// # Arguments
/// * `arg0` - Pointer to buffer for wait message
/// * `arg1` - Buffer size
/// 
/// # Returns
/// * Number of bytes written to buffer
fn sys_internalawait(frame: &SyscallFrame) -> Result<usize> {
    let buf_ptr = frame.arg(0);
    let bufsize = frame.arg(1) as usize;
    
    // Validate buffer pointer
    if buf_ptr == 0 || bufsize == 0 {
        return Err(Error::Ebadf);
    }
    
    // Check if address is in user space
    if !is_user_addr(buf_ptr) || !is_user_addr(buf_ptr + bufsize as u64 - 1) {
        return Err(Error::Ebadf);
    }
    
    // Call do_await to get wait result
    let result = match crate::proc::do_await() {
        Some(r) => r,
        None => return Err(Error::Enochild), // No children to wait for
    };
    
    // Format wait message: "pid status time[0] time[1] time[2] message"
    // Build the wait message
    let mut msg = alloc::vec::Vec::new();
    
    // Format: pid status
    use core::fmt::Write;
    let _ = write!(&mut msg, "{} ", result.pid);
    let _ = write!(&mut msg, "{} ", result.status.raw());
    
    // Format: time[0] time[1] time[2]
    let _ = write!(&mut msg, "{} ", result.utime);
    let _ = write!(&mut msg, "{} ", result.ktime);
    let _ = write!(&mut msg, "{} ", result.pid); // ctime
    
    // Add a default message based on exit status
    if result.status.is_exit() {
        let _ = write!(&mut msg, "exit: code={}", result.status.exit_code());
    } else if result.status.is_signaled() {
        let _ = write!(&mut msg, "signal: {}", result.status.signal());
    }
    msg.push(0); // Null terminate
    
    // Copy to user buffer
    let len = msg.len().min(bufsize);
    
    // In a real implementation, we would copy to user memory here
    // For now, just return the length
    // SAFETY: In real code, this would use a copy_to_user function
    let _ = unsafe {
        core::ptr::copy_nonoverlapping(msg.as_ptr(), buf_ptr as *mut u8, len);
    };
    
    Ok(len)
}

/// Thread structure - represents a kernel thread within a process
#[derive(Debug)]
pub struct Thread {
    /// Thread ID
    pub tid: Pid,
    /// Parent process ID
    pub pid: Pid,
    /// Current state
    pub state: State,
    /// Stack pointer
    pub kstack: u64,
    /// Stack size
    pub stack_size: usize,
    /// Scheduler context (setjmp/longjmp)
    pub sched: Label,
    /// Function to execute
    pub entry: Option<unsafe fn(arg: *mut u8)>,
    /// Argument to entry function
    pub arg: *mut u8,
}

impl Thread {
    /// Create a new thread
    pub fn new(pid: Pid, entry: u64, arg: u64, stack_size: usize) -> Option<Self> {
        Some(Self {
            tid: 0, // Will be allocated by process
            pid,
            state: State::Ready,
            kstack: 0,
            stack_size,
            sched: Label::new(),
            entry: if entry != 0 {
                Some(unsafe { core::mem::transmute(entry) })
            } else {
                None
            },
            arg: arg as *mut u8,
        })
    }

    /// Check if thread is runnable
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, State::Ready | State::Running)
    }
}

/// Process threads manager
pub struct ThreadGroup {
    /// List of threads in this process
    threads: alloc::vec::Vec<Thread>,
    /// Next TID to allocate
    next_tid: Pid,
}

impl ThreadGroup {
    /// Create a new thread group
    pub fn new() -> Self {
        Self {
            threads: alloc::vec::Vec::new(),
            next_tid: 1,
        }
    }

    /// Allocate a new TID
    fn alloc_tid(&mut self) -> Option<Pid> {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);
        if self.next_tid == 0 {
            self.next_tid = 1;
        }
        Some(tid)
    }

    /// Add a thread to the group
    pub fn add_thread(&mut self, mut thread: Thread) -> Option<Pid> {
        let tid = self.alloc_tid()?;
        thread.tid = tid;
        self.threads.push(thread);
        Some(tid)
    }

    /// Remove a thread by TID
    pub fn remove_thread(&mut self, tid: Pid) -> Option<Thread> {
        self.threads.retain(|t| t.tid != tid);
        self.threads.iter().position(|t| t.tid == tid).map(|i| self.threads.remove(i))
    }

    /// Get thread by TID
    pub fn get_thread(&self, tid: Pid) -> Option<&Thread> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    /// Get mutable thread by TID
    pub fn get_thread_mut(&mut self, tid: Pid) -> Option<&mut Thread> {
        self.threads.iter_mut().find(|t| t.tid == tid)
    }

    /// Number of threads
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

/// THREADCREATE - create thread
///
/// Creates a new thread within the current process.
/// The thread shares the process's address space but has its own stack.
fn sys_internalthreadcreate(frame: &SyscallFrame) -> Result<usize> {
    let func = frame.arg(0);  // Thread function
    let arg = frame.arg(1);    // Argument to function
    let stack_size = frame.arg(2);  // Stack size

    let proc = crate::proc::curproc_mut().ok_or(Error::Eperm)?;

    // In a full implementation, this would:
    // 1. Allocate a new kernel stack
    // 2. Set up the thread's context (sched label)
    // 3. Create the thread structure
    // 4. Add to process's thread list
    // 5. Return the TID

    // For now, return error as thread support is stub
    let _ = func;
    let _ = arg;
    let _ = stack_size;
    Err(Error::Ebadf)
}

/// THREADEXIT - terminate thread
///
/// Terminates the current thread. If it's the last thread in the process,
/// the entire process exits.
fn sys_internalthreadexit(_frame: &SyscallFrame) -> Result<usize> {
    // Get current process
    let proc = crate::proc::curproc_mut().ok_or(Error::Eperm)?;

    // In a full implementation:
    // 1. Free the thread's stack
    // 2. Remove thread from process's thread list
    // 3. If last thread, call scheduler().exit()
    // 4. Otherwise, call scheduler().yield_()

    // For now, just exit the process
    scheduler().exit(0);
    Ok(0)
}

/// THREADWAIT - wait for thread to exit
///
/// Waits for a specific thread or any thread to exit.
fn sys_internalthreadwait(frame: &SyscallFrame) -> Result<usize> {
    let _tid_ptr = frame.arg(0);  // Pointer to store TID
    let _status_ptr = frame.arg(1);  // Pointer to store exit status

    // In a full implementation, this would:
    // 1. Add process to wait queue for thread exits
    // 2. Call scheduler to sleep
    // 3. Return when a thread exits

    Err(Error::Ebadf)
}

/// YIELD - yield processor
fn sys_internalyield(_frame: &SyscallFrame) -> Result<usize> {
    sched_yield();
    Ok(0)
}

/// SEGBRK - change memory segment
///
/// Changes the size of the data segment for the current process.
/// This is Plan 9's segbrk syscall for growing/shrinking data segment.
fn sys_internalsegbrk(frame: &SyscallFrame) -> Result<usize> {
    let new_addr = frame.arg(0);
    
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Find the data/bss segment (SG_DATA or SG_BSS)
    let seg = proc.seg.iter()
        .find(|s| {
            if let Some(seg) = s {
                matches!(seg.segtype, SegType::Data | SegType::Bss)
            } else {
                false
            }
        });
    
    if let Some(Some(segment)) = seg {
        // Validate new address is within reasonable bounds
        if new_addr < USER_BASE || new_addr > USER_STACK_BASE {
            return Err(Error::Einval);
        }
        
        // Check for overlap with other segments
        for (i, opt_seg) in proc.seg.iter().enumerate() {
            if let Some(ref s) = opt_seg {
                if s.base <= new_addr && new_addr < s.top {
                    // Overlaps with existing segment
                    return Err(Error::Einval);
                }
            }
        }
        
        // In a full implementation, this would:
        // 1. If growing: allocate new pages up to new_addr
        // 2. If shrinking: free pages above new_addr
        // 3. Update the segment's top
        
        // For now, just return the new address
        return Ok(new_addr as usize);
    }
    
    Err(Error::Einval)
}

/// SEGATTACH - attach shared memory
///
/// Attaches a region of memory to the process's address space.
/// The memory can be from an existing segment or anonymous.
///
/// # Arguments
/// * `arg0` - Segment type (SG_TEXT, SG_DATA, SG_BSS, SG_STACK, SG_SHARED)
/// * `arg1` - Virtual address (0 = find any hole)
/// * `arg2` - Length in bytes
/// * `arg3` - File descriptor (for file-backed segments, -1 for anonymous)
fn sys_internalsegattach(frame: &SyscallFrame) -> Result<usize> {
    let seg_type = frame.arg(0) as u32;
    let addr = frame.arg(1);
    let len = frame.arg(2);
    let fd = frame.arg(3) as i32;
    
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Validate length
    if len == 0 {
        return Err(Error::Einval);
    }
    
    // Find a free segment slot
    let seg_idx = proc.seg.iter().position(|s| s.is_none())
        .ok_or(Error::Enomem)?;
    
    // Calculate the base address
    let base = if addr == 0 {
        // Find a hole in the address space
        find_free_segment_hole(len, proc.seg)?
    } else {
        // Use the specified address
        addr
    };
    
    // Check for overlap with existing segments
    let top = base + len;
    for opt_seg in &proc.seg {
        if let Some(ref seg) = opt_seg {
            if !(top <= seg.base || base >= seg.top) {
                // Overlaps
                return Err(Error::Einval);
            }
        }
    }
    
    // Validate address is in user space
    if base > MAX_VADDR || top > MAX_VADDR {
        return Err(Error::Einval);
    }
    
    // Create the segment
    let segtype = match seg_type {
        1 => SegType::Text,
        2 => SegType::Data,
        3 => SegType::Bss,
        4 => SegType::Stack,
        5 => SegType::Shared,
        6 => SegType::Physical,
        _ => return Err(Error::Einval),
    };
    
    let mut segment = Segment::new(segtype, base, len as usize);
    
    // If file-backed (fd >= 0), this would load the file
    // For now, anonymous segments are zero-filled on demand
    
    // Store in process's segment table
    proc.seg[seg_idx] = Some(segment);
    
    Ok(base as usize)
}

/// Find a hole in the address space for a new segment
fn find_free_segment_hole(len: u64, segments: [Option<Segment>; 10]) -> Result<u64> {
    let mut start = USER_BASE;
    let end = USER_STACK_BASE - (8 * 1024 * 1024); // Leave space for stack
    
    // Sort segments by base address and find gaps
    let mut sorted: Vec<(u64, u64)> = segments.iter()
        .filter_map(|s| s.as_ref().map(|seg| (seg.base, seg.top)))
        .collect();
    sorted.sort_by_key(|k| k.0);
    
    for (seg_base, seg_top) in sorted {
        if start + len <= seg_base {
            // Found a hole
            return Ok(start);
        }
        start = seg_top;
        if start >= end {
            break;
        }
    }
    
    // Check final gap
    if start + len <= end {
        Ok(start)
    } else {
        Err(Error::Enomem)
    }
}

/// SEGDETACH - detach shared memory
///
/// Detaches a segment from the process's address space.
fn sys_internalsegdetach(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0);
    
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Find the segment containing this address
    let seg_idx = proc.seg.iter().position(|opt_seg| {
        if let Some(ref seg) = opt_seg {
            seg.base <= addr && addr < seg.top
        } else {
            false
        }
    }).ok_or(Error::Einval)?;
    
    // Cannot detach stack segment
    if let Some(ref seg) = proc.seg[seg_idx] {
        if seg.segtype == SegType::Stack {
            return Err(Error::Einval);
        }
    }
    
    // Decrement reference count and free if last reference
    if let Some(ref mut seg) = proc.seg[seg_idx] {
        seg.decref();
        if seg.refcount == 0 {
            // Free the segment's pages
            // In a full implementation, this would call pagefree for each page
        }
    }
    
    // Remove from segment table
    proc.seg[seg_idx] = None;
    
    Ok(0)
}

/// SEGFREE - free shared memory
///
/// Frees a portion of a shared memory segment.
fn sys_internalsegfree(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0);
    let len = frame.arg(1);
    
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Find the segment containing this address
    let seg_idx = proc.seg.iter().position(|opt_seg| {
        if let Some(ref seg) = opt_seg {
            seg.base <= addr && addr < seg.top
        } else {
            false
        }
    }).ok_or(Error::Einval)?;
    
    // Align addresses to page boundaries
    let start_page = (addr - (addr % PAGE_SIZE));
    let end_page = ((addr + len + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    
    // Validate range is within segment
    if let Some(ref seg) = proc.seg[seg_idx] {
        if end_page > seg.top {
            return Err(Error::Einval);
        }
    }
    
    // Free the pages in the range
    // In a full implementation, this would:
    // 1. Walk the page table
    // 2. Call pagefree for each valid PTE
    // 3. Clear the PTE entries
    // 4. Flush TLB for the range
    
    // For now, just acknowledge the request
    let _ = start_page;
    let _ = end_page;
    
    Ok(0)
}

/// SEGFLUSH - flush instruction cache
///
/// Flushes the instruction cache and TLB for a memory region.
/// This is necessary after writing code to memory or modifying page tables.
///
/// On x86_64, the instruction cache is automatically coherent with the
/// data cache, but we need to invalidate the TLB entries.
fn sys_internalsegflush(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0);
    let len = frame.arg(1);
    
    // Validate address
    if !is_user_addr(addr) {
        return Err(Error::Einval);
    }
    
    // Find the segment containing this address
    let proc = curproc().ok_or(Error::Eperm)?;
    
    // Check if address is in a valid segment
    let _seg = proc.seg.iter().find(|opt_seg| {
        if let Some(ref seg) = opt_seg {
            seg.base <= addr && addr < seg.top
        } else {
            false
        }
    }).ok_or(Error::Einval)?;
    
    // On x86_64, we need to flush the TLB for the affected pages
    // This is done by calling invlpg for each page in the range
    
    // Calculate page range
    let page_size = PAGE_SIZE;
    let start_page = addr & !(page_size - 1);
    let end_addr = addr.saturating_add(len);
    let end_page = (end_addr + page_size - 1) & !(page_size - 1);
    
    // Flush TLB for each page in the range
    // In a full implementation, this would use the invlpg instruction
    // for x86_64, or the appropriate instruction for other architectures
    
    // For now, mark the flush needed flag in the segment
    // The actual TLB flush would happen on next context switch
    
    // On x86_64, instruction cache and data cache are coherent,
    // so we don't need to flush the icache.
    // We only need to invalidate TLB entries.
    
    let _ = start_page;
    let _ = end_page;
    
    Ok(0)
}

/// ERRSTR - get error string
fn sys_internalerrstr(_frame: &SyscallFrame) -> Result<usize> {
    Ok(0)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if an address is in user space
fn is_user_addr(addr: u64) -> bool {
    // User space is 0x0 to 0x7FFFFFFFFFFF
    addr < 0x8000_0000_0000
}

// ============================================================================
// Semaphore Syscalls
// ============================================================================

/// SEMACQUIRE - acquire semaphore
///
/// Acquires a semaphore, blocking until available if necessary.
/// 
/// # Arguments
/// * `arg0` - Pointer to semaphore count in user space
/// 
/// # Returns
/// * `0` on success
/// * Error code on failure
fn sys_internalsemacquire(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0) as usize;
    
    // Validate address
    if !is_user_addr(addr as u64) {
        return Err(Error::Ebadf);
    }
    
    // Try to acquire the semaphore
    match crate::sema::semacquire(addr, true) {
        Ok(true) => Ok(0),
        Ok(false) => Ok(0), // Would block but we don't block
        Err(()) => Err(Error::Eintr), // Interrupted
    }
}

/// SEMRELEASE - release semaphore
///
/// Releases a semaphore and wakes waiting processes.
/// 
/// # Arguments
/// * `arg0` - Pointer to semaphore count in user space
/// * `arg1` - Amount to increment (typically 1)
/// 
/// # Returns
/// * New semaphore value
fn sys_internalsemrelease(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0) as usize;
    let delta = frame.arg(1) as i32;
    
    // Validate address
    if !is_user_addr(addr as u64) {
        return Err(Error::Ebadf);
    }
    
    // Release the semaphore
    let new_val = crate::sema::semrelease(addr, delta);
    Ok(new_val as usize)
}

/// TSEMACQUIRE - timed acquire semaphore
///
/// Attempts to acquire a semaphore with a timeout.
/// 
/// # Arguments
/// * `arg0` - Pointer to semaphore count in user space
/// * `arg1` - Timeout in milliseconds
/// 
/// # Returns
/// * `0` on success
/// * Error code on failure or timeout
fn sys_internaltsemacquire(frame: &SyscallFrame) -> Result<usize> {
    let addr = frame.arg(0) as usize;
    let ms = frame.arg(1) as u64;
    
    // Validate address
    if !is_user_addr(addr as u64) {
        return Err(Error::Ebadf);
    }
    
    // Try to acquire with timeout
    match crate::sema::tsemacquire(addr, ms) {
        Ok(true) => Ok(0),
        Ok(false) => Err(Error::Etimedout), // Timed out
        Err(()) => Err(Error::Eintr), // Interrupted
    }
}

// ============================================================================
// Process Control Syscall
// ============================================================================

/// Process control requests
pub mod procctl_request {
    /// Exit the process
    pub const EXIT: u32 = 1;
    /// Exit with "insufficient memory" message
    pub const EXITBIG: u32 = 2;
    /// Enable tracing (stop on next syscall)
    pub const TRACEME: u32 = 3;
    /// Stop the process
    pub const STOP: u32 = 4;
    /// Wait for stop to release
    pub const WAITSTOP: u32 = 5;
    /// Disable parent's ability to kill
    pub const NOPARENTCTRL: u32 = 6;
    /// Set trace permissions
    pub const PERMTRACE: u32 = 7;
    /// Clear all trace flags
    pub const CLEARTRACE: u32 = 8;
    /// Set CPU affinity
    pub const SETAFFINITY: u32 = 9;
    /// Set process group
    pub const SETPGRP: u32 = 10;
    /// Enable FPU usage
    pub const FPFPU: u32 = 11;
}

/// PROCCTL - process control
///
/// Controls various aspects of process execution.
/// 
/// # Arguments
/// * `arg0` - Request type
/// * `arg1` - PID (0 = self)
/// * `arg2` - Data (depends on request)
/// 
/// # Returns
/// * `0` on success
/// * Error code on failure
fn sys_internalprocctl(frame: &SyscallFrame) -> Result<usize> {
    let req = frame.arg(0) as u32;
    let pid = frame.arg(1) as i32;
    let data = frame.arg(2);
    
    // Get target process (0 = self)
    let proc = if pid == 0 {
        curproc().ok_or(Error::Eperm)?
    } else {
        // Find process by PID
        // For now, only support self
        return Err(Error::Ebadpid);
    };
    
    match req {
        procctl_request::EXIT => {
            // Exit the process
            proc.exit("Killed");
            Ok(0) // Never returns
        }
        
        procctl_request::EXITBIG => {
            // Exit with memory message
            proc.exit("Killed: Insufficient physical memory");
            Ok(0)
        }
        
        procctl_request::TRACEME => {
            // Enable tracing - stop on next syscall
            proc.state = State::Stopped;
            Ok(0)
        }
        
        procctl_request::STOP => {
            // Stop the process
            proc.state = State::Stopped;
            // Yield to scheduler
            crate::sched::yield_();
            Ok(0)
        }
        
        procctl_request::WAITSTOP => {
            // Wait for stop to release (used by debugger)
            while proc.state == State::Stopped {
                crate::sched::yield_();
            }
            Ok(0)
        }
        
        procctl_request::SETAFFINITY => {
            // Set CPU affinity mask
            // proc.cpu_affinity = CpuMask::from_bits(data as u64);
            Ok(0)
        }
        
        _ => Err(Error::Einval),
    }
}

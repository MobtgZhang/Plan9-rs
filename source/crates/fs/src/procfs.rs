//! ProcFS - Process File System
//!
//! Implements the /proc filesystem following Plan 9's devproc.c
//! Reference: sys/src/9/port/devproc.c
//!
//! ProcFS exposes process and system information through a file-like interface.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// Constants (from devproc.c)
// ============================================================================

/// Maximum length of process arguments
pub const MAXARG: usize = 1024;

/// Maximum number of fds
pub const MAXFD: usize = 64;

/// Maximum processes
const MAXPROCS: usize = 4096;

/// Create an array of None values for ProcFd
fn create_none_fd_array() -> [Option<ProcFd>; MAXFD] {
    // SAFETY: This is safe because we're creating a const array with a known layout.
    // We use unsafe block because const fn cannot call unsafe directly in some configurations.
    const NONE: Option<ProcFd> = None;
    [NONE; MAXFD]
}

/// Create an array of None values for Box<Proc>
fn create_none_proc_array() -> [Option<Box<Proc>>; MAXPROCS] {
    const NONE: Option<Box<Proc>> = None;
    [NONE; MAXPROCS]
}

/// ProcFS QID types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcQid {
    None = 0,
    Ctl = 1,
    Note = 2,
    Noteid = 3,
    Status = 4,
    Fd = 5,
    FdDir = 6,
    Memory = 7,
    Profile = 8,
    Regs = 9,
    Fpregs = 10,
    Kstack = 11,
    Pctl = 12,
    Pfd = 13,
    Wait = 14,
    Args = 15,
}

/// Process control commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProcCtl {
    /// Start the process
    Start = 0,
    /// Stop the process
    Stop = 1,
    /// Kill the process
    Kill = 2,
    /// Detach from debugger
    Detach = 3,
    /// Attach debugger
    Attach = 4,
    /// Hang the process
    Hang = 5,
    /// Wait for process to stop
    Waitstop = 6,
    /// Wait for process to exit
    Waitidle = 7,
}

/// Thread state (matching kernel scheduler)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Dead = 0,
    Running = 1,
    Ready = 2,
    Sleeping = 3,
    Stopped = 4,
    Rendezvous = 5,
}

// ============================================================================
// Process Information Structure
// ============================================================================

/// Process information structure
pub struct ProcInfo {
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
    /// Process state
    pub state: ProcState,
    /// Thread ID
    pub tid: i32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Command name
    pub comm: [u8; 64],
    /// Pointer size (32 or 64)
    pub ptrsize: u8,
    /// No file descriptors (yet)
    pub nfd: u32,
}

impl ProcInfo {
    /// Create a new ProcInfo
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            ppid: 0,
            state: ProcState::Dead,
            tid: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; 64],
            ptrsize: core::mem::size_of::<usize>() as u8 * 8,
            nfd: 0,
        }
    }
    
    /// Get state as string
    pub fn state_str(&self) -> &'static str {
        match self.state {
            ProcState::Dead => "Dead",
            ProcState::Running => "Run",
            ProcState::Ready => "Ready",
            ProcState::Sleeping => "Sleep",
            ProcState::Stopped => "Stop",
            ProcState::Rendezvous => "Rendez",
        }
    }
}

// ============================================================================
// Process Control Block
// ============================================================================

/// Process Control Block
pub struct Proc {
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
    /// Process state
    pub state: ProcState,
    /// Exit status
    pub exit_status: i32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Command name
    pub comm: [u8; 64],
    /// Memory map pointer
    pub mm: *mut u8,
    /// Stack pointer
    pub kstack: *mut u8,
    /// Stack size
    pub kstacksize: usize,
    /// Pointer to registers
    pub regs: *mut u8,
    /// File descriptor table
    pub fds: UnsafeCell<[Option<ProcFd>; MAXFD]>,
    /// Number of open file descriptors
    pub nfd: AtomicUsize,
    /// Rendezvous tag
    pub rndtag: *mut u8,
    /// Note/signal pending
    pub note: UnsafeCell<Option<u8>>,
    /// Thread list
    pub threads: UnsafeCell<*mut ProcThread>,
}

impl Proc {
    /// Create a new process
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            ppid: 0,
            state: ProcState::Dead,
            exit_status: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; 64],
            mm: core::ptr::null_mut(),
            kstack: core::ptr::null_mut(),
            kstacksize: 0,
            regs: core::ptr::null_mut(),
            fds: UnsafeCell::new(create_none_fd_array()),
            nfd: AtomicUsize::new(0),
            rndtag: core::ptr::null_mut(),
            note: UnsafeCell::new(None),
            threads: UnsafeCell::new(core::ptr::null_mut()),
        }
    }
    
    /// Get process info
    pub fn info(&self) -> ProcInfo {
        ProcInfo {
            pid: self.pid,
            ppid: self.ppid,
            state: self.state,
            tid: self.pid,
            uid: self.uid,
            gid: self.gid,
            comm: self.comm,
            ptrsize: core::mem::size_of::<usize>() as u8 * 8,
            nfd: self.nfd.load(Ordering::Relaxed) as u32,
        }
    }
}

/// Thread within a process
pub struct ProcThread {
    /// Thread ID
    pub tid: i32,
    /// Process this thread belongs to
    pub proc: *mut Proc,
    /// Thread state
    pub state: ProcState,
    /// Stack pointer
    pub kstack: *mut u8,
    /// Stack size
    pub kstacksize: usize,
    /// Register state
    pub regs: *mut u8,
}

impl ProcThread {
    /// Create a new thread
    pub fn new(tid: i32, proc: *mut Proc) -> Self {
        Self {
            tid,
            proc,
            state: ProcState::Dead,
            kstack: core::ptr::null_mut(),
            kstacksize: 0,
            regs: core::ptr::null_mut(),
        }
    }
}

/// File descriptor within a process
pub struct ProcFd {
    /// File descriptor number
    pub fd: i32,
    /// Open flags
    pub flags: u32,
    /// Offset in file
    pub offset: u64,
    /// Reference to underlying file (placeholder)
    pub file: *mut u8,
}

// ============================================================================
// ProcFS State
// ============================================================================

/// ProcFS global state
static mut PROCFS_STATE: ProcFsState = ProcFsState::new();

struct ProcFsState {
    /// Lock for process table (simple spinlock using atomic)
    lock: AtomicU8,
    /// Process table
    procs: UnsafeCell<[Option<Box<Proc>>; MAXPROCS]>,
    /// Next PID
    next_pid: AtomicI32,
    /// Number of processes
    num_procs: AtomicUsize,
}

impl ProcFsState {
    const fn new() -> Self {
        const NONE_PROC: Option<Box<Proc>> = None;
        Self {
            lock: AtomicU8::new(0),
            procs: UnsafeCell::new([NONE_PROC; MAXPROCS]),
            next_pid: AtomicI32::new(1),
            num_procs: AtomicUsize::new(0),
        }
    }
    
    /// Acquire lock (simple test-and-set)
    fn lock(&self) {
        while self.lock.swap(1, Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    }
    
    /// Release lock
    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }
    
    /// Allocate a new PID
    pub fn alloc_pid(&self) -> i32 {
        self.next_pid.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Add a process to the table
    pub fn add_proc(&self, proc: Box<Proc>) -> i32 {
        self.lock();
        let pid = proc.pid;
        
        // Find empty slot
        let procs = unsafe { &mut *self.procs.get() };
        let mut slot = -1isize;
        for i in 0..MAXPROCS {
            if procs[i].is_none() {
                slot = i as isize;
                break;
            }
        }
        
        if slot >= 0 {
            procs[slot as usize] = Some(proc);
            self.num_procs.fetch_add(1, Ordering::Relaxed);
            self.unlock();
            return pid;
        }
        
        self.unlock();
        -1 // Table full
    }
    
    /// Get a process by PID
    pub fn get_proc(&self, pid: i32) -> Option<&'static Proc> {
        self.lock();
        let procs = unsafe { &*self.procs.get() };
        
        for proc in procs.iter() {
            if let Some(ref p) = proc {
                if p.pid == pid {
                    self.unlock();
                    return Some(p);
                }
            }
        }
        self.unlock();
        None
    }
    
    /// Remove a process
    pub fn remove_proc(&self, pid: i32) -> bool {
        self.lock();
        let procs = unsafe { &mut *self.procs.get() };
        
        for i in 0..MAXPROCS {
            if let Some(ref p) = procs[i] {
                if p.pid == pid {
                    procs[i] = None;
                    self.num_procs.fetch_sub(1, Ordering::Relaxed);
                    self.unlock();
                    return true;
                }
            }
        }
        self.unlock();
        false
    }
    
    /// Get process count
    pub fn proc_count(&self) -> usize {
        self.num_procs.load(Ordering::Relaxed)
    }

    /// Get a mutable process by PID
    pub fn get_proc_mut(&mut self, pid: i32) -> Option<&mut Proc> {
        let procs = unsafe { &mut *self.procs.get() };

        for proc in procs.iter_mut() {
            if let Some(ref mut p) = proc {
                if p.pid == pid {
                    return Some(p);
                }
            }
        }
        None
    }
}

// ============================================================================
// ProcFS API Functions
// ============================================================================

/// Create a new process
pub fn proc_create(pid: i32) -> Option<Box<Proc>> {
    let proc = Box::new(Proc::new(pid));
    if unsafe { PROCFS_STATE.add_proc(proc) } == pid {
        // Need to recreate since add_proc takes ownership
        Some(Box::new(Proc::new(pid)))
    } else {
        None
    }
}

/// Get process by PID
pub fn proc_get(pid: i32) -> Option<&'static Proc> {
    unsafe { PROCFS_STATE.get_proc(pid) }
}

/// Allocate a new PID
pub fn proc_alloc_pid() -> i32 {
    unsafe { PROCFS_STATE.alloc_pid() }
}

/// Kill a process
pub fn proc_kill(pid: i32) -> i32 {
    if let Some(proc) = unsafe { PROCFS_STATE.get_proc_mut(pid) } {
        proc.exit_status = -1;
        proc.state = ProcState::Dead;
        0
    } else {
        -1
    }
}

/// Send a note (signal) to a process
pub fn proc_note(_pid: i32, _note: &[u8]) -> i32 {
    // TODO: properly store the note
    0
}

/// Set process priority
pub fn proc_setpri(_pid: i32, _pri: i32) -> i32 {
    // TODO: implement priority setting
    -1
}

/// Wait for process state change
pub fn proc_wait(_pid: i32) -> i32 {
    // TODO: implement wait
    0
}

// ============================================================================
// ProcFS File Operations (API Stubs)
// ============================================================================

/// Generate a QID for a proc file
pub fn proc_qid(pid: i32, ftype: ProcQid) -> u64 {
    let shifted = (pid as u64) << 8;
    shifted | (ftype as u64)
}

/// Parse QID to get PID and type
pub fn proc_parse_qid(qid: u64) -> (i32, ProcQid) {
    let pid = (qid >> 8) as i32;
    let ftype = (qid & 0xFF) as u8;
    let ftype = match ftype {
        1 => ProcQid::Ctl,
        2 => ProcQid::Note,
        3 => ProcQid::Noteid,
        4 => ProcQid::Status,
        5 => ProcQid::Fd,
        6 => ProcQid::FdDir,
        7 => ProcQid::Memory,
        _ => ProcQid::None,
    };
    (pid, ftype)
}

// ============================================================================
// Memory Reading
// ============================================================================

/// Read from process memory
pub fn proc_readmem(pid: i32, addr: *mut u8, buf: &mut [u8]) -> i32 {
    if let Some(proc) = unsafe { PROCFS_STATE.get_proc(pid) } {
        if proc.state == ProcState::Dead {
            return -1;
        }
        
        // TODO: actual memory reading with proper page table traversal
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr as u8);
        }
        
        buf.len() as i32
    } else {
        -1
    }
}

/// Write to process memory
pub fn proc_writemem(pid: i32, _addr: *mut u8, buf: &[u8]) -> i32 {
    if let Some(proc) = unsafe { PROCFS_STATE.get_proc(pid) } {
        if proc.state == ProcState::Dead {
            return -1;
        }
        
        // TODO: actual memory writing with proper page table traversal
        buf.len() as i32
    } else {
        -1
    }
}

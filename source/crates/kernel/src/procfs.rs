//! ProcFS - Process File System
//!
//! Implements the /proc filesystem following Plan 9's devproc.c
//! Reference: sys/src/9/port/devproc.c
//!
//! This is a standalone module that provides process management and
//! /proc-like functionality for the kernel.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// Constants (from devproc.c)
// ============================================================================

/// Maximum length of process arguments
pub const MAXARG: usize = 1024;

/// Maximum number of fds per process
pub const MAXFD: usize = 64;

/// Maximum number of processes
const MAXPROCS: usize = 4096;

/// Maximum thread name length
const MAXTHREADNAME: usize = 32;

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
    Start = 0,
    Stop = 1,
    Kill = 2,
    Detach = 3,
    Attach = 4,
    Hang = 5,
    Waitstop = 6,
    Waitidle = 7,
}

/// Process/Thread state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Dead = 0,
    Running = 1,
    Ready = 2,
    Sleeping = 3,
    Stopped = 4,
    Rendezvous = 5,
}

impl ProcState {
    pub fn as_str(&self) -> &'static str {
        match self {
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
    comm: [u8; 64],
    /// Memory base address
    pub mm_base: usize,
    /// Memory size
    pub mm_size: usize,
    /// Kernel stack base
    pub kstack_base: usize,
    /// Kernel stack size
    pub kstack_size: usize,
    /// Register state pointer
    pub regs: usize,
    /// Scheduling priority
    pub priority: i32,
    /// Number of threads
    pub nthread: AtomicU32,
    /// File descriptor count
    pub nfd: AtomicU32,
    /// Creation time
    pub ctime: u64,
    /// Start time
    pub start_time: u64,
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
            mm_base: 0,
            mm_size: 0,
            kstack_base: 0,
            kstack_size: 0,
            regs: 0,
            priority: 0,
            nthread: AtomicU32::new(1),
            nfd: AtomicU32::new(0),
            ctime: 0,
            start_time: 0,
        }
    }

    /// Set process command name
    pub fn set_comm(&mut self, name: &[u8]) {
        let len = name.len().min(63);
        self.comm[..len].copy_from_slice(&name[..len]);
        self.comm[len] = 0;
    }

    /// Get process command name as string
    pub fn comm(&self) -> &[u8] {
        let len = self.comm.iter().position(|&c| c == 0).unwrap_or(64);
        &self.comm[..len]
    }

    /// Check if process is alive
    pub fn is_alive(&self) -> bool {
        self.state != ProcState::Dead
    }
}

/// Thread Control Block
pub struct ProcThread {
    /// Thread ID
    pub tid: i32,
    /// Process ID
    pub pid: i32,
    /// Thread state
    pub state: ProcState,
    /// Stack pointer
    pub sp: usize,
    /// Program counter
    pub pc: usize,
    /// Stack base
    pub stack_base: usize,
    /// Stack size
    pub stack_size: usize,
}

impl ProcThread {
    /// Create a new thread
    pub fn new(tid: i32, pid: i32) -> Self {
        Self {
            tid,
            pid,
            state: ProcState::Dead,
            sp: 0,
            pc: 0,
            stack_base: 0,
            stack_size: 0,
        }
    }
}

// ============================================================================
// Process Table
// ============================================================================

/// Process table entry
struct ProcTableEntry {
    proc: Option<Proc>,
    in_use: bool,
}

/// Global process table
struct ProcessTable {
    entries: [ProcTableEntry; MAXPROCS],
    next_pid: AtomicI32,
    count: AtomicUsize,
}

impl ProcessTable {
    const fn new() -> Self {
        let entries = [(); MAXPROCS].map(|_| ProcTableEntry {
            proc: None,
            in_use: false,
        });
        Self {
            entries,
            next_pid: AtomicI32::new(1),
            count: AtomicUsize::new(0),
        }
    }

    /// Allocate a new PID
    fn alloc_pid(&self) -> i32 {
        self.next_pid.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a process to the table
    fn add(&self, proc: Proc) -> Option<i32> {
        for entry in &self.entries {
            if !entry.in_use {
                // Can't modify in const context, will be initialized at runtime
                break;
            }
        }
        None
    }

    /// Get process by PID
    fn get(&self, pid: i32) -> Option<&Proc> {
        for entry in &self.entries {
            if entry.in_use {
                if let Some(ref p) = &entry.proc {
                    if p.pid == pid {
                        return Some(p);
                    }
                }
            }
        }
        None
    }

    /// Remove process by PID
    fn remove(&self, pid: i32) -> bool {
        for entry in &self.entries {
            if entry.in_use {
                if let Some(ref p) = &entry.proc {
                    if p.pid == pid {
                        // Mark as not in use
                        return true;
                    }
                }
            }
        }
        false
    }
}

static PROCESS_TABLE: ProcessTable = ProcessTable::new();

// ============================================================================
// Public API
// ============================================================================

/// Create a new process
pub fn proc_create(pid: Option<i32>, _comm: &[u8]) -> Option<Proc> {
    let pid = pid.unwrap_or_else(|| PROCESS_TABLE.alloc_pid());
    let mut proc = Proc::new(pid);
    // proc.set_comm(comm);
    Some(proc)
}

/// Get process by PID
pub fn proc_get(pid: i32) -> Option<&'static Proc> {
    PROCESS_TABLE.get(pid)
}

/// Allocate a new PID
pub fn proc_alloc_pid() -> i32 {
    PROCESS_TABLE.alloc_pid()
}

/// Kill a process
pub fn proc_kill(pid: i32) -> i32 {
    if PROCESS_TABLE.get(pid).is_some() {
        0
    } else {
        -1
    }
}

/// Send a note (signal) to a process
pub fn proc_note(_pid: i32, _note: &[u8]) -> i32 {
    0
}

/// Get process state as string
pub fn proc_state_str(state: ProcState) -> &'static str {
    state.as_str()
}

/// Generate a QID for a proc file
pub fn proc_qid(pid: i32, ftype: ProcQid) -> u64 {
    let pid64 = pid as u64;
    let type64 = ftype as u64;
    (pid64 << 8) | type64
}

/// Parse a QID to get PID and type
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

/// Format process information as string
pub fn proc_format_info(proc: &Proc) -> [u8; 256] {
    let mut buf = [0u8; 256];
    // Format: "PID STATE PRI UID GID THREADS FDS CMD\n"
    // Simplified for no_std compatibility
    let mut offset = 0;
    
    // PID
    let pid_str = proc.pid.to_le_bytes();
    for &b in &pid_str {
        if b != 0 && offset < 255 {
            buf[offset] = b;
            offset += 1;
        }
    }
    buf[offset] = b' ';
    offset += 1;
    
    // State
    let state = proc.state.as_str();
    for &b in state.as_bytes() {
        if offset < 255 {
            buf[offset] = b;
            offset += 1;
        }
    }
    buf[offset] = b'\n';
    
    buf
}

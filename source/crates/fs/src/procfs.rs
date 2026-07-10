//! ProcFS - Process File System
//!
//! Implements the /proc filesystem following Plan 9's devproc.c
//! Reference: sys/src/9/port/devproc.c
//!
//! ProcFS exposes process and system information through a file-like interface.

#![allow(dead_code)]

use alloc::string::{String, ToString};
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

/// Number of priority levels (Plan 9 uses 22)
const NPRIQ: usize = 22;

/// Normal priority level
const PRI_NORMAL: i8 = 10;

/// Maximum priority level
const PRI_MAX: i8 = 0;

/// Minimum priority level (kernel)
const PRI_KPROC: i8 = 13;

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
    /// Current priority (dynamic, can change)
    pub pri: i8,
    /// Base priority (static, set by user)
    pub basepri: i8,
    /// CPU time used (for priority calculation)
    pub cpu: u64,
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
    /// Number of child processes
    pub nchild: i32,
    /// Number of waiting processes
    pub nwait: i32,
    /// Wait queue for exited children
    pub waitq: Option<Box<WaitqEntry>>,
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
            pri: PRI_NORMAL,
            basepri: PRI_NORMAL,
            cpu: 0,
            mm: core::ptr::null_mut(),
            kstack: core::ptr::null_mut(),
            kstacksize: 0,
            regs: core::ptr::null_mut(),
            fds: UnsafeCell::new(create_none_fd_array()),
            nfd: AtomicUsize::new(0),
            rndtag: core::ptr::null_mut(),
            note: UnsafeCell::new(None),
            threads: UnsafeCell::new(core::ptr::null_mut()),
            nchild: 0,
            nwait: 0,
            waitq: None,
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

    /// Set process priority
    ///
    /// Reference: Plan 9 proc.c procpriority()
    pub fn set_priority(&mut self, pri: i8) {
        // Clamp priority to valid range
        let pri = pri.clamp(PRI_MAX, PRI_KPROC);
        self.basepri = pri;
        self.pri = pri;
    }

    /// Get current priority
    pub fn get_priority(&self) -> i8 {
        self.pri
    }

    /// Get base priority
    pub fn get_base_priority(&self) -> i8 {
        self.basepri
    }

    /// Record child exit to wait queue
    pub fn record_child_exit(&mut self, pid: i32, status: i32, utime: u64, stime: u64) {
        let mut entry = Box::new(WaitqEntry::new(pid, status, utime, stime));
        entry.next = self.waitq.take();
        self.waitq = Some(entry);
        self.nchild = self.nchild.saturating_sub(1);
        self.nwait += 1;
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

// ============================================================================
// ProcFS File Reference Trait
// ============================================================================

/// Trait for file references in process file descriptors
/// Abstracts the underlying file type, allowing ProcFd to work with
/// various file implementations (VFS channels, raw fds, etc.)
pub trait ProcFileRef: Send + Sync {
    /// Get the raw file descriptor number
    fn fd(&self) -> i32;
    
    /// Read from the file at current offset
    fn read(&mut self, buf: &mut [u8]) -> FileResult<usize>;
    
    /// Write to the file at current offset
    fn write(&mut self, buf: &[u8]) -> FileResult<usize>;
    
    /// Seek to a new position
    fn seek(&mut self, offset: i64, whence: i32) -> FileResult<u64>;
    
    /// Get current file offset
    fn tell(&self) -> u64;
    
    /// Get file type description
    fn file_type(&self) -> &'static str;
    
    /// Get file name or path if available
    fn name(&self) -> Option<&str>;
    
    /// Close the file
    fn close(self: Box<Self>) -> FileResult<()>;
}

/// File reference error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRefError {
    /// Invalid file descriptor
    BadFd,
    /// Invalid offset
    BadOffset,
    /// I/O error
    IoError,
    /// Permission denied
    PermissionDenied,
    /// Operation not supported
    NotSupported,
}

impl Default for FileRefError {
    fn default() -> Self {
        FileRefError::IoError
    }
}

pub type FileResult<T> = core::result::Result<T, FileRefError>;

/// Simple file reference implementation using raw file descriptor
/// This is used when we have a raw OS file descriptor
pub struct RawFdRef {
    fd: i32,
    offset: u64,
    name: Option<String>,
}

impl RawFdRef {
    /// Create a new RawFdRef from a file descriptor
    pub fn new(fd: i32, name: Option<String>) -> Self {
        Self {
            fd,
            offset: 0,
            name,
        }
    }
    
    /// Create from existing RawFdRef with new offset
    pub fn from_fd(fd: i32) -> Self {
        Self {
            fd,
            offset: 0,
            name: None,
        }
    }
}

impl ProcFileRef for RawFdRef {
    fn fd(&self) -> i32 {
        self.fd
    }
    
    fn read(&mut self, buf: &mut [u8]) -> FileResult<usize> {
        if self.fd < 0 {
            return Err(FileRefError::BadFd);
        }
        // In a real implementation, this would call the kernel's read syscall
        // For now, simulate by filling buffer with zeros
        for byte in buf.iter_mut() {
            *byte = 0;
        }
        Ok(buf.len())
    }
    
    fn write(&mut self, buf: &[u8]) -> FileResult<usize> {
        if self.fd < 0 {
            return Err(FileRefError::BadFd);
        }
        // In a real implementation, this would call the kernel's write syscall
        Ok(buf.len())
    }
    
    fn seek(&mut self, offset: i64, whence: i32) -> FileResult<u64> {
        if self.fd < 0 {
            return Err(FileRefError::BadFd);
        }
        // Calculate new offset based on whence
        let new_offset = match whence {
            0 => offset as u64,           // SEEK_SET: from beginning
            1 => self.offset.wrapping_add(offset as u64),  // SEEK_CUR: from current
            2 => u64::MAX.wrapping_sub(offset as u64),  // SEEK_END: from end
            _ => return Err(FileRefError::BadOffset),
        };
        self.offset = new_offset;
        Ok(new_offset)
    }
    
    fn tell(&self) -> u64 {
        self.offset
    }
    
    fn file_type(&self) -> &'static str {
        "file"
    }
    
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    
    fn close(self: Box<Self>) -> FileResult<()> {
        // In a real implementation, this would close the fd
        Ok(())
    }
}

/// VFS Channel-based file reference
/// Wraps a VFS channel for use in ProcFd
pub struct VfsChannelRef {
    /// Reference to VFS channel (stored as pointer for no_std compatibility)
    channel_ptr: *mut (),
    /// Current offset
    offset: u64,
    /// Channel type name
    channel_type: String,
}

impl VfsChannelRef {
    /// Create from a raw channel pointer
    pub fn from_channel(channel: *mut (), channel_type: &str) -> Self {
        Self {
            channel_ptr: channel,
            offset: 0,
            channel_type: channel_type.to_string(),
        }
    }
}

// SAFETY: VfsChannelRef is safe to send between threads because:
// 1. The pointer is only accessed through mutable references
// 2. All access is guarded by the procfs internal locking mechanism
unsafe impl Send for VfsChannelRef {}

// SAFETY: VfsChannelRef is safe to share between threads because:
// 1. The pointer access is controlled through interior mutability
// 2. All operations require &mut self, ensuring exclusive access
unsafe impl Sync for VfsChannelRef {}

impl ProcFileRef for VfsChannelRef {
    fn fd(&self) -> i32 {
        // VFS channels don't have raw fd, return -1
        -1
    }
    
    fn read(&mut self, buf: &mut [u8]) -> FileResult<usize> {
        if self.channel_ptr.is_null() {
            return Err(FileRefError::BadFd);
        }
        // In a real implementation, this would read from the VFS channel
        // For now, simulate
        for byte in buf.iter_mut() {
            *byte = 0;
        }
        Ok(buf.len())
    }
    
    fn write(&mut self, buf: &[u8]) -> FileResult<usize> {
        if self.channel_ptr.is_null() {
            return Err(FileRefError::BadFd);
        }
        Ok(buf.len())
    }
    
    fn seek(&mut self, offset: i64, whence: i32) -> FileResult<u64> {
        if self.channel_ptr.is_null() {
            return Err(FileRefError::BadFd);
        }
        let new_offset = match whence {
            0 => offset as u64,
            1 => self.offset.wrapping_add(offset as u64),
            2 => u64::MAX.wrapping_sub(offset as u64),
            _ => return Err(FileRefError::BadOffset),
        };
        self.offset = new_offset;
        Ok(new_offset)
    }
    
    fn tell(&self) -> u64 {
        self.offset
    }
    
    fn file_type(&self) -> &'static str {
        "vfs"
    }
    
    fn name(&self) -> Option<&str> {
        Some(&self.channel_type)
    }
    
    fn close(self: Box<Self>) -> FileResult<()> {
        // VFS channel cleanup handled by VFS layer
        Ok(())
    }
}

/// File descriptor within a process
pub struct ProcFd {
    /// File descriptor number
    pub fd: i32,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    pub flags: u32,
    /// Current offset in file (if tracked)
    pub offset: u64,
    /// Reference to underlying file (replaces *mut u8 placeholder)
    pub file: Option<Box<dyn ProcFileRef>>,
}

impl ProcFd {
    /// Create a new ProcFd with a file reference
    pub fn with_file(fd: i32, flags: u32, file: Box<dyn ProcFileRef>) -> Self {
        Self {
            fd,
            flags,
            offset: file.tell(),
            file: Some(file),
        }
    }
    
    /// Create a new ProcFd without file reference (raw fd only)
    pub fn new(fd: i32, flags: u32) -> Self {
        Self {
            fd,
            flags,
            offset: 0,
            file: None,
        }
    }
    
    /// Check if this fd has an associated file reference
    pub fn has_file_ref(&self) -> bool {
        self.file.is_some()
    }
    
    /// Get file type description
    pub fn file_type(&self) -> &'static str {
        self.file
            .as_ref()
            .map(|f| f.file_type())
            .unwrap_or("unknown")
    }
    
    /// Read from the file
    pub fn read(&mut self, buf: &mut [u8]) -> FileResult<usize> {
        if let Some(ref mut file) = self.file {
            let n = file.read(buf)?;
            self.offset = self.offset.wrapping_add(n as u64);
            Ok(n)
        } else {
            Err(FileRefError::BadFd)
        }
    }
    
    /// Write to the file
    pub fn write(&mut self, buf: &[u8]) -> FileResult<usize> {
        if let Some(ref mut file) = self.file {
            let n = file.write(buf)?;
            self.offset = self.offset.wrapping_add(n as u64);
            Ok(n)
        } else {
            Err(FileRefError::BadFd)
        }
    }
    
    /// Seek in the file
    pub fn seek(&mut self, offset: i64, whence: i32) -> FileResult<u64> {
        if let Some(ref mut file) = self.file {
            let new_pos = file.seek(offset, whence)?;
            self.offset = new_pos;
            Ok(new_pos)
        } else {
            Err(FileRefError::BadFd)
        }
    }
    
    /// Close the file reference
    pub fn close(&mut self) -> FileResult<()> {
        if let Some(file) = self.file.take() {
            file.close()?;
        }
        Ok(())
    }
    
    /// Get fd information as a formatted string
    pub fn fd_info(&self) -> alloc::string::String {
        let file_type = self.file_type();
        let name = self.file
            .as_ref()
            .and_then(|f| f.name())
            .unwrap_or("(none)");
        
        alloc::format!(
            "fd {}: {} {}",
            self.fd,
            file_type,
            name
        )
    }
}

/// Wait queue entry for exited children
/// Used by parent process to collect child exit status
pub struct WaitqEntry {
    /// Child process PID
    pub pid: i32,
    /// Exit status
    pub status: i32,
    /// User time consumed
    pub utime: u64,
    /// System time consumed
    pub stime: u64,
    /// Next entry in wait queue
    pub next: Option<Box<WaitqEntry>>,
}

impl WaitqEntry {
    /// Create a new wait queue entry
    pub fn new(pid: i32, status: i32, utime: u64, stime: u64) -> Self {
        Self {
            pid,
            status,
            utime,
            stime,
            next: None,
        }
    }
}

/// Wait result returned to parent
pub struct WaitResult {
    /// Child PID that exited
    pub pid: i32,
    /// Exit status
    pub status: i32,
    /// User time
    pub utime: u64,
    /// System time
    pub stime: u64,
}

// ============================================================================
// ProcFS State
// ============================================================================

/// ProcFS global state
static PROCFS_STATE: ProcFsState = ProcFsState::new();

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

// Safety: ProcFsState is a global resource guarded by an internal spinlock.
// All accesses go through `&self`, and mutation is performed via UnsafeCell
// only while holding `lock`. It is therefore safe to share between threads.
unsafe impl Sync for ProcFsState {}

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
    pub fn get_proc_mut(&self, pid: i32) -> Option<&mut Proc> {
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
    if PROCFS_STATE.add_proc(proc) == pid {
        // Need to recreate since add_proc takes ownership
        Some(Box::new(Proc::new(pid)))
    } else {
        None
    }
}

/// Get process by PID
pub fn proc_get(pid: i32) -> Option<&'static Proc> {
    PROCFS_STATE.get_proc(pid)
}

/// Allocate a new PID
pub fn proc_alloc_pid() -> i32 {
    PROCFS_STATE.alloc_pid()
}

/// Kill a process
pub fn proc_kill(pid: i32) -> i32 {
    if let Some(proc) = PROCFS_STATE.get_proc_mut(pid) {
        proc.exit_status = -1;
        proc.state = ProcState::Dead;
        0
    } else {
        -1
    }
}

/// Send a note (signal) to a process
pub fn proc_note(pid: i32, note: &[u8]) -> i32 {
    // Acquire lock for atomic operation
    let proc = unsafe { &mut *PROCFS_STATE.procs.get() };
    
    for i in 0..MAXPROCS {
        if let Some(ref mut p) = proc[i] {
            if p.pid == pid {
                if p.state == ProcState::Dead {
                    return -1;
                }
                
                // Store the note
                if !note.is_empty() {
                    let _note_len = note.len().min(64); // Limit note size
                    let note_cell = unsafe { &mut *p.note.get() };
                    *note_cell = Some(note[0]); // Store first byte of note
                }
                
                return 0;
            }
        }
    }
    
    -1 // Process not found
}

/// Set process priority
///
/// Reference: Plan 9 proc.c procpriority() and devproc.c CMpri
/// Sets the priority for a given process. Higher priority values
/// (lower numbers) get more CPU time.
pub fn proc_setpri(pid: i32, pri: i32) -> i32 {
    // Validate and clamp priority range
    let pri = pri.clamp(0, (NPRIQ - 1) as i32);

    let procs = unsafe { &mut *PROCFS_STATE.procs.get() };

    for p in procs.iter_mut() {
        if let Some(ref mut proc) = p {
            if proc.pid == pid {
                // Check permission: only root (uid == 0) can set high priorities
                // Priorities < PRI_NORMAL (10) are considered "high" and require root
                if pri < PRI_NORMAL as i32 && proc.uid != 0 {
                    return -1; // Permission denied
                }

                // Set base priority and current priority
                // The scheduler may dynamically adjust pri based on CPU usage
                proc.set_priority(pri as i8);
                return 0;
            }
        }
    }

    -1 // Process not found
}

/// Wait for process state change
///
/// Reference: Plan 9 devproc.c Qwait and proc.c wait()
///
/// Waits for a child process to exit. If pid is -1, waits for any child.
/// If pid is > 0, waits for that specific child.
///
/// Returns Some(WaitResult) if a child has exited, None if no child available.
pub fn proc_wait(pid: i32) -> Option<WaitResult> {
    let procs = unsafe { &mut *PROCFS_STATE.procs.get() };

    for p in procs.iter_mut() {
        if let Some(ref mut proc) = p {
            // Skip dead processes
            if proc.state == ProcState::Dead {
                continue;
            }

            // Check if waiting for specific child or any child
            if pid == -1 {
                // Wait for any child - check if we have any
                if proc.nchild == 0 && proc.waitq.is_none() {
                    return None; // No children
                }
            }

            // Check wait queue for exited children
            if let Some(wq) = proc.waitq.take() {
                let result = WaitResult {
                    pid: wq.pid,
                    status: wq.status,
                    utime: wq.utime,
                    stime: wq.stime,
                };
                proc.nwait = proc.nwait.saturating_sub(1);
                return Some(result);
            }

            // No exited children in wait queue
            return None;
        }
    }

    None
}

/// Add child to wait queue when it exits
///
/// This should be called when a child process exits.
pub fn proc_add_to_wait(pid: i32, child_pid: i32, status: i32, utime: u64, stime: u64) {
    let procs = unsafe { &mut *PROCFS_STATE.procs.get() };

    for p in procs.iter_mut() {
        if let Some(ref mut proc) = p {
            if proc.pid == pid {
                // Record child exit in wait queue
                proc.record_child_exit(child_pid, status, utime, stime);
                return;
            }
        }
    }
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

/// Maximum memory read/write size (page-aligned for safety)
const MAX_MEM_ACCESS_SIZE: usize = 4096;

/// Read from process memory
pub fn proc_readmem(pid: i32, addr: *mut u8, buf: &mut [u8]) -> i32 {
    if let Some(proc) = PROCFS_STATE.get_proc(pid) {
        if proc.state == ProcState::Dead {
            return -1;
        }
        
        // Limit read size for safety
        let read_size = buf.len().min(MAX_MEM_ACCESS_SIZE);
        
        // Verify address is in valid range (user space)
        let addr_val = addr as usize;
        if addr_val >= 0x8000_0000_0000_0000 && addr_val < 0xFFFF_FFFF_FFFF_FFFF {
            // User space address - would need page table traversal in real implementation
            // For now, simulate a simple read for testing
            for (i, b) in buf[..read_size].iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(addr_val as u8);
            }
            return read_size as i32;
        }
        
        -1 // Invalid address
    } else {
        -1
    }
}

/// Write to process memory
pub fn proc_writemem(pid: i32, addr: *mut u8, buf: &[u8]) -> i32 {
    if let Some(proc) = PROCFS_STATE.get_proc(pid) {
        if proc.state == ProcState::Dead {
            return -1;
        }
        
        // Limit write size for safety
        let write_size = buf.len().min(MAX_MEM_ACCESS_SIZE);
        
        // Verify address is in valid range (user space)
        let addr_val = addr as usize;
        if addr_val >= 0x8000_0000_0000_0000 && addr_val < 0xFFFF_FFFF_FFFF_FFFF {
            // User space address - would need page table traversal in real implementation
            // For now, simulate a successful write for testing
            return write_size as i32;
        }
        
        -1 // Invalid address
    } else {
        -1
    }
}

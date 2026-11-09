//! ProcFS - Process File System
//!
//! Implements the /proc filesystem following Plan 9's devproc.c
//! Reference: sys/src/9/port/devproc.c
//!
//! This is a standalone module that provides process management and
//! /proc-like functionality for the kernel.

#![allow(dead_code)]

// use core::cell::UnsafeCell;
use core::sync::atomic::{ AtomicI32, AtomicU32, AtomicUsize, Ordering };use crate::dev::{Chan, Qid, DirEntry, Error as DevError, devtype, qidtype, Dev};

use alloc::boxed::Box;
// use alloc::vec::Vec;
// use alloc::string::String;

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

impl Clone for ProcTableEntry {
    fn clone(&self) -> Self {
        // Don't clone proc - for procfs we just reference the same data
        Self {
            proc: None, // Skip actual proc cloning for procfs
            in_use: self.in_use,
        }
    }
}

/// Global process table
struct ProcessTable {
    entries: [ProcTableEntry; MAXPROCS],
    next_pid: AtomicI32,
    count: AtomicUsize,
}

impl ProcessTable {
    const fn new() -> Self {
        let entries = {
            let mut arr: [ProcTableEntry; MAXPROCS] = unsafe {
                core::mem::zeroed()
            };
            let mut i = 0;
            while i < MAXPROCS {
                arr[i] = ProcTableEntry {
                    proc: None,
                    in_use: false,
                };
                i += 1;
            }
            arr
        };
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
    fn add(&self, _proc: Proc) -> Option<i32> {
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
    let proc = Proc::new(pid);
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

// ============================================================================
// ProcFS Device Implementation
// ============================================================================

/// ProcFS device state
pub struct ProcFsDev {
    /// Device character
    dev_char: char,
    /// Device name
    name: &'static str,
}

impl ProcFsDev {
    /// Create new ProcFS device
    pub fn new() -> Self {
        Self {
            dev_char: 'p',
            name: "proc",
        }
    }
    
    /// Get PID from channel
    fn get_pid(ch: &Chan) -> Option<i32> {
        let path = ch.qid.path;
        if path == 0 {
            None // Root directory
        } else {
            Some((path >> 8) as i32)
        }
    }
    
    /// Get file type from channel
    fn get_ftype(ch: &Chan) -> ProcQid {
        let path = ch.qid.path;
        if path == 0 {
            ProcQid::None // Root or top directory
        } else {
            let ftype = (path & 0xFF) as u8;
            match ftype {
                1 => ProcQid::Ctl,
                2 => ProcQid::Note,
                3 => ProcQid::Noteid,
                4 => ProcQid::Status,
                5 => ProcQid::Fd,
                6 => ProcQid::FdDir,
                7 => ProcQid::Memory,
                8 => ProcQid::Profile,
                9 => ProcQid::Regs,
                10 => ProcQid::Fpregs,
                _ => ProcQid::None,
            }
        }
    }
}

impl Dev for ProcFsDev {
    /// Attach to proc filesystem
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        // Return root channel
        Ok(Chan::new(devtype::PROC, Qid::new(0, 0, qidtype::DIR), 0))
    }
    
    /// Walk in proc filesystem
    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
//         use alloc::string::ToString;
        
        if name.is_empty() || name == "." {
            return Ok(Some(ch.qid));
        }
        
        if name == ".." {
            // Return parent (root)
            return Ok(Some(Qid::new(0, 0, qidtype::DIR)));
        }
        
        // Directory level decides what names are legal: the root holds
        // PID directories, a PID directory holds that process's files.
        // NOTE: namec() discards the returned Qid, so the channel must be
        // updated in place (the convention used by the other devices).
        if ch.qid.path == 0 {
            // Root: only a PID directory name is accepted.
            if let Ok(pid) = name.parse::<i32>() {
                if Self::real_proc(pid).is_some() {
                    ch.qid = Qid::new(proc_qid(pid, ProcQid::None), 0, qidtype::DIR);
                    return Ok(Some(ch.qid));
                }
            }
            return Err(DevError::Enoent);
        }

        // Inside a PID directory: accept that process's file names.
        let pid = (ch.qid.path >> 8) as i32;
        if Self::real_proc(pid).is_none() {
            return Err(DevError::Enoent);
        }
        let ftype = match name {
            "ctl" => ProcQid::Ctl,
            "status" => ProcQid::Status,
            "note" => ProcQid::Note,
            "mem" => ProcQid::Memory,
            "regs" => ProcQid::Regs,
            "fpregs" => ProcQid::Fpregs,
            "fd" => ProcQid::FdDir,
            "wait" => ProcQid::Wait,
            _ => return Err(DevError::Enoent),
        };
        ch.qid = Qid::new(proc_qid(pid, ftype), 0, qidtype::FILE);
        Ok(Some(ch.qid))
    }
    
    /// Open a proc file
    fn open(&mut self, ch: &mut Chan, _mode: u8) -> Result<(), DevError> {
        // Just verify the file exists
        if ch.qid.path == 0 {
            // Root directory - always ok
            return Ok(());
        }
        
        let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
        if Self::real_proc(pid).is_none() {
            return Err(DevError::Enoent);
        }

        Ok(())
    }
    
    /// Read from proc file
    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        // Root directory listing
        if ch.qid.path == 0 {
            return Self::read_dir(ch, buf, offset);
        }
        
        let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
        let ftype = Self::get_ftype(ch);
        
        match ftype {
            ProcQid::None => {
                // Process directory - list files
                Self::read_proc_dir(pid, buf, offset)
            }
            ProcQid::Status => {
                // Process status
                Self::read_status(pid, buf, offset)
            }
            ProcQid::Ctl => {
                // Control file (write-only usually)
                Err(DevError::Eperm)
            }
            ProcQid::Note => {
                // Notes (signals)
                Err(DevError::Eperm)
            }
            ProcQid::Memory => {
                // Process memory segment map
                Self::read_memory(pid, buf, offset)
            }
            ProcQid::Regs => {
                // Registers
                Err(DevError::Eperm)
            }
            _ => Err(DevError::Enoent),
        }
    }
    
    /// Write to proc file
    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
        let ftype = Self::get_ftype(ch);
        
        match ftype {
            ProcQid::Ctl => {
                // Process control commands
                Self::write_ctl(pid, buf)
            }
            ProcQid::Note => {
                // Send note (signal) to process
                Self::write_note(pid, buf)
            }
            _ => Err(DevError::Eperm),
        }
    }
    
    /// Get file status
    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let name = if ch.qid.path == 0 {
            "proc"
        } else if let Some(pid) = Self::get_pid(ch) {
            let ftype = Self::get_ftype(ch);
            match ftype {
                ProcQid::None => {
                    // Process directory - return PID as name
                    return Ok(DirEntry {
                        dev: devtype::PROC,
                        qid: ch.qid,
                        mode: 0o0555 | (qidtype::DIR as u32),
                        atime: 0,
                        mtime: 0,
                        length: 0,
                        name: alloc::format!("{}", pid).into_bytes(),
                    });
                }
                ProcQid::Status => "status",
                ProcQid::Ctl => "ctl",
                ProcQid::Note => "note",
                ProcQid::Memory => "mem",
                ProcQid::Regs => "regs",
                _ => return Err(DevError::Enoent),
            }
        } else {
            return Err(DevError::Enoent);
        };
        
        let mode = if matches!(Self::get_ftype(ch), ProcQid::None) {
            0o0555 | (qidtype::DIR as u32)
        } else {
            0o0666
        };
        
        Ok(DirEntry {
            dev: devtype::PROC,
            qid: ch.qid,
            mode,
            atime: 0,
            mtime: 0,
            length: 0,
            name: name.as_bytes().to_vec(),
        })
    }
    
    fn dev_char(&self) -> char { self.dev_char }
    fn name(&self) -> &'static str { self.name }
}

// ProcFS device helper functions
impl ProcFsDev {
    /// Find a process in the scheduler's real process table.
    fn real_proc(pid: i32) -> Option<&'static crate::proc::Proc> {
        let target = pid as crate::proc::Pid;
        crate::proc::proctable()
            .iter()
            .find(|p| p.pid == target)
    }

    /// Human-readable state name from the scheduler State enum.
    fn state_str(state: crate::proc::State) -> &'static str {
        match state {
            crate::proc::State::Dead => "Dead",
            crate::proc::State::Moribund => "Moribund",
            crate::proc::State::Ready => "Ready",
            crate::proc::State::Running => "Run",
            crate::proc::State::Scheding => "Scheding",
            crate::proc::State::Wakeme => "Wakeme",
            crate::proc::State::Rendez => "Rendez",
            crate::proc::State::Wait => "Wait",
            crate::proc::State::Broken => "Broken",
            crate::proc::State::Stopped => "Stop",
        }
    }

    /// Read directory listing
    fn read_dir(_ch: &Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let mut total = 0;
        let mut index = 0usize;
        
        // Skip entries based on offset
        if offset > 0 {
            index = offset as usize;
        }
        
        // List processes from the scheduler's real process table.
        for proc in crate::proc::proctable().iter() {
            if index > 0 {
                index -= 1;
                continue;
            }

            let entry_str = alloc::format!("{}\n", proc.pid);
            let entry_bytes = entry_str.as_bytes();

            if total + entry_bytes.len() > buf.len() {
                break;
            }

            buf[total..total + entry_bytes.len()].copy_from_slice(entry_bytes);
            total += entry_bytes.len();
        }
        
        Ok(total)
    }
    
    /// Read process directory (list files in /proc/<pid>/)
    fn read_proc_dir(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let files = ["ctl", "status", "note", "mem", "regs", "fpregs"];
        
        let mut total = 0;
        let mut index = (offset / 64) as usize;
        let entry_size = 64;
        
        // Skip entries based on offset
        if offset > 0 {
            index = offset as usize;
        }
        
        while index < files.len() && total + entry_size <= buf.len() {
            let name = files[index];
            let ftype = match name {
                "ctl" => ProcQid::Ctl as u8,
                "status" => ProcQid::Status as u8,
                "note" => ProcQid::Note as u8,
                "mem" => ProcQid::Memory as u8,
                "regs" => ProcQid::Regs as u8,
                "fpregs" => ProcQid::Fpregs as u8,
                _ => 0,
            };
            
            let path = proc_qid(pid, ProcQid::None) | (ftype as u64);
            let _qid = Qid::new(path, 0, qidtype::FILE);
            
            // Format directory entry (simplified Stat format)
            let entry_str = alloc::format!(
                "{}          1 root root 0 {} M {} 0 0\n",
                name,
                0,
                path
            );
            
            let entry_bytes = entry_str.as_bytes();
            let copy_len = entry_bytes.len().min(entry_size);
            buf[total..total + copy_len].copy_from_slice(&entry_bytes[..copy_len]);
            total += entry_size;
            index += 1;
        }
        
        Ok(total)
    }
    
    /// Read process status
    fn read_status(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;

        // Sum the resident bytes across the process segments.
        let mut mem_bytes = 0usize;
        let mut seg_count = 0usize;
        for seg in proc.seg.iter() {
            if let Some(s) = seg {
                if s.segtype != crate::proc::SegType::None {
                    mem_bytes += s.size();
                    seg_count += 1;
                }
            }
        }

        let status_str = alloc::format!(
            "PID\t{}\nState\t{}\nSegments\t{}\nMemBytes\t{}\n",
            proc.pid,
            Self::state_str(proc.state),
            seg_count,
            mem_bytes
        );

        // Stream with offset so repeated reads walk the file instead of
        // re-printing the first window (see read_memory).
        let bytes = status_str.as_bytes();
        let off = offset as usize;
        if off >= bytes.len() {
            return Ok(0);
        }
        let end = (off + buf.len()).min(bytes.len());
        buf[..end - off].copy_from_slice(&bytes[off..end]);
        Ok(end - off)
    }

    /// Read `/proc/N/mem`: dump the process segment map.
    fn read_memory(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;

        let mut text = alloc::string::String::new();
        text.push_str("Segment\tType\tBase\tTop\tSize\n");
        for (i, seg) in proc.seg.iter().enumerate() {
            if let Some(s) = seg {
                if s.segtype == crate::proc::SegType::None {
                    continue;
                }
                let name = match s.segtype {
                    crate::proc::SegType::Text => "text",
                    crate::proc::SegType::Data => "data",
                    crate::proc::SegType::Bss => "bss",
                    crate::proc::SegType::Stack => "stack",
                    crate::proc::SegType::Shared => "shared",
                    crate::proc::SegType::Physical => "phys",
                    crate::proc::SegType::None => continue,
                };
                text.push_str(&alloc::format!(
                    "{}\t{}\t{:#x}\t{:#x}\t{}\n",
                    i,
                    name,
                    s.base,
                    s.top,
                    s.size()
                ));
            }
        }

        // Stream: the caller's channel offset advances by the number of
        // bytes returned, so serve the window [offset, offset+buf.len())
        // of the pre-built text and report EOF with a zero-length read.
        let bytes = text.as_bytes();
        let off = offset as usize;
        if off >= bytes.len() {
            return Ok(0);
        }
        let end = (off + buf.len()).min(bytes.len());
        buf[..end - off].copy_from_slice(&bytes[off..end]);
        Ok(end - off)
    }
    
    /// Write to control file
    fn write_ctl(pid: i32, buf: &[u8]) -> Result<usize, DevError> {
        // Parse control command
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| DevError::Einval)?;
        
        let cmd = cmd.trim();
        
        match cmd {
            "kill" => {
                // Kill the process
                if PROCESS_TABLE.remove(pid) {
                    Ok(buf.len())
                } else {
                    Err(DevError::Enoent)
                }
            }
            "stop" => {
                // Stop the process
                Ok(buf.len())
            }
            "start" => {
                // Start/resume the process
                Ok(buf.len())
            }
            _ => Err(DevError::Einval),
        }
    }
    
    /// Write note (signal) to process
    fn write_note(_pid: i32, buf: &[u8]) -> Result<usize, DevError> {
        // Notes are Plan 9's equivalent of signals
        // For now, just acknowledge
        let _note = core::str::from_utf8(buf)
            .map_err(|_| DevError::Einval)?;
        
        Ok(buf.len())
    }
}

// ============================================================================
// Global ProcFS Device Instance
// ============================================================================

use core::sync::atomic::AtomicPtr;

static PROCFS_DEVICE: AtomicPtr<ProcFsDev> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the ProcFS device
pub fn init() {
    let dev = Box::new(ProcFsDev::new());
    let ptr = Box::into_raw(dev);
    PROCFS_DEVICE.store(ptr, Ordering::SeqCst);
}

/// Get the ProcFS device
pub fn procfs_device() -> &'static mut ProcFsDev {
    unsafe { &mut *PROCFS_DEVICE.load(Ordering::SeqCst) }
}

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

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use crate::plan9_common::sync::Spinlock;
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
    Notepg = 16,
    Segment = 17,
    Text = 18,
}

const PROC_FILES: &[(&str, ProcQid, u32)] = &[
    ("args", ProcQid::Args, 0o444),
    ("ctl", ProcQid::Ctl, 0o200),
    ("mem", ProcQid::Memory, 0o600),
    ("note", ProcQid::Note, 0o600),
    ("noteid", ProcQid::Noteid, 0o664),
    ("notepg", ProcQid::Notepg, 0o200),
    ("profile", ProcQid::Profile, 0o400),
    ("regs", ProcQid::Regs, 0o600),
    ("segment", ProcQid::Segment, 0o444),
    ("status", ProcQid::Status, 0o444),
    ("text", ProcQid::Text, 0o400),
    ("wait", ProcQid::Wait, 0o400),
];

const TRACE_PATH: u64 = u64::MAX;
const TRACE_CAPACITY: usize = 0x4000;
const TRACE_RECORD_SIZE: usize = 16;
static TRACE: Spinlock<Option<TraceQueue>> = Spinlock::new(None);

pub(crate) fn is_memory_channel(channel: &Chan) -> bool {
    crate::dev::devs().find_by_char('p') == Some(channel.dev)
        && ProcFsDev::get_ftype(channel) == ProcQid::Memory
}

pub(crate) fn wait_target(channel: &Chan) -> Option<crate::proc::Pid> {
    (crate::dev::devs().find_by_char('p') == Some(channel.dev)
        && ProcFsDev::get_ftype(channel) == ProcQid::Wait)
        .then_some((channel.qid.path >> 8) as crate::proc::Pid)
}

pub(crate) fn open_exec_image(channel: &Chan, mode: u32) -> Option<Result<Chan, DevError>> {
    if crate::dev::devs().find_by_char('p') != Some(channel.dev)
        || ProcFsDev::get_ftype(channel) != ProcQid::Text
    {
        return None;
    }
    Some((|| {
        let pid = ProcFsDev::get_pid(channel).ok_or(DevError::Enoent)?;
        let target = ProcFsDev::real_proc(pid).ok_or(DevError::Enoent)?;
        ProcFsDev::check_owner(target)?;
        if mode != 0 || target.private_memory {
            return Err(DevError::Eperm);
        }
        target.exec_image.as_ref().map(Chan::dup).ok_or(DevError::Enoent)
    })())
}

struct TraceQueue {
    records: VecDeque<[u8; TRACE_RECORD_SIZE]>,
    epoch_ns: u64,
}

pub(crate) enum TraceEvent {
    Run = 3,
    Ready = 4,
    Sleep = 5,
    Slice = 7,
    Dead = 10,
    User = 13,
}

struct TraceReader;

impl Drop for TraceReader {
    fn drop(&mut self) {
        let queue = TRACE.lock().take();
        drop(queue);
    }
}

pub(crate) fn record_trace(proc: &crate::proc::Proc, event: TraceEvent) {
    if !proc.trace_enabled {
        return;
    }
    if let Some(queue) = TRACE.lock().as_mut() {
        if queue.records.len() < TRACE_CAPACITY {
            let mut record = [0; TRACE_RECORD_SIZE];
            record[..4].copy_from_slice(&proc.pid.to_ne_bytes());
            record[4..8].copy_from_slice(&(event as u32).to_ne_bytes());
            let uptime_ns = plan9_arch::hal::timer::ms_since_boot().saturating_mul(1_000_000);
            let timestamp = queue.epoch_ns.saturating_add(uptime_ns);
            record[8..].copy_from_slice(&timestamp.to_ne_bytes());
            queue.records.push_back(record);
        }
    }
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
        17 => ProcQid::Segment,
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
                14 => ProcQid::Wait,
                15 => ProcQid::Args,
                16 => ProcQid::Notepg,
                17 => ProcQid::Segment,
                18 => ProcQid::Text,
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
            ch.qid = Qid::new(0, 0, qidtype::DIR);
            return Ok(Some(ch.qid));
        }
        
        // Directory level decides what names are legal: the root holds
        // PID directories, a PID directory holds that process's files.
        // NOTE: namec() discards the returned Qid, so the channel must be
        // updated in place (the convention used by the other devices).
        if ch.qid.path == 0 {
            if name == "trace" {
                ch.qid = Qid::new(TRACE_PATH, 0, qidtype::FILE);
                return Ok(Some(ch.qid));
            }
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
        let ftype = PROC_FILES.iter().find(|entry| entry.0 == name)
            .map(|entry| entry.1).ok_or(DevError::Enoent)?;
        ch.qid = Qid::new(proc_qid(pid, ftype), 0, qidtype::FILE);
        Ok(Some(ch.qid))
    }
    
    /// Open a proc file
    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        if ch.qid.path == 0 {
            return if mode & 3 == 0 { Ok(()) } else { Err(DevError::Eperm) };
        }
        if ch.qid.path == TRACE_PATH {
            if mode != 0 {
                return Err(DevError::Eperm);
            }
            let mut trace = TRACE.lock();
            if trace.is_some() {
                return Err(DevError::Eexists);
            }
            let mut records = VecDeque::new();
            records.try_reserve_exact(TRACE_CAPACITY).map_err(|_| DevError::Enomem)?;
            let epoch_ns = crate::rtc::now_unix()
                .and_then(|seconds| u64::try_from(seconds).ok())
                .map_or(0, |seconds| {
                    let uptime = plan9_arch::hal::timer::ms_since_boot() / 1000;
                    seconds.saturating_sub(uptime).saturating_mul(1_000_000_000)
                });
            *trace = Some(TraceQueue { records, epoch_ns });
            ch.aux = Some(Arc::new(TraceReader));
            return Ok(());
        }
        let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
        let target = Self::real_proc(pid).ok_or(DevError::Enoent)?;
        let ftype = Self::get_ftype(ch);
        if matches!(ftype, ProcQid::Ctl | ProcQid::Note | ProcQid::Notepg | ProcQid::Noteid) {
            Self::check_owner(target)?;
        }
        if target.private_memory && matches!(ftype, ProcQid::Ctl | ProcQid::Note | ProcQid::Memory | ProcQid::Regs) {
            return Err(DevError::Eperm);
        }
        if matches!(ftype, ProcQid::Memory | ProcQid::Profile | ProcQid::Wait | ProcQid::Regs) {
            Self::check_owner(target)?;
        }
        match (ftype, mode & 3) {
            (ProcQid::Notepg, 1) if target.note_group != 1 => {
                ch.aux = Some(alloc::sync::Arc::new(target.note_group));
                Ok(())
            }
            (ProcQid::Ctl, 1) | (ProcQid::Note | ProcQid::Noteid | ProcQid::Memory | ProcQid::Regs, 0..=2) => Ok(()),
            (ProcQid::None | ProcQid::Status | ProcQid::Profile | ProcQid::Segment | ProcQid::Args | ProcQid::Wait, 0) => Ok(()),
            _ => Err(DevError::Eperm),
        }
    }
    
    /// Read from proc file
    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        // Root directory listing
        if ch.qid.path == 0 {
            return Self::read_dir(ch, buf, offset);
        }
        if ch.qid.path == TRACE_PATH {
            ch.aux.as_ref().filter(|token| token.is::<TraceReader>()).ok_or(DevError::Eperm)?;
            let mut trace = TRACE.lock();
            let records = &mut trace.as_mut().ok_or(DevError::Eio)?.records;
            let count = (buf.len() / TRACE_RECORD_SIZE).min(records.len());
            for chunk in buf.chunks_exact_mut(TRACE_RECORD_SIZE).take(count) {
                chunk.copy_from_slice(&records.pop_front().unwrap());
            }
            return Ok(count * TRACE_RECORD_SIZE);
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
                let proc = Self::writable_proc(pid)?;
                if proc.private_memory {
                    return Err(DevError::Eperm);
                }
                if buf.is_empty() {
                    return Err(DevError::Einval);
                }
                let Some(note) = proc.pop_signal() else { return Ok(0) };
                let count = note.msg.iter().position(|byte| *byte == 0)
                    .unwrap_or(note.msg.len()).min(buf.len() - 1);
                buf[..count].copy_from_slice(&note.msg[..count]);
                buf[count] = 0;
                Ok(count + 1)
            }
            ProcQid::Noteid => {
                let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
                Self::check_owner(proc)?;
                let value = alloc::format!("{}\n", proc.note_group);
                let remaining = value.as_bytes().get(offset as usize..).unwrap_or_default();
                let count = remaining.len().min(buf.len());
                buf[..count].copy_from_slice(&remaining[..count]);
                Ok(count)
            }
            ProcQid::Memory => Self::read_memory(pid, buf, offset),
            ProcQid::Segment => Self::read_segments(pid, buf, offset),
            ProcQid::Args => {
                let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
                Ok(crate::dev::read_bytes(&proc.exec_args, buf, offset))
            }
            ProcQid::Profile => {
                let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
                let profile = Self::profile(proc).ok_or(DevError::Einval)?;
                Ok(profile.read(buf, offset))
            }
            ProcQid::Regs => Self::read_registers(pid, buf, offset),
            _ => Err(DevError::Enoent),
        }
    }
    
    /// Write to proc file
    fn write(&mut self, ch: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
        let ftype = Self::get_ftype(ch);
        
        match ftype {
            ProcQid::Ctl => {
                // Process control commands
                Self::write_ctl(pid, buf)
            }
            ProcQid::Note => {
                let proc = Self::writable_proc(pid)?;
                if proc.private_memory {
                    return Err(DevError::Eperm);
                }
                proc.postnote(0, Self::note_message(buf)?).map_err(|_| DevError::Eio)?;
                Ok(buf.len())
            }
            ProcQid::Noteid => Self::write_noteid(pid, buf),
            ProcQid::Memory => Self::write_memory(pid, buf, offset),
            ProcQid::Regs => Self::write_registers(pid, buf, offset),
            ProcQid::Notepg => {
                let group = ch.aux.as_deref().and_then(|aux| aux.downcast_ref::<crate::proc::Pid>())
                    .ok_or(DevError::Eperm)?;
                Self::write_note_group(*group, buf)
            }
            _ => Err(DevError::Eperm),
        }
    }
    
    /// Get file status
    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let (name, mode, length) = if ch.qid.path == 0 {
            (b"proc".to_vec(), 0x8000_0000 | 0o555, 0)
        } else if ch.qid.path == TRACE_PATH {
            (b"trace".to_vec(), 0o444, 0)
        } else {
            let pid = Self::get_pid(ch).ok_or(DevError::Enoent)?;
            let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
            let ftype = Self::get_ftype(ch);
            if ftype == ProcQid::None {
                (alloc::format!("{pid}").into_bytes(), 0x8000_0000 | 0o555, 0)
            } else {
                let &(name, _, mode) = PROC_FILES.iter().find(|entry| entry.1 == ftype)
                    .ok_or(DevError::Enoent)?;
                let length = match ftype {
                    ProcQid::Profile => Self::profile(proc).map_or(0, |profile| profile.byte_len() as u64),
                    ProcQid::Args => proc.exec_args.len() as u64,
                    ProcQid::Status => 176,
                    ProcQid::Regs => Self::register_size() as u64,
                    ProcQid::Wait => {
                        let mut count = 0;
                        let mut entry = proc.waitq.as_deref();
                        while let Some(record) = entry {
                            count += 1;
                            entry = record.next.as_deref();
                        }
                        count
                    }
                    _ => 0,
                };
                (name.as_bytes().to_vec(), mode, length)
            }
        };
        
        Ok(DirEntry {
            dev: devtype::PROC,
            qid: ch.qid,
            mode,
            atime: 0,
            mtime: 0,
            length,
            name,
            uid: 0,
            gid: 0,
})
    }
    
    fn dev_char(&self) -> char { self.dev_char }
    fn name(&self) -> &'static str { self.name }
}

// ProcFS device helper functions
impl ProcFsDev {
    fn profile(proc: &crate::proc::Proc) -> Option<&crate::proc::ProfileData> {
        proc.seg.iter().flatten().find(|segment| segment.segtype == crate::proc::SegType::Text)?.profile.as_ref()
    }

    fn visible(proc: &crate::proc::Proc) -> bool {
        proc.pid > 0 && !matches!(proc.state, crate::proc::State::Dead | crate::proc::State::Moribund)
    }

    /// Find a process in the scheduler's real process table.
    fn real_proc(pid: i32) -> Option<&'static crate::proc::Proc> {
        let target = pid as crate::proc::Pid;
        crate::proc::proctable()
            .iter()
            .find(|proc| proc.pid == target && Self::visible(proc))
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
        use core::fmt::Write;

        let mut pids: alloc::vec::Vec<_> = crate::proc::proctable().iter()
            .filter(|proc| Self::visible(proc)).map(|proc| proc.pid).collect();
        pids.sort_unstable();
        let mut text = alloc::string::String::from("trace\n");
        for pid in pids {
            let _ = writeln!(text, "{pid}");
        }
        Ok(crate::dev::read_bytes(text.as_bytes(), buf, offset))
    }
    
    /// Read process directory (list files in /proc/<pid>/)
    fn read_proc_dir(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        Self::real_proc(pid).ok_or(DevError::Enoent)?;
        let mut text = alloc::string::String::new();
        for (name, _, _) in PROC_FILES {
            text.push_str(name);
            text.push('\n');
        }
        Ok(crate::dev::read_bytes(text.as_bytes(), buf, offset))
    }
    
    /// Read process status
    fn read_status(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
        let mem_kib = proc.seg.iter().flatten()
            .filter(|segment| !matches!(segment.segtype, crate::proc::SegType::None | crate::proc::SegType::Stack))
            .map(|segment| segment.size() as u64).sum::<u64>() / 1024;
        let elapsed = plan9_arch::hal::timer::ms_since_boot().saturating_sub(proc.wtime);
        let mut record = [b' '; 176];
        Self::status_name(&proc.text, &mut record[..27]);
        Self::status_name(&proc.uname, &mut record[28..55]);
        Self::status_name(Self::state_str(proc.state).as_bytes(), &mut record[56..67]);
        let values = [proc.utime, proc.ktime, elapsed, proc.ctime, proc.child_system_time, 0,
            mem_kib, proc.basepri.max(0) as u64, proc.pri.max(0) as u64];
        for (value, field) in values.into_iter().zip(record[68..].chunks_exact_mut(12)) {
            let digits = alloc::format!("{value:>11}");
            field[..11].copy_from_slice(&digits.as_bytes()[..11]);
        }
        Ok(crate::dev::read_bytes(&record, buf, offset))
    }

    fn status_name(text: &[u8], field: &mut [u8]) {
        let text = text.split(|byte| *byte == 0).next().unwrap_or_default();
        let text = core::str::from_utf8(text).unwrap_or("?");
        let mut length = text.len().min(field.len());
        while !text.is_char_boundary(length) {
            length -= 1;
        }
        field[..length].copy_from_slice(&text.as_bytes()[..length]);
    }

    fn read_memory(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
        Self::check_owner(proc)?;
        if proc.private_memory {
            return Err(DevError::Eperm);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let segment = proc.find_segment(offset).ok_or(DevError::Einval)?;
        let count = Self::memory_window(buf.len(), offset, segment.top);
        let mut page = [0; crate::segment::PAGE_SIZE as usize];
        crate::syscall::get_user_bytes(proc, offset, &mut page[..count]).map_err(|_| DevError::Eio)?;
        buf[..count].copy_from_slice(&page[..count]);
        Ok(count)
    }

    fn write_memory(pid: i32, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        use crate::proc::{SegType, State};

        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
        Self::check_owner(proc)?;
        if proc.private_memory || proc.state != State::Stopped {
            return Err(DevError::Eperm);
        }
        let segment = proc.find_segment(offset).ok_or(DevError::Einval)?;
        if !matches!(segment.segtype, SegType::Data | SegType::Bss | SegType::Stack) {
            return Err(DevError::Eperm);
        }
        let count = Self::memory_window(buf.len(), offset, segment.top);
        let mut page = [0; crate::segment::PAGE_SIZE as usize];
        page[..count].copy_from_slice(&buf[..count]);
        crate::syscall::put_user_bytes(proc, offset, &page[..count]).map_err(|_| DevError::Eio)?;
        Ok(count)
    }

    fn memory_window(count: usize, offset: u64, top: u64) -> usize {
        let page_size = crate::segment::PAGE_SIZE as usize;
        count.min((top - offset) as usize).min(page_size - offset as usize % page_size)
    }

    fn register_size() -> usize {
        use crate::proc::SavedUserFrame;

        #[cfg(target_arch = "aarch64")]
        { core::mem::offset_of!(SavedUserFrame, simd) }
        #[cfg(not(target_arch = "aarch64"))]
        { core::mem::size_of::<SavedUserFrame>() }
    }

    fn read_registers(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let proc = Self::real_proc(pid).ok_or(DevError::Enoent)?;
        Self::check_owner(proc)?;
        if proc.private_memory {
            return Err(DevError::Eperm);
        }
        let frame = proc.user_frame.as_ref().ok_or(DevError::Einval)?;
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(frame).cast(), Self::register_size())
        };
        Ok(crate::dev::read_bytes(bytes, buf, offset))
    }

    fn write_registers(pid: i32, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        use crate::proc::{SegType, State};

        let proc = Self::writable_proc(pid)?;
        if proc.private_memory || proc.state != State::Stopped {
            return Err(DevError::Eperm);
        }
        let original = proc.user_frame.ok_or(DevError::Einval)?;
        if offset >= Self::register_size() as u64 {
            return Ok(0);
        }
        let offset = offset as usize;
        let count = buf.len().min(Self::register_size() - offset);
        let mut frame = original;
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut frame).cast(), Self::register_size())
        };
        bytes[offset..offset + count].copy_from_slice(&buf[..count]);
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        if frame.x[2] != original.x[2] {
            frame.set_stack(frame.x[2]);
        }
        frame.restore_mode_from(&original);
        if (frame.entry() != original.entry()
            && !proc.find_segment(frame.entry()).is_some_and(|segment| segment.segtype == SegType::Text))
            || (frame.stack() != original.stack()
                && !proc.find_segment(frame.stack()).is_some_and(|segment| segment.segtype == SegType::Stack))
        {
            return Err(DevError::Einval);
        }
        proc.user_frame = Some(frame);
        Ok(count)
    }

    fn read_segments(pid: i32, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
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
    
    fn check_owner(target: &crate::proc::Proc) -> Result<(), DevError> {
        let caller = crate::proc::curproc().ok_or(DevError::Eperm)?;
        if caller.uid == 0 || caller.uname == target.uname {
            Ok(())
        } else {
            Err(DevError::Eperm)
        }
    }

    fn writable_proc(pid: i32) -> Result<&'static mut crate::proc::Proc, DevError> {
        let target = crate::proc::find_proc(pid as _).filter(|proc| Self::visible(proc)).ok_or(DevError::Enoent)?;
        Self::check_owner(target)?;
        Ok(target)
    }

    /// Write to control file
    fn write_ctl(pid: i32, buf: &[u8]) -> Result<usize, DevError> {
        use crate::proc::State;

        let mut fields = core::str::from_utf8(buf).map_err(|_| DevError::Einval)?.split_whitespace();
        let cmd = fields.next().ok_or(DevError::Einval)?;
        let argument = fields.next();
        let takes_argument = matches!(cmd, "close" | "pri" | "fixedpri" | "wired");
        if fields.next().is_some() || (takes_argument && argument.is_none())
            || (argument.is_some() && !takes_argument && cmd != "trace")
        {
            return Err(DevError::Einval);
        }
        let proc = Self::writable_proc(pid)?;
        if proc.user_frame.is_none() || proc.pid == 1 {
            return Err(DevError::Eperm);
        }
        match cmd {
            "kill" => {
                if crate::proc::curproc().is_some_and(|current| current.pid == proc.pid) {
                    proc.notify = None;
                    proc.notified = false;
                    proc.nnote = 0;
                    proc.postnote(0, b"killed").map_err(|_| DevError::Eio)?;
                } else {
                    crate::syscall::finish_user_with_status(proc.pid, 1, Some(alloc::string::String::from("killed")));
                }
            }
            "stop" => {
                if proc.state != State::Stopped {
                    proc.stopped_from = Some(if proc.state == State::Running { State::Ready } else { proc.state });
                    proc.state = State::Stopped;
                    crate::syscall::wake_stop_waiters(pid as _, true);
                }
            }
            "start" if proc.state == State::Stopped => Self::restart(proc),
            "startstop" | "startsyscall" | "waitstop" => {
                let step = cmd != "waitstop";
                if step && proc.state != State::Stopped {
                    return Err(DevError::Einval);
                }
                if !step && proc.state == State::Stopped {
                    return Ok(buf.len());
                }
                let caller = crate::proc::curproc_mut().ok_or(DevError::Eperm)?;
                if caller.pid == proc.pid {
                    return Err(DevError::Einval);
                }
                caller.waiting_stop = Some((proc.pid, buf.len()));
                if step {
                    proc.stop_on_return = cmd == "startstop";
                    proc.stop_on_syscall = cmd == "startsyscall";
                    Self::restart(proc);
                }
            }
            "hang" => proc.stop_on_exec = true,
            "nohang" => proc.stop_on_exec = false,
            "noswap" => proc.noswap = true,
            "pri" | "fixedpri" => {
                let priority = argument.unwrap().parse::<i32>().map_err(|_| DevError::Einval)?;
                let caller = crate::proc::curproc().ok_or(DevError::Eperm)?;
                if caller.uid != 0 && priority > i32::from(crate::proc::PRI_NORMAL) {
                    return Err(DevError::Eperm);
                }
                let priority = priority.clamp(0, crate::proc::NPRIQ as i32 - 1) as i8;
                proc.basepri = priority;
                proc.pri = priority;
                proc.fixedpri = cmd == "fixedpri";
            }
            "wired" => {
                argument.unwrap().parse::<i32>().map_err(|_| DevError::Einval)?;
                proc.wired.wire_to(0);
            }
            "private" => proc.private_memory = true,
            "trace" => {
                proc.trace_enabled = match argument {
                    Some(value) => value.parse::<i32>().map_err(|_| DevError::Einval)? != 0,
                    None => !proc.trace_enabled,
                };
            }
            "event" => {
                let caller = crate::proc::curproc().ok_or(DevError::Eperm)?;
                record_trace(caller, TraceEvent::User);
            }
            "profile" => {
                let text = proc.seg.iter_mut().flatten()
                    .find(|segment| segment.segtype == crate::proc::SegType::Text)
                    .ok_or(DevError::Einval)?;
                text.enable_profiling().map_err(|_| DevError::Enomem)?;
            }
            "close" => {
                let fd = argument.and_then(|value| value.parse::<i32>().ok())
                    .filter(|fd| *fd >= 0 && (*fd as usize) < crate::proc::NFD)
                    .ok_or(DevError::Einval)?;
                let files = proc.fgrp.as_mut().ok_or(DevError::Enoent)?;
                if let Some(mut channel) = files.close_fd(fd) {
                    channel.close();
                }
            }
            "closefiles" => proc.fgrp.as_mut().ok_or(DevError::Enoent)?.close_all(),
            _ => return Err(DevError::Einval),
        }
        Ok(buf.len())
    }

    fn restart(proc: &mut crate::proc::Proc) {
        let state = proc.stopped_from.take().unwrap_or(crate::proc::State::Ready);
        if state == crate::proc::State::Ready {
            crate::syscall::set_user_ready(proc);
        } else {
            proc.state = state;
        }
    }
    
    fn note_message(buf: &[u8]) -> Result<&[u8], DevError> {
        let message = buf.strip_suffix(b"\n").unwrap_or(buf);
        if message.is_empty() || message.len() >= 128 || message.contains(&0) {
            return Err(DevError::Einval);
        }
        Ok(message)
    }

    fn write_noteid(pid: i32, buf: &[u8]) -> Result<usize, DevError> {
        let group = core::str::from_utf8(buf).map_err(|_| DevError::Einval)?.trim()
            .parse::<crate::proc::Pid>().map_err(|_| DevError::Einval)?;
        let proc = Self::writable_proc(pid)?;
        if group != proc.pid && group != proc.note_group {
            let member = crate::proc::proctable().iter()
                .find(|entry| entry.note_group == group && Self::visible(entry))
                .ok_or(DevError::Einval)?;
            if member.uname != proc.uname {
                return Err(DevError::Eperm);
            }
        }
        proc.note_group = group;
        Ok(buf.len())
    }

    fn write_note_group(group: crate::proc::Pid, buf: &[u8]) -> Result<usize, DevError> {
        let message = Self::note_message(buf)?;
        let caller = crate::proc::curproc().ok_or(DevError::Eperm)?.pid;
        let members: alloc::vec::Vec<_> = crate::proc::proctable().iter()
            .filter(|entry| entry.note_group == group && entry.pid != caller && Self::visible(entry))
            .map(|entry| entry.pid).collect();
        for pid in members {
            if let Some(member) = crate::proc::find_proc(pid) {
                let _ = member.postnote(0, message);
            }
        }
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

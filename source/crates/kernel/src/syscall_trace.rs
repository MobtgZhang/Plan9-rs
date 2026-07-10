//! System Call Tracing
//!
//! Implements system call tracing for debugging and performance analysis.
//! Similar to Linux's strace but integrated into the kernel.
//!
//! ## Reference
//! - Plan 9: similar to various debugging facilities in `/sys/src/9/port/`

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::proc::{ Pid, curproc };use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

/// Maximum number of trace records
pub const SYSCALL_TRACE_SIZE: usize = 4096;

/// System call trace record
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallRecord {
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
    /// Process ID
    pub pid: Pid,
    /// Parent process ID
    pub ppid: Pid,
    /// System call number
    pub syscall: usize,
    /// Arguments
    pub args: [u64; 6],
    /// Return value
    pub ret: isize,
    /// Duration in nanoseconds
    pub duration_ns: u64,
    /// Whether the call succeeded
    pub success: bool,
}

impl Default for SyscallRecord {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            ppid: 0,
            syscall: 0,
            args: [0; 6],
            ret: 0,
            duration_ns: 0,
            success: true,
        }
    }
}

/// Trace entry point
#[derive(Debug, Clone, Copy)]
pub enum TracePoint {
    /// Entering a system call
    Enter,
    /// Exiting a system call
    Exit,
}

/// System call tracing configuration
pub struct SyscallTraceConfig {
    /// Whether tracing is enabled globally
    pub enabled: AtomicBool,
    /// Whether to trace all processes
    pub trace_all: AtomicBool,
    /// Traced process IDs
    traced_pids: SpinlessVec<Pid>,
    /// Traced system call numbers (empty = trace all)
    traced_syscalls: SpinlessVec<usize>,
    /// Total records collected
    pub total_records: AtomicU64,
}

impl SyscallTraceConfig {
    /// Create new configuration
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            trace_all: AtomicBool::new(false),
            traced_pids: SpinlessVec::new(),
            traced_syscalls: SpinlessVec::new(),
            total_records: AtomicU64::new(0),
        }
    }

    /// Enable tracing
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable tracing
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Enable tracing for all processes
    pub fn set_trace_all(&self, value: bool) {
        self.trace_all.store(value, Ordering::SeqCst);
    }

    /// Check if we should trace a process
    pub fn should_trace(&self, pid: Pid) -> bool {
        if !self.is_enabled() {
            return false;
        }
        if self.trace_all.load(Ordering::SeqCst) {
            return true;
        }
        // Check if process is in traced list
        // Note: This is simplified - real implementation would use a hash set
        for &p in self.traced_pids.iter() {
            if p == pid {
                return true;
            }
        }
        false
    }

    /// Check if we should trace a system call
    pub fn should_trace_syscall(&self, num: usize) -> bool {
        if self.traced_syscalls.is_empty() {
            return true;  // Trace all if no specific syscalls specified
        }
        for &n in self.traced_syscalls.iter() {
            if n == num {
                return true;
            }
        }
        false
    }

    /// Add a process to trace
    pub fn add_pid(&self, pid: Pid) {
        self.traced_pids.push(pid);
    }

    /// Remove a process from trace
    pub fn remove_pid(&self, pid: Pid) {
        // Note: Simplified - real implementation would remove properly
        self.traced_pids.retain(|&p| p != pid);
    }

    /// Add a syscall to trace
    pub fn add_syscall(&self, num: usize) {
        self.traced_syscalls.push(num);
    }

    /// Clear all traced processes
    pub fn clear_pids(&self) {
        self.traced_pids.clear();
    }

    /// Clear all traced syscalls
    pub fn clear_syscalls(&self) {
        self.traced_syscalls.clear();
    }

    /// Increment record count
    pub fn increment_records(&self) {
        self.total_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total records
    pub fn total_records(&self) -> u64 {
        self.total_records.load(Ordering::Relaxed)
    }
}

/// Simple spinlock-free vector for basic types
pub struct SpinlessVec<T> {
    data: core::cell::UnsafeCell<Vec<T>>,
}

impl<T> SpinlessVec<T> {
    pub fn new() -> Self {
        Self {
            data: core::cell::UnsafeCell::new(Vec::new()),
        }
    }

    pub fn push(&self, val: T) {
        unsafe { (*self.data.get()).push(val); }
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        unsafe { (*self.data.get()).iter() }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { (*self.data.get()).is_empty() }
    }

    pub fn clear(&self) {
        unsafe { (*self.data.get()).clear(); }
    }

    pub fn retain<F>(&self, f: F)
    where
        F: FnMut(&T) -> bool,
    {
        unsafe { (*self.data.get()).retain(f); }
    }
}

unsafe impl<T: Send + Sync> Sync for SpinlessVec<T> {}

/// System call tracer
pub struct SyscallTracer {
    /// Configuration
    config: SyscallTraceConfig,
    /// Trace buffer (circular)
    records: [SyscallRecord; SYSCALL_TRACE_SIZE],
    /// Next record index
    next: AtomicUsize,
    /// Sequence number for buffer wrap detection
    sequence: AtomicU64,
}

impl SyscallTracer {
    /// Create new tracer
    pub fn new() -> Self {
        Self {
            config: SyscallTraceConfig::new(),
            records: [SyscallRecord::default(); SYSCALL_TRACE_SIZE],
            next: AtomicUsize::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    /// Record a system call entry
    pub fn enter(&mut self, syscall_num: usize) {
        if !self.should_record(syscall_num) {
            return;
        }

        let idx = self.next.load(Ordering::Relaxed);
        let record = &mut self.records[idx];

        // Get current process info
        let (pid, ppid) = curproc()
            .map(|p| (p.pid, p.parent.unwrap_or(0)))
            .unwrap_or((0, 0));

        // Get current time (would use HPET/APIC timer in real impl)
        let timestamp = get_ticks_ns();

        record.timestamp_ns = timestamp;
        record.pid = pid;
        record.ppid = ppid;
        record.syscall = syscall_num;
        record.ret = 0;
        record.duration_ns = 0;
        record.success = true;

        self.advance();
    }

    /// Record a system call exit
    pub fn exit(&self, syscall_num: usize, ret: isize) {
        if !self.should_record(syscall_num) {
            return;
        }

        // Go back one record to update it
        let idx = (self.next.load(Ordering::Relaxed) + SYSCALL_TRACE_SIZE - 1)
            % SYSCALL_TRACE_SIZE;
        let records_ptr = self.records.as_ptr() as *mut SyscallRecord;
        let record = unsafe { &mut *records_ptr.add(idx) };

        // Only update if this record matches
        if record.syscall == syscall_num && record.ret == 0 {
            let timestamp = get_ticks_ns();
            record.ret = ret;
            record.duration_ns = timestamp - record.timestamp_ns;
            record.success = ret >= 0;
            self.config.increment_records();
        }
    }

    /// Check if we should record this syscall
    fn should_record(&self, syscall_num: usize) -> bool {
        if !self.config.is_enabled() {
            return false;
        }

        // Check if we should trace this process
        if let Some(proc) = curproc() {
            if !self.config.should_trace(proc.pid) {
                return false;
            }
        } else {
            return false;
        }

        // Check if we should trace this syscall
        self.config.should_trace_syscall(syscall_num)
    }

    /// Advance to next record slot
    fn advance(&self) {
        let idx = self.next.load(Ordering::Relaxed);
        let next_idx = (idx + 1) % SYSCALL_TRACE_SIZE;

        // If we're about to wrap, increment sequence
        if next_idx == 0 {
            self.sequence.fetch_add(1, Ordering::Relaxed);
        }

        self.next.store(next_idx, Ordering::Relaxed);
    }

    /// Read records
    pub fn read_records(&self, buf: &mut [SyscallRecord]) -> usize {
        let count = self.config.total_records() as usize;
        let next = self.next.load(Ordering::Relaxed);
        let seq = self.sequence.load(Ordering::Relaxed);

        if count == 0 {
            return 0;
        }

        let records_to_read = count.min(buf.len()).min(SYSCALL_TRACE_SIZE);

        // Determine start index based on whether buffer has wrapped
        let start = if seq > 0 || count >= SYSCALL_TRACE_SIZE {
            next  // Buffer has wrapped
        } else {
            0     // Buffer not full
        };

        for i in 0..records_to_read {
            let idx = (start + i) % SYSCALL_TRACE_SIZE;
            buf[i] = self.records[idx];
        }

        records_to_read
    }

    /// Get configuration
    pub fn config(&self) -> &SyscallTraceConfig {
        &self.config
    }

    /// Reset tracer
    pub fn reset(&self) {
        self.config.total_records.store(0, Ordering::Relaxed);
        self.next.store(0, Ordering::Relaxed);
        self.sequence.store(0, Ordering::Relaxed);
    }
}

/// Get current time in nanoseconds (simplified)
fn get_ticks_ns() -> u64 {
    // Would use HPET or LAPIC timer in real implementation
    // For now, use a simple counter
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1000, Ordering::Relaxed)
}

// ============================================================================
// Global System Call Tracer
// ============================================================================

use core::sync::atomic::AtomicPtr;

static SYSCALL_TRACER: AtomicPtr<SyscallTracer> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize system call tracer
pub fn init_syscall_trace() {
    let tracer = Box::new(SyscallTracer::new());
    SYSCALL_TRACER.store(Box::into_raw(tracer), Ordering::SeqCst);
}

/// Get global tracer
pub fn syscall_tracer() -> &'static SyscallTracer {
    unsafe { &*SYSCALL_TRACER.load(Ordering::SeqCst) }
}

/// Get mutable global tracer
pub fn syscall_tracer_mut() -> &'static mut SyscallTracer {
    unsafe { &mut *SYSCALL_TRACER.load(Ordering::SeqCst) }
}

/// Called on syscall entry
pub fn syscall_trace_enter(syscall_num: usize) {
    syscall_tracer_mut().enter(syscall_num);
}

/// Called on syscall exit
pub fn syscall_trace_exit(syscall_num: usize, ret: isize) {
    syscall_tracer_mut().exit(syscall_num, ret);
}

// ============================================================================
// Syscall Trace Device
// ============================================================================

/// System call trace device
pub struct SyscallTraceDev {
    name: &'static str,
    dev_char: char,
}

impl SyscallTraceDev {
    /// Create new device
    pub fn new() -> Self {
        Self {
            name: "syscalltrace",
            dev_char: 'S',  // 'S' for syscall/System
        }
    }
}

impl Dev for SyscallTraceDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Err(Error::Enoent)
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Read syscall trace records
        let mut records = [SyscallRecord::default(); SYSCALL_TRACE_SIZE];
        let count = syscall_tracer().read_records(&mut records);

        let len = (count * core::mem::size_of::<SyscallRecord>()).min(buf.len());

        let src = unsafe {
            core::slice::from_raw_parts(
                records.as_ptr() as *const u8,
                len
            )
        };
        buf[..len].copy_from_slice(src);

        Ok(len)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // Control tracing via writes
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| Error::Einval)?
            .trim();

        if cmd == "enable" {
            syscall_tracer().config().enable();
            Ok(buf.len())
        } else if cmd == "disable" {
            syscall_tracer().config().disable();
            Ok(buf.len())
        } else if cmd == "traceall" {
            syscall_tracer().config().set_trace_all(true);
            Ok(buf.len())
        } else if cmd == "notraceall" {
            syscall_tracer().config().set_trace_all(false);
            Ok(buf.len())
        } else if cmd == "reset" {
            syscall_tracer().reset();
            Ok(buf.len())
        } else if cmd.starts_with("pid=") {
            // Add PID to trace: "pid=123"
            if let Ok(pid) = cmd[4..].parse::<Pid>() {
                syscall_tracer().config().add_pid(pid);
                Ok(buf.len())
            } else {
                Err(Error::Einval)
            }
        } else if cmd.starts_with("syscall=") {
            // Add syscall to trace: "syscall=0" (read), "syscall=1" (write), etc.
            if let Ok(num) = cmd[8..].parse::<usize>() {
                syscall_tracer().config().add_syscall(num);
                Ok(buf.len())
            } else {
                Err(Error::Einval)
            }
        } else if cmd == "clearpids" {
            syscall_tracer().config().clear_pids();
            Ok(buf.len())
        } else if cmd == "clearsyscalls" {
            syscall_tracer().config().clear_syscalls();
            Ok(buf.len())
        } else {
            Err(Error::Einval)
        }
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length: syscall_tracer().config().total_records()
                * (core::mem::size_of::<SyscallRecord>() as u64),
            name: b"syscalltrace".to_vec(),
        })
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Integration with Syscall Handler
// ============================================================================

/// Called from syscall handler to trace entry
pub fn trace_syscall_entry(syscall_num: usize) {
    if syscall_tracer().config().is_enabled() {
        syscall_trace_enter(syscall_num);
    }
}

/// Called from syscall handler to trace exit
pub fn trace_syscall_exit(syscall_num: usize, ret: isize) {
    if syscall_tracer().config().is_enabled() {
        syscall_trace_exit(syscall_num, ret);
    }
}

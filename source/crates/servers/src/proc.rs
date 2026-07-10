//! Proc Server
//!
//! Implements the Plan 9 process management server.


extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ============================================================================
// Types
// ============================================================================

/// Process ID type
pub type Pid = u32;

/// Error type for proc server operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    Esrch,      // No such process
    Eintr,      // Interrupted system call
    Eproclim,   // Too many processes
    Ebadf,      // Bad file descriptor
}

impl ProcError {
    pub fn errno(&self) -> u32 {
        match self {
            ProcError::Esrch => 3,
            ProcError::Eintr => 4,
            ProcError::Eproclim => 11,
            ProcError::Ebadf => 9,
        }
    }
}

pub type Result<T> = core::result::Result<T, ProcError>;

// ============================================================================
// Process State
// ============================================================================

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Dead,
    Sleeping,
    Ready,
    Running,
    Exited,
}

/// Process information
#[derive(Debug, Clone)]
pub struct ProcInfo {
    /// Process ID
    pub pid: Pid,
    /// Parent process ID
    pub ppid: Pid,
    /// Process state
    pub state: ProcState,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Program name
    pub name: String,
    /// Start time
    pub start_time: u64,
    /// CPU time used
    pub cpu_time: u64,
    /// Memory usage
    pub memory: u64,
    /// Command line
    pub args: Vec<String>,
}

impl ProcInfo {
    pub fn new(pid: Pid, name: &str) -> Self {
        Self {
            pid,
            ppid: 0,
            state: ProcState::Ready,
            uid: 0,
            gid: 0,
            name: name.to_string(),
            start_time: 0,
            cpu_time: 0,
            memory: 0,
            args: Vec::new(),
        }
    }
}

// ============================================================================
// Process Table
// ============================================================================

/// Process table
pub struct ProcTable {
    /// Process entries
    processes: Vec<ProcInfo>,
    /// Next PID
    next_pid: u32,
}

impl ProcTable {
    /// Create new process table
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            next_pid: 1,
        }
    }

    /// Allocate a new PID
    pub fn alloc_pid(&mut self) -> Pid {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }

    /// Add a new process
    pub fn add(&mut self, info: ProcInfo) -> Pid {
        let pid = info.pid;
        self.processes.push(info);
        pid
    }

    /// Get process by PID
    pub fn get(&self, pid: Pid) -> Option<&ProcInfo> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    /// Get process by PID (mutable)
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut ProcInfo> {
        self.processes.iter_mut().find(|p| p.pid == pid)
    }

    /// Remove a process
    pub fn remove(&mut self, pid: Pid) -> Option<ProcInfo> {
        if let Some(pos) = self.processes.iter().position(|p| p.pid == pid) {
            Some(self.processes.remove(pos))
        } else {
            None
        }
    }

    /// List all processes
    pub fn list(&self) -> Vec<&ProcInfo> {
        self.processes.iter().collect()
    }

    /// Find processes by name
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcInfo> {
        self.processes.iter().filter(|p| p.name == name).collect()
    }

    /// Count processes
    pub fn count(&self) -> usize {
        self.processes.len()
    }
}

impl Default for ProcTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Proc Server
// ============================================================================

/// Proc server
pub struct ProcServer {
    /// Process table
    table: ProcTable,
    /// Maximum processes
    max_procs: usize,
}

impl ProcServer {
    /// Create new proc server
    pub fn new() -> Self {
        Self {
            table: ProcTable::new(),
            max_procs: 256,
        }
    }

    /// Spawn a new process
    pub fn spawn(&mut self, name: &str) -> Result<Pid> {
        if self.table.count() >= self.max_procs {
            return Err(ProcError::Eproclim);
        }

        let pid = self.table.alloc_pid();
        let info = ProcInfo::new(pid, name);
        self.table.add(info);

        Ok(pid)
    }

    /// Kill a process
    pub fn kill(&mut self, pid: Pid) -> Result<()> {
        if let Some(proc) = self.table.get_mut(pid) {
            proc.state = ProcState::Dead;
            Ok(())
        } else {
            Err(ProcError::Esrch)
        }
    }

    /// Wait for a process
    pub fn wait(&mut self, pid: Pid) -> Result<ProcInfo> {
        if pid == 0 {
            // Wait for any child
            if let Some(pos) = self.table.processes.iter().position(|p| p.state == ProcState::Dead) {
                return Ok(self.table.processes.remove(pos));
            }
            Err(ProcError::Eintr)
        } else {
            // Wait for specific child
            if let Some(pos) = self.table.processes.iter().position(|p| p.pid == pid && p.state == ProcState::Dead) {
                Ok(self.table.processes.remove(pos))
            } else {
                Err(ProcError::Esrch)
            }
        }
    }

    /// Get process info
    pub fn info(&self, pid: Pid) -> Result<ProcInfo> {
        self.table.get(pid).cloned().ok_or(ProcError::Esrch)
    }

    /// List all processes
    pub fn ps(&self) -> Vec<ProcInfo> {
        self.table.list().into_iter().cloned().collect()
    }

    /// Set process state
    pub fn set_state(&mut self, pid: Pid, state: ProcState) -> Result<()> {
        if let Some(proc) = self.table.get_mut(pid) {
            proc.state = state;
            Ok(())
        } else {
            Err(ProcError::Esrch)
        }
    }
}

impl Default for ProcServer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// /proc Interface
// ============================================================================

/// /proc file system entries
pub mod procfs {
    use super::*;

    /// Read process status
    pub fn read_status(_pid: Pid) -> Vec<u8> {
        Vec::new()
    }

    /// Read process memory maps
    pub fn read_maps(_pid: Pid) -> Vec<u8> {
        Vec::new()
    }

    /// Read process command line
    pub fn read_cmdline(_pid: Pid) -> Vec<u8> {
        Vec::new()
    }

    /// Read process environ
    pub fn read_environ(_pid: Pid) -> Vec<u8> {
        Vec::new()
    }

    /// Read process fd directory
    pub fn read_fd(_pid: Pid) -> Vec<u8> {
        Vec::new()
    }
}

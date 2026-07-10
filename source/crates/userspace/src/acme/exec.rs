//! Execution Module
//!
//! Handles execution of external commands in Acme windows.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/exec.c`

/// Command execution context
pub struct Executor {
    /// Working directory
    cwd: alloc::string::String,
    /// Environment variables
    env: alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
    /// Active processes
    processes: alloc::vec::Vec<ProcessInfo>,
}

impl Executor {
    /// Create a new executor
    pub fn new() -> Self {
        Self {
            cwd: alloc::string::String::from("."),
            env: alloc::collections::BTreeMap::new(),
            processes: alloc::vec::Vec::new(),
        }
    }

    /// Set working directory
    pub fn set_cwd(&mut self, dir: &str) {
        self.cwd = alloc::string::String::from(dir);
    }

    /// Get working directory
    pub fn get_cwd(&self) -> &str {
        &self.cwd
    }

    /// Set environment variable
    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env.insert(
            alloc::string::String::from(key),
            alloc::string::String::from(value),
        );
    }

    /// Get environment variable
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(|s| s.as_str())
    }

    /// Execute a command
    pub fn execute(&mut self, cmd: &str) -> Result<ProcessInfo, Error> {
        use std::string::String;
        
        // Parse command line
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err(Error::new("empty command"));
        }
        
        let program = parts[0];
        let args = &parts[1..];
        
        // For now, just record the command
        // In a real implementation, this would spawn a process
        let info = ProcessInfo {
            pid: self.processes.len() as u64 + 1,
            cmd: String::from(cmd),
            status: ProcessStatus::Running,
        };
        
        self.processes.push(info.clone());
        Ok(info)
    }

    /// Kill a process
    pub fn kill(&mut self, pid: u64) -> bool {
        if let Some(p) = self.processes.iter_mut().find(|p| p.pid == pid) {
            p.status = ProcessStatus::Killed;
            true
        } else {
            false
        }
    }

    /// Wait for a process
    pub fn wait(&mut self, pid: u64) -> Option<ProcessInfo> {
        if let Some(p) = self.processes.iter_mut().find(|p| p.pid == pid) {
            p.status = ProcessStatus::Done;
            Some(p.clone())
        } else {
            None
        }
    }

    /// Get running processes
    pub fn running(&self) -> alloc::vec::Vec<&ProcessInfo> {
        self.processes.iter()
            .filter(|p| p.status == ProcessStatus::Running)
            .collect()
    }

    /// Clean up finished processes
    pub fn cleanup(&mut self) {
        self.processes.retain(|p| p.status == ProcessStatus::Running);
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

/// Process information
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub cmd: alloc::string::String,
    pub status: ProcessStatus,
}

/// Process status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    Done,
    Killed,
    Error,
}

/// Error type
#[derive(Debug)]
pub struct Error {
    pub msg: alloc::string::String,
}

impl Error {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: alloc::string::String::from(msg),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

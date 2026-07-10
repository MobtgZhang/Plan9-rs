//! File System Module
//!
//! Implements the 9P file system interface for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/fsys.c`

use super::window::WindowId;

/// File system entry
#[derive(Debug)]
pub struct RioFsysEntry {
    /// Entry name
    pub name: alloc::string::String,
    /// Entry type
    pub entry_type: RioEntryType,
    /// Window ID (for window entries)
    pub wid: Option<WindowId>,
}

/// Entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioEntryType {
    Root,
    Win,
    Wctl,
    Wdir,
    Snarf,
    Cons,
    Mouse,
    Label,
    Unnamed,
}

/// Rio file system
pub struct RioFsys {
    /// Root entries
    entries: alloc::vec::Vec<RioFsysEntry>,
    /// Current working directory
    cwd: alloc::string::String,
}

impl RioFsys {
    /// Create new file system
    pub fn new() -> Self {
        let mut fs = Self {
            entries: alloc::vec::Vec::new(),
            cwd: alloc::string::String::from("/"),
        };
        fs.init();
        fs
    }

    /// Initialize file system
    fn init(&mut self) {
        // Root directory
        self.entries.push(RioFsysEntry {
            name: alloc::string::String::from("."),
            entry_type: RioEntryType::Root,
            wid: None,
        });
        
        // Snarf file
        self.entries.push(RioFsysEntry {
            name: alloc::string::String::from("snarf"),
            entry_type: RioEntryType::Snarf,
            wid: None,
        });
        
        // Cons file
        self.entries.push(RioFsysEntry {
            name: alloc::string::String::from("cons"),
            entry_type: RioEntryType::Cons,
            wid: None,
        });
        
        // Mouse file
        self.entries.push(RioFsysEntry {
            name: alloc::string::String::from("mouse"),
            entry_type: RioEntryType::Mouse,
            wid: None,
        });
    }

    /// Add window to file system
    pub fn add_window(&mut self, id: WindowId) {
        let id_str = alloc::format!("{}", id);
        
        // Window control file
        self.entries.push(RioFsysEntry {
            name: alloc::format!("{}/wctl", id_str),
            entry_type: RioEntryType::Wctl,
            wid: Some(id),
        });
        
        // Window directory
        self.entries.push(RioFsysEntry {
            name: id_str.clone(),
            entry_type: RioEntryType::Win,
            wid: Some(id),
        });
        
        // Window label
        self.entries.push(RioFsysEntry {
            name: alloc::format!("{}/label", id_str),
            entry_type: RioEntryType::Label,
            wid: Some(id),
        });
        
        // Unnamed file
        self.entries.push(RioFsysEntry {
            name: alloc::format!("{}/unnamed", id_str),
            entry_type: RioEntryType::Unnamed,
            wid: Some(id),
        });
    }

    /// Remove window from file system
    pub fn remove_window(&mut self, id: WindowId) {
        let prefix = alloc::format!("{}/", id);
        
        self.entries.retain(|e| {
            if let Some(wid) = e.wid {
                wid != id
            } else {
                !e.name.starts_with(&prefix)
            }
        });
    }

    /// Find entry by path
    pub fn find(&self, path: &str) -> Option<&RioFsysEntry> {
        self.entries.iter().find(|e| e.name == path)
    }

    /// Find entry by path mutably
    pub fn find_mut(&mut self, path: &str) -> Option<&mut RioFsysEntry> {
        self.entries.iter_mut().find(|e| e.name == path)
    }

    /// List directory entries
    pub fn list(&self, path: &str) -> alloc::vec::Vec<&RioFsysEntry> {
        if path == "/" || path == "" || path == "." {
            // List root
            return self.entries.iter()
                .filter(|e| e.name.contains('/'))
                .filter(|e| {
                    let parts: Vec<&str> = e.name.split('/').collect();
                    parts.len() == 1
                })
                .collect();
        }
        
        // List window contents
        let prefix = alloc::format!("{}/", path.trim_start_matches('/'));
        return self.entries.iter()
            .filter(|e| e.name.starts_with(&prefix))
            .collect();
    }

    /// Read from file
    pub fn read(&self, path: &str, offset: usize, count: usize) -> Result<alloc::vec::Vec<u8>, FsysError> {
        let entry = self.find(path).ok_or_else(|| FsysError::new("not found"))?;
        
        match entry.entry_type {
            RioEntryType::Root => {
                // Directory listing
                let entries = self.list(path);
                let mut data = alloc::vec::Vec::new();
                
                for e in entries {
                    data.extend_from_slice(e.name.as_bytes());
                    data.push(b'\n');
                }
                
                let data_len = data.len();
                let start = offset.min(data_len);
                let end = (offset + count).min(data_len);
                
                Ok(data[start..end].to_vec())
            }
            RioEntryType::Snarf => {
                // Would read from snarf buffer
                Ok(alloc::vec::Vec::new())
            }
            RioEntryType::Cons => {
                // Would read from console
                Ok(alloc::vec::Vec::new())
            }
            RioEntryType::Mouse => {
                // Would read from mouse
                Ok(alloc::vec::Vec::new())
            }
            RioEntryType::Wctl => {
                // Window control - write only
                Err(FsysError::new("write only"))
            }
            RioEntryType::Label => {
                // Would read window label
                Ok(alloc::vec::Vec::new())
            }
            RioEntryType::Win | RioEntryType::Wdir | RioEntryType::Unnamed => {
                // Directory listing
                let entries = self.list(path);
                let mut data = alloc::vec::Vec::new();
                
                for e in entries {
                    data.extend_from_slice(e.name.as_bytes());
                    data.push(b'\n');
                }
                
                Ok(data)
            }
        }
    }

    /// Write to file
    pub fn write(&self, path: &str, data: &[u8]) -> Result<usize, FsysError> {
        let entry = self.find(path).ok_or_else(|| FsysError::new("not found"))?;
        
        match entry.entry_type {
            RioEntryType::Snarf => {
                // Would write to snarf buffer
                Ok(data.len())
            }
            RioEntryType::Cons => {
                // Would write to console
                Ok(data.len())
            }
            RioEntryType::Wctl => {
                // Window control commands
                self.parse_wctl(String::from_utf8_lossy(data).as_ref())?;
                Ok(data.len())
            }
            RioEntryType::Label => {
                // Would write window label
                Ok(data.len())
            }
            _ => Err(FsysError::new("not writable")),
        }
    }

    /// Parse window control command
    fn parse_wctl(&self, cmd: &str) -> Result<(), FsysError> {
        let cmd = cmd.trim();
        
        if cmd.starts_with("resize") {
            // resize max/min/restore/here
            Ok(())
        } else if cmd.starts_with("move") {
            // move dx dy
            Ok(())
        } else if cmd.starts_with("top") {
            // Bring to front
            Ok(())
        } else if cmd.starts_with("bottom") {
            // Send to back
            Ok(())
        } else if cmd == "delete" {
            // Delete window
            Ok(())
        } else if cmd == "hide" {
            // Hide window
            Ok(())
        } else {
            Err(FsysError::new("unknown wctl command"))
        }
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for RioFsys {
    fn default() -> Self {
        Self::new()
    }
}

/// File system error
#[derive(Debug)]
pub struct FsysError {
    pub message: alloc::string::String,
}

impl FsysError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: alloc::string::String::from(msg),
        }
    }
}

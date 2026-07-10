//! File System Module
//!
//! Implements the file system interface for Acme windows.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/fsys.c`

use crate::acme::window::{Window, WindowId};
use crate::acme::text::Text;

/// File system entry
#[derive(Debug)]
pub struct FsysEntry {
    /// Entry name
    pub name: alloc::string::String,
    /// Entry type
    pub entry_type: FsysEntryType,
    /// Window ID (for window entries)
    pub wid: Option<WindowId>,
}

/// Entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsysEntryType {
    Root,
    Acme,
    Window,
    Body,
    Tag,
    Edit,
    Event,
    Undo,
    Snarf,
    Nil,
}

/// File system node
pub struct Fsys {
    /// Root entries
    entries: alloc::vec::Vec<FsysEntry>,
    /// Current directory
    current: alloc::string::String,
}

impl Fsys {
    /// Create new file system
    pub fn new() -> Self {
        let mut fs = Self {
            entries: alloc::vec::Vec::new(),
            current: alloc::string::String::from("/"),
        };
        fs.init();
        fs
    }

    /// Initialize file system
    fn init(&mut self) {
        // Root directory
        self.entries.push(FsysEntry {
            name: alloc::string::String::from("."),
            entry_type: FsysEntryType::Root,
            wid: None,
        });
        
        // Acme directory
        self.entries.push(FsysEntry {
            name: alloc::string::String::from("acme"),
            entry_type: FsysEntryType::Acme,
            wid: None,
        });
    }

    /// Add window to file system
    pub fn add_window(&mut self, id: WindowId) {
        // Add window directory
        let name = alloc::format!("{}", id);
        self.entries.push(FsysEntry {
            name: name.clone(),
            entry_type: FsysEntryType::Window,
            wid: Some(id),
        });
        
        // Add body file
        self.entries.push(FsysEntry {
            name: alloc::format!("{}/body", id),
            entry_type: FsysEntryType::Body,
            wid: Some(id),
        });
        
        // Add tag file
        self.entries.push(FsysEntry {
            name: alloc::format!("{}/tag", id),
            entry_type: FsysEntryType::Tag,
            wid: Some(id),
        });
        
        // Add edit file
        self.entries.push(FsysEntry {
            name: alloc::format!("{}/edit", id),
            entry_type: FsysEntryType::Edit,
            wid: Some(id),
        });
        
        // Add event file
        self.entries.push(FsysEntry {
            name: alloc::format!("{}/event", id),
            entry_type: FsysEntryType::Event,
            wid: Some(id),
        });
    }

    /// Remove window from file system
    pub fn remove_window(&mut self, id: WindowId) {
        let prefix = alloc::format!("{}", id);
        
        self.entries.retain(|e| {
            if let Some(wid) = e.wid {
                wid != id
            } else {
                !e.name.starts_with(&prefix)
            }
        });
    }

    /// Find entry by path
    pub fn find(&self, path: &str) -> Option<&FsysEntry> {
        self.entries.iter().find(|e| e.name == path)
    }

    /// Find entry by path mutably
    pub fn find_mut(&mut self, path: &str) -> Option<&mut FsysEntry> {
        self.entries.iter_mut().find(|e| e.name == path)
    }

    /// List directory entries
    pub fn list(&self, path: &str) -> alloc::vec::Vec<&FsysEntry> {
        if path == "/" || path == "" {
            // List root
            return self.entries.iter()
                .filter(|e| e.entry_type == FsysEntryType::Acme)
                .collect();
        }
        
        if path == "/acme" {
            // List windows
            return self.entries.iter()
                .filter(|e| e.entry_type == FsysEntryType::Window)
                .collect();
        }
        
        // List window contents
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() == 2 && parts[0] == "acme" {
            let id = parts[1];
            return self.entries.iter()
                .filter(|e| e.name.starts_with(&format!("{}/", id)))
                .collect();
        }
        
        alloc::vec::Vec::new()
    }

    /// Read from file
    pub fn read(&self, path: &str, offset: usize, count: usize) -> Result<alloc::vec::Vec<u8>, FsysError> {
        use std::string::String;
        
        let entry = self.find(path).ok_or_else(|| FsysError::new("not found"))?;
        
        match entry.entry_type {
            FsysEntryType::Root | FsysEntryType::Acme | FsysEntryType::Window => {
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
            FsysEntryType::Body | FsysEntryType::Tag | FsysEntryType::Edit => {
                // Would read from window text
                Ok(alloc::vec::Vec::new())
            }
            FsysEntryType::Snarf => {
                // Would read from snarf buffer
                Ok(alloc::vec::Vec::new())
            }
            FsysEntryType::Event | FsysEntryType::Undo | FsysEntryType::Nil => {
                Ok(alloc::vec::Vec::new())
            }
        }
    }

    /// Write to file
    pub fn write(&self, path: &str, data: &[u8], offset: usize) -> Result<usize, FsysError> {
        use std::string::String;
        
        let entry = self.find(path).ok_or_else(|| FsysError::new("not found"))?;
        
        match entry.entry_type {
            FsysEntryType::Body | FsysEntryType::Tag | FsysEntryType::Edit => {
                // Would write to window text
                Ok(data.len())
            }
            _ => Err(FsysError::new("not writable")),
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

impl Default for Fsys {
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

//! 9P File System Operations Module
//!
//! Implements 9P (Plan 9 file system protocol) operations for Acme.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/xfid.c`, `fsys.c`

use crate::acme::window::{Window, WindowId};
use crate::acme::text::Text;

/// 9P file ID
pub type Fid = u32;

/// 9P tag
pub type Tag = u16;

/// Xfid operation
#[derive(Debug, Clone, Copy)]
pub enum XfidOp {
    Version,
    Auth,
    Attach,
    Flush,
    Walk,
    Open,
    Create,
    Read,
    Write,
    Clunk,
    Remove,
    Stat,
    WStat,
}

/// Xfid request
#[derive(Debug)]
pub struct XfidRequest {
    pub tag: Tag,
    pub fid: Fid,
    pub op: XfidOp,
    pub data: alloc::vec::Vec<u8>,
}

/// Xfid reply
#[derive(Debug)]
pub struct XfidReply {
    pub tag: Tag,
    pub data: alloc::vec::Vec<u8>,
    pub error: Option<alloc::string::String>,
}

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Dir,
    Body,
    Tag,
    Rdsel,
    Wrisel,
    Address,
    Execute,
    Event,
    Undo,
    Snarf,
    Nil,
}

/// Xfid file
pub struct Xfid {
    /// File path
    pub path: alloc::string::String,
    /// File type
    pub file_type: FileType,
    /// Window ID (if window file)
    pub wid: Option<WindowId>,
    /// Index (for numbered files)
    pub index: Option<u32>,
}

/// Xfid manager
pub struct XfidManager {
    /// Current file ID
    next_fid: Fid,
    /// Open files
    files: alloc::vec::Vec<XfidFile>,
    /// Root directory entries
    root_entries: alloc::vec::Vec<DirEntry>,
}

impl XfidManager {
    /// Create a new Xfid manager
    pub fn new() -> Self {
        let mut manager = Self {
            next_fid: 100,
            files: alloc::vec::Vec::new(),
            root_entries: alloc::vec::Vec::new(),
        };
        manager.init_root();
        manager
    }

    /// Initialize root directory
    fn init_root(&mut self) {
        // Add standard Acme directories
        self.root_entries.push(DirEntry {
            name: alloc::string::String::from("acme"),
            mode: FileMode::Dir,
            ..Default::default()
        });
    }

    /// Allocate a new file ID
    pub fn alloc_fid(&mut self) -> Fid {
        let fid = self.next_fid;
        self.next_fid += 1;
        fid
    }

    /// Handle 9P request
    pub fn handle(&mut self, req: XfidRequest) -> XfidReply {
        match req.op {
            XfidOp::Version => self.op_version(req),
            XfidOp::Walk => self.op_walk(req),
            XfidOp::Open => self.op_open(req),
            XfidOp::Read => self.op_read(req),
            XfidOp::Write => self.op_write(req),
            XfidOp::Clunk => self.op_clunk(req),
            XfidOp::Stat => self.op_stat(req),
            _ => XfidReply {
                tag: req.tag,
                data: alloc::vec::Vec::new(),
                error: Some(alloc::string::String::from("unsupported operation")),
            },
        }
    }

    /// Version operation
    fn op_version(&self, req: XfidRequest) -> XfidReply {
        // Return 9P2000 version
        let version = b"9P2000".to_vec();
        XfidReply {
            tag: req.tag,
            data: version,
            error: None,
        }
    }

    /// Walk operation
    fn op_walk(&mut self, req: XfidRequest) -> XfidReply {
        // Parse walk path
        let name = String::from_utf8_lossy(&req.data).into_owned();
        
        // Find or create file
        let qid = Qid {
            qtype: 0,
            path: self.files.len() as u64,
            vers: 0,
        };
        
        XfidReply {
            tag: req.tag,
            data: encode_qid(&qid),
            error: None,
        }
    }

    /// Open operation
    fn op_open(&mut self, req: XfidRequest) -> XfidReply {
        let qid = Qid {
            qtype: 0,
            path: req.fid as u64,
            vers: 0,
        };
        
        XfidReply {
            tag: req.tag,
            data: encode_qid(&qid),
            error: None,
        }
    }

    /// Read operation
    fn op_read(&mut self, req: XfidRequest) -> XfidReply {
        // Return directory listing or file content
        let data = if let Some(file) = self.files.get(req.fid as usize - 100) {
            match file.file_type {
                FileType::Dir => self.read_dir(file),
                FileType::Body | FileType::Tag => {
                    // Would read from window
                    alloc::vec::Vec::new()
                }
                _ => alloc::vec::Vec::new(),
            }
        } else {
            alloc::vec::Vec::new()
        };
        
        XfidReply {
            tag: req.tag,
            data,
            error: None,
        }
    }

    /// Read directory
    fn read_dir(&self, _file: &XfidFile) -> alloc::vec::Vec<u8> {
        let mut data = alloc::vec::Vec::new();
        
        // Encode directory entries
        for entry in &self.root_entries {
            let encoded = encode_dir_entry(entry);
            data.extend_from_slice(&encoded);
        }
        
        data
    }

    /// Write operation
    fn op_write(&mut self, req: XfidRequest) -> XfidReply {
        // Would write to window/file
        let count = req.data.len() as u32;
        
        XfidReply {
            tag: req.tag,
            data: count.to_le_bytes().to_vec(),
            error: None,
        }
    }

    /// Clunk operation (close file)
    fn op_clunk(&mut self, req: XfidRequest) -> XfidReply {
        XfidReply {
            tag: req.tag,
            data: alloc::vec::Vec::new(),
            error: None,
        }
    }

    /// Stat operation
    fn op_stat(&mut self, req: XfidRequest) -> XfidReply {
        let data = if let Some(file) = self.files.get(req.fid as usize - 100) {
            let entry = DirEntry {
                name: file.path.clone(),
                mode: match file.file_type {
                    FileType::Dir => FileMode::Dir,
                    _ => FileMode::File,
                },
                ..Default::default()
            };
            encode_dir_entry(&entry)
        } else {
            alloc::vec::Vec::new()
        };
        
        XfidReply {
            tag: req.tag,
            data,
            error: None,
        }
    }
}

impl Default for XfidManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Xfid file
#[derive(Debug)]
struct XfidFile {
    pub path: alloc::string::String,
    pub file_type: FileType,
    pub wid: Option<WindowId>,
    pub index: Option<u32>,
    pub offset: u64,
}

/// Directory entry
#[derive(Debug, Default)]
struct DirEntry {
    pub name: alloc::string::String,
    pub qid: Qid,
    pub mode: FileMode,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
}

/// QID (unique file identifier in 9P)
#[derive(Debug, Clone, Copy)]
struct Qid {
    pub qtype: u8,
    pub path: u64,
    pub vers: u32,
}

/// File mode
#[derive(Debug, Clone, Copy)]
enum FileMode {
    File,
    Dir,
    Nonamed,
}

impl Default for FileMode {
    fn default() -> Self {
        Self::File
    }
}

/// Encode QID to bytes
fn encode_qid(qid: &Qid) -> alloc::vec::Vec<u8> {
    let mut data = alloc::vec::Vec::with_capacity(13);
    data.push(qid.qtype);
    data.extend_from_slice(&qid.path.to_le_bytes());
    data.extend_from_slice(&qid.vers.to_le_bytes());
    data
}

/// Encode directory entry to 9P stat format
fn encode_dir_entry(entry: &DirEntry) -> alloc::vec::Vec<u8> {
    use std::string::String;
    
    let name = entry.name.as_bytes();
    let mode = match entry.mode {
        FileMode::Dir => 0o40000,
        FileMode::File => 0o100000,
        FileMode::Nonamed => 0o100000,
    };
    
    // Calculate total size
    let size = 2 + 13 + 2 + name.len() + 2 + 4 + 4 + 8 + 4 + 4 + 4 + 2;
    
    let mut data = alloc::vec::Vec::with_capacity(size);
    
    // Size (2 bytes)
    data.extend_from_slice(&(size as u16).to_le_bytes());
    
    // Type (2 bytes)
    data.extend_from_slice(&0u16.to_le_bytes());
    
    // Dev (4 bytes)
    data.extend_from_slice(&0u32.to_le_bytes());
    
    // QID
    data.push(entry.qid.qtype);
    data.extend_from_slice(&entry.qid.path.to_le_bytes());
    data.extend_from_slice(&entry.qid.vers.to_le_bytes());
    
    // Mode
    data.extend_from_slice(&(mode as u32).to_le_bytes());
    
    // Atime, Mtime
    data.extend_from_slice(&entry.atime.to_le_bytes());
    data.extend_from_slice(&entry.mtime.to_le_bytes());
    
    // Length
    data.extend_from_slice(&entry.length.to_le_bytes());
    
    // Name
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(name);
    
    // Extension (empty)
    data.extend_from_slice(&0u16.to_le_bytes());
    
    // UID, GID, MUID (empty strings)
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    
    data
}

/// Xfid wrapper for use with windows
pub struct XfidWindow {
    pub wid: WindowId,
    pub text: *const Text,
    pub offset: u64,
}

impl XfidWindow {
    pub fn new(wid: WindowId, text: *const Text) -> Self {
        Self {
            wid,
            text,
            offset: 0,
        }
    }
}

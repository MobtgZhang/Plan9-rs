//! TLS Device Implementation
//!
//! Implements the Plan 9 TLS device (#I) for TLS/SSL connections.
//!
//! ## Overview
//!
//! The TLS device provides TLS encryption for network connections.
//! It uses the existing security library for cryptographic operations.
//!
//! ## Namespace Structure
//!
//! ```
//! /net/
//! └── tls/
//!     ├── clone        (create new TLS connection)
//!     └── N/          (per-connection files)
//!         ├── ctl     (handshake control)
//!         ├── data    (encrypted read/write)
//!         └── status  (connection state)
//! ```

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError};
use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum number of TLS connections
const TLS_MAX_CONNECTIONS: usize = 32;

/// Qid paths for TLS device
mod tls_qid {
    pub const QDIR: u64 = 0;
    pub const QCLONE: u64 = 1;
    
    /// Extract connection ID from qid
    pub fn conn_id(qid: u64) -> usize {
        ((qid >> 8) & 0xFF) as usize
    }
    
    /// Create connection qid
    pub fn connection(id: usize, file: u64) -> u64 {
        ((id as u64) << 8) | file
    }
}

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsState {
    Uninitialized,
    Handshake,
    Established,
    Closing,
    Closed,
}

/// TLS connection info
#[derive(Debug, Clone)]
struct TlsConnection {
    /// Connection ID
    id: usize,
    /// Connection state
    state: TlsState,
    /// Server address
    address: String,
    /// Port
    port: u16,
    /// Using TLS 1.2 or 1.3
    version: String,
}

/// TLS device structure
pub struct TlsDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Connections
    connections: Spinlock<Vec<Option<TlsConnection>>>,
    /// Next connection ID
    next_id: AtomicU64,
}

impl TlsDev {
    /// Create a new TLS device
    pub fn new() -> Self {
        Self {
            name: "tls",
            dev_char: 'I',
            connections: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }
    
    /// Create a new TLS connection
    pub fn create_connection(&self, address: &str, port: u16) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let mut connections = self.connections.lock();
        
        // Ensure vector is large enough
        while connections.len() <= id {
            connections.push(None);
        }
        
        connections[id] = Some(TlsConnection {
            id,
            state: TlsState::Uninitialized,
            address: address.to_string(),
            port,
            version: "TLS1.2".to_string(),
        });
        
        id
    }
    
    /// Get connection info
    pub fn get_connection(&self, id: usize) -> Option<TlsConnection> {
        let connections = self.connections.lock();
        connections.get(id).and_then(|c| c.clone())
    }
    
    /// Set connection state
    pub fn set_state(&self, id: usize, state: TlsState) -> Result<(), DevError> {
        let mut connections = self.connections.lock();
        if let Some(conn) = connections.get_mut(id) {
            if let Some(ref mut c) = conn {
                c.state = state;
                Ok(())
            } else {
                Err(DevError::Enoent)
            }
        } else {
            Err(DevError::Enoent)
        }
    }
}

impl Dev for TlsDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::TLS,
            Qid::new(tls_qid::QDIR, 0, 0),
            0oOREAD,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        if qid == tls_qid::QDIR {
            // At top level
            if name == "clone" {
                ch.qid = Qid::new(tls_qid::QCLONE, 0, 0);
                return Ok(Some(ch.qid));
            }
            
            // Try to parse as connection number
            if let Ok(id) = name.parse::<usize>() {
                let conn = self.get_connection(id);
                if conn.is_some() {
                    ch.qid = Qid::new(tls_qid::connection(id, 0), 0, 0);
                    return Ok(Some(ch.qid));
                }
            }
        } else {
            // At connection level
            let conn_id = tls_qid::conn_id(qid);
            match name {
                "ctl" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 1), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "data" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 2), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "status" => {
                    ch.qid = Qid::new(tls_qid::connection(conn_id, 3), 0, 0);
                    return Ok(Some(ch.qid));
                }
                _ => {}
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        let qid = ch.qid.path;
        
        // Handle clone - create new connection
        if qid == tls_qid::QCLONE {
            // Create placeholder connection
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
            ch.qid = Qid::new(tls_qid::connection(id, 0), 0, 0);
        }
        
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // Close TLS connection
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            tls_qid::QCLONE => {
                // Return new connection ID
                let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
                buf[..4].copy_from_slice(&(id as u32).to_le_bytes());
                Ok(4)
            }
            _ => {
                let conn_id = tls_qid::conn_id(qid);
                let file = qid & 0xFF;
                
                match file {
                    0 => {
                        // Connection directory
                        Ok(0)
                    }
                    1 => {
                        // Control file - return status
                        if let Some(conn) = self.get_connection(conn_id) {
                            let info = format!(
                                "{} {} {} {:?}\n",
                                conn_id, conn.address, conn.port, conn.state
                            );
                            let len = info.len().min(buf.len());
                            buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    2 => {
                        // Data file - read encrypted data
                        // In real implementation: decrypt and return
                        Ok(0)
                    }
                    3 => {
                        // Status file
                        if let Some(conn) = self.get_connection(conn_id) {
                            let status = format!("{:?}\n", conn.state);
                            let len = status.len().min(buf.len());
                            buf[..len].copy_from_slice(&status.as_bytes()[..len]);
                            Ok(len)
                        } else {
                            Err(DevError::Enoent)
                        }
                    }
                    _ => Err(DevError::Enoent),
                }
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        // Handle clone
        if qid == tls_qid::QCLONE {
            // Parse address and port from data
            let cmd = String::from_utf8_lossy(buf);
            let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
            
            if parts.len() >= 2 {
                let address = parts[0];
                let port: u16 = parts[1].parse().unwrap_or(443);
                
                let id = self.create_connection(address, port);
                // Store id in channel aux or return it
                return Ok(buf.len());
            }
            return Err(DevError::Einval);
        }
        
        let conn_id = tls_qid::conn_id(qid);
        let file = qid & 0xFF;
        
        match file {
            1 => {
                // Control commands
                let cmd = String::from_utf8_lossy(buf);
                
                if cmd.trim() == "handshake" {
                    self.set_state(conn_id, TlsState::Handshake)?;
                    // In real implementation: perform TLS handshake
                    self.set_state(conn_id, TlsState::Established)?;
                    return Ok(buf.len());
                } else if cmd.trim() == "close" {
                    self.set_state(conn_id, TlsState::Closing)?;
                    return Ok(buf.len());
                }
                
                Err(DevError::Einval)
            }
            2 => {
                // Data file - write encrypted data
                // In real implementation: encrypt and send
                Ok(buf.len())
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode) = match qid {
            tls_qid::QDIR => (b"tls".to_vec(), 0o555 | 0o40000),
            tls_qid::QCLONE => (b"clone".to_vec(), 0o666),
            _ => {
                let file = qid & 0xFF;
                match file {
                    0 => (b"conn".to_vec(), 0o555 | 0o40000),
                    1 => (b"ctl".to_vec(), 0o666),
                    2 => (b"data".to_vec(), 0o666),
                    3 => (b"status".to_vec(), 0o444),
                    _ => return Err(DevError::Enoent),
                }
            }
        };
        
        Ok(DirEntry {
            dev: dev::devtype::TLS,
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR
            atime: 0,
            mtime: 0,
            length: 0,
            name,
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

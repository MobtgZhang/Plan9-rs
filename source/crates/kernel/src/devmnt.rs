
//! Mnt Device Implementation
//!
//! Implements the Plan 9 mount device (#M) for 9P filesystem mounting.
//!
//! ## Overview
//!
//! The mnt device provides the mount driver functionality for mounting
//! 9P filesystem servers.
//!
//! ## Namespace Structure
//!
//! ```
//! /mnt/
//! └── N/              (mount points)
//!     └── ctl         (mount configuration)
//! ```

extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};
use crate::plan9_common::sync::{ Spinlock };use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{ AtomicU64, Ordering };
/// Maximum number of mount points
const MNT_MAX_MOUNTS: usize = 16;

/// Qid paths for mnt device
mod mnt_qid {
    pub const QDIR: u64 = 0;
    pub const QCTL: u64 = 1;
    
    /// Extract mount ID from qid
    pub fn mount_id(qid: u64) -> usize {
        ((qid >> 4) & 0xFF) as usize
    }
}

/// Mount information
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Mount ID
    id: usize,
    /// Server address
    address: String,
    /// Mount point path
    path: String,
    /// Whether mounted
    mounted: bool,
    /// 9P version (e.g., "9P2000", "9P2000.u")
    version: String,
}

/// Mnt device structure
pub struct MntDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Mount points
    mounts: Spinlock<Vec<MountInfo>>,
    /// Next mount ID
    next_id: AtomicU64,
}

impl MntDev {
    /// Create a new mnt device
    pub fn new() -> Self {
        Self {
            name: "mnt",
            dev_char: 'M',
            mounts: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }
    
    /// Create a new mount
    pub fn create_mount(&self, address: &str, path: &str) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let mut mounts = self.mounts.lock();
        
        let info = MountInfo {
            id,
            address: alloc::string::String::from(address),
            path: alloc::string::String::from(path),
            mounted: false,
            version: alloc::string::String::from("9P2000"),
        };
        
        // Ensure vector is large enough
        while mounts.len() <= id {
            mounts.push(MountInfo {
                id: 0,
                address: String::new(),
                path: String::new(),
                mounted: false,
                version: String::new(),
            });
        }
        mounts[id] = info;
        
        id
    }
    
    /// Get mount info
    pub fn get_mount(&self, id: usize) -> Option<MountInfo> {
        let mounts = self.mounts.lock();
        mounts.get(id).filter(|m| m.id == id).cloned()
    }
    
    /// Mount a server
    pub fn mount(&self, id: usize, version: &str) -> Result<(), DevError> {
        let mut mounts = self.mounts.lock();
        if let Some(mount) = mounts.get_mut(id) {
            if mount.mounted {
                return Err(DevError::Eexists);
            }
            mount.mounted = true;
            if !version.is_empty() {
                mount.version = alloc::string::String::from(version);
            }
            Ok(())
        } else {
            Err(DevError::Enoent)
        }
    }
    
    /// Unmount a server
    pub fn unmount(&self, id: usize) -> Result<(), DevError> {
        let mut mounts = self.mounts.lock();
        if let Some(mount) = mounts.get_mut(id) {
            if !mount.mounted {
                return Err(DevError::Eio);
            }
            mount.mounted = false;
            Ok(())
        } else {
            Err(DevError::Enoent)
        }
    }
}

impl Dev for MntDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::MNT,
            Qid::new(mnt_qid::QDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        if qid == mnt_qid::QDIR {
            // At top level - look for mount point directories
            if name.is_empty() || name == "." {
                return Ok(Some(ch.qid));
            }
            
            // Try to parse as mount number
            if let Ok(id) = name.parse::<usize>() {
                let mounts = self.mounts.lock();
                if let Some(mount) = mounts.get(id) {
                    if mount.id == id && mount.mounted {
                        drop(mounts);
                        ch.qid = Qid::new((id as u64) << 4 | mnt_qid::QDIR, 0, qidtype::DIR);
                        return Ok(Some(ch.qid));
                    }
                }
            }
        } else {
            // At mount level - look for ctl
            let mount_id = mnt_qid::mount_id(qid);
            if name == "ctl" {
                ch.qid = Qid::new((mount_id as u64) << 4 | mnt_qid::QCTL, 0, 0);
                return Ok(Some(ch.qid));
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        // Can't create files in mnt device
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            mnt_qid::QDIR => {
                // Read directory - list mount points
                let mut pos = 0;
                let mounts = self.mounts.lock();
                
                for (i, mount) in mounts.iter().enumerate() {
                    if mount.id == i && mount.mounted {
                        if pos >= offset as usize {
                            let entry = format!("{}\n", i);
                            let entry_bytes = entry.as_bytes();
                            if pos + entry_bytes.len() <= buf.len() {
                                buf[pos..pos + entry_bytes.len()].copy_from_slice(entry_bytes);
                                pos += entry_bytes.len();
                            } else {
                                break;
                            }
                        }
                    }
                }
                Ok(pos)
            }
            _ => {
                if qid & 0xF == mnt_qid::QCTL {
                    // Read mount status
                    let mount_id = mnt_qid::mount_id(qid);
                    if let Some(mount) = self.get_mount(mount_id) {
                        let status = format!(
                            "{} {} {} {}\n",
                            mount_id, mount.address, mount.path, mount.version
                        );
                        let len = status.len().min(buf.len());
                        buf[..len].copy_from_slice(&status.as_bytes()[..len]);
                        Ok(len)
                    } else {
                        Err(DevError::Enoent)
                    }
                } else {
                    Err(DevError::Enoent)
                }
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let _qid =ch.qid.path;
        
        // Parse command
        let cmd = String::from_utf8_lossy(buf);
        let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(DevError::Einval);
        }
        
        match parts[0] {
            "mount" => {
                // mount address path [version]
                if parts.len() >= 3 {
                    let address = parts[1];
                    let path = parts[2];
                    let version = parts.get(3).unwrap_or(&"9P2000");
                    
                    let id = self.create_mount(address, path);
                    self.mount(id, version)?;
                    
                    // Return mount ID
                    return Ok(buf.len());
                }
                Err(DevError::Einval)
            }
            "unmount" => {
                // unmount id
                if parts.len() >= 2 {
                    if let Ok(id) = parts[1].parse::<usize>() {
                        self.unmount(id)?;
                        return Ok(buf.len());
                    }
                }
                Err(DevError::Einval)
            }
            _ => Err(DevError::Einval),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode, _qtype) = if qid == mnt_qid::QDIR {
            (b"mnt".to_vec(), 0o555 | 0o40000, qidtype::DIR)
        } else {
            (b"ctl".to_vec(), 0o666, 0)
        };
        
        Ok(DirEntry {
            dev: dev::devtype::MNT,
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

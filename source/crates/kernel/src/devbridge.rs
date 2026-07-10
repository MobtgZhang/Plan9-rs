

//! Bridge Device Implementation
//!
//! Implements the Plan 9 bridge device (#l) for Ethernet bridging.
//!
//! ## Overview
//!
//! The bridge device provides Ethernet bridging functionality for connecting
//! multiple network interfaces.
//!
//! ## Namespace Structure
//!
//! ```
//! /net/
//! ├── bridgeN/       (bridge interfaces)
//! │   ├── ctl       (configuration)
//! │   ├── stats     (packet statistics)
//! │   └── cache     (MAC learning cache)
//! └── externN/      (external ports)
//!     ├── ctl       (port configuration)
//!     └── status    (port status)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{ AtomicU64, Ordering};

/// Maximum number of bridges
const BRIDGE_MAX_COUNT: usize = 4;
/// Maximum MAC entries in cache
const BRIDGE_MAC_CACHE_SIZE: usize = 256;

/// Qid paths for bridge device
mod bridge_qid {
    pub const QDIR: u64 = 0;
    pub const QCTL: u64 = 1;
    pub const QSTATS: u64 = 2;
    pub const QCACHE: u64 = 3;
    
    /// Extract bridge number from qid
    pub fn bridge_num(qid: u64) -> usize {
        ((qid >> 8) & 0xF) as usize
    }
    
    /// Extract port from qid
    pub fn port(qid: u64) -> usize {
        ((qid >> 12) & 0xF) as usize
    }
    
    /// Create bridge qid
    pub fn bridge(num: usize, file: u64) -> u64 {
        ((num as u64) << 8) | file
    }
    
    /// Create extern port qid
    pub fn extern_port(bridge: usize, port: usize, file: u64) -> u64 {
        ((bridge as u64) << 8) | ((port as u64) << 12) | file | 0x1000
    }
}

/// MAC address
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn new() -> Self {
        Self([0; 6])
    }
    
    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        Self(*bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
    
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }
    
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

/// MAC cache entry
#[derive(Debug, Clone)]
struct MacEntry {
    /// MAC address
    mac: MacAddr,
    /// Port number
    port: usize,
    /// Age counter
    age: u32,
}

/// Bridge statistics
#[derive(Debug, Default)]
struct BridgeStats {
    /// Frames received
    rx_frames: AtomicU64,
    /// Frames transmitted
    tx_frames: AtomicU64,
    /// Bytes received
    rx_bytes: AtomicU64,
    /// Bytes transmitted
    tx_bytes: AtomicU64,
    /// Dropped frames
    dropped: AtomicU64,
    /// Forwarded frames
    forwarded: AtomicU64,
    /// CAM misses
    cam_miss: AtomicU64,
}

impl Clone for BridgeStats {
    fn clone(&self) -> Self {
        Self {
            rx_frames: AtomicU64::new(self.rx_frames.load(Ordering::Relaxed)),
            tx_frames: AtomicU64::new(self.tx_frames.load(Ordering::Relaxed)),
            rx_bytes: AtomicU64::new(self.rx_bytes.load(Ordering::Relaxed)),
            tx_bytes: AtomicU64::new(self.tx_bytes.load(Ordering::Relaxed)),
            dropped: AtomicU64::new(self.dropped.load(Ordering::Relaxed)),
            forwarded: AtomicU64::new(self.forwarded.load(Ordering::Relaxed)),
            cam_miss: AtomicU64::new(self.cam_miss.load(Ordering::Relaxed)),
        }
    }
}

/// Bridge port info
#[derive(Debug, Clone)]
struct BridgePort {
    /// Port number
    num: usize,
    /// Interface name
    name: String,
    /// Port is up
    up: bool,
    /// Frames received
    rx: u64,
    /// Frames transmitted
    tx: u64,
}

/// Bridge information
#[derive(Debug, Clone)]
pub struct BridgeInfo {
    /// Bridge number
    num: usize,
    /// Bridge name
    name: String,
    /// Ports
    ports: Vec<BridgePort>,
    /// MAC cache
    mac_cache: Vec<MacEntry>,
    /// Statistics
    stats: BridgeStats,
    /// Forwarding enabled
    forwarding: bool,
    /// Learning enabled
    learning: bool,
}

/// Bridge device structure
pub struct BridgeDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Bridges
    bridges: Spinlock<Vec<BridgeInfo>>,
}

impl BridgeDev {
    /// Create a new bridge device
    pub fn new() -> Self {
        Self {
            name: "bridge",
            dev_char: 'l',
            bridges: Spinlock::new(Vec::new()),
        }
    }
    
    /// Create a new bridge
    pub fn create_bridge(&self, name: &str) -> usize {
        let mut bridges = self.bridges.lock();
        let num = bridges.len();
        
        let info = BridgeInfo {
            num,
            name: alloc::string::String::from(name),
            ports: Vec::new(),
            mac_cache: Vec::new(),
            stats: BridgeStats::default(),
            forwarding: true,
            learning: true,
        };
        
        bridges.push(info);
        num
    }
    
    /// Get bridge info
    pub fn get_bridge(&self, num: usize) -> Option<BridgeInfo> {
        let bridges = self.bridges.lock();
        bridges.get(num).cloned()
    }
    
    /// Learn MAC address
    pub fn learn_mac(&self, bridge_num: usize, mac: MacAddr, port: usize) {
        let mut bridges = self.bridges.lock();
        if let Some(bridge) = bridges.get_mut(bridge_num) {
            // Update or add MAC entry
            for entry in bridge.mac_cache.iter_mut() {
                if entry.mac == mac {
                    entry.port = port;
                    entry.age = 0;
                    return;
                }
            }
            
            // Add new entry
            if bridge.mac_cache.len() < BRIDGE_MAC_CACHE_SIZE {
                bridge.mac_cache.push(MacEntry {
                    mac,
                    port,
                    age: 0,
                });
            }
        }
    }
    
    /// Lookup MAC address
    pub fn lookup_mac(&self, bridge_num: usize, mac: &MacAddr) -> Option<usize> {
        let bridges = self.bridges.lock();
        if let Some(bridge) = bridges.get(bridge_num) {
            for entry in bridge.mac_cache.iter() {
                if entry.mac == *mac {
                    return Some(entry.port);
                }
            }
        }
        None
    }
}

impl Dev for BridgeDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::BRIDGE,
            Qid::new(bridge_qid::QDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        if qid == bridge_qid::QDIR {
            // At top level - look for bridges
            if name.starts_with("bridge") {
                if let Ok(num) = name[6..].parse::<usize>() {
                    let bridges = self.bridges.lock();
                    if num < bridges.len() {
                        drop(bridges);
                        ch.qid = Qid::new(bridge_qid::bridge(num, bridge_qid::QDIR), 0, qidtype::DIR);
                        return Ok(Some(ch.qid));
                    }
                }
            } else if name.starts_with("extern") {
                if let Ok(num) = name[6..].parse::<usize>() {
                    ch.qid = Qid::new(bridge_qid::extern_port(num, 0, bridge_qid::QDIR), 0, qidtype::DIR);
                    return Ok(Some(ch.qid));
                }
            }
        } else {
            // At bridge level
            let bridge_num = bridge_qid::bridge_num(qid);
            
            if (qid & 0x1000) != 0 {
                // Extern port
                let port = bridge_qid::port(qid);
                match name {
                    "ctl" => {
                        ch.qid = Qid::new(bridge_qid::extern_port(bridge_num, port, bridge_qid::QCTL), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    "status" => {
                        ch.qid = Qid::new(bridge_qid::extern_port(bridge_num, port, bridge_qid::QSTATS), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    _ => {}
                }
            } else {
                // Bridge directory files
                match name {
                    "ctl" => {
                        ch.qid = Qid::new(bridge_qid::bridge(bridge_num, bridge_qid::QCTL), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    "stats" => {
                        ch.qid = Qid::new(bridge_qid::bridge(bridge_num, bridge_qid::QSTATS), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    "cache" => {
                        ch.qid = Qid::new(bridge_qid::bridge(bridge_num, bridge_qid::QCACHE), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    _ => {}
                }
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            bridge_qid::QDIR => {
                // List bridges
                let mut pos = 0;
                let bridges = self.bridges.lock();
                
                for (i, _bridge) in bridges.iter().enumerate() {
                    if pos >= offset as usize {
                        let entry = format!("bridge{}\n", i);
                        let entry_bytes = entry.as_bytes();
                        if pos + entry_bytes.len() <= buf.len() {
                            buf[pos..pos + entry_bytes.len()].copy_from_slice(entry_bytes);
                            pos += entry_bytes.len();
                        } else {
                            break;
                        }
                    }
                }
                Ok(pos)
            }
            _ => {
                if (qid & 0x1000) != 0 {
                    // Extern port file
                    Ok(0)
                } else {
                    // Bridge file
                    let bridge_num = bridge_qid::bridge_num(qid);
                    let file = qid & 0xFF;
                    
                    if let Some(bridge) = self.get_bridge(bridge_num) {
                        match file {
                            bridge_qid::QSTATS => {
                                let info = format!(
                                    "rx {} tx {} rxbytes {} txbytes {} dropped {} forwarded {} cam_miss {}\n",
                                    bridge.stats.rx_frames.load(Ordering::Relaxed),
                                    bridge.stats.tx_frames.load(Ordering::Relaxed),
                                    bridge.stats.rx_bytes.load(Ordering::Relaxed),
                                    bridge.stats.tx_bytes.load(Ordering::Relaxed),
                                    bridge.stats.dropped.load(Ordering::Relaxed),
                                    bridge.stats.forwarded.load(Ordering::Relaxed),
                                    bridge.stats.cam_miss.load(Ordering::Relaxed),
                                );
                                let len = info.len().min(buf.len());
                                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                                Ok(len)
                            }
                            bridge_qid::QCACHE => {
                                let mut pos = 0;
                                for entry in &bridge.mac_cache {
                                    let line = format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {}\n",
                                        entry.mac.0[0], entry.mac.0[1], entry.mac.0[2],
                                        entry.mac.0[3], entry.mac.0[4], entry.mac.0[5],
                                        entry.port
                                    );
                                    let line_bytes = line.as_bytes();
                                    if pos + line_bytes.len() <= buf.len() {
                                        buf[pos..pos + line_bytes.len()].copy_from_slice(line_bytes);
                                        pos += line_bytes.len();
                                    } else {
                                        break;
                                    }
                                }
                                Ok(pos)
                            }
                            _ => Ok(0),
                        }
                    } else {
                        Err(DevError::Enoent)
                    }
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
            "create" => {
                // Create new bridge
                let name = parts.get(1).unwrap_or(&"bridge");
                self.create_bridge(name);
                Ok(buf.len())
            }
            "add" => {
                // Add port to bridge
                // "add bridge port interface"
                Err(DevError::Enoent)  // Simplified
            }
            _ => Err(DevError::Einval),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode, _qtype) = if qid == bridge_qid::QDIR {
            (b"bridge".to_vec(), 0o555 | 0o40000, qidtype::DIR)
        } else {
            (b"data".to_vec(), 0o666, 0)
        };
        
        Ok(DirEntry {
            dev: dev::devtype::BRIDGE,
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

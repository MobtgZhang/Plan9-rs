//! SD (Storage/Disk) Device Implementation
//!
//! Implements the Plan 9 SD device (#s) for storage access.
//!
//! ## Overview
//!
//! The SD device provides access to disk storage through various interfaces
//! (ATA, SCSI, VirtIO). It supports partitioning and raw block access.
//!
//! ## Namespace Structure
//!
//! ```
//! #s/
//! ├── sd0/              (first storage unit)
//! │   ├── ctl          (control file)
//! │   ├── raw          (raw block access)
//! │   ├── 0            (partition 0)
//! │   ├── 1            (partition 1)
//! │   ├── ...          (more partitions)
//! │   └── part         (partition info)
//! └── sd1/             (second storage unit, etc.)
//! ```

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Dirtab, Error as DevError, qidtype};
use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Maximum number of SD units
const SD_MAX_UNITS: usize = 8;
/// Maximum partitions per unit
const SD_MAX_PARTS: usize = 16;
/// Block size
const SD_BLOCK_SIZE: usize = 512;

/// Qid paths for SD device
mod sd_qid {
    use super::*;
    
    /// Top-level directory
    pub const QTOPDIR: u64 = 0;
    /// Unit directory (shift by this to get unit-specific qids)
    pub const UNIT_SHIFT: u64 = 8;
    /// Partition bits
    pub const PART_SHIFT: u64 = 4;
    
    /// Qid type values
    pub const QCTL: u64 = 1;
    pub const QRAW: u64 = 2;
    pub const QPART: u64 = 3;
    
    /// Extract unit number from qid
    pub fn unit(qid: u64) -> usize {
        ((qid >> UNIT_SHIFT) & 0xFF) as usize
    }
    
    /// Extract partition number from qid
    pub fn part(qid: u64) -> usize {
        ((qid >> PART_SHIFT) & 0x0F) as usize
    }
    
    /// Create unit directory qid
    pub fn unit_dir(unit: usize) -> u64 {
        ((unit as u64) << UNIT_SHIFT) | QTOPDIR
    }
    
    /// Create control file qid
    pub fn ctl(unit: usize) -> u64 {
        ((unit as u64) << UNIT_SHIFT) | QCTL
    }
    
    /// Create raw device qid
    pub fn raw(unit: usize) -> u64 {
        ((unit as u64) << UNIT_SHIFT) | QRAW
    }
    
    /// Create partition qid
    pub fn part_file(unit: usize, part: usize) -> u64 {
        ((unit as u64) << UNIT_SHIFT) | ((part as u64) << PART_SHIFT) | QPART
    }
    
    /// Check if qid is a directory
    pub fn is_dir(qid: u64) -> bool {
        (qid & 0xF) == QTOPDIR
    }
}

/// Partition information
#[derive(Debug, Clone)]
pub struct SdPart {
    /// Partition name
    pub name: String,
    /// Start sector
    pub start: u64,
    /// End sector
    pub end: u64,
    /// Valid flag
    pub valid: bool,
}

impl SdPart {
    /// Create a new partition
    pub fn new(name: &str, start: u64, end: u64) -> Self {
        Self {
            name: name.to_string(),
            start,
            end,
            valid: true,
        }
    }
}

/// SD Unit - represents a single storage device
pub struct SdUnit {
    /// Unit number
    pub unit: usize,
    /// Device is online
    pub online: AtomicBool,
    /// Device is removable
    pub removable: bool,
    /// Block size
    pub block_size: usize,
    /// Total sectors
    pub sectors: u64,
    /// Partition table
    pub parts: Spinlock<Vec<SdPart>>,
    /// Device model
    pub model: [u8; 40],
    /// Device serial
    pub serial: [u8; 20],
}

impl SdUnit {
    /// Create a new SD unit
    pub fn new(unit: usize) -> Self {
        Self {
            unit,
            online: AtomicBool::new(false),
            removable: false,
            block_size: SD_BLOCK_SIZE,
            sectors: 0,
            parts: Spinlock::new(Vec::new()),
            model: [0; 40],
            serial: [0; 20],
        }
    }
    
    /// Set unit online with info
    pub fn set_online(&self, sectors: u64, block_size: usize) {
        self.sectors = sectors;
        self.block_size = block_size;
        self.online.store(true, Ordering::SeqCst);
    }
    
    /// Add a partition
    pub fn add_part(&self, name: &str, start: u64, end: u64) -> Result<(), DevError> {
        if start > end || end > self.sectors {
            return Err(DevError::Einval);
        }
        
        let mut parts = self.parts.lock();
        
        // Check if partition name already exists
        for part in parts.iter() {
            if part.name == name && part.valid {
                return Err(DevError::Eexists);
            }
        }
        
        // Remove invalid partitions with same name
        parts.retain(|p| p.name != name || !p.valid);
        
        // Add new partition
        parts.push(SdPart::new(name, start, end));
        Ok(())
    }
    
    /// Remove a partition
    pub fn del_part(&self, name: &str) -> Result<(), DevError> {
        let mut parts = self.parts.lock();
        
        for part in parts.iter_mut() {
            if part.name == name && part.valid {
                part.valid = false;
                return Ok(());
            }
        }
        
        Err(DevError::Enoent)
    }
    
    /// Get partition by index
    pub fn get_part(&self, index: usize) -> Option<SdPart> {
        let parts = self.parts.lock();
        parts.get(index).filter(|p| p.valid).cloned()
    }
    
    /// Get partition by name
    pub fn get_part_by_name(&self, name: &str) -> Option<SdPart> {
        let parts = self.parts.lock();
        parts.iter().find(|p| p.name == name && p.valid).cloned()
    }
}

/// SD Device structure
pub struct SdDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Storage units
    units: [Option<SdUnit>; SD_MAX_UNITS],
    /// Next unit number
    next_unit: AtomicUsize,
}

impl SdDev {
    /// Create a new SD device
    pub fn new() -> Self {
        let mut units = [const { None }; SD_MAX_UNITS];
        for i in 0..SD_MAX_UNITS {
            units[i] = Some(SdUnit::new(i));
        }
        
        Self {
            name: "sd",
            dev_char: 's',
            units,
            next_unit: AtomicUsize::new(0),
        }
    }
    
    /// Get unit by number
    pub fn get_unit(&self, unit: usize) -> Option<&SdUnit> {
        self.units.get(unit)?.as_ref()
    }
    
    /// Allocate a new unit number
    pub fn alloc_unit(&self) -> Option<usize> {
        let unit = self.next_unit.fetch_add(1, Ordering::Relaxed);
        if unit < SD_MAX_UNITS {
            Some(unit)
        } else {
            None
        }
    }
}

impl Dev for SdDev {
    fn attach(&mut self, spec: Option<&str>) -> Result<Chan, DevError> {
        // Attach to #s - top level directory
        Ok(Chan::new(
            dev::devtype::SD,
            Qid::new(sd_qid::QTOPDIR, 0, qidtype::DIR),
            0oOREAD,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid;
        
        // If already at a unit, look for partitions or files
        let unit = sd_qid::unit(qid.path);
        
        if sd_qid::is_dir(qid.path) {
            // At top level or unit level
            if unit == 0 {
                // At top level - look for sdN
                if let Some(num) = parse_sd_name(name) {
                    if num < SD_MAX_UNITS && self.units[num].is_some() {
                        ch.qid = Qid::new(sd_qid::unit_dir(num), 0, qidtype::DIR);
                        return Ok(Some(ch.qid));
                    }
                }
            } else if let Some(unit_ref) = self.get_unit(unit) {
                // At unit level - look for ctl, raw, or partition
                match name {
                    "ctl" => {
                        ch.qid = Qid::new(sd_qid::ctl(unit), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    "raw" => {
                        ch.qid = Qid::new(sd_qid::raw(unit), 0, 0);
                        return Ok(Some(ch.qid));
                    }
                    "part" => {
                        ch.qid = Qid::new(
                            ((unit as u64) << sd_qid::UNIT_SHIFT) | 0x10,
                            0, qidtype::DIR
                        );
                        return Ok(Some(ch.qid));
                    }
                    _ => {
                        // Check for partition by name
                        if let Some(_part) = unit_ref.get_part_by_name(name) {
                            // Parse partition index from the parts list
                            let parts = unit_ref.parts.lock();
                            for (i, p) in parts.iter().enumerate() {
                                if p.name == name && p.valid {
                                    ch.qid = Qid::new(sd_qid::part_file(unit, i), 0, 0);
                                    return Ok(Some(ch.qid));
                                }
                            }
                        }
                        
                        // Check for numeric partition (0-15)
                        if let Ok(part_num) = name.parse::<usize>() {
                            if part_num < SD_MAX_PARTS {
                                if let Some(_part) = unit_ref.get_part(part_num) {
                                    ch.qid = Qid::new(sd_qid::part_file(unit, part_num), 0, 0);
                                    return Ok(Some(ch.qid));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, ch: &mut Chan, name: &str, _mode: u8, perm: u32) -> Result<(), DevError> {
        // Can't create files in SD device
        let _ = (ch, name, perm);
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid;
        let unit = sd_qid::unit(qid.path);
        
        // Get unit reference
        let unit_ref = self.get_unit(unit).ok_or(DevError::Enoent)?;
        
        // Check if unit is online
        if !unit_ref.online.load(Ordering::SeqCst) {
            return Err(DevError::Eio);
        }
        
        match qid.path & 0xF {
            sd_qid::QTOPDIR => {
                // Read directory - list units
                let mut pos = 0;
                let unit_dir_size = 64; // Approximate dir entry size
                let start_idx = (offset / unit_dir_size as u64) as usize;
                
                for (i, unit_opt) in self.units.iter().enumerate().skip(start_idx) {
                    if let Some(ref u) = unit_opt {
                        if u.online.load(Ordering::SeqCst) {
                            if pos + 32 > buf.len() {
                                break;
                            }
                            
                            let name = format!("sd{}", u.unit);
                            let entry = format_dir_entry(
                                &name,
                                sd_qid::unit_dir(u.unit),
                                0,
                                qidtype::DIR,
                                0o755 | 0o40000,
                            );
                            
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
            sd_qid::QCTL => {
                // Read control file - return unit info
                let info = format!(
                    "online {} sectors {} block {} model {}\n",
                    if unit_ref.online.load(Ordering::SeqCst) { 1 } else { 0 },
                    unit_ref.sectors,
                    unit_ref.block_size,
                    String::from_utf8_lossy(&unit_ref.model)
                );
                
                let start = offset as usize;
                if start >= info.len() {
                    return Ok(0);
                }
                
                let end = (start + buf.len()).min(info.len());
                let slice = &info.as_bytes()[start..end];
                buf[..slice.len()].copy_from_slice(slice);
                Ok(slice.len())
            }
            sd_qid::QRAW | sd_qid::QPART => {
                // Read from raw device or partition
                // In a real implementation, this would read from the block device
                // For now, return zeros (simulating empty device)
                let part_num = sd_qid::part(qid.path);
                
                if part_num > 0 {
                    // Partition read
                    if let Some(part) = unit_ref.get_part(part_num - 1) {
                        let start_sector = part.start;
                        let end_sector = part.end;
                        let sector_offset = offset / SD_BLOCK_SIZE as u64;
                        let sector_byte_offset = (offset % SD_BLOCK_SIZE as u64) as usize;
                        
                        // Calculate how many sectors we can read
                        let max_sectors = ((end_sector - start_sector) as usize)
                            .min(buf.len() / SD_BLOCK_SIZE + 1);
                        
                        // In real implementation: read from storage device
                        // For now, return zeros
                        let bytes_to_read = (buf.len())
                            .min(((end_sector - start_sector - sector_offset) * SD_BLOCK_SIZE as u64) as usize);
                        
                        buf[..bytes_to_read].fill(0);
                        Ok(bytes_to_read)
                    } else {
                        Err(DevError::Enoent)
                    }
                } else {
                    // Raw read
                    let max_sectors = (unit_ref.sectors as usize).min(buf.len() / SD_BLOCK_SIZE + 1);
                    buf[..(max_sectors * SD_BLOCK_SIZE).min(buf.len())].fill(0);
                    Ok(max_sectors * SD_BLOCK_SIZE)
                }
            }
            _ => {
                Err(DevError::Enoent)
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid;
        let unit = sd_qid::unit(qid.path);
        
        let unit_ref = self.get_unit(unit).ok_or(DevError::Enoent)?;
        
        if !unit_ref.online.load(Ordering::SeqCst) {
            return Err(DevError::Eio);
        }
        
        match qid.path & 0xF {
            sd_qid::QCTL => {
                // Control commands
                let cmd_str = String::from_utf8_lossy(buf);
                
                // Parse command
                if cmd_str.starts_with("part ") {
                    // part name start end
                    let parts: Vec<&str> = cmd_str.trim().split_whitespace().collect();
                    if parts.len() >= 4 {
                        let name = parts[1];
                        let start = parts[2].parse::<u64>().map_err(|_| DevError::Einval)?;
                        let end = parts[3].parse::<u64>().map::<(), _>(|_| DevError::Einval).map_err(|_| DevError::Einval)?;
                        
                        unit_ref.add_part(name, start, end)?;
                        return Ok(buf.len());
                    }
                } else if cmd_str.trim() == "flush" {
                    // Flush cache
                    return Ok(buf.len());
                }
                
                Err(DevError::Einval)
            }
            sd_qid::QRAW | sd_qid::QPART => {
                // Write to raw device or partition
                // In real implementation: write to storage device
                Ok(buf.len())
            }
            _ => {
                Err(DevError::Eperm)
            }
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid;
        let unit = sd_qid::unit(qid.path);
        
        let (name, mode, qtype) = if sd_qid::is_dir(qid.path) {
            if unit == 0 {
                ("sd".as_bytes().to_vec(), 0o555 | 0o40000, qidtype::DIR)
            } else {
                (format!("sd{}", unit).into_bytes(), 0o555 | 0o40000, qidtype::DIR)
            }
        } else {
            match qid.path & 0xF {
                sd_qid::QCTL => (b"ctl".to_vec(), 0o666, 0),
                sd_qid::QRAW => (b"raw".to_vec(), 0o666, 0),
                _ => (b"part".to_vec(), 0o666, 0),
            }
        };
        
        Ok(DirEntry {
            dev: dev::devtype::SD,
            qid,
            mode: mode | 0o120000, // S_IFBLK for raw/partition, S_IFDIR for dirs
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

/// Parse sd name like "sd0" to unit number
fn parse_sd_name(name: &str) -> Option<usize> {
    if name.starts_with("sd") {
        name[2..].parse().ok()
    } else {
        None
    }
}

/// Format a directory entry (Plan 9 format)
fn format_dir_entry(name: &str, path: u64, vers: u32, qtype: u8, perm: u32) -> alloc::string::String {
    // Simplified - real implementation would use proper binary encoding
    alloc::format!("{} {} {} {} {} {}\n", name, path, vers, qtype, perm, 0)
}

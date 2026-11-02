

//! SD (Storage/Disk) Device Implementation
//!
//! Implements the Plan 9 SD device (#s) for storage access.
//!
//! ## Overview
//!
//! The SD device provides access to disk storage through various interfaces
//! (ATA, SCSI, VirtIO, AHCI). It supports partitioning and raw block access.
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


extern crate alloc;

use crate::dev::{ self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype };
use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{ AtomicBool, AtomicUsize, Ordering };
/// Maximum number of SD units
const SD_MAX_UNITS: usize = 8;
/// Maximum partitions per unit
const SD_MAX_PARTS: usize = 16;
/// Block size
const SD_BLOCK_SIZE: usize = 512;

/// SD operation error type
#[derive(Debug, Clone, Copy)]
pub enum SdError {
    /// No such device
    NoDevice,
    /// Device not online
    NotOnline,
    /// Invalid operation
    Invalid,
    /// I/O error
    IoError,
    /// Timeout
    Timeout,
    /// Media error
    MediaError,
    /// Write protected
    WriteProtected,
    /// No media
    NoMedia,
}

impl From<SdError> for DevError {
    fn from(e: SdError) -> Self {
        match e {
            SdError::NoDevice => DevError::Enoent,
            SdError::NotOnline => DevError::Eio,
            SdError::Invalid => DevError::Einval,
            SdError::IoError => DevError::Eio,
            SdError::Timeout => DevError::Eio,
            SdError::MediaError => DevError::Eio,
            SdError::WriteProtected => DevError::Eperm,
            SdError::NoMedia => DevError::Eio,
        }
    }
}

/// SD operation result
pub type SdResult<T> = Result<T, SdError>;

/// Storage device backend trait
/// This trait allows different storage backends (ATA, AHCI, VirtIO, SCSI) to be used
pub trait StorageBackend: Send + Sync {
    /// Read sectors from the device
    fn read_sectors(&self, lba: u64, count: usize, buf: &mut [u8]) -> SdResult<usize>;
    
    /// Write sectors to the device
    fn write_sectors(&mut self, lba: u64, count: usize, buf: &[u8]) -> SdResult<usize>;
    
    /// Flush any pending writes
    fn flush(&mut self) -> SdResult<()>;
    
    /// Get device capacity in sectors
    fn capacity(&self) -> u64;
    
    /// Get block size
    fn block_size(&self) -> usize;
    
    /// Check if device is online
    fn is_online(&self) -> bool;
    
    /// Get device model string
    fn model(&self) -> [u8; 40];
    
    /// Get device serial string
    fn serial(&self) -> [u8; 20];
}

/// Qid paths for SD device
mod sd_qid {
//     use super::*;
    
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
            name: String::from(name),
            start,
            end,
            valid: true,
        }
    }
    
    /// Get partition size in sectors
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
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
    /// Storage backend
    backend: Spinlock<Option<Arc<dyn StorageBackend>>>,
    /// Lock for I/O operations
    io_lock: Spinlock<()>,
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
            backend: Spinlock::new(None),
            io_lock: Spinlock::new(()),
        }
    }
    
    /// Register a storage backend
    pub fn set_backend(&mut self, backend: Arc<dyn StorageBackend>) {
        let mut backend_lock = self.backend.lock();
        
        if backend.is_online() {
            self.sectors = backend.capacity();
            self.block_size = backend.block_size();
            self.model = backend.model();
            self.serial = backend.serial();
            self.online.store(true, Ordering::SeqCst);
        }
        
        *backend_lock = Some(backend);
    }
    
    /// Set unit online with info
    pub fn set_online(&mut self, sectors: u64, block_size: usize) {
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
    
    /// Read from the underlying storage device
    pub fn read(&self, lba: u64, buf: &mut [u8]) -> SdResult<usize> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(SdError::NotOnline);
        }
        
        let _guard = self.io_lock.lock();
        let backend = self.backend.lock();
        
        if let Some(ref be) = *backend {
            be.read_sectors(lba, buf.len() / self.block_size, buf)
        } else {
            Err(SdError::NoDevice)
        }
    }
    
    /// Write to the underlying storage device
    pub fn write(&self, lba: u64, buf: &[u8]) -> SdResult<usize> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(SdError::NotOnline);
        }
        
        let _guard = self.io_lock.lock();
        let backend = self.backend.lock();
        
        if let Some(be) = backend.as_ref() {
            // Use raw pointer to call methods since Arc<dyn> doesn't allow mut deref
            let be_ptr = be.as_ref() as *const dyn StorageBackend as *mut dyn StorageBackend;
            unsafe { (*be_ptr).write_sectors(lba, buf.len() / self.block_size, buf) }
        } else {
            Err(SdError::NoDevice)
        }
    }
    
    /// Flush pending writes
    pub fn flush(&self) -> SdResult<()> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(SdError::NotOnline);
        }
        
        let _guard = self.io_lock.lock();
        let backend = self.backend.lock();
        
        if let Some(be) = backend.as_ref() {
            let be_ptr = be.as_ref() as *const dyn StorageBackend as *mut dyn StorageBackend;
            unsafe { (*be_ptr).flush() }
        } else {
            Err(SdError::NoDevice)
        }
    }
}

/// SD Device structure
pub struct SdDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Storage units (wrapped in UnsafeCell for interior mutability)
    units: core::cell::UnsafeCell<[Option<SdUnit>; SD_MAX_UNITS]>,
    /// Next unit number
    next_unit: AtomicUsize,
}

// SAFETY: SdDev is used in single-threaded kernel context, so Send/Sync are safe
unsafe impl Send for SdDev {}
unsafe impl Sync for SdDev {}

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
            units: core::cell::UnsafeCell::new(units),
            next_unit: AtomicUsize::new(0),
        }
    }
    
    /// Get unit by number
    pub fn get_unit(&self, unit: usize) -> Option<&SdUnit> {
        unsafe { (*self.units.get()).get(unit)?.as_ref() }
    }
    
    /// Get mutable unit by number
    pub fn get_unit_mut(&self, unit: usize) -> Option<&mut SdUnit> {
        if unit < SD_MAX_UNITS {
            unsafe { (*self.units.get()).get_unchecked_mut(unit).as_mut() }
        } else {
            None
        }
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
    
    /// Register a storage backend for a unit
    pub fn register_backend(&self, unit: usize, backend: Arc<dyn StorageBackend>) -> Result<(), DevError> {
        if unit >= SD_MAX_UNITS {
            return Err(DevError::Enoent);
        }
        let unit_ref = unsafe { (*self.units.get()).get_unchecked_mut(unit) };
        let unit_ref = unit_ref.as_mut().ok_or(DevError::Enoent)?;
        unit_ref.set_backend(backend);
        Ok(())
    }
    
    /// Get the SD device instance registered in the kernel's device table.
    ///
    /// Devices are registered as `Box<dyn Dev>`; this downcast recovers the
    /// concrete `SdDev` so the filesystem device reads from the same units
    /// that `init()` populated with AHCI backends.
    pub fn get_global() -> &'static SdDev {
        if let Some(idx) = crate::dev::devs().find_by_char('s') {
            if let Some(dev) = crate::dev::devs().get(idx) {
                if let Some(sd) = dev.as_any().downcast_ref::<SdDev>() {
                    return sd;
                }
            }
        }
        unsafe {
            struct SyncCell<T>(core::cell::UnsafeCell<T>);
            unsafe impl<T> Sync for SyncCell<T> {}
            static SD_DEV: SyncCell<Option<SdDev>> = SyncCell(core::cell::UnsafeCell::new(None));
            let ptr: *const Option<SdDev> = SD_DEV.0.get();
            if (*ptr).is_none() {
                core::ptr::write(SD_DEV.0.get(), Some(SdDev::new()));
            }
            ptr.as_ref().unwrap_unchecked().as_ref().unwrap_unchecked()
        }
    }
}

impl Dev for SdDev {
    fn init(&mut self) {
        // Probe ATA, AHCI, and NVMe backends.  Each discovered backend is
        // assigned to its own storage unit in order.
        let backends = crate::storage_backend::probe_all();
        for (unit, backend) in backends.into_iter().enumerate() {
            if unit >= SD_MAX_UNITS {
                break;
            }
            let _ = self.register_backend(unit, backend);
            crate::serial::put_bytes(b"[sd] unit registered\n");
        }
        crate::serial::put_bytes(b"[sd] backends probed\n");
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        // Attach to #s - top level directory
        Ok(Chan::new(
            dev::devtype::SD,
            Qid::new(sd_qid::QTOPDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid;
        
        // Handle ".." specially
        if name == ".." {
            // Going up from unit directory
            let unit = sd_qid::unit(qid.path);
            if unit > 0 {
                ch.qid = Qid::new(sd_qid::unit_dir(0), 0, qidtype::DIR);
            }
            return Ok(Some(ch.qid));
        }
        
        // If already at a unit, look for partitions or files
        let unit = sd_qid::unit(qid.path);
        
        if sd_qid::is_dir(qid.path) {
            // At top level or unit level
            if unit == 0 {
                // At top level - look for sdN
                if let Some(num) = parse_sd_name(name) {
                    if num < SD_MAX_UNITS && unsafe { (*self.units.get())[num].is_some() } {
                        let unit_ref = self.get_unit(num).unwrap();
                        if unit_ref.online.load(Ordering::SeqCst) {
                            ch.qid = Qid::new(sd_qid::unit_dir(num), 0, qidtype::DIR);
                            return Ok(Some(ch.qid));
                        }
                    }
                }
            } else if let Some(unit_ref) = self.get_unit(unit) {
                if unit_ref.online.load(Ordering::SeqCst) {
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
                                let parts = unit_ref.parts.lock();
                                for (i, p) in parts.iter().enumerate() {
                                    if p.name == name && p.valid {
                                        ch.qid = Qid::new(sd_qid::part_file(unit, i + 1), 0, 0);
                                        return Ok(Some(ch.qid));
                                    }
                                }
                            }
                            
                            // Check for numeric partition (1-15, 0 is raw)
                            if let Ok(part_num) = name.parse::<usize>() {
                                if part_num > 0 && part_num < SD_MAX_PARTS {
                                    if let Some(_part) = unit_ref.get_part(part_num - 1) {
                                        ch.qid = Qid::new(sd_qid::part_file(unit, part_num), 0, 0);
                                        return Ok(Some(ch.qid));
                                    }
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
                
                let units_slice: &[Option<SdUnit>; SD_MAX_UNITS] = unsafe { &(*self.units.get()) };
                for (_i, unit_opt) in units_slice.iter().enumerate().skip(start_idx) {
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
                    String::from_utf8_lossy(&unit_ref.model).trim()
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
            sd_qid::QRAW => {
                // Read from raw device
                let lba = offset / unit_ref.block_size as u64;
                let bytes_read = unit_ref.read(lba, buf)
                    .map_err(|e| DevError::from(e))?;
                Ok(bytes_read)
            }
            sd_qid::QPART => {
                // Read from partition
                let part_num = sd_qid::part(qid.path);
                
                if part_num > 0 {
                    // Partition read
                    if let Some(part) = unit_ref.get_part(part_num - 1) {
                        // Calculate offset within partition
                        let part_offset = offset;
                        let part_lba = part.start + (part_offset / unit_ref.block_size as u64);
                        
                        // Calculate how many bytes we can read from this partition
                        let part_remaining = part.end.saturating_sub(part_lba);
                        let bytes_available = (part_remaining * unit_ref.block_size as u64) as usize;
                        let bytes_to_read = buf.len().min(bytes_available);
                        
                        if bytes_to_read > 0 {
                            let mut tmp_buf = &mut buf[..bytes_to_read];
                            let _ = unit_ref.read(part_lba, &mut tmp_buf)
                                .map_err(|e| DevError::from(e))?;
                        }
                        
                        Ok(bytes_to_read)
                    } else {
                        Err(DevError::Enoent)
                    }
                } else {
                    // part_num == 0, treat as raw
                    let lba = offset / unit_ref.block_size as u64;
                    let bytes_read = unit_ref.read(lba, buf)
                        .map_err(|e| DevError::from(e))?;
                    Ok(bytes_read)
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
                        let end = parts[3].parse::<u64>().map_err(|_| DevError::Einval)?;
                        
                        unit_ref.add_part(name, start, end)?;
                        return Ok(buf.len());
                    }
                } else if cmd_str.trim() == "flush" {
                    // Flush cache
                    unit_ref.flush().map_err(|e| DevError::from(e))?;
                    return Ok(buf.len());
                } else if cmd_str.trim() == "online" {
                    // Return online status
                    return Ok(buf.len());
                }
                
                Err(DevError::Einval)
            }
            sd_qid::QRAW => {
                // Write to raw device
                let lba = offset / unit_ref.block_size as u64;
                let bytes_written = unit_ref.write(lba, buf)
                    .map_err(|e| DevError::from(e))?;
                Ok(bytes_written)
            }
            sd_qid::QPART => {
                // Write to partition
                let part_num = sd_qid::part(qid.path);
                
                if part_num > 0 {
                    if let Some(part) = unit_ref.get_part(part_num - 1) {
                        let part_offset = offset;
                        let part_lba = part.start + (part_offset / unit_ref.block_size as u64);
                        
                        // Verify write doesn't exceed partition
                        let part_remaining = part.end.saturating_sub(part_lba);
                        let bytes_available = (part_remaining * unit_ref.block_size as u64) as usize;
                        let bytes_to_write = buf.len().min(bytes_available);
                        
                        if bytes_to_write > 0 {
                            let _ = unit_ref.write(part_lba, &buf[..bytes_to_write])
                                .map_err(|e| DevError::from(e))?;
                        }
                        
                        Ok(bytes_to_write)
                    } else {
                        Err(DevError::Enoent)
                    }
                } else {
                    let lba = offset / unit_ref.block_size as u64;
                    let bytes_written = unit_ref.write(lba, buf)
                        .map_err(|e| DevError::from(e))?;
                    Ok(bytes_written)
                }
            }
            _ => {
                Err(DevError::Eperm)
            }
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid;
        let unit = sd_qid::unit(qid.path);
        
        let (name, mode, _qtype) = if sd_qid::is_dir(qid.path) {
            if unit == 0 {
                ("sd".as_bytes().to_vec(), 0o555 | 0o40000, qidtype::DIR)
            } else {
                (format!("sd{}", unit).into_bytes(), 0o555 | 0o40000, qidtype::DIR)
            }
        } else {
            match qid.path & 0xF {
                sd_qid::QCTL => (b"ctl".to_vec(), 0o666, 0),
                sd_qid::QRAW => (b"raw".to_vec(), 0o666, 0),
                _ => {
                    let part_num = sd_qid::part(qid.path);
                    if part_num > 0 {
                        let unit_ref = self.get_unit(unit).ok_or(DevError::Enoent)?;
                        if let Some(part) = unit_ref.get_part(part_num - 1) {
                            (part.name.as_bytes().to_vec(), 0o666, 0)
                        } else {
                            (b"part".to_vec(), 0o666, 0)
                        }
                    } else {
                        (b"part".to_vec(), 0o666, 0)
                    }
                }
            }
        };
        
        let length = if !sd_qid::is_dir(qid.path) && unit > 0 {
            let unit_ref = self.get_unit(unit).ok_or(DevError::Enoent)?;
            let part_num = sd_qid::part(qid.path);
            if part_num > 0 {
                if let Some(part) = unit_ref.get_part(part_num - 1) {
                    part.size() * unit_ref.block_size as u64
                } else {
                    0
                }
            } else {
                unit_ref.sectors * unit_ref.block_size as u64
            }
        } else {
            0
        };
        
        Ok(DirEntry {
            dev: dev::devtype::SD,
            qid,
            mode: mode | 0o120000,
            atime: 0,
            mtime: 0,
            length,
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
    alloc::format!("{} {} {} {} {} {}\n", name, path, vers, qtype, perm, 0)
}

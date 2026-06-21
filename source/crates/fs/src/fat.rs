//! FAT File System Implementation
//!
//! Supports FAT12, FAT16, and FAT32 file systems.
//!
//! ## Features
//! - Boot sector parsing and validation
//! - FAT12/16/32 cluster chain following
//! - Directory entry reading and parsing
//! - Long file name (LFN) support
//! - Complete read/write operations
//! - File creation and deletion
//! - Directory entry management
//! - Cluster allocation and deallocation
//!
//! ## Architecture
//! - Block device abstraction via `FatDevice` trait
//! - Buffer cache for sector I/O optimization
//! - FAT chain traversal for file access

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;

use super::common::error::Error;
use super::common::types::Qid;
use crate::vfs::{FileOperations, DirectoryOperations, DirEntry, Inode, FileType, Result};

// ============================================================================
// FAT Constants
// ============================================================================

/// FAT file system types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

/// FAT boot sector
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FatBootSector {
    pub jmp_boot: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entries: u16,
    pub total_sectors_16: u16,
    pub media: u8,
    pub fat_size_16: u16,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    // FAT32 specific
    pub fat_size_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info: u16,
    pub backup_boot: u16,
    pub reserved: [u8; 12],
    pub drive_number: u8,
    pub reserved1: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    pub fs_type: [u8; 8],
}

impl FatBootSector {
    /// Check if this is a valid FAT boot sector
    pub fn is_valid(&self) -> bool {
        // Check jump instruction
        (self.jmp_boot[0] == 0xEB && self.jmp_boot[2] == 0x90) ||
        (self.jmp_boot[0] == 0xE9)
    }

    /// Get FAT type
    pub fn fat_type(&self) -> FatType {
        let sectors_per_fat = if self.fat_size_16 != 0 {
            self.fat_size_16 as u32
        } else {
            self.fat_size_32
        };

        let data_sectors = if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        } - self.reserved_sectors as u32
        - (self.num_fats as u32 * sectors_per_fat)
        - ((self.root_entries as u32 * 32 + self.bytes_per_sector as u32 - 1) /
           self.bytes_per_sector as u32);

        let total_clusters = data_sectors / self.sectors_per_cluster as u32;

        if total_clusters < 4085 {
            FatType::Fat12
        } else if total_clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }

    /// Get bytes per sector
    pub fn bytes_per_sector(&self) -> usize {
        self.bytes_per_sector as usize
    }

    /// Get sectors per cluster
    pub fn sectors_per_cluster(&self) -> usize {
        self.sectors_per_cluster as usize
    }

    /// Get bytes per cluster
    pub fn bytes_per_cluster(&self) -> usize {
        self.bytes_per_sector() * self.sectors_per_cluster()
    }

    /// Get first FAT sector
    pub fn first_fat_sector(&self) -> u32 {
        self.reserved_sectors as u32
    }

    /// Get first root directory sector
    pub fn first_root_sector(&self) -> u32 {
        self.reserved_sectors as u32 +
        (self.num_fats as u32 * self.fat_size()) +
        (self.root_entries as u32 * 32 / self.bytes_per_sector as u32)
    }

    /// Get FAT size in sectors
    pub fn fat_size(&self) -> u32 {
        if self.fat_size_16 != 0 {
            self.fat_size_16 as u32
        } else {
            self.fat_size_32
        }
    }

    /// Get first data sector
    pub fn first_data_sector(&self) -> u32 {
        self.reserved_sectors as u32 +
        (self.num_fats as u32 * self.fat_size()) +
        if self.fat_type() != FatType::Fat32 {
            (self.root_entries as u32 * 32 + self.bytes_per_sector as u32 - 1) /
            self.bytes_per_sector as u32
        } else {
            0
        }
    }

    /// Get total sectors
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        }
    }

    /// Get root entry count
    pub fn root_entry_count(&self) -> u32 {
        if self.fat_type() == FatType::Fat32 {
            0
        } else {
            self.root_entries as u32
        }
    }
}

// ============================================================================
// FAT Directory Entry
// ============================================================================

/// FAT directory entry
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FatDirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub nt_reserved: u8,
    pub creation_time_tenth: u8,
    pub creation_time: u16,
    pub creation_date: u16,
    pub last_access_date: u16,
    pub first_cluster_high: u16,
    pub last_write_time: u16,
    pub last_write_date: u16,
    pub first_cluster_low: u16,
    pub file_size: u32,
}

impl FatDirEntry {
    /// Check if entry is free
    pub fn is_free(&self) -> bool {
        self.name[0] == 0xE5 || self.name[0] == 0x00
    }

    /// Check if entry is a long file name entry
    pub fn is_long_filename(&self) -> bool {
        self.attr == 0x0F
    }

    /// Check if entry is a directory
    pub fn is_directory(&self) -> bool {
        (self.attr & 0x10) != 0
    }

    /// Check if entry is a file
    pub fn is_file(&self) -> bool {
        (self.attr & 0x18) == 0
    }

    /// Check if entry is hidden
    pub fn is_hidden(&self) -> bool {
        (self.attr & 0x02) != 0
    }

    /// Check if entry is system
    pub fn is_system(&self) -> bool {
        (self.attr & 0x04) != 0
    }

    /// Check if entry is read-only
    pub fn is_readonly(&self) -> bool {
        (self.attr & 0x01) != 0
    }

    /// Check if entry is volume label
    pub fn is_volume_label(&self) -> bool {
        (self.attr & 0x08) != 0
    }

    /// Get first cluster number
    pub fn first_cluster(&self) -> u32 {
        let high = self.first_cluster_high as u32;
        let low = self.first_cluster_low as u32;
        (high << 16) | low
    }

    /// Set first cluster number
    pub fn set_first_cluster(&mut self, cluster: u32) {
        self.first_cluster_low = cluster as u16;
        self.first_cluster_high = (cluster >> 16) as u16;
    }

    /// Get file size
    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    /// Get short file name as string
    pub fn name_str(&self) -> alloc::string::String {
        let mut name = Vec::new();
        for &c in &self.name[0..8] {
            if c == b' ' { break; }
            name.push(c);
        }
        if !self.name[8..11].iter().all(|&c| c == b' ') {
            name.push(b'.');
            for &c in &self.name[8..11] {
                if c == b' ' { break; }
                name.push(c);
            }
        }
        alloc::string::String::from_utf8_lossy(&name).into_owned()
    }

    /// Check if this is "." entry
    pub fn is_dot(&self) -> bool {
        self.name[0] == b'.'
    }

    /// Check if this is ".." entry
    pub fn is_dot_dot(&self) -> bool {
        self.name[0] == b'.' && self.name[1] == b'.'
    }
}

/// FAT long file name entry
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FatLfnEntry {
    pub seq_number: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub lfn_type: u8,
    pub checksum: u8,
    pub name2: [u16; 6],
    pub first_cluster: u16,
    pub name3: [u16; 2],
}

impl FatLfnEntry {
    /// Get sequence number (without last flag)
    pub fn seq_number(&self) -> u8 {
        self.seq_number & 0x3F
    }

    /// Check if this is the last LFN entry
    pub fn is_last(&self) -> bool {
        (self.seq_number & 0x40) != 0
    }

    /// Get name part
    pub fn name_part(&self) -> Vec<u16> {
        let mut result = alloc::vec::Vec::new();
        result.extend_from_slice(&self.name1);
        result.extend_from_slice(&self.name2);
        result.extend_from_slice(&self.name3);
        // Remove trailing 0xFFFF and 0x0000
        while let Some(&last) = result.last() {
            if last == 0xFFFF || last == 0x0000 {
                result.pop();
            } else {
                break;
            }
        }
        result
    }
}

// ============================================================================
// FAT File
// ============================================================================

/// FAT file handle with full I/O support
pub struct FatFile<'a> {
    /// Mutable reference to the FAT file system
    fs: &'a mut FatFileSystem,
    /// First cluster of the file
    first_cluster: u32,
    /// Current file size
    size: u32,
    /// Current position in file
    position: u64,
    /// Directory entry for this file (cached)
    dir_entry: Option<FatDirEntry>,
    /// Parent directory cluster
    parent_cluster: u32,
    /// File name (for directory updates)
    name: Vec<u8>,
    /// Dirty flag (needs directory update)
    dirty: bool,
}

impl<'a> FatFile<'a> {
    /// Create a new FAT file handle
    pub fn new(
        fs: &'a mut FatFileSystem,
        first_cluster: u32,
        size: u32,
        parent_cluster: u32,
        name: &[u8],
    ) -> Self {
        Self {
            fs,
            first_cluster,
            size,
            position: 0,
            dir_entry: None,
            parent_cluster,
            name: name.to_vec(),
            dirty: false,
        }
    }

    /// Create from directory entry
    pub fn from_entry(
        fs: &'a mut FatFileSystem,
        entry: &FatDirEntry,
        parent_cluster: u32,
        name: &[u8],
    ) -> Self {
        Self {
            fs,
            first_cluster: entry.first_cluster(),
            size: entry.file_size(),
            position: 0,
            dir_entry: Some(*entry),
            parent_cluster,
            name: name.to_vec(),
            dirty: false,
        }
    }

    /// Get file size
    pub fn file_size(&self) -> u32 {
        self.size
    }

    /// Get first cluster
    pub fn first_cluster(&self) -> u32 {
        self.first_cluster
    }

    /// Set file size
    pub fn set_size(&mut self, size: u32) {
        self.size = size;
        self.dirty = true;
    }

    /// Check if file needs sync
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Get the current cluster for a given position
    fn get_cluster_for_position(&self, offset: u64) -> Result<u32> {
        let cluster_size = self.fs.boot.bytes_per_cluster() as u64;
        let cluster_index = (offset / cluster_size) as usize;

        let mut current = self.first_cluster;
        if current == 0 {
            return Err(Error::Eio);
        }

        if cluster_index == 0 {
            return Ok(current);
        }

        for _ in 0..cluster_index {
            current = self.fs.get_next_cluster(current)?;
            if current >= self.fs.fat_eoc_marker() {
                return Err(Error::Eio);
            }
        }

        Ok(current)
    }
}

impl<'a> FileOperations for FatFile<'a> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size as u64 {
            return Ok(0);
        }

        let cluster_size = self.fs.boot.bytes_per_cluster() as u64;
        let mut total_read = 0;
        let mut current_pos = offset;
        let remaining = (self.size as u64 - offset) as usize;
        let to_read = buf.len().min(remaining);

        while total_read < to_read {
            let cluster = self.get_cluster_for_position(current_pos)?;
            let cluster_offset = (current_pos % cluster_size) as usize;

            let mut cluster_buf = alloc::vec![0u8; cluster_size as usize];
            self.fs.read_cluster(cluster, &mut cluster_buf)?;

            let bytes_in_cluster = cluster_size as usize - cluster_offset;
            let remaining_in_buf = to_read - total_read;
            let to_copy = bytes_in_cluster.min(remaining_in_buf);

            buf[total_read..total_read + to_copy]
                .copy_from_slice(&cluster_buf[cluster_offset..cluster_offset + to_copy]);

            total_read += to_copy;
            current_pos += to_copy as u64;
        }

        Ok(total_read)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        let cluster_size = self.fs.boot.bytes_per_cluster() as u64;
        let mut total_written = 0;
        let mut current_pos = offset;
        let mut write_pos = 0;

        while write_pos < buf.len() {
            // Get or allocate cluster for current position
            let cluster_index = (current_pos / cluster_size) as usize;
            let cluster_offset = (current_pos % cluster_size) as usize;

            let cluster = if cluster_index == 0 && self.first_cluster == 0 {
                // Need to allocate first cluster
                let new_cluster = self.fs.alloc_cluster()?;
                self.first_cluster = new_cluster;
                self.fs.write_fat_entry(new_cluster, self.fs.fat_eoc_marker())?;
                new_cluster
            } else {
                // Find existing cluster or allocate new one
                self.get_or_allocate_cluster(cluster_index)?
            };

            // Read current cluster data
            let mut cluster_buf = alloc::vec![0u8; cluster_size as usize];
            if cluster_offset > 0 || buf.len() - write_pos < cluster_size as usize {
                self.fs.read_cluster(cluster, &mut cluster_buf)?;
            }

            // Write data to cluster buffer
            let bytes_in_cluster = cluster_size as usize - cluster_offset;
            let remaining_in_buf = buf.len() - write_pos;
            let to_copy = bytes_in_cluster.min(remaining_in_buf);

            cluster_buf[cluster_offset..cluster_offset + to_copy]
                .copy_from_slice(&buf[write_pos..write_pos + to_copy]);

            // Write cluster back
            self.fs.write_cluster(cluster, &cluster_buf)?;

            total_written += to_copy;
            write_pos += to_copy;
            current_pos += to_copy as u64;

            // Extend file size if needed
            let new_size = current_pos as u32;
            if new_size > self.size {
                self.size = new_size;
                self.dirty = true;
            }
        }

        self.dirty = true;
        Ok(total_written)
    }

    fn size(&self) -> u64 {
        self.size as u64
    }

    fn file_type(&self) -> FileType {
        FileType::File
    }

    fn qid(&self) -> Qid {
        Qid::new(self.first_cluster as u64, 0, 0)
    }

    fn truncate(&mut self, _size: u64) -> Result<()> {
        let new_size = _size as u32;

        if new_size < self.size {
            // Truncate: free clusters beyond new size
            let cluster_size = self.fs.boot.bytes_per_cluster() as u32;
            let last_cluster_index = (new_size + cluster_size - 1) / cluster_size;
            let cluster_index = (self.size + cluster_size - 1) / cluster_size;

            if last_cluster_index < cluster_index {
                // Free clusters from last_cluster_index to cluster_index
                let mut current = self.first_cluster;
                for i in 0..cluster_index {
                    let next = self.fs.get_next_cluster(current)?;
                    if i >= last_cluster_index {
                        self.fs.write_fat_entry(current, 0)?;
                    }
                    current = next;
                    if current >= self.fs.fat_eoc_marker() {
                        break;
                    }
                }
            }
        }

        self.size = new_size;
        self.dirty = true;
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        if self.dirty {
            // Update directory entry
            if let Some(ref mut entry) = self.dir_entry {
                entry.file_size = self.size;
                self.fs.update_dir_entry(self.parent_cluster, &self.name, entry)?;
            }
            self.dirty = false;
        }
        Ok(())
    }
}

impl<'a> FatFile<'a> {
    /// Get or allocate a cluster at the given index
    fn get_or_allocate_cluster(&mut self, index: usize) -> Result<u32> {
        let mut current = self.first_cluster;

        for i in 0..index {
            let next = self.fs.get_next_cluster(current)?;
            if next >= self.fs.fat_eoc_marker() {
                // Need to allocate new cluster
                let new_cluster = self.fs.alloc_cluster()?;
                self.fs.write_fat_entry(current, new_cluster)?;
                self.fs.write_fat_entry(new_cluster, self.fs.fat_eoc_marker())?;
                return Ok(new_cluster);
            }
            current = next;
        }

        Ok(current)
    }
}

// ============================================================================
// FAT File System
// ============================================================================

/// FAT file system instance
pub struct FatFileSystem {
    /// Boot sector info
    boot: FatBootSector,
    /// Device for reading sectors
    device: Option<Box<dyn FatDevice>>,
}

impl FatFileSystem {
    /// Create FAT file system from boot sector
    pub fn new(boot: FatBootSector) -> Self {
        Self {
            boot,
            device: None,
        }
    }

    /// Set the device
    pub fn set_device(&mut self, device: Box<dyn FatDevice>) {
        self.device = Some(device);
    }

    /// Get FAT type
    pub fn fat_type(&self) -> FatType {
        self.boot.fat_type()
    }

    /// Convert cluster to sector
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        (cluster - 2) as u32 * self.boot.sectors_per_cluster as u32 +
        self.boot.first_data_sector()
    }

    /// Read sector from device
    pub fn read_sector(&self, sector: u32, buf: &mut [u8]) -> Result<()> {
        if let Some(ref dev) = self.device {
            dev.read_sector(sector, buf)
        } else {
            Err(Error::Eio)
        }
    }

    /// Write sector to device
    pub fn write_sector(&self, sector: u32, buf: &[u8]) -> Result<()> {
        if let Some(ref dev) = self.device {
            dev.write_sector(sector, buf)
        } else {
            Err(Error::Eio)
        }
    }

    /// Read a cluster
    pub fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<()> {
        let sector = self.cluster_to_sector(cluster);
        let spc = self.boot.sectors_per_cluster as usize;

        for i in 0..spc {
            self.read_sector(sector + i as u32, &mut buf[i * self.boot.bytes_per_sector()..])?;
        }

        Ok(())
    }

    /// Get next cluster in FAT chain
    pub fn get_next_cluster(&self, cluster: u32) -> Result<u32> {
        match self.fat_type() {
            FatType::Fat12 => self.get_next_cluster_fat12(cluster),
            FatType::Fat16 => self.get_next_cluster_fat16(cluster),
            FatType::Fat32 => self.get_next_cluster_fat32(cluster),
        }
    }

    fn get_next_cluster_fat12(&self, cluster: u32) -> Result<u32> {
        let fat_offset = cluster * 3 / 2;
        let fat_sector = self.boot.first_fat_sector() + fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        let mut buf = [0u8; 512];
        self.read_sector(fat_sector, &mut buf)?;

        // FAT12 entries may span sector boundaries
        // An entry needs 2 bytes, so we need to check if offset+1 crosses the sector boundary
        let bytes_per_sector = self.boot.bytes_per_sector();
        let value = if offset + 1 < bytes_per_sector {
            // Both bytes are in the same sector
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            // Entry spans across sector boundary - read low byte from current sector,
            // high byte from next sector
            let low = buf[offset];
            self.read_sector(fat_sector + 1, &mut buf)?;
            u16::from_le_bytes([low, buf[0]])
        };

        if cluster & 1 != 0 {
            Ok((value >> 4) as u32)
        } else {
            Ok((value & 0xFFF) as u32)
        }
    }

    fn get_next_cluster_fat16(&self, cluster: u32) -> Result<u32> {
        let fat_offset = cluster * 2;
        let fat_sector = self.boot.first_fat_sector() + fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        let mut buf = [0u8; 512];
        self.read_sector(fat_sector, &mut buf)?;

        let value = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        Ok(value as u32)
    }

    fn get_next_cluster_fat32(&self, cluster: u32) -> Result<u32> {
        let fat_offset = cluster * 4;
        let fat_sector = self.boot.first_fat_sector() + fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        let mut buf = [0u8; 512];
        self.read_sector(fat_sector, &mut buf)?;

        let value = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        Ok(value & 0x0FFF_FFFF)
    }

    /// Read directory entries from a cluster
    pub fn read_directory(&self, start_cluster: u32) -> Result<Vec<FatDirEntry>> {
        let bpc = self.boot.bytes_per_cluster();
        let mut buf = vec![0u8; bpc];

        let mut entries = Vec::new();
        let mut current_cluster = start_cluster;

        while current_cluster >= 2 && current_cluster < 0x0FFF_FFF0 {
            self.read_cluster(current_cluster, &mut buf)?;

            for chunk in buf.chunks(32) {
                if chunk.len() < 32 { break; }

                let mut entry_bytes = [0u8; 32];
                entry_bytes.copy_from_slice(chunk);
                let entry = FatDirEntry::from_bytes(&entry_bytes);

                if entry.is_free() {
                    if entry.name[0] == 0x00 { break; }
                } else if !entry.is_long_filename() {
                    entries.push(entry);
                }
            }

            current_cluster = self.get_next_cluster(current_cluster)?;
        }

        Ok(entries)
    }

    /// Find entry in directory
    pub fn find_entry(&self, parent_cluster: u32, name: &[u8]) -> Result<Option<FatDirEntry>> {
        let entries = self.read_directory(parent_cluster)?;
        let search_name = name.to_ascii_uppercase();

        for entry in entries {
            let entry_name = entry.name_str().into_bytes();
            if entry_name.to_ascii_uppercase() == search_name {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Create a file entry
    pub fn create_entry(name: &[u8], is_dir: bool) -> Result<FatDirEntry> {
        let mut entry = FatDirEntry::default();

        // Set name (8.3 format)
        let name_upper = name.to_ascii_uppercase();
        let parts: Vec<&[u8]> = name_upper.split(|&c| c == b'.').collect();

        if let Some(name_part) = parts.first() {
            let name_bytes = name_part.iter().take(8).cloned().collect::<Vec<u8>>();
            entry.name[..name_bytes.len()].copy_from_slice(&name_bytes);
        }

        if parts.len() > 1 {
            let ext = parts[1].iter().take(3).cloned().collect::<Vec<u8>>();
            entry.name[8..8 + ext.len()].copy_from_slice(&ext);
        }

        entry.attr = if is_dir { 0x10 } else { 0x20 };

        Ok(entry)
    }

    /// Allocate a new cluster
    ///
    /// Scans the FAT for a free cluster and marks it as end of chain.
    /// Returns the cluster number on success.
    pub fn alloc_cluster(&mut self) -> Result<u32> {
        // Scan FAT for free cluster
        let fat_sectors = self.boot.fat_size();
        let entry_size = match self.fat_type() {
            FatType::Fat12 => 2,
            FatType::Fat16 => 2,
            FatType::Fat32 => 4,
        };
        let total_clusters = (fat_sectors * self.boot.bytes_per_sector() as u32) / entry_size as u32;

        for cluster in 2..total_clusters {
            let next = self.get_next_cluster(cluster)?;
            if next == 0 {
                // Found free cluster - mark as end of chain
                // In a full implementation, this would write to the FAT
                // For now, just return the cluster number
                self.write_fat_entry(cluster, self.fat_eoc_marker())?;
                return Ok(cluster);
            }
        }

        Err(Error::Enospc)
    }

    /// Get the end-of-chain marker for this FAT type
    pub fn fat_eoc_marker(&self) -> u32 {
        match self.fat_type() {
            FatType::Fat12 => 0xFF8,  // 0xFF8-0xFFF = EOC
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// Write a FAT entry
    ///
    /// Writes the FAT entry for a given cluster number.
    pub fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
        match self.fat_type() {
            FatType::Fat12 => self.write_fat_entry_fat12(cluster, value),
            FatType::Fat16 => self.write_fat_entry_fat16(cluster, value),
            FatType::Fat32 => self.write_fat_entry_fat32(cluster, value),
        }
    }

    fn write_fat_entry_fat12(&mut self, cluster: u32, value: u32) -> Result<()> {
        let fat_offset = cluster * 3 / 2;
        let fat_sector_offset = fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        let mask = if cluster & 1 != 0 {
            0x0F
        } else {
            0xFFF
        };

        // Update all FAT copies
        let num_fats = self.boot.num_fats as u32;
        for fat_num in 0..num_fats {
            let fat_sector = self.boot.first_fat_sector() + fat_num * self.boot.fat_size() + fat_sector_offset;
            
            let mut buf = vec![0u8; 512];
            self.read_sector(fat_sector, &mut buf)?;

            let new_value = if cluster & 1 != 0 {
                ((value as u16) << 4) | (u16::from_le_bytes([buf[offset], buf[offset + 1]]) & mask)
            } else {
                ((value as u16) & 0xFFF) | (u16::from_le_bytes([buf[offset], buf[offset + 1]]) & 0xF000)
            };

            buf[offset..offset + 2].copy_from_slice(&new_value.to_le_bytes());
            self.write_sector(fat_sector, &buf)?;
        }
        Ok(())
    }

    fn write_fat_entry_fat16(&mut self, cluster: u32, value: u32) -> Result<()> {
        let fat_offset = cluster * 2;
        let fat_sector_offset = fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        // Update all FAT copies
        let num_fats = self.boot.num_fats as u32;
        for fat_num in 0..num_fats {
            let fat_sector = self.boot.first_fat_sector() + fat_num * self.boot.fat_size() + fat_sector_offset;
            
            let mut buf = vec![0u8; 512];
            self.read_sector(fat_sector, &mut buf)?;
            buf[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
            self.write_sector(fat_sector, &buf)?;
        }
        Ok(())
    }

    fn write_fat_entry_fat32(&mut self, cluster: u32, value: u32) -> Result<()> {
        let fat_offset = cluster * 4;
        let fat_sector_offset = fat_offset / self.boot.bytes_per_sector() as u32;
        let offset = (fat_offset % self.boot.bytes_per_sector() as u32) as usize;

        // Update all FAT copies
        let num_fats = self.boot.num_fats as u32;
        for fat_num in 0..num_fats {
            let fat_sector = self.boot.first_fat_sector() + fat_num * self.boot.fat_size() + fat_sector_offset;
            
            let mut buf = vec![0u8; 512];
            self.read_sector(fat_sector, &mut buf)?;
            buf[offset..offset + 4].copy_from_slice(&(value & 0x0FFF_FFFF).to_le_bytes());
            self.write_sector(fat_sector, &buf)?;
        }
        Ok(())
    }

    /// Free a cluster chain
    ///
    /// Frees all clusters in the chain starting from the given cluster.
    pub fn free_chain(&mut self, start_cluster: u32) -> Result<()> {
        let mut current = start_cluster;

        while current >= 2 && current < self.fat_eoc_marker() {
            let next = self.get_next_cluster(current)?;
            self.write_fat_entry(current, 0)?;
            current = next;
        }

        Ok(())
    }

    /// Read file data following cluster chain
    ///
    /// Reads up to `buf.len()` bytes starting from the given cluster.
    pub fn read_file(&self, start_cluster: u32, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let cluster_size = self.boot.bytes_per_cluster();
        let start_cluster_offset = offset / cluster_size;
        let start_offset = offset % cluster_size;

        // Follow cluster chain to find starting position
        let mut current_cluster = start_cluster;
        for _ in 0..start_cluster_offset {
            current_cluster = self.get_next_cluster(current_cluster)?;
            if current_cluster >= self.fat_eoc_marker() {
                return Ok(0); // Reached end of file
            }
        }

        // Read first cluster
        let mut read_buf = vec![0u8; cluster_size];
        self.read_cluster(current_cluster, &mut read_buf)?;

        let mut total_read = 0;
        let mut remaining = buf.len();

        // Copy from start offset
        let to_copy = core::cmp::min(cluster_size - start_offset, remaining);
        buf[..to_copy].copy_from_slice(&read_buf[start_offset..start_offset + to_copy]);
        total_read += to_copy;
        remaining -= to_copy;

        // Continue reading clusters
        while remaining > 0 {
            current_cluster = self.get_next_cluster(current_cluster)?;
            if current_cluster >= self.fat_eoc_marker() {
                break;
            }

            self.read_cluster(current_cluster, &mut read_buf)?;
            let to_copy = core::cmp::min(cluster_size, remaining);
            buf[total_read..total_read + to_copy].copy_from_slice(&read_buf[..to_copy]);
            total_read += to_copy;
            remaining -= to_copy;
        }

        Ok(total_read)
    }
}

impl FatDirEntry {
    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut entry = Self::default();
        if bytes.len() >= 32 {
            entry.name.copy_from_slice(&bytes[0..11]);
            entry.attr = bytes[11];
            entry.nt_reserved = bytes[12];
            entry.creation_time_tenth = bytes[13];
            entry.creation_time = u16::from_le_bytes([bytes[14], bytes[15]]);
            entry.creation_date = u16::from_le_bytes([bytes[16], bytes[17]]);
            entry.last_access_date = u16::from_le_bytes([bytes[18], bytes[19]]);
            entry.first_cluster_high = u16::from_le_bytes([bytes[20], bytes[21]]);
            entry.last_write_time = u16::from_le_bytes([bytes[22], bytes[23]]);
            entry.last_write_date = u16::from_le_bytes([bytes[24], bytes[25]]);
            entry.first_cluster_low = u16::from_le_bytes([bytes[26], bytes[27]]);
            entry.file_size = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        }
        entry
    }
}

// ============================================================================
// FAT Device Trait
// ============================================================================

/// Device for reading/writing sectors
pub trait FatDevice: Send + Sync {
    /// Read a sector
    fn read_sector(&self, sector: u32, buf: &mut [u8]) -> Result<()>;
    /// Write a sector
    fn write_sector(&self, sector: u32, buf: &[u8]) -> Result<()>;
    /// Get sector size
    fn sector_size(&self) -> usize;
    /// Get total sectors
    fn total_sectors(&self) -> u64;
}

// ============================================================================
// FAT Write Operations (Extension)
// ============================================================================

impl FatFileSystem {
    /// Write data to a file
    ///
    /// This extends the file if needed, allocating new clusters.
    pub fn write_file(&mut self, path: &[u8], data: &[u8], offset: u64) -> Result<usize> {
        // Parse the path to find parent directory and file name
        let components = parse_path_components(path);
        
        if components.is_empty() {
            return Err(Error::Einval);
        }
        
        // Get file name and parent directory
        let file_name = components.last().ok_or(Error::Einval)?;
        let parent_path = if components.len() > 1 {
            &path[..path.len() - file_name.len() - 1]
        } else {
            &path[..0]
        };
        
        // Find or create the file entry
        let parent_cluster = self.find_or_create_parent(parent_path)?;
        let mut entry = self.find_entry(parent_cluster, file_name)?
            .ok_or(Error::Enoent)?;
        
        // Calculate target cluster and offset
        let cluster_size = self.boot.bytes_per_cluster() as u64;
        let target_cluster_offset = offset / cluster_size;
        let target_byte_offset = (offset % cluster_size) as usize;
        
        // Get or allocate file clusters
        let mut clusters = self.get_file_clusters(entry.first_cluster())?;
        
        // Extend clusters if needed
        while (clusters.len() as u64) <= target_cluster_offset {
            let new_cluster = self.alloc_cluster()?;
            if clusters.is_empty() {
                entry.set_first_cluster(new_cluster);
                entry.file_size = 0;
            } else {
                // Link to new cluster
                self.write_fat_entry(*clusters.last().unwrap(), new_cluster)?;
                self.write_fat_entry(new_cluster, self.fat_eoc_marker())?;
            }
            clusters.push(new_cluster);
        }
        
        // Calculate clusters needed for data
        let end_offset = offset as usize + data.len();
        let end_cluster = (end_offset as u64 + cluster_size - 1) / cluster_size;
        
        while (clusters.len() as u64) < end_cluster {
            let new_cluster = self.alloc_cluster()?;
            self.write_fat_entry(*clusters.last().unwrap(), new_cluster)?;
            self.write_fat_entry(new_cluster, self.fat_eoc_marker())?;
            clusters.push(new_cluster);
        }
        
        // Get target cluster
        let target_cluster = clusters[target_cluster_offset as usize];
        
        // Read current cluster data
        let mut cluster_buf = vec![0u8; self.boot.bytes_per_cluster()];
        self.read_cluster(target_cluster, &mut cluster_buf)?;
        
        // Write data to cluster
        let write_start = target_byte_offset;
        let write_end = core::cmp::min(write_start + data.len(), cluster_buf.len());
        let bytes_to_write = write_end - write_start;
        
        cluster_buf[write_start..write_end].copy_from_slice(&data[..bytes_to_write]);
        
        // Write cluster back
        self.write_cluster(target_cluster, &cluster_buf)?;
        
        // Update file size if extended
        let new_size = core::cmp::max(entry.file_size, offset as u32 + bytes_to_write as u32);
        entry.file_size = new_size;
        
        // Update directory entry
        self.update_dir_entry(parent_cluster, file_name, &entry)?;
        
        Ok(bytes_to_write)
    }

    /// Write a cluster to disk
    pub fn write_cluster(&mut self, cluster: u32, data: &[u8]) -> Result<()> {
        let sector = self.cluster_to_sector(cluster);
        let spc = self.boot.sectors_per_cluster as usize;
        let sector_size = self.boot.bytes_per_sector();
        
        for i in 0..spc {
            let sector_data = &data[i * sector_size..(i + 1) * sector_size];
            self.write_sector(sector + i as u32, sector_data)?;
        }
        
        Ok(())
    }

    /// Get the list of clusters for a file
    fn get_file_clusters(&self, first_cluster: u32) -> Result<Vec<u32>> {
        let mut clusters = Vec::new();
        let mut current = first_cluster;
        
        while current >= 2 && current < self.fat_eoc_marker() {
            clusters.push(current);
            current = self.get_next_cluster(current)?;
        }
        
        Ok(clusters)
    }

    /// Find or create parent directory
    fn find_or_create_parent(&self, path: &[u8]) -> Result<u32> {
        if path.is_empty() || path == b"/" {
            // Root directory
            if self.fat_type() == FatType::Fat32 {
                Ok(self.boot.root_cluster)
            } else {
                // FAT12/16 root is at fixed location
                Ok(0) // Special marker
            }
        } else {
            // Parse path and find directory
            let components = parse_path_components(path);
            let mut current_cluster = if self.fat_type() == FatType::Fat32 {
                self.boot.root_cluster
            } else {
                0
            };

            for comp in components {
                if let Some(entry) = self.find_entry(current_cluster, comp)? {
                    if entry.is_directory() {
                        current_cluster = entry.first_cluster();
                    } else {
                        return Err(Error::Enotdir);
                    }
                } else {
                    return Err(Error::Enoent);
                }
            }

            Ok(current_cluster)
        }
    }

    /// Find or update a directory entry slot in the directory cluster chain
    ///
    /// Returns the sector and offset where the entry should be written.
    fn find_entry_slot(&mut self, parent_cluster: u32, name: &[u8]) -> Result<Option<(u32, usize)>> {
        let bpc = self.boot.bytes_per_cluster();
        let mut buf = vec![0u8; bpc];
        let mut current_cluster = parent_cluster;

        let search_name = name.to_ascii_uppercase();

        while current_cluster >= 2 && current_cluster < 0x0FFF_FFF0 {
            self.read_cluster(current_cluster, &mut buf)?;

            for offset in (0..bpc).step_by(32) {
                let chunk = &buf[offset..offset + 32];
                if chunk.len() < 32 { break; }

                let entry = FatDirEntry::from_bytes(chunk);

                // Check if this slot is free or matches our target
                if entry.is_free() {
                    // Return this free slot
                    let sector = self.cluster_to_sector(current_cluster);
                    let sector_offset = offset / self.boot.bytes_per_sector();
                    return Ok(Some((sector + sector_offset as u32, offset % self.boot.bytes_per_sector())));
                }

                // Check if this is our target entry
                let entry_name = entry.name_str().into_bytes();
                if entry_name.to_ascii_uppercase() == search_name {
                    let sector = self.cluster_to_sector(current_cluster);
                    let sector_offset = offset / self.boot.bytes_per_sector();
                    return Ok(Some((sector + sector_offset as u32, offset % self.boot.bytes_per_sector())));
                }
            }

            current_cluster = self.get_next_cluster(current_cluster)?;
        }

        Ok(None)
    }

    /// Find a free entry slot for creating a new file
    fn find_free_slot(&mut self, parent_cluster: u32) -> Result<Option<(u32, usize)>> {
        let bpc = self.boot.bytes_per_cluster();
        let mut buf = vec![0u8; bpc];
        let mut current_cluster = parent_cluster;

        while current_cluster >= 2 && current_cluster < 0x0FFF_FFF0 {
            self.read_cluster(current_cluster, &mut buf)?;

            for offset in (0..bpc).step_by(32) {
                let chunk = &buf[offset..offset + 32];
                if chunk.len() < 32 { break; }

                let entry = FatDirEntry::from_bytes(chunk);
                if entry.is_free() {
                    // Found a free slot
                    let sector = self.cluster_to_sector(current_cluster);
                    let sector_offset = offset / self.boot.bytes_per_sector();
                    return Ok(Some((sector + sector_offset as u32, offset % self.boot.bytes_per_sector())));
                }
            }

            current_cluster = self.get_next_cluster(current_cluster)?;
        }

        // No free slot found - need to allocate a new cluster for the directory
        let new_cluster = self.alloc_cluster()?;
        self.write_fat_entry(new_cluster, self.fat_eoc_marker())?;

        // Clear the new cluster
        let cluster_buf = vec![0u8; bpc];
        self.write_cluster(new_cluster, &cluster_buf)?;

        let sector = self.cluster_to_sector(new_cluster);
        Ok(Some((sector, 0)))
    }

    /// Update a directory entry in the parent directory
    pub fn update_dir_entry(&mut self, parent_cluster: u32, name: &[u8], entry: &FatDirEntry) -> Result<()> {
        // Find the entry location
        if let Some((sector, offset)) = self.find_entry_slot(parent_cluster, name)? {
            let sector_size = self.boot.bytes_per_sector();
            let mut buf = vec![0u8; sector_size];

            // Read the sector containing the entry
            self.read_sector(sector, &mut buf)?;

            // Write the updated entry
            let entry_bytes = Self::entry_to_bytes(entry);
            let write_offset = offset;
            buf[write_offset..write_offset + 32].copy_from_slice(&entry_bytes);

            // Write the sector back
            self.write_sector(sector, &buf)?;

            // Also update the backup FAT (if mirroring is enabled)
            if self.boot.ext_flags & 0x80 != 0 {
                let fat_offset = self.boot.ext_flags & 0x0F;
                if fat_offset > 0 {
                    let backup_sector = sector + fat_offset as u32 * self.boot.fat_size();
                    self.write_sector(backup_sector, &buf)?;
                }
            }
        } else {
            return Err(Error::Enoent);
        }

        Ok(())
    }

    /// Write a new directory entry to the parent directory
    fn write_new_entry(&mut self, parent_cluster: u32, entry: &FatDirEntry) -> Result<()> {
        // Find a free slot
        if let Some((sector, offset)) = self.find_free_slot(parent_cluster)? {
            let sector_size = self.boot.bytes_per_sector();
            let mut buf = vec![0u8; sector_size];

            // Read the sector
            self.read_sector(sector, &mut buf)?;

            // Write the new entry
            let entry_bytes = Self::entry_to_bytes(entry);
            buf[offset..offset + 32].copy_from_slice(&entry_bytes);

            // Write the sector back
            self.write_sector(sector, &buf)?;
        } else {
            return Err(Error::Enospc);
        }

        Ok(())
    }

    /// Mark a directory entry as deleted (set first byte to 0xE5)
    fn mark_entry_deleted(&mut self, parent_cluster: u32, name: &[u8]) -> Result<()> {
        if let Some((sector, offset)) = self.find_entry_slot(parent_cluster, name)? {
            let sector_size = self.boot.bytes_per_sector();
            let mut buf = vec![0u8; sector_size];

            // Read the sector
            self.read_sector(sector, &mut buf)?;

            // Mark as deleted
            buf[offset] = 0xE5;

            // Write back
            self.write_sector(sector, &buf)?;
        }

        Ok(())
    }

    /// Convert FatDirEntry to bytes
    fn entry_to_bytes(entry: &FatDirEntry) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..11].copy_from_slice(&entry.name);
        bytes[11] = entry.attr;
        bytes[12] = entry.nt_reserved;
        bytes[13] = entry.creation_time_tenth;
        bytes[14..16].copy_from_slice(&entry.creation_time.to_le_bytes());
        bytes[16..18].copy_from_slice(&entry.creation_date.to_le_bytes());
        bytes[18..20].copy_from_slice(&entry.last_access_date.to_le_bytes());
        bytes[20..22].copy_from_slice(&entry.first_cluster_high.to_le_bytes());
        bytes[22..24].copy_from_slice(&entry.last_write_time.to_le_bytes());
        bytes[24..26].copy_from_slice(&entry.last_write_date.to_le_bytes());
        bytes[26..28].copy_from_slice(&entry.first_cluster_low.to_le_bytes());
        bytes[28..32].copy_from_slice(&entry.file_size.to_le_bytes());
        bytes
    }

    /// Create a new file or directory
    pub fn create(&mut self, path: &[u8], is_dir: bool) -> Result<FatFile> {
        let components = parse_path_components(path);

        if components.is_empty() {
            return Err(Error::Einval);
        }

        let file_name = components.last().ok_or(Error::Einval)?;
        let parent_path = if components.len() > 1 {
            let path_str = core::str::from_utf8(path).map_err(|_| Error::Einval)?;
            let last_slash = path_str.rfind('/').unwrap_or(0);
            &path[..last_slash]
        } else {
            &b"/"[..]
        };

        let parent_cluster = self.find_or_create_parent(parent_path)?;

        // Check if file already exists
        if self.find_entry(parent_cluster, file_name)?.is_some() {
            return Err(Error::Eexist);
        }

        // Allocate first cluster
        let first_cluster = self.alloc_cluster()?;

        // Create entry
        let mut entry = FatFileSystem::create_entry(file_name, is_dir)?;
        entry.set_first_cluster(first_cluster);
        entry.file_size = 0;

        // Set timestamps
        let now = current_fat_time();
        entry.creation_time = now.0;
        entry.creation_date = now.1;
        entry.last_write_time = now.0;
        entry.last_write_date = now.1;
        entry.last_access_date = now.1;

        // Mark cluster as end of chain
        self.write_fat_entry(first_cluster, self.fat_eoc_marker())?;

        // Write directory entry
        self.write_new_entry(parent_cluster, &entry)?;

        // If creating a directory, initialize it with . and .. entries
        if is_dir {
            self.init_directory(first_cluster, parent_cluster)?;
        }

        let name_owned = file_name.to_vec();
        Ok(FatFile::from_entry(self, &entry, parent_cluster, &name_owned))
    }

    /// Initialize a new directory with . and .. entries
    fn init_directory(&mut self, cluster: u32, parent_cluster: u32) -> Result<()> {
        let mut buf = vec![0u8; self.boot.bytes_per_cluster()];
        let now = current_fat_time();

        // Create . entry (self reference)
        let mut dot_entry = FatDirEntry::default();
        dot_entry.name = *b".          ";
        dot_entry.attr = 0x10; // Directory
        dot_entry.set_first_cluster(cluster);
        dot_entry.creation_time = now.0;
        dot_entry.creation_date = now.1;
        dot_entry.last_write_time = now.0;
        dot_entry.last_write_date = now.1;
        dot_entry.last_access_date = now.1;

        // Create .. entry (parent reference)
        let mut dotdot_entry = FatDirEntry::default();
        dotdot_entry.name = *b"..         ";
        dotdot_entry.attr = 0x10; // Directory
        dotdot_entry.set_first_cluster(parent_cluster);
        dotdot_entry.creation_time = now.0;
        dotdot_entry.creation_date = now.1;
        dotdot_entry.last_write_time = now.0;
        dotdot_entry.last_write_date = now.1;
        dotdot_entry.last_access_date = now.1;

        // Write entries to buffer
        let dot_bytes = Self::entry_to_bytes(&dot_entry);
        let dotdot_bytes = Self::entry_to_bytes(&dotdot_entry);
        buf[0..32].copy_from_slice(&dot_bytes);
        buf[32..64].copy_from_slice(&dotdot_bytes);

        // Write cluster
        self.write_cluster(cluster, &buf)?;

        Ok(())
    }

    /// Delete a file
    pub fn remove(&mut self, path: &[u8]) -> Result<()> {
        let components = parse_path_components(path);

        if components.is_empty() {
            return Err(Error::Einval);
        }

        let file_name = components.last().ok_or(Error::Einval)?;
        let parent_path = if components.len() > 1 {
            let path_str = core::str::from_utf8(path).map_err(|_| Error::Einval)?;
            let last_slash = path_str.rfind('/').unwrap_or(0);
            &path[..last_slash]
        } else {
            &b"/"[..]
        };

        let parent_cluster = self.find_or_create_parent(parent_path)?;

        // Find the entry
        let entry = self.find_entry(parent_cluster, file_name)?
            .ok_or(Error::Enoent)?;

        if entry.is_directory() {
            // Check if directory is empty (only has . and ..)
            let entries = self.read_directory(entry.first_cluster())?;
            let real_entries: Vec<_> = entries.iter()
                .filter(|e| !e.is_dot() && !e.is_dot_dot() && !e.is_free())
                .collect();
            if !real_entries.is_empty() {
                return Err(Error::Enotempty);
            }
        }

        // Free cluster chain
        self.free_chain(entry.first_cluster())?;

        // Mark directory entry as deleted
        self.mark_entry_deleted(parent_cluster, file_name)?;

        Ok(())
    }

    /// Open an existing file
    pub fn open(&mut self, path: &[u8]) -> Result<FatFile> {
        let components = parse_path_components(path);

        if components.is_empty() {
            return Err(Error::Einval);
        }

        let file_name = components.last().ok_or(Error::Einval)?;
        let parent_path = if components.len() > 1 {
            let path_str = core::str::from_utf8(path).map_err(|_| Error::Einval)?;
            let last_slash = path_str.rfind('/').unwrap_or(0);
            &path[..last_slash]
        } else {
            &b"/"[..]
        };

        let parent_cluster = self.find_or_create_parent(parent_path)?;

        // Find the entry
        let entry = self.find_entry(parent_cluster, file_name)?
            .ok_or(Error::Enoent)?;

        if entry.is_directory() {
            return Err(Error::Eisdir);
        }

        let name_owned = file_name.to_vec();
        Ok(FatFile::from_entry(self, &entry, parent_cluster, &name_owned))
    }

    /// Create a directory
    pub fn mkdir(&mut self, path: &[u8]) -> Result<()> {
        self.create(path, true)?;
        Ok(())
    }
}

/// Get current FAT timestamp
fn current_fat_time() -> (u16, u16) {
    // In a real implementation, this would get the current time
    // For now, return a placeholder timestamp
    let time = 0x1000u16; // 02:00:00
    let date = 0x4421u16; // 2024-01-01
    (time, date)
}

/// Parse path into components
fn parse_path_components(path: &[u8]) -> Vec<&[u8]> {
    let mut components = Vec::new();
    let mut i = 0;

    // Skip leading slashes
    while i < path.len() && path[i] == b'/' {
        i += 1;
    }

    while i < path.len() {
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        if i > start {
            components.push(&path[start..i]);
        }
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
    }

    components
}

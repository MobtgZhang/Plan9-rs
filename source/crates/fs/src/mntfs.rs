//! MNT File System - Mount Point Management
//!
//! This module provides mount point management functionality.
//! It supports bind mounts and tracks active mount points.

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};
use plan9_common::sync::{Spinlock as CommonSpinlock, Mutex as CommonMutex};

// ============================================================================
// MNT Constants
// ============================================================================

/// Maximum number of mount points
pub const MAX_MOUNT_POINTS: usize = 64;

/// Mount flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MountFlags {
    /// Read-only mount
    ReadOnly = 0x01,
    /// No execute (security)
    NoExec = 0x02,
    /// No setuid
    NoSetUid = 0x04,
    /// Bind mount
    Bind = 0x10,
    /// Move mount
    Move = 0x20,
    /// Recursive bind
    Recursive = 0x40,
    /// Private mount
    Private = 0x80,
    /// Shared mount
    Shared = 0x100,
    /// Slave mount
    Slave = 0x200,
    /// Unbindable
    Unbindable = 0x400,
}

impl Default for MountFlags {
    fn default() -> Self {
        MountFlags::Private
    }
}

// ============================================================================
// Mount Entry
// ============================================================================

/// Mount point entry
#[derive(Debug)]
pub struct MountEntry {
    /// Mount ID
    pub id: u32,
    /// Source path (what is being mounted)
    pub source: Vec<u8>,
    /// Target path (where it is mounted)
    pub target: Vec<u8>,
    /// File system type
    pub fs_type: String,
    /// Mount flags
    pub flags: MountFlags,
    /// Reference count
    refcount: AtomicU32,
    /// Parent mount ID (for shared mounts)
    pub parent_id: Option<u32>,
}

impl Clone for MountEntry {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            source: self.source.clone(),
            target: self.target.clone(),
            fs_type: self.fs_type.clone(),
            flags: self.flags,
            refcount: AtomicU32::new(1), // Reset refcount for clone
            parent_id: self.parent_id,
        }
    }
}

impl MountEntry {
    /// Create a new mount entry
    pub fn new(source: &[u8], target: &[u8], fs_type: &str, flags: MountFlags) -> Self {
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);
        
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            source: source.to_vec(),
            target: target.to_vec(),
            fs_type: alloc::string::String::from(fs_type),
            flags,
            refcount: AtomicU32::new(1),
            parent_id: None,
        }
    }
    
    /// Increment reference count
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Decrement reference count
    pub fn dec_ref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Relaxed)
    }
    
    /// Check if this is a bind mount
    pub fn is_bind_mount(&self) -> bool {
        (self.flags as u32 & MountFlags::Bind as u32) != 0
    }
    
    /// Check if this is read-only
    pub fn is_readonly(&self) -> bool {
        (self.flags as u32 & MountFlags::ReadOnly as u32) != 0
    }
}

// ============================================================================
// Mount Table
// ============================================================================

/// Global mount table
pub struct MountTable {
    /// List of mount points
    entries: Vec<MountEntry>,
    /// Lock for thread safety
    lock: Spinlock,
}

impl MountTable {
    /// Create a new mount table
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            lock: Spinlock::new(),
        }
    }
    
    /// Add a mount point
    pub fn add(&mut self, source: &[u8], target: &[u8], fs_type: &str, flags: MountFlags) -> Option<u32> {
        let _guard = self.lock.lock();
        
        // Check if target already has a mount
        if self.find_by_target(target).is_some() {
            return None;
        }
        
        let entry = MountEntry::new(source, target, fs_type, flags);
        let id = entry.id;
        self.entries.push(entry);
        Some(id)
    }
    
    /// Remove a mount point by ID
    pub fn remove(&mut self, id: u32) -> bool {
        let _guard = self.lock.lock();
        
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let entry = &self.entries[pos];
            if entry.refcount.load(Ordering::Relaxed) <= 1 {
                self.entries.remove(pos);
                return true;
            }
        }
        false
    }
    
    /// Remove a mount point by target path
    pub fn remove_by_target(&mut self, target: &[u8]) -> bool {
        let _guard = self.lock.lock();
        
        if let Some(pos) = self.entries.iter().position(|e| e.target == target) {
            let entry = &self.entries[pos];
            if entry.refcount.load(Ordering::Relaxed) <= 1 {
                self.entries.remove(pos);
                return true;
            }
        }
        false
    }
    
    /// Find a mount point by ID
    pub fn find_by_id(&self, id: u32) -> Option<&MountEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
    
    /// Find a mount point by target path
    pub fn find_by_target(&self, target: &[u8]) -> Option<&MountEntry> {
        // Find the most specific (longest) match
        let mut best: Option<&MountEntry> = None;
        let mut best_len = 0;
        
        for entry in &self.entries {
            let target_vec: Vec<u8> = target.to_vec();
            if target_vec.starts_with(&entry.target) && entry.target.len() > best_len {
                best = Some(entry);
                best_len = entry.target.len();
            }
        }
        
        best
    }
    
    /// Find a mount point by source path
    pub fn find_by_source(&self, source: &[u8]) -> Option<&MountEntry> {
        self.entries.iter().find(|e| e.source == source)
    }
    
    /// Get all mount points
    pub fn list(&self) -> Vec<&MountEntry> {
        self.entries.iter().collect()
    }
    
    /// Get number of mount points
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Spinlock Implementation
// ============================================================================

/// Simple spinlock for thread safety
struct Spinlock {
    locked: core::sync::atomic::AtomicBool,
}

impl Spinlock {
    const fn new() -> Self {
        Self {
            locked: core::sync::atomic::AtomicBool::new(false),
        }
    }
    
    fn lock(&self) -> SpinlockGuard<'_> {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        SpinlockGuard { lock: self }
    }
}

struct SpinlockGuard<'a> {
    lock: &'a Spinlock,
}

impl Drop for SpinlockGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// Global Mount Table
// ============================================================================

/// Global mount table storage
static MOUNT_TABLE_DATA: CommonMutex<Option<MountTable>> = CommonMutex::new(None);
static MOUNT_TABLE_LOCK: CommonSpinlock<()> = CommonSpinlock::new(());

/// Initialize mount table
fn init_mount_table() {
    let mut guard = MOUNT_TABLE_DATA.lock();
    if guard.is_none() {
        *guard = Some(MountTable::new());
    }
}

/// Get mutable reference to mount table
fn with_mount_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut MountTable) -> R,
{
    let _lock = MOUNT_TABLE_LOCK.lock();
    init_mount_table();

    let mut guard = MOUNT_TABLE_DATA.lock();
    if let Some(ref mut table) = *guard {
        f(table)
    } else {
        panic!("Mount table not initialized")
    }
}

/// Add a bind mount
pub fn bind_mount(source: &[u8], target: &[u8]) -> Option<u32> {
    with_mount_table(|table| table.add(source, target, "bind", MountFlags::Bind))
}

/// Remove a mount
pub fn umount(target: &[u8]) -> bool {
    with_mount_table(|table| table.remove_by_target(target))
}

/// Find mount point for a path
pub fn lookup_mount(path: &[u8]) -> Option<alloc::sync::Arc<MountEntry>> {
    // This requires a read-only view, which is more complex
    // For now, return None
    let _ = path;
    None
}

/// List all mount points
pub fn list_mounts() -> Vec<alloc::sync::Arc<MountEntry>> {
    // Simplified: return empty list for now
    Vec::new()
}

// ============================================================================
// Mount Operations
// ============================================================================

/// Perform a bind mount
/// 
/// This creates a bind mount that makes the file or directory at source
/// visible at target.
pub fn sys_bind_mount(source: &[u8], target: &[u8], flags: u32) -> i32 {
    let _mount_flags = match flags {
        0 => MountFlags::default(),
        f if (f & MountFlags::ReadOnly as u32) != 0 => MountFlags::ReadOnly,
        f if (f & MountFlags::Bind as u32) != 0 => MountFlags::Bind,
        _ => MountFlags::default(),
    };
    
    if bind_mount(source, target).is_some() {
        0
    } else {
        -1
    }
}

/// Perform an unmount
pub fn sys_unmount(target: &[u8]) -> i32 {
    if umount(target) {
        0
    } else {
        -1
    }
}

/// Change mount flags
pub fn sys_mount_setflags(target: &[u8], _flags: u32) -> i32 {
    // Would need mutable access to the entry to change flags
    // For now, just return success if mount exists
    with_mount_table(|table| {
        if table.find_by_target(target).is_some() {
            0
        } else {
            -1
        }
    })
}

//! Snapshot Management for Fossil File System
//!
//! Handles creation, listing, and restoration of file system snapshots.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::sync::Mutex;

use crate::venti::Score;

// ============================================================================
// Snapshot
// ============================================================================

/// A snapshot represents a point-in-time view of the file system
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Unique snapshot ID
    pub id: u32,
    /// Snapshot name
    pub name: String,
    /// Creation timestamp
    pub ctime: u32,
    /// Root directory score (Venti address)
    pub root_score: Score,
    /// Epoch at creation
    pub epoch: u32,
    /// Optional comment
    pub comment: String,
    /// Active reference count
    pub refcount: u32,
}

impl Snapshot {
    /// Create a new snapshot
    pub fn new(id: u32, name: &str, root_score: Score, epoch: u32) -> Self {
        Self {
            id,
            name: name.to_string(),
            ctime: 0,
            root_score,
            epoch,
            comment: String::new(),
            refcount: 0,
        }
    }

    /// Create a snapshot with a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = comment.to_string();
        self
    }

    /// Check if this snapshot is active (has active references)
    pub fn is_active(&self) -> bool {
        self.refcount > 0
    }

    /// Increment reference count
    pub fn acquire(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn release(&mut self) {
        self.refcount = self.refcount.saturating_sub(1);
    }
}

// ============================================================================
// Snapshot Manager
// ============================================================================

/// Manages snapshots for a Fossil file system
pub struct SnapshotManager {
    /// All snapshots
    snapshots: Vec<Snapshot>,
    /// Next available ID
    next_id: u32,
    /// Active snapshot (currently being served)
    active: Option<u32>,
    /// Maximum snapshots allowed
    max_snapshots: usize,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            next_id: 1,
            active: None,
            max_snapshots: 256,
        }
    }

    /// Create a new snapshot
    ///
    /// Returns the snapshot ID on success, or None if the limit is reached.
    pub fn create(&mut self, name: &str, root_score: Score, epoch: u32) -> Option<u32> {
        if self.snapshots.len() >= self.max_snapshots {
            // Remove oldest snapshot if at limit
            self.remove_oldest()?;
        }

        let id = self.next_id;
        self.next_id += 1;

        let snap = Snapshot::new(id, name, root_score, epoch);
        self.snapshots.push(snap);

        Some(id)
    }

    /// Remove the oldest snapshot
    fn remove_oldest(&mut self) -> Option<()> {
        // Find snapshot with lowest refcount
        let idx = self.snapshots.iter()
            .position(|s| s.refcount == 0)?;

        self.snapshots.remove(idx);
        Some(())
    }

    /// Get a snapshot by ID
    pub fn get(&self, id: u32) -> Option<&Snapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Get a mutable snapshot by ID
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Snapshot> {
        self.snapshots.iter_mut().find(|s| s.id == id)
    }

    /// Get a snapshot by name
    pub fn get_by_name(&self, name: &str) -> Option<&Snapshot> {
        self.snapshots.iter().find(|s| s.name == name)
    }

    /// List all snapshots
    pub fn list(&self) -> &[Snapshot] {
        &self.snapshots
    }

    /// List active (referenced) snapshots
    pub fn list_active(&self) -> Vec<&Snapshot> {
        self.snapshots.iter().filter(|s| s.is_active()).collect()
    }

    /// Set the active snapshot
    pub fn set_active(&mut self, id: Option<u32>) {
        // Release previous
        if let Some(prev) = self.active {
            if let Some(snap) = self.get_mut(prev) {
                snap.release();
            }
        }

        // Acquire new
        if let Some(id) = id {
            if let Some(snap) = self.get_mut(id) {
                snap.acquire();
            }
        }

        self.active = id;
    }

    /// Get the active snapshot
    pub fn active(&self) -> Option<u32> {
        self.active
    }

    /// Remove a snapshot by ID
    pub fn remove(&mut self, id: u32) -> bool {
        if let Some(idx) = self.snapshots.iter().position(|s| s.id == id) {
            // Don't remove active snapshot
            if self.active == Some(id) {
                return false;
            }

            self.snapshots.remove(idx);
            true
        } else {
            false
        }
    }

    /// Remove a snapshot by name
    pub fn remove_by_name(&mut self, name: &str) -> bool {
        if let Some(idx) = self.snapshots.iter().position(|s| s.name == name) {
            let snap = &self.snapshots[idx];

            // Don't remove active snapshot
            if self.active == Some(snap.id) {
                return false;
            }

            self.snapshots.remove(idx);
            true
        } else {
            false
        }
    }

    /// Get the number of snapshots
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get the maximum number of snapshots
    pub fn max_count(&self) -> usize {
        self.max_snapshots
    }

    /// Set the maximum number of snapshots
    pub fn set_max_count(&mut self, max: usize) {
        self.max_snapshots = max;

        // Remove excess snapshots
        while self.snapshots.len() > self.max_snapshots {
            if self.remove_oldest().is_none() {
                break;
            }
        }
    }

    /// Check if a snapshot exists
    pub fn exists(&self, id: u32) -> bool {
        self.snapshots.iter().any(|s| s.id == id)
    }

    /// Check if a snapshot with the given name exists
    pub fn exists_name(&self, name: &str) -> bool {
        self.snapshots.iter().any(|s| s.name == name)
    }

    /// Clear all snapshots
    pub fn clear(&mut self) {
        // Don't clear if there's an active snapshot
        if self.active.is_some() {
            return;
        }
        self.snapshots.clear();
    }

    /// Get the oldest snapshot
    pub fn oldest(&self) -> Option<&Snapshot> {
        self.snapshots.first()
    }

    /// Get the newest snapshot
    pub fn newest(&self) -> Option<&Snapshot> {
        self.snapshots.last()
    }
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Thread-Safe Snapshot Manager
// ============================================================================

/// Thread-safe wrapper for SnapshotManager
pub struct SharedSnapshotManager {
    inner: Arc<Mutex<SnapshotManager>>,
}

impl SharedSnapshotManager {
    /// Create a new shared snapshot manager
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SnapshotManager::new())),
        }
    }

    /// Create a snapshot
    pub fn create(&self, name: &str, root_score: Score, epoch: u32) -> Option<u32> {
        self.inner.lock().unwrap().create(name, root_score, epoch)
    }

    /// Get a snapshot by ID
    pub fn get(&self, id: u32) -> Option<Snapshot> {
        self.inner.lock().unwrap().get(id).cloned()
    }

    /// Get a snapshot by name
    pub fn get_by_name(&self, name: &str) -> Option<Snapshot> {
        self.inner.lock().unwrap().get_by_name(name).cloned()
    }

    /// List all snapshots
    pub fn list(&self) -> Vec<Snapshot> {
        self.inner.lock().unwrap().list().to_vec()
    }

    /// Set the active snapshot
    pub fn set_active(&self, id: Option<u32>) {
        self.inner.lock().unwrap().set_active(id);
    }

    /// Get the active snapshot ID
    pub fn active(&self) -> Option<u32> {
        self.inner.lock().unwrap().active()
    }

    /// Remove a snapshot
    pub fn remove(&self, id: u32) -> bool {
        self.inner.lock().unwrap().remove(id)
    }

    /// Check if a snapshot exists
    pub fn exists(&self, id: u32) -> bool {
        self.inner.lock().unwrap().exists(id)
    }

    /// Get the number of snapshots
    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().count()
    }
}

impl Clone for SharedSnapshotManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for SharedSnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Epoch Management
// ============================================================================

/// Represents a file system epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch {
    /// Epoch number
    pub number: u32,
    /// Start time
    pub start_time: u32,
    /// End time (0 if current)
    pub end_time: u32,
}

impl Epoch {
    /// Create a new epoch
    pub fn new(number: u32, start_time: u32) -> Self {
        Self {
            number,
            start_time,
            end_time: 0,
        }
    }

    /// Check if this is the current epoch
    pub fn is_current(&self) -> bool {
        self.end_time == 0
    }

    /// End this epoch
    pub fn end(&mut self, end_time: u32) {
        self.end_time = end_time;
    }
}

/// Manages epochs for a Fossil file system
pub struct EpochManager {
    /// Current epoch
    current: u32,
    /// Epoch history
    epochs: Vec<Epoch>,
    /// Maximum epochs to keep
    max_epochs: usize,
}

impl EpochManager {
    /// Create a new epoch manager
    pub fn new() -> Self {
        let mut manager = Self {
            current: 0,
            epochs: Vec::new(),
            max_epochs: 256,
        };
        // Create initial epoch
        manager.epochs.push(Epoch::new(0, 0));
        manager
    }

    /// Get the current epoch number
    pub fn current(&self) -> u32 {
        self.current
    }

    /// Start a new epoch
    pub fn new_epoch(&mut self, start_time: u32) -> u32 {
        // End current epoch
        if let Some(epoch) = self.epochs.iter_mut().find(|e| e.number == self.current) {
            epoch.end(start_time);
        }

        // Create new epoch
        self.current += 1;
        let epoch = Epoch::new(self.current, start_time);
        self.epochs.push(epoch);

        // Trim old epochs if necessary
        while self.epochs.len() > self.max_epochs {
            self.epochs.remove(0);
        }

        self.current
    }

    /// Get epoch by number
    pub fn get(&self, number: u32) -> Option<&Epoch> {
        self.epochs.iter().find(|e| e.number == number)
    }

    /// Get the current epoch info
    pub fn current_epoch(&self) -> Option<&Epoch> {
        self.get(self.current)
    }

    /// List all epochs
    pub fn list(&self) -> &[Epoch] {
        &self.epochs
    }

    /// List completed epochs (not current)
    pub fn completed(&self) -> Vec<&Epoch> {
        self.epochs.iter().filter(|e| !e.is_current()).collect()
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new()
    }
}

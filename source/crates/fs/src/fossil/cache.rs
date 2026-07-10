//! Block Cache for Fossil File System
//!
//! Manages an LRU cache of file system blocks with Venti integration.

#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use alloc::sync::Mutex;
use core::cell::RefCell;

use crate::venti::Score;

// ============================================================================
// Cache Entry
// ============================================================================

/// Cache entry for a file system block
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Block score (Venti address)
    pub score: Score,
    /// Block data
    pub data: Vec<u8>,
    /// Reference count
    pub refcount: u32,
    /// Dirty flag (needs to be written to Venti)
    pub dirty: bool,
    /// LRU list pointers
    lru_prev: Option<usize>,
    lru_next: Option<usize>,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(score: Score, data: Vec<u8>) -> Self {
        Self {
            score,
            data,
            refcount: 1,
            dirty: false,
            lru_prev: None,
            lru_next: None,
        }
    }

    /// Check if entry is clean (not dirty)
    pub fn is_clean(&self) -> bool {
        !self.dirty
    }

    /// Check if entry can be evicted (no active references)
    pub fn can_evict(&self) -> bool {
        self.refcount == 0 && !self.dirty
    }
}

// ============================================================================
// Block Cache
// ============================================================================

/// LRU block cache implementation
pub struct BlockCache {
    /// Maximum cache size in bytes
    max_size: usize,
    /// Current size in bytes
    current_size: usize,
    /// Cache entries indexed by position
    entries: Vec<Option<CacheEntry>>,
    /// LRU head (most recently used)
    lru_head: Option<usize>,
    /// LRU tail (least recently used)
    lru_tail: Option<usize>,
    /// Score to index mapping
    score_map: Vec<(Score, usize)>,
}

impl BlockCache {
    /// Create a new block cache with the given maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            current_size: 0,
            entries: Vec::new(),
            lru_head: None,
            lru_tail: None,
            score_map: Vec::new(),
        }
    }

    /// Get the maximum cache size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get the current cache size
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| e.is_none())
    }

    /// Get block from cache by score
    pub fn get(&mut self, score: &Score) -> Option<Vec<u8>> {
        // Find entry by score
        let index = self.score_map.iter()
            .find(|(s, _)| s == score)
            .map(|(_, i)| *i)?;

        // Get and update entry
        if let Some(ref mut entry) = self.entries[index] {
            // Move to head of LRU
            self.move_to_head(index);
            entry.refcount += 1;
            return Some(entry.data.clone());
        }

        None
    }

    /// Put block into cache
    pub fn put(&mut self, score: Score, data: Vec<u8>) {
        let size = data.len();

        // Check if already exists
        if let Some(index) = self.score_map.iter()
            .find(|(s, _)| s == &score)
            .map(|(_, i)| *i)
        {
            if let Some(ref mut entry) = self.entries[index] {
                // Update existing entry
                self.current_size -= entry.data.len();
                entry.data = data;
                entry.dirty = true;
                self.current_size += entry.data.len();
                self.move_to_head(index);
                return;
            }
        }

        // Evict entries if necessary
        while self.current_size + size > self.max_size {
            if let Some(lru) = self.lru_tail {
                if !self.evict_one(lru) {
                    break; // No more evictable entries
                }
            } else {
                break;
            }
        }

        // Add new entry
        let entry = CacheEntry::new(score.clone(), data);
        let index = self.entries.len();
        self.entries.push(Some(entry));
        self.current_size += size;

        // Update LRU list
        if let Some(head) = self.lru_head {
            if let Some(ref mut head_entry) = self.entries[head] {
                head_entry.lru_prev = Some(index);
            }
        }
        if let Some(ref mut tail_entry) = self.entries[index] {
            tail_entry.lru_next = self.lru_head;
        }
        self.lru_head = Some(index);

        if self.lru_tail.is_none() {
            self.lru_tail = Some(index);
        }

        // Update score map
        self.score_map.push((score, index));
    }

    /// Move entry to head of LRU list
    fn move_to_head(&mut self, index: usize) {
        if self.lru_head == Some(index) {
            return;
        }

        if let Some(ref mut entry) = self.entries[index] {
            // Remove from current position
            if let Some(prev) = entry.lru_prev {
                if let Some(ref mut prev_entry) = self.entries[prev] {
                    prev_entry.lru_next = entry.lru_next;
                }
            }
            if let Some(next) = entry.lru_next {
                if let Some(ref mut next_entry) = self.entries[next] {
                    next_entry.lru_prev = entry.lru_prev;
                }
            }

            // Update tail if necessary
            if self.lru_tail == Some(index) {
                self.lru_tail = entry.lru_prev;
            }

            // Add to head
            entry.lru_prev = None;
            entry.lru_next = self.lru_head;

            if let Some(head) = self.lru_head {
                if let Some(ref mut head_entry) = self.entries[head] {
                    head_entry.lru_prev = Some(index);
                }
            }

            self.lru_head = Some(index);
        }
    }

    /// Evict one entry from the tail of the LRU list
    fn evict_one(&mut self, index: usize) -> bool {
        if let Some(ref entry) = self.entries[index] {
            if entry.refcount > 0 || entry.dirty {
                return false; // Cannot evict active or dirty entry
            }
        }

        self.evict(index);
        true
    }

    /// Evict entry at given index
    fn evict(&mut self, index: usize) {
        if let Some(entry) = self.entries[index].take() {
            self.current_size -= entry.data.len();

            // Remove from LRU list
            if let Some(prev) = entry.lru_prev {
                if let Some(ref mut prev_entry) = self.entries[prev] {
                    prev_entry.lru_next = entry.lru_next;
                }
            }
            if let Some(next) = entry.lru_next {
                if let Some(ref mut next_entry) = self.entries[next] {
                    next_entry.lru_prev = entry.lru_prev;
                }
            }

            // Update head/tail
            if self.lru_head == Some(index) {
                self.lru_head = entry.lru_next;
            }
            if self.lru_tail == Some(index) {
                self.lru_tail = entry.lru_prev;
            }

            // Remove from score map
            self.score_map.retain(|(s, _)| s != &entry.score);
        }
    }

    /// Release a reference to a cached block
    pub fn release(&mut self, score: &Score) {
        if let Some(index) = self.score_map.iter()
            .find(|(s, _)| s == score)
            .map(|(_, i)| *i)
        {
            if let Some(ref mut entry) = self.entries[index] {
                entry.refcount = entry.refcount.saturating_sub(1);
            }
        }
    }

    /// Mark a block as dirty
    pub fn mark_dirty(&mut self, score: &Score) {
        if let Some(index) = self.score_map.iter()
            .find(|(s, _)| s == score)
            .map(|(_, i)| *i)
        {
            if let Some(ref mut entry) = self.entries[index] {
                entry.dirty = true;
            }
        }
    }

    /// Get all dirty blocks
    pub fn get_dirty_blocks(&self) -> Vec<(Score, Vec<u8>)> {
        self.entries.iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.dirty)
            .map(|e| (e.score.clone(), e.data.clone()))
            .collect()
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.entries.clear();
        self.score_map.clear();
        self.current_size = 0;
        self.lru_head = None;
        self.lru_tail = None;
    }

    /// Flush dirty blocks (mark them as clean)
    pub fn flush_dirty(&mut self) {
        for entry in &mut self.entries {
            if let Some(ref mut e) = entry {
                e.dirty = false;
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_entries = self.entries.iter().filter(|e| e.is_some()).count();
        let dirty_entries = self.entries.iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.dirty)
            .count();

        CacheStats {
            total_entries,
            dirty_entries,
            current_size: self.current_size,
            max_size: self.max_size,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of entries
    pub total_entries: usize,
    /// Number of dirty entries
    pub dirty_entries: usize,
    /// Current size in bytes
    pub current_size: usize,
    /// Maximum size in bytes
    pub max_size: usize,
}

// ============================================================================
// Thread-Safe Cache Wrapper
// ============================================================================

/// Thread-safe wrapper for BlockCache
pub struct SharedBlockCache {
    inner: Arc<Mutex<BlockCache>>,
}

impl SharedBlockCache {
    /// Create a new shared cache
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BlockCache::new(max_size))),
        }
    }

    /// Get block from cache
    pub fn get(&self, score: &Score) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().get(score)
    }

    /// Put block into cache
    pub fn put(&self, score: Score, data: Vec<u8>) {
        self.inner.lock().unwrap().put(score, data);
    }

    /// Mark block as dirty
    pub fn mark_dirty(&self, score: &Score) {
        self.inner.lock().unwrap().mark_dirty(score);
    }

    /// Release a reference
    pub fn release(&self, score: &Score) {
        self.inner.lock().unwrap().release(score);
    }

    /// Flush dirty blocks
    pub fn flush_dirty(&self) {
        self.inner.lock().unwrap().flush_dirty();
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Get statistics
    pub fn stats(&self) -> CacheStats {
        self.inner.lock().unwrap().stats()
    }

    /// Get inner cache reference
    pub fn inner(&self) -> Arc<Mutex<BlockCache>> {
        Arc::clone(&self.inner)
    }
}

impl Clone for SharedBlockCache {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

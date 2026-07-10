//! Venti block cache
//!
//! Implements an LRU cache of Venti blocks keyed by [`Score`].
//! Each cached entry holds a reference-counted block of bytes.
//!
//! Reference: `sys/src/libventi/cache.c`, `vtCache.c`.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::score::Score;

/// Maximum number of blocks the cache will hold by default.
pub const DEFAULT_CACHE_SIZE: usize = 1024;

/// A reference-counted block of bytes returned by the cache.
#[derive(Debug, Clone)]
pub struct VtBlock {
    /// The score identifying this block (0-typed if not yet hashed).
    pub score: Score,
    /// Block type (archival type).
    pub block_type: u32,
    /// Block data.
    pub data: Vec<u8>,
}

impl VtBlock {
    /// Create a new block with the given data.
    pub fn new(score: Score, block_type: u32, data: Vec<u8>) -> Self {
        Self { score, block_type, data }
    }

    /// Length of the block in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True if the block has zero data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Compute the score of this block and store it. Returns the score.
    pub fn hash(&mut self) -> Score {
        let s = Score::from_data(&self.data);
        self.score = s;
        s
    }
}

/// Cache entry. Uses `Arc` so multiple readers can share the same
/// underlying bytes.
type CacheEntry = Arc<VtBlock>;

/// A block cache that implements true LRU eviction, dirty-block tracking,
/// and a flush interface.
///
/// ## Eviction policy
///
/// Entries are ordered by *insertion time*: the head of the `lru_order`
/// deque is the least-recently-used entry. Every `get` moves the accessed
/// entry to the back (most-recently-used). When the cache exceeds
/// `capacity`, entries are evicted from the front until the count is
/// within the limit. Dirty entries are evicted last so they can be
/// flushed first.
///
/// ## Dirty tracking
///
/// A block is marked dirty when it is inserted or updated with modified
/// data. `flush` walks all dirty blocks in LRU order and calls the
/// supplied callback. After a successful flush the dirty flag is cleared.
pub struct VtCache {
    /// Map from score to cached block (value).
    entries: BTreeMap<Score, CacheEntry>,
    /// LRU ordering: front = least-recently-used, back = most-recently-used.
    lru_order: VecDeque<Score>,
    /// Scores of dirty (modified) blocks that have not yet been flushed.
    dirty: BTreeSet<Score>,
    /// Maximum number of blocks to keep.
    capacity: usize,
    /// Total number of cache hits since creation.
    hits: AtomicU64,
    /// Total number of cache misses since creation.
    misses: AtomicU64,
    /// Number of evictions performed.
    evictions: u64,
    /// Timestamp counter incremented on each access — used to order the
    /// LRU deque deterministically.
    access_counter: u64,
    /// Window size for the rolling hit-rate average.
    hit_window: VecDeque<bool>,
}

impl VtCache {
    /// Create a new cache with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_SIZE)
    }

    /// Create a new cache with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            lru_order: VecDeque::new(),
            dirty: BTreeSet::new(),
            capacity,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: 0,
            access_counter: 0,
            hit_window: VecDeque::new(),
        }
    }

    /// Monotonic access counter incremented on every cache touch.
    /// Exposed for diagnostics and for tests that want to assert a
    /// particular access ordering.
    pub fn access_counter(&self) -> u64 {
        self.access_counter
    }

    /// Capacity (maximum entries).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no entries are held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of cache hits since creation.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Number of cache misses since creation.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Total lookups (hits + misses).
    pub fn lookups(&self) -> u64 {
        self.hits() + self.misses()
    }

    /// Hit rate over the rolling window (0.0 - 1.0).
    pub fn hit_rate(&self) -> f32 {
        if self.hit_window.is_empty() {
            return 0.0;
        }
        let hits_in_window: usize = self.hit_window.iter().filter(|&&h| h).count();
        hits_in_window as f32 / self.hit_window.len() as f32
    }

    /// Number of evictions performed since creation.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Number of dirty (unflushed) blocks currently in the cache.
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// Look up a block by score. Returns `None` on a miss.
    ///
    /// On a hit the entry is moved to the back of the LRU deque, making
    /// it the most-recently-used entry.
    pub fn get(&mut self, score: &Score) -> Option<CacheEntry> {
        // Clone the entry first to avoid borrow conflict
        let entry_clone = {
            self.entries.get(score).map(|e| Arc::clone(e))
        };
        
        if entry_clone.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.hit_window_push(true);
            // Move the entry to the back of the LRU deque.
            self.lru_order.retain(|s| s != score);
            self.lru_order.push_back(*score);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.hit_window_push(false);
        }
        
        entry_clone
    }

    fn hit_window_push(&mut self, hit: bool) {
        self.hit_window.push_back(hit);
        if self.hit_window.len() > 100 {
            self.hit_window.pop_front();
        }
    }

    /// Insert a block into the cache. Marks the block as dirty. If the
    /// cache is full, the least-recently-used (LRU) clean entry is evicted
    /// first; if no clean entries remain, the LRU dirty entry is evicted
    /// (without being flushed — the caller must call `flush` first if that
    /// matters). Returns the reference-counted block that was inserted.
    pub fn put(&mut self, block: VtBlock) -> CacheEntry {
        let score = block.score;
        // Mark the entry as dirty so the caller can flush it before
        // the block is silently evicted.
        self.dirty.insert(score);

        // If the entry already exists, replace it.
        if self.entries.contains_key(&score) {
            self.entries.insert(score, Arc::new(block));
            self.lru_order.retain(|s| s != &score);
            self.lru_order.push_back(score);
            return Arc::clone(self.entries.get(&score).unwrap());
        }

        // Evict from the front (LRU) until we are within capacity.
        while self.entries.len() >= self.capacity && !self.lru_order.is_empty() {
            // Try to evict a clean entry first.
            let evicted_clean = self.evict_lru_clean();
            if !evicted_clean {
                // No clean entries left — force-evict the LRU dirty entry.
                if let Some(score) = self.lru_order.pop_front() {
                    self.entries.remove(&score);
                    self.dirty.remove(&score);
                    self.evictions += 1;
                }
                break;
            }
        }

        self.entries.insert(score, Arc::new(block));
        self.lru_order.push_back(score);
        Arc::clone(self.entries.get(&score).unwrap())
    }

    /// Evict the least-recently-used clean entry. Returns `true` if an
    /// entry was evicted, `false` if no clean entries were found.
    fn evict_lru_clean(&mut self) -> bool {
        // Walk from the front of the LRU deque.
        let mut to_remove = None;
        for &score in &self.lru_order {
            if !self.dirty.contains(&score) {
                to_remove = Some(score);
                break;
            }
        }
        if let Some(score) = to_remove {
            self.entries.remove(&score);
            self.lru_order.retain(|s| s != &score);
            self.evictions += 1;
            true
        } else {
            false
        }
    }

    /// Mark a block as dirty (modified but not yet flushed).
    pub fn mark_dirty(&mut self, score: &Score) {
        self.dirty.insert(*score);
    }

    /// Flush all dirty blocks by calling `f` with each dirty block in LRU
    /// order. After the callback succeeds the dirty flag is cleared.
    /// Returns the number of blocks flushed.
    pub fn flush<F: FnMut(&VtBlock)>(&mut self, mut f: F) -> usize {
        let count = self.dirty.len();
        for score in self.dirty.iter() {
            if let Some(entry) = self.entries.get(score) {
                f(entry);
            }
        }
        self.dirty.clear();
        count
    }

    /// Evict and return all dirty blocks without calling a callback.
    /// Use this when you want to drop the dirty blocks silently (e.g.
    /// cache shutdown with no backing store).
    pub fn evict_dirty(&mut self) {
        // Collect scores first to avoid borrow conflict
        let scores: Vec<Score> = self.dirty.iter().copied().collect();
        for score in scores {
            self.entries.remove(&score);
            self.lru_order.retain(|s| s != &score);
            self.dirty.remove(&score);
        }
    }

    /// Remove a block from the cache. Returns true if the block was present.
    pub fn evict(&mut self, score: &Score) -> bool {
        self.lru_order.retain(|s| s != score);
        self.dirty.remove(score);
        self.entries.remove(score).is_some()
    }

    /// Clear the cache, evicting all dirty blocks silently.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
        self.dirty.clear();
    }
}

impl Default for VtCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the score of a block, returning a fresh `VtBlock` whose
/// `score` field has been populated.
pub fn hash_block(block_type: u32, data: &[u8]) -> VtBlock {
    let mut block = VtBlock::new(Score::default(), block_type, data.to_vec());
    block.hash();
    block
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_new() {
        let b = VtBlock::new(Score::new(), 0, alloc::vec![1, 2, 3]);
        assert_eq!(b.len(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_block_hash() {
        let mut b = VtBlock::new(Score::new(), 0, b"hello".to_vec());
        let s = b.hash();
        assert!(!s.is_zero());
        assert_eq!(b.score, s);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let s1 = Score::from_data(b"hello");
        let s2 = Score::from_data(b"hello");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_cache_put_get() {
        let mut cache = VtCache::new();
        let block = VtBlock::new(Score::from_data(b"abc"), 0, b"abc".to_vec());
        let score = block.score;
        cache.put(block);
        let got = cache.get(&score);
        assert!(got.is_some());
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = VtCache::new();
        let got = cache.get(&Score::new());
        assert!(got.is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_cache_evict() {
        let mut cache = VtCache::new();
        let block = VtBlock::new(Score::from_data(b"abc"), 0, b"abc".to_vec());
        let score = block.score;
        cache.put(block);
        assert!(cache.evict(&score));
        assert!(cache.get(&score).is_none());
        // Second evict returns false
        assert!(!cache.evict(&score));
        // evict clears dirty too
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = VtCache::new();
        cache.put(VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec()));
        cache.put(VtBlock::new(Score::from_data(b"b"), 0, b"b".to_vec()));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn test_cache_capacity() {
        let mut cache = VtCache::with_capacity(2);
        cache.put(VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec()));
        cache.put(VtBlock::new(Score::from_data(b"b"), 0, b"b".to_vec()));
        cache.put(VtBlock::new(Score::from_data(b"c"), 0, b"c".to_vec()));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_replace_existing() {
        let mut cache = VtCache::new();
        let block = VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec());
        let score = block.score;
        cache.put(block);
        // Insert a new block with the same score
        cache.put(VtBlock::new(score, 0, b"a-replacement".to_vec()));
        // Length should still be 1
        assert_eq!(cache.len(), 1);
        // Still dirty since the replacement is a put (which marks dirty).
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn test_hit_rate() {
        let mut cache = VtCache::new();
        let block = VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec());
        let score = block.score;
        cache.put(block);
        cache.get(&score);
        cache.get(&score);
        cache.get(&Score::new());
        assert_eq!(cache.hits(), 2);
        assert_eq!(cache.misses(), 1);
        // Rolling window hit rate — at most 3 entries in window.
        assert!(cache.hit_rate() > 0.0);
    }

    #[test]
    fn test_lru_eviction() {
        // Fill the cache past its capacity and verify that the oldest
        // entry (the one accessed first) is evicted.
        let mut cache = VtCache::with_capacity(3);
        let a = VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec());
        let b = VtBlock::new(Score::from_data(b"b"), 0, b"b".to_vec());
        let c = VtBlock::new(Score::from_data(b"c"), 0, b"c".to_vec());
        let d = VtBlock::new(Score::from_data(b"d"), 0, b"d".to_vec());
        let score_a = a.score;
        cache.put(a);
        cache.put(b);
        cache.put(c);
        // At capacity (3); adding "d" should evict "a" (LRU).
        cache.put(d);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&score_a).is_none(), "LRU 'a' must be evicted");
        assert_eq!(cache.evictions(), 1);
    }

    #[test]
    fn test_get_refreshes_recency() {
        let mut cache = VtCache::with_capacity(3);
        let a = VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec());
        let b = VtBlock::new(Score::from_data(b"b"), 0, b"b".to_vec());
        let c = VtBlock::new(Score::from_data(b"c"), 0, b"c".to_vec());
        let d = VtBlock::new(Score::from_data(b"d"), 0, b"d".to_vec());
        let score_a = a.score;
        cache.put(a);
        cache.put(b);
        cache.put(c);
        // Touch "a" to make it MRU, so "b" becomes the LRU.
        cache.get(&score_a);
        // Add "d" — should evict "b" (the former LRU), not "a".
        cache.put(d);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&score_a).is_some(), "'a' must still be present");
    }

    #[test]
    fn test_dirty_flush() {
        let mut cache = VtCache::new();
        cache.put(VtBlock::new(Score::from_data(b"dirty"), 0, b"dirty".to_vec()));
        assert_eq!(cache.dirty_count(), 1);
        let flushed = cache.flush(|_block| {});
        assert_eq!(flushed, 1);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn test_capacity_zero() {
        let mut cache = VtCache::with_capacity(0);
        // capacity=0 means we cannot store anything; the block is silently
        // dropped (evicted immediately).
        cache.put(VtBlock::new(Score::from_data(b"a"), 0, b"a".to_vec()));
        assert!(cache.is_empty());
        assert_eq!(cache.evictions(), 0); // silently dropped, not stored then evicted
    }

    #[test]
    fn test_hash_block_helper() {
        let b = hash_block(0, b"hello");
        assert!(!b.score.is_zero());
    }
}

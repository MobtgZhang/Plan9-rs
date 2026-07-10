//! Integer Hash Map Module
//!
//! Provides a hash map for mapping integer keys to values.
//! Based on Plan 9's Intmap implementation.

use alloc::vec::Vec;
use core::cell::{RefCell, Ref};

/// Number of hash buckets
const NHASH: usize = 128;

/// Integer list entry
#[derive(Debug, Clone)]
pub struct Intlist {
    /// Integer key
    id: u64,
    /// Associated value (stored as index into another array)
    aux: usize,
    /// Next entry in hash chain
    next: Option<usize>,
}

/// Integer hash map
///
/// This map uses a simple hash table with chaining to store
/// integer keys mapped to arbitrary values.
pub struct Intmap {
    /// Hash buckets (wrapped in RefCell for interior mutability)
    hash: RefCell<Vec<Option<usize>>>,
    /// All entries in the map
    entries: RefCell<Vec<Intlist>>,
    /// Next free entry slot
    free: RefCell<Option<usize>>,
}

impl Intmap {
    /// Create a new empty intmap
    pub fn new() -> Self {
        let mut hash = Vec::with_capacity(NHASH);
        for _ in 0..NHASH {
            hash.push(None);
        }
        Self {
            hash: RefCell::new(hash),
            entries: RefCell::new(Vec::new()),
            free: RefCell::new(None),
        }
    }

    /// Get a reference to entries
    pub fn entries(&self) -> Ref<'_, Vec<Intlist>> {
        self.entries.borrow()
    }

    /// Get a mutable reference to entries
    pub fn entries_mut(&self) -> core::cell::RefMut<'_, Vec<Intlist>> {
        self.entries.borrow_mut()
    }

    /// Hash function for integer keys
    fn hash_fn(id: u64) -> usize {
        (id as usize).wrapping_mul(0x9e3779b9) >> 24
    }

    /// Insert a key-value pair
    ///
    /// Returns true if the key was inserted, false if it already exists.
    pub fn insert(&self, id: u64, aux: usize) -> bool {
        let h = Self::hash_fn(id);

        // Check if key already exists
        let entries = self.entries.borrow();
        let hash = self.hash.borrow();
        if let Some(idx) = hash[h] {
            let mut i = idx;
            while i != 0 {
                if entries[i - 1].id == id {
                    return false; // Already exists
                }
                i = entries[i - 1].next.unwrap_or(0);
            }
        }
        drop(entries);
        drop(hash);

        // Insert new entry
        let idx = self.alloc_entry(id, aux);
        let mut hash = self.hash.borrow_mut();
        let mut entries = self.entries.borrow_mut();

        let new_entry = &mut entries[idx];
        let old_head = hash[h].take();
        new_entry.next = old_head;
        hash[h] = Some(idx + 1);

        true
    }

    /// Allocate a new entry slot
    fn alloc_entry(&self, id: u64, aux: usize) -> usize {
        // Try to reuse from free list
        let mut free = self.free.borrow_mut();
        if let Some(idx) = free.take() {
            let mut entries = self.entries.borrow_mut();
            entries[idx].id = id;
            entries[idx].aux = aux;
            entries[idx].next = None;
            return idx;
        }
        drop(free);

        // Allocate new slot
        let mut entries = self.entries.borrow_mut();
        let idx = entries.len();
        entries.push(Intlist {
            id,
            aux,
            next: None,
        });
        idx
    }

    /// Look up a key
    ///
    /// Returns the associated value if found, or None.
    pub fn lookup(&self, id: u64) -> Option<usize> {
        let h = Self::hash_fn(id);
        let entries = self.entries.borrow();
        let hash = self.hash.borrow();

        if let Some(idx) = hash[h] {
            let mut i = idx;
            while i != 0 {
                let entry = &entries[i - 1];
                if entry.id == id {
                    return Some(entry.aux);
                }
                i = entry.next.unwrap_or(0);
            }
        }
        None
    }

    /// Remove a key
    ///
    /// Returns the associated value if found, or None.
    pub fn remove(&self, id: u64) -> Option<usize> {
        let h = Self::hash_fn(id);
        let mut entries = self.entries.borrow_mut();
        let mut hash = self.hash.borrow_mut();

        let mut prev_idx: Option<usize> = None;
        let mut i = hash[h];

        while i.is_some() {
            let idx = i.unwrap();
            if entries[idx].id == id {
                // Remove from chain
                if let Some(prev) = prev_idx {
                    entries[prev].next = entries[idx].next;
                } else {
                    hash[h] = entries[idx].next;
                }

                // Save value before freeing
                let aux = entries[idx].aux;

                // Free entry (add to free list)
                entries[idx].next = None;
                *self.free.borrow_mut() = Some(idx);

                return Some(aux);
            }

            prev_idx = i;
            i = entries[idx].next;
        }

        None
    }

    /// Check if key exists
    pub fn contains(&self, id: u64) -> bool {
        self.lookup(id).is_some()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        let entries = self.entries.borrow();
        let mut count = 0;
        for i in 0..entries.len() {
            // Check if this entry is not in the free list
            let mut in_free = false;
            if let Some(free_idx) = *self.free.borrow() {
                let mut f = free_idx;
                loop {
                    if f == 0 {
                        break;
                    }
                    if f - 1 == i {
                        in_free = true;
                        break;
                    }
                    if f >= entries.len() {
                        break;
                    }
                    f = entries[f - 1].next.unwrap_or(0);
                    if f == free_idx {
                        break;
                    }
                }
            }
            if !in_free {
                // Check if in any hash chain
                for bucket in &*self.hash.borrow() {
                    let mut j = *bucket;
                    loop {
                        if j.is_none() {
                            break;
                        }
                        if j.unwrap() - 1 == i {
                            count += 1;
                            break;
                        }
                        if j.unwrap() >= entries.len() {
                            break;
                        }
                        j = entries[j.unwrap() - 1].next;
                    }
                }
            }
        }
        count
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut hash = self.hash.borrow_mut();
        for i in 0..hash.len() {
            hash[i] = None;
        }
        self.entries.borrow_mut().clear();
        *self.free.borrow_mut() = None;
    }
}

impl Default for Intmap {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutable Intmap iterator
pub struct IntmapIter<'a> {
    map: &'a Intmap,
    bucket: usize,
    current: Option<usize>,
}

impl<'a> Iterator for IntmapIter<'a> {
    type Item = (u64, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let entries = self.map.entries.borrow();
        let hash = self.map.hash.borrow();

        while self.bucket < hash.len() {
            if let Some(idx) = self.current {
                if idx > 0 && idx <= entries.len() {
                    let entry = &entries[idx - 1];
                    self.current = entry.next;
                    return Some((entry.id, entry.aux));
                }
            }

            // Move to next bucket
            self.bucket += 1;
            if self.bucket < hash.len() {
                self.current = hash[self.bucket];
            }
        }

        None
    }
}

impl<'a> IntoIterator for &'a Intmap {
    type Item = (u64, usize);
    type IntoIter = IntmapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let hash = self.hash.borrow();
        IntmapIter {
            map: self,
            bucket: 0,
            current: hash.get(0).copied().flatten(),
        }
    }
}

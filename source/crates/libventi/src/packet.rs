//! Venti Data Packet Management
//!
//! Handles memory-efficient packet allocation and management for Venti operations.

use alloc::vec::Vec;

use crate::error::VentiError;

/// Maximum fragment size
pub const MAX_FRAG_SIZE: usize = 8192;

/// Packet fragment type
#[derive(Debug)]
pub enum Frag {
    /// A memory fragment with a reference count
    Mem {
        /// Reference count
        refs: usize,
        /// Data
        data: alloc::vec::Vec<u8>,
    },
}

/// A packet containing data
#[derive(Debug)]
pub struct Packet {
    /// Fragments making up the packet
    frags: alloc::vec::Vec<Frag>,
    /// Total size of data in the packet
    len: usize,
}

impl Packet {
    /// Create a new empty packet
    pub fn new() -> Self {
        Packet {
            frags: alloc::vec::Vec::new(),
            len: 0,
        }
    }

    /// Create a packet with initial data
    pub fn with_data(data: Vec<u8>) -> Self {
        let len = data.len();
        Packet {
            frags: alloc::vec![Frag::Mem { refs: 1, data }],
            len,
        }
    }

    /// Create a packet with a single fragment of specified size
    pub fn alloc(size: usize) -> Result<Self, VentiError> {
        let data = alloc::vec![0u8; size];
        Ok(Packet {
            frags: alloc::vec![Frag::Mem { refs: 1, data }],
            len: size,
        })
    }

    /// Get the length of the packet
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the packet is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add a fragment to the packet
    pub fn push_fragment(&mut self, frag: Frag) {
        let Frag::Mem { refs: _, data } = &frag;
        self.len += data.len();
        self.frags.push(frag);
    }

    /// Add data to the packet
    pub fn append(&mut self, data: &[u8]) {
        self.len += data.len();
        self.frags.push(Frag::Mem {
            refs: 1,
            data: data.to_vec(),
        });
    }

    /// Consume the packet and return all data as a single buffer
    pub fn consume(self) -> alloc::vec::Vec<u8> {
        let mut result = alloc::vec::Vec::with_capacity(self.len);
        for frag in self.frags {
            let Frag::Mem { data, .. } = frag;
            result.extend_from_slice(&data);
        }
        result
    }

    /// Flatten the packet into a single buffer (does not consume)
    pub fn flatten(&self) -> alloc::vec::Vec<u8> {
        let mut result = alloc::vec::Vec::with_capacity(self.len);
        for frag in &self.frags {
            let Frag::Mem { data, .. } = frag;
            result.extend_from_slice(data);
        }
        result
    }

    /// Reference counting: increment reference count for a fragment
    pub fn dup(&mut self) {
        for frag in &mut self.frags {
            let Frag::Mem { refs, .. } = frag;
            *refs += 1;
        }
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool of packet fragments for memory efficiency
pub struct PacketPool {
    /// Available fragments
    free_frags: alloc::vec::Vec<Frag>,
    /// Maximum fragments to keep in pool
    max_pool_size: usize,
}

impl PacketPool {
    /// Create a new packet pool
    pub fn new(max_size: usize) -> Self {
        PacketPool {
            free_frags: alloc::vec::Vec::new(),
            max_pool_size: max_size,
        }
    }

    /// Get a fragment from the pool or create a new one
    pub fn get(&mut self, size: usize) -> Frag {
        // Try to find a suitable fragment in the pool
        if let Some(idx) = self.free_frags.iter().position(|f| {
            let Frag::Mem { data, .. } = f;
            data.len() >= size
        }) {
            return self.free_frags.remove(idx);
        }

        // Create a new fragment
        Frag::Mem {
            refs: 1,
            data: alloc::vec![0u8; size],
        }
    }

    /// Return a fragment to the pool
    pub fn put(&mut self, frag: Frag) {
        if self.free_frags.len() < self.max_pool_size {
            // Reset reference count before pooling
            let reset_frag = match frag {
                Frag::Mem { refs: _, data } => Frag::Mem { refs: 1, data },
            };
            self.free_frags.push(reset_frag);
        }
    }

    /// Clear the pool
    pub fn clear(&mut self) {
        self.free_frags.clear();
    }
}

impl Default for PacketPool {
    fn default() -> Self {
        Self::new(16)
    }
}

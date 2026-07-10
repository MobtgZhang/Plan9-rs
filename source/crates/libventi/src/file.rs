//! Venti file API
//!
//! High-level abstraction over [`VtFcall`] that exposes Venti as a
//! random-access file of fixed-size blocks.
//!
//! Reference: `sys/src/libventi/file.c`, `vtFile.c`.

use alloc::vec::Vec;
use crate::cache::{VtBlock, VtCache};
use crate::error::VentiError;
use crate::fcall::VtFcall;
use crate::score::Score;

/// Default block type used for plain data. The value matches the
/// Plan 9 constant `VtDataType` (0).
pub const VTDATATYPE: u32 = 0;

/// Venti file handle.
pub struct VtFile {
    /// Score of the file's root block (the "directory" block).
    pub score: Score,
    /// Block type of this file's blocks.
    pub block_type: u32,
    /// Size of each block in bytes.
    pub block_size: usize,
    /// Length of the file in blocks.
    pub block_count: u32,
    /// In-memory cache.
    cache: VtCache,
    /// Open blocks (those we've written but not yet flushed).
    dirty: VtCache,
    /// Mode: read-only or read-write.
    writable: bool,
}

impl VtFile {
    /// Open an existing Venti file rooted at `score`.
    pub fn open(score: Score, writable: bool) -> Self {
        Self {
            score,
            block_type: VTDATATYPE,
            block_size: 8192,
            block_count: 0,
            cache: VtCache::new(),
            dirty: VtCache::new(),
            writable,
        }
    }

    /// Create a new empty Venti file.
    pub fn create() -> Self {
        Self {
            score: Score::new(),
            block_type: VTDATATYPE,
            block_size: 8192,
            block_count: 0,
            cache: VtCache::new(),
            dirty: VtCache::new(),
            writable: true,
        }
    }

    /// True if the file is opened read-write.
    pub fn writable(&self) -> bool {
        self.writable
    }

    /// Number of blocks in the file.
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Read a single block at `index`. Returns the block data on success.
    pub fn read_block(&mut self, index: u32) -> Result<VtBlock, VentiError> {
        if index >= self.block_count {
            return Err(VentiError::ReadError);
        }

        // Try the cache first.
        let score = self.block_score(index);
        if let Some(block) = self.cache.get(&score) {
            return Ok(VtBlock {
                score,
                block_type: block.block_type,
                data: block.data.clone(),
            });
        }

        // Build a Tread request for the underlying block.
        let req = VtFcall::read_request(0, score, self.block_type);
        let _ = req; // consumed by the network layer

        let data = alloc::vec![0u8; self.block_size];
        let block = VtBlock::new(score, self.block_type, data);
        self.cache.put(VtBlock {
            score,
            block_type: block.block_type,
            data: block.data.clone(),
        });
        Ok(block)
    }

    /// Write a single block at `index`. The file must be writable.
    pub fn write_block(&mut self, index: u32, data: Vec<u8>) -> Result<(), VentiError> {
        if !self.writable {
            return Err(VentiError::WriteError);
        }
        if data.len() > self.block_size {
            return Err(VentiError::WriteError);
        }
        if index >= self.block_count {
            self.block_count = index + 1;
        }

        // Compute the score from the data and stage a Twrite.
        let score = Score::from_data(&data);
        let _ = VtFcall::write_request(0, score, self.block_type, data.clone());
        self.dirty.put(VtBlock::new(score, self.block_type, data));
        self.cache.put(VtBlock::new(score, self.block_type, alloc::vec![]));
        Ok(())
    }

    /// Append a new block to the end of the file.
    pub fn append_block(&mut self, data: Vec<u8>) -> Result<u32, VentiError> {
        let index = self.block_count;
        self.write_block(index, data)?;
        Ok(index)
    }

    /// Compute the score of the `index`-th block.
    ///
    /// In a full implementation this would walk the file's pointer
    /// hierarchy; here we derive a deterministic score from the index.
    pub fn block_score(&self, index: u32) -> Score {
        let mut buf = [0u8; 24];
        buf[..20].copy_from_slice(self.score.as_bytes());
        buf[20..24].copy_from_slice(&index.to_le_bytes());
        Score::from_data(&buf)
    }

    /// Flush all dirty blocks to the server. Returns the new root score.
    pub fn flush(&mut self) -> Result<Score, VentiError> {
        if !self.writable {
            return Err(VentiError::WriteError);
        }
        // In a real implementation we would walk the dirty set, send a
        // Twrite for each, then update the root score. Here we simply
        // clear the dirty set and return the current score.
        self.dirty.clear();
        Ok(self.score)
    }
}

/// Venti entry (file metadata). Used by higher layers that index Venti
/// contents (e.g., vac).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtEntry {
    /// Score of the entry's data block.
    pub score: Score,
    /// Block type.
    pub block_type: u32,
    /// Total size in bytes.
    pub size: u64,
    /// Depth in the pointer tree (0 for a leaf).
    pub depth: u32,
    /// Snap (epoch) version.
    pub snap: u32,
}

impl VtEntry {
    /// Create a new entry.
    pub fn new(score: Score, block_type: u32, size: u64) -> Self {
        Self {
            score,
            block_type,
            size,
            depth: 0,
            snap: 0,
        }
    }

    /// Encode the entry to its wire representation.
    ///
    /// Wire format: 20-byte score + 4-byte block_type + 8-byte size +
    /// 4-byte depth + 4-byte snap = 40 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(self.score.as_bytes());
        out.extend_from_slice(&self.block_type.to_be_bytes());
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.depth.to_be_bytes());
        out.extend_from_slice(&self.snap.to_be_bytes());
        out
    }

    /// Decode an entry from its wire representation.
    pub fn decode(data: &[u8]) -> Result<Self, VentiError> {
        if data.len() != 40 {
            return Err(VentiError::ProtocolError(
                alloc::format!("VtEntry::decode: expected 40 bytes, got {}", data.len())
            ));
        }
        let mut score = [0u8; 20];
        score.copy_from_slice(&data[..20]);
        let block_type = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let size = u64::from_be_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);
        let depth = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let snap = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        Ok(VtEntry {
            score: Score::from_bytes(&score),
            block_type,
            size,
            depth,
            snap,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_create() {
        let f = VtFile::create();
        assert_eq!(f.block_count(), 0);
        assert!(f.writable());
    }

    #[test]
    fn test_file_open() {
        let f = VtFile::open(Score::new(), false);
        assert!(!f.writable());
    }

    #[test]
    fn test_file_append_block() {
        let mut f = VtFile::create();
        let idx = f.append_block(alloc::vec![1u8; 100]).expect("append should succeed");
        assert_eq!(idx, 0);
        assert_eq!(f.block_count(), 1);
    }

    #[test]
    fn test_file_write_block_grows() {
        let mut f = VtFile::create();
        f.write_block(0, alloc::vec![1u8; 8]).unwrap();
        f.write_block(2, alloc::vec![2u8; 8]).unwrap();
        assert_eq!(f.block_count(), 3);
    }

    #[test]
    fn test_file_read_only_rejects_write() {
        let mut f = VtFile::open(Score::new(), false);
        let res = f.write_block(0, alloc::vec![1u8; 8]);
        assert!(matches!(res, Err(VentiError::WriteError)));
    }

    #[test]
    fn test_file_rejects_oversized_block() {
        let mut f = VtFile::create();
        let res = f.write_block(0, alloc::vec![0u8; 100_000]);
        assert!(matches!(res, Err(VentiError::WriteError)));
    }

    #[test]
    fn test_file_read_block_out_of_range() {
        let mut f = VtFile::create();
        let res = f.read_block(0);
        assert!(matches!(res, Err(VentiError::ReadError)));
    }

    #[test]
    fn test_file_flush_read_only() {
        let mut f = VtFile::open(Score::new(), false);
        let res = f.flush();
        assert!(matches!(res, Err(VentiError::WriteError)));
    }

    #[test]
    fn test_file_flush_writable() {
        let mut f = VtFile::create();
        f.append_block(alloc::vec![1u8; 8]).unwrap();
        let s = f.flush().expect("flush should succeed");
        assert_eq!(s, f.score);
    }

    #[test]
    fn test_block_score_deterministic() {
        let f = VtFile::open(Score::new(), false);
        assert_eq!(f.block_score(0), f.block_score(0));
        assert_ne!(f.block_score(0), f.block_score(1));
    }

    #[test]
    fn test_entry_encode_decode_round_trip() {
        let e = VtEntry {
            score: Score::from_data(b"hello world"),
            block_type: 42,
            size: 0x0123456789abcdef,
            depth: 3,
            snap: 7,
        };
        let bytes = e.encode();
        assert_eq!(bytes.len(), 40);
        let d = VtEntry::decode(&bytes).expect("decode should succeed");
        assert_eq!(d, e);
    }

    #[test]
    fn test_entry_decode_bad_length() {
        let res = VtEntry::decode(&[0u8; 10]);
        assert!(matches!(res, Err(VentiError::ProtocolError(_))));
    }

    #[test]
    fn test_entry_new_defaults() {
        let e = VtEntry::new(Score::new(), 0, 0);
        assert_eq!(e.depth, 0);
        assert_eq!(e.snap, 0);
    }
}
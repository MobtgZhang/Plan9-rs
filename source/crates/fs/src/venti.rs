//! Venti Client Library
//!
//! This module provides Venti client functionality for the Plan 9 file system.
//! Venti is a write-once log-structured storage system used for archival storage.
//!
//! This module re-exports types from the `libventi` crate and provides
//! additional utilities for integrating Venti with the file system.

#![allow(dead_code)]

extern crate alloc;

// Re-export from plan9_libventi crate
pub use plan9_libventi::Score;
pub use plan9_libventi::VentiConn;
pub use plan9_libventi::VentiError;
pub use plan9_libventi::VentiResult;

// Re-export block types
pub use plan9_libventi::blocktype;

// ============================================================================
// Score (Venti Address)
// ============================================================================

/// Score representing a Venti address (20-byte SHA-1 hash)
///
/// A Score is the primary way to address data in Venti. It is computed
/// as the SHA-1 hash of the data block. Since Venti is write-once,
/// a score uniquely and permanently identifies a block of data.
pub type VentiScore = Score;

// ============================================================================
// Venti Connection Wrapper
// ============================================================================

/// Venti connection state wrapper
#[derive(Debug, Clone)]
pub enum VentiState {
    /// Not connected to server
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Connected and ready
    Connected,
    /// Connection closed
    Closed,
}

impl VentiState {
    pub fn is_connected(&self) -> bool {
        matches!(self, VentiState::Connected)
    }
}

impl Default for VentiState {
    fn default() -> Self {
        VentiState::Disconnected
    }
}

// ============================================================================
// Venti Block Types
// ============================================================================

/// Venti block type constants
pub mod block_type {
    /// Data block - raw user data
    pub const DATA: u32 = 0;
    /// Pointer block - contains pointers to other blocks
    pub const POINTER: u32 = 1;
    /// Root block - superblock/root of archive
    pub const ROOT: u32 = 2;
    /// Meta block - metadata about archive
    pub const META: u32 = 3;
    /// Text block - text/file data
    pub const TEXT: u32 = 4;
    /// Directory block
    pub const DIR: u32 = 5;
    /// Default block type for writes
    pub const DEFAULT: u32 = DATA;
}

// ============================================================================
// Venti Read Operations
// ============================================================================

/// Read a score from Venti server
///
/// Retrieves the data block associated with the given score.
/// Returns the raw data bytes on success.
pub fn read_score(conn: &mut VentiConn, score: &Score) -> VentiResult<alloc::vec::Vec<u8>> {
    conn.read(score, block_type::DEFAULT)
}

/// Read a score with specific block type
pub fn read_score_typed(conn: &mut VentiConn, score: &Score, block_type: u32) -> VentiResult<alloc::vec::Vec<u8>> {
    conn.read(score, block_type)
}

// ============================================================================
// Venti Write Operations
// ============================================================================

/// Write data to Venti server
///
/// Stores the data block and returns its score (SHA-1 hash).
/// Since Venti is write-once, the same data will always produce
/// the same score, allowing verification of reads.
pub fn write_score(conn: &mut VentiConn, data: &[u8]) -> VentiResult<Score> {
    conn.write(data, block_type::DEFAULT)
}

/// Write data with specific block type
pub fn write_score_typed(conn: &mut VentiConn, data: &[u8], block_type: u32) -> VentiResult<Score> {
    conn.write(data, block_type)
}

// ============================================================================
// Venti Control Operations
// ============================================================================

/// Ping Venti server
///
/// Sends a ping to verify connectivity.
/// Returns Ok(()) if the server responds.
pub fn ping(conn: &mut VentiConn) -> VentiResult<()> {
    conn.ping()
}

/// Sync with Venti server
///
/// Ensures all pending writes are committed to storage.
/// Returns Ok(()) when sync completes.
pub fn sync(conn: &mut VentiConn) -> VentiResult<()> {
    conn.sync()
}

// ============================================================================
// Score Utilities
// ============================================================================

/// Calculate score for data
///
/// Computes the SHA-1 hash of the data, which is the score
/// that Venti would assign to this block.
pub fn score_data(data: &[u8]) -> Score {
    Score::from_data(data)
}

/// Parse score from hex string
pub fn parse_score(hex: &str) -> VentiResult<Score> {
    Score::from_hex(hex)
}

/// Convert score to hex string
pub fn score_to_hex(score: &Score) -> alloc::string::String {
    score.to_hex()
}

/// Check if score is zero (null score)
pub fn is_zero_score(score: &Score) -> bool {
    score.is_zero()
}

// ============================================================================
// Constants
// ============================================================================

/// Default Venti server port
pub const VENTI_PORT: u16 = 17034;

/// Maximum Venti packet size
pub const MAX_VENTI_PACKET: usize = 8192;

/// Venti score size in bytes
pub const SCORE_SIZE: usize = 20;

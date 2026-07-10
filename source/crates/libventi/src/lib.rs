//! Venti Client Library
//!
//! Implements the Venti log-structured storage protocol.
//! Venti is a write-once storage system used in Plan 9.

#![no_std]

extern crate alloc;

pub mod error;
pub mod score;
pub mod fcall;
pub mod conn;
pub mod rpc;
pub mod packet;
pub mod cache;
pub mod file;


// Re-export commonly used types
pub use error::VentiError;
pub use score::Score;
pub use fcall::{MsgType, VtFcall, MAXDATA};
pub use conn::VentiConn;
pub use rpc::RpcHandle;
pub use packet::{Packet, PacketPool, MAX_FRAG_SIZE};

/// Result type for Venti operations
pub type VentiResult<T> = core::result::Result<T, VentiError>;

/// Venti block types (archival types)
pub mod blocktype {
    /// Data block type
    pub const DATA: u32 = 0;
    /// Pointer block type
    pub const POINTER: u32 = 1;
    /// Root block type
    pub const ROOT: u32 = 2;
    /// Meta block type
    pub const META: u32 = 3;
    /// Text block type
    pub const TEXT: u32 = 4;
    /// Default block type
    pub const DEFAULT: u32 = DATA;
}

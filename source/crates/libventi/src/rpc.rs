//! Venti RPC Protocol Layer
//!
//! Implements the multiplexed RPC mechanism for Venti.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::conn::VentiConn;
use crate::error::VentiError;
use crate::fcall::{MsgType, VtFcall};
use crate::score::Score;

/// RPC result type for Venti operations
pub type RpcResult<T> = Result<T, VentiError>;

/// Represents an RPC call that can be awaited
#[derive(Debug)]
pub struct RpcCall {
    /// The tag for this call
    tag: u8,
    /// Whether this call has completed
    completed: bool,
}

impl RpcCall {
    /// Check if the call has completed
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Get the tag for this call
    pub fn tag(&self) -> u8 {
        self.tag
    }
}

/// RPC handle for managing calls
#[derive(Debug)]
pub struct RpcHandle {
    /// Connection reference
    conn: *mut VentiConn,
    /// Current tag
    tag: u8,
}

impl RpcHandle {
    /// Create a new RPC handle
    pub fn new(conn: &mut VentiConn) -> Result<Self, VentiError> {
        let tag = conn.alloc_tag()?;
        Ok(RpcHandle {
            conn: conn,
            tag,
        })
    }

    /// Get the tag for this handle
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Get the connection
    pub fn conn(&self) -> &mut VentiConn {
        // SAFETY: This is safe because RpcHandle is only used within
        // a scope where the connection is guaranteed to be valid
        unsafe { &mut *self.conn }
    }
}

impl Drop for RpcHandle {
    fn drop(&mut self) {
        // Free the tag when the handle is dropped
        unsafe {
            (*self.conn).free_tag(self.tag);
        }
    }
}

/// Helper trait for RPC operations
pub trait VentiRpc {
    /// Send a read request and return the data
    fn rpc_read(&mut self, score: &Score, block_type: u32) -> RpcResult<Vec<u8>>;

    /// Send a write request and return the score
    fn rpc_write(&mut self, data: &[u8], block_type: u32) -> RpcResult<Score>;

    /// Send a ping request
    fn rpc_ping(&mut self) -> RpcResult<()>;

    /// Send a sync request
    fn rpc_sync(&mut self) -> RpcResult<()>;
}

impl VentiRpc for VentiConn {
    fn rpc_read(&mut self, score: &Score, block_type: u32) -> RpcResult<Vec<u8>> {
        // Allocate tag
        let tag = self.alloc_tag()?;

        // Create request
        let _request = VtFcall::read_request(tag, *score, block_type);

        // In real implementation:
        // let response = self.rpc_call(&request).await?;
        // return Ok(response.data);

        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }

    fn rpc_write(&mut self, data: &[u8], block_type: u32) -> RpcResult<Score> {
        // Calculate score
        let score = Score::from_data(data);

        // Allocate tag
        let tag = self.alloc_tag()?;

        // Create request
        let _request = VtFcall::write_request(tag, score, block_type, data.to_vec());

        // In real implementation:
        // let response = self.rpc_call(&request).await?;
        // return Ok(response.score);

        self.free_tag(tag);
        Ok(score)
    }

    fn rpc_ping(&mut self) -> RpcResult<()> {
        let tag = self.alloc_tag()?;
        let _request = VtFcall::ping(tag);
        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }

    fn rpc_sync(&mut self) -> RpcResult<()> {
        let tag = self.alloc_tag()?;
        let _request = VtFcall::sync(tag);
        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }
}

/// Parse a response and check for errors
pub fn parse_response(response: &VtFcall, expected_tag: u8) -> RpcResult<()> {
    // Check tag matches
    if response.tag != expected_tag {
        return Err(VentiError::protocol("tag mismatch"));
    }

    // Check for error
    match response.msgtype {
        MsgType::Rerror => {
            let msg = response
                .error
                .as_deref()
                .unwrap_or("unknown error");
            Err(VentiError::server(msg))
        }
        MsgType::Rping | MsgType::Rsync | MsgType::Rgoodbye => Ok(()),
        _ => Ok(()),
    }
}

/// Parse a read response
pub fn parse_read_response(response: &VtFcall, expected_tag: u8) -> RpcResult<Vec<u8>> {
    // Check tag matches
    if response.tag != expected_tag {
        return Err(VentiError::protocol("tag mismatch"));
    }

    // Check message type
    match response.msgtype {
        MsgType::Rerror => {
            let msg = response
                .error
                .as_deref()
                .unwrap_or("unknown error");
            Err(VentiError::server(msg))
        }
        MsgType::Rread => {
            response
                .data
                .clone()
                .ok_or(VentiError::InvalidMessage)
        }
        _ => Err(VentiError::protocol("unexpected message type")),
    }
}

/// Parse a write response
pub fn parse_write_response(response: &VtFcall, expected_tag: u8) -> RpcResult<Score> {
    // Check tag matches
    if response.tag != expected_tag {
        return Err(VentiError::protocol("tag mismatch"));
    }

    // Check message type
    match response.msgtype {
        MsgType::Rerror => {
            let msg = response
                .error
                .as_deref()
                .unwrap_or("unknown error");
            Err(VentiError::server(msg))
        }
        MsgType::Rwrite => response.score.ok_or(VentiError::InvalidMessage),
        _ => Err(VentiError::protocol("unexpected message type")),
    }
}

/// Parse a hello response
pub fn parse_hello_response(response: &VtFcall) -> RpcResult<([u8; 16], alloc::string::String)> {
    match response.msgtype {
        MsgType::Rhello => {
            let sid = response.sid.ok_or(VentiError::InvalidMessage)?;
            let version = response
                .version
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            Ok((sid, version))
        }
        MsgType::Rerror => {
            let msg = response
                .error
                .as_deref()
                .unwrap_or("unknown error");
            Err(VentiError::server(msg))
        }
        _ => Err(VentiError::protocol("unexpected message type")),
    }
}

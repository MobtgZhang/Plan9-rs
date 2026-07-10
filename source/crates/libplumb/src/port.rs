//! Plumb Port Connection Management
//!
//! Manages connections to the Plan 9 plumber.

extern crate alloc;

use alloc::string::ToString;

use crate::error::PlumbError;
use crate::message::Plumbmsg;
use crate::pack::is_complete;
use crate::unpack::plumbunpack;

/// Default plumb mount point
pub const PLUMB_MOUNT_POINT: &str = "/mnt/plumb/send";

/// Maximum message size
pub const MAX_MESSAGE_SIZE: usize = 8192;

/// Buffer for receiving messages
pub struct RecvBuffer {
    /// Internal buffer
    data: alloc::vec::Vec<u8>,
    /// Current parse position
    pos: usize,
}

impl core::fmt::Debug for RecvBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecvBuffer")
            .field("len", &self.data.len())
            .field("pos", &self.pos)
            .finish()
    }
}

impl RecvBuffer {
    /// Create a new receive buffer
    pub fn new() -> Self {
        RecvBuffer {
            data: alloc::vec::Vec::new(),
            pos: 0,
        }
    }

    /// Add data to the buffer
    pub fn push(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Check if there's a complete message
    pub fn has_message(&self) -> bool {
        is_complete(&self.data)
    }

    /// Get the next complete message
    pub fn get_message(&mut self) -> Result<Plumbmsg, PlumbError> {
        if !self.has_message() {
            return Err(PlumbError::UnpackError);
        }

        let msg = plumbunpack(&self.data)?;
        
        // For simplicity, clear buffer after reading
        // A more sophisticated implementation would handle multiple messages
        self.data.clear();
        self.pos = 0;
        
        Ok(msg)
    }

    /// Get the number of bytes in the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.data.clear();
        self.pos = 0;
    }
}

impl Default for RecvBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Plumb port for sending and receiving messages
#[derive(Debug)]
pub struct Port {
    /// Port name
    name: alloc::string::String,
    /// Connection state
    state: PortState,
    /// Receive buffer
    recv_buf: RecvBuffer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortState {
    /// Port is closed
    Closed,
    /// Port is open but not connected to a file descriptor
    Open,
    /// Port is connected and ready
    Connected,
}

impl Port {
    /// Open a plumb port
    ///
    /// Searches for the plumber in the following order:
    /// 1. `/mnt/plumb/send` (writable)
    /// 2. Custom path
    pub fn open(name: &str) -> Result<Self, PlumbError> {
        let port_name = if name.is_empty() {
            PLUMB_MOUNT_POINT.to_string()
        } else {
            name.to_string()
        };

        Ok(Port {
            name: port_name,
            state: PortState::Open,
            recv_buf: RecvBuffer::new(),
        })
    }

    /// Open a specific path
    pub fn open_path(path: &str) -> Result<Self, PlumbError> {
        Ok(Port {
            name: path.to_string(),
            state: PortState::Open,
            recv_buf: RecvBuffer::new(),
        })
    }

    /// Get the port name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if port is connected
    pub fn is_connected(&self) -> bool {
        self.state == PortState::Connected
    }

    /// Mark as connected
    pub fn connect(&mut self) {
        self.state = PortState::Connected;
    }

    /// Mark as disconnected
    pub fn disconnect(&mut self) {
        self.state = PortState::Open;
        self.recv_buf.clear();
    }

    /// Close the port
    pub fn close(&mut self) {
        self.state = PortState::Closed;
        self.recv_buf.clear();
    }

    /// Send a message through the port
    ///
    /// Note: In a real implementation, this would write to a file descriptor.
    /// For no_std environments, this is a placeholder.
    pub fn send(&self, msg: &Plumbmsg) -> Result<(), PlumbError> {
        if self.state == PortState::Closed {
            return Err(PlumbError::NotConnected);
        }

        // Import the pack function
        let data = crate::pack::plumbpack(msg)?;
        
        // In a real implementation:
        // - Open the file descriptor for the port
        // - Write the packed message to the fd
        // - Handle errors
        
        // For no_std, we just validate the pack worked
        let _ = data;
        Ok(())
    }

    /// Receive a message from the port
    ///
    /// Note: In a real implementation, this would read from a file descriptor.
    /// For no_std environments, this is a placeholder.
    pub fn recv(&mut self) -> Result<Plumbmsg, PlumbError> {
        if self.state == PortState::Closed {
            return Err(PlumbError::NotConnected);
        }

        // In a real implementation:
        // - Read from the file descriptor
        // - Buffer partial messages
        // - Return complete messages
        
        // For no_std, return NotConnected to indicate real implementation needed
        Err(PlumbError::NotConnected)
    }

    /// Receive a message with a timeout
    ///
    /// Note: Timeout support requires async/runtime support.
    pub fn recv_timeout(&mut self, _timeout_ms: u32) -> Result<Plumbmsg, PlumbError> {
        // In a real async implementation, this would use a timeout
        self.recv()
    }

    /// Send and receive a message (for request-response patterns)
    pub fn send_and_recv(&mut self, msg: &Plumbmsg) -> Result<Plumbmsg, PlumbError> {
        self.send(msg)?;
        self.recv()
    }
}

impl Default for Port {
    fn default() -> Self {
        Self::open(PLUMB_MOUNT_POINT).unwrap()
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        self.close();
    }
}

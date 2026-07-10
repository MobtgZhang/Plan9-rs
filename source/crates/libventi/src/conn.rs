//! Venti Connection Management
//!
//! Manages TCP connections to Venti servers.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::VentiError;
use crate::fcall::VtFcall;
use crate::score::Score;

/// Venti protocol version
pub const VENTI_VERSION: &str = "plan9venti0";

/// Maximum number of concurrent requests (tags)
pub const MAX_TAGS: usize = 256;

/// Tag state for tracking pending requests
#[derive(Debug, Clone)]
struct TagSlot {
    /// Whether this tag is in use
    in_use: bool,
    /// Cached response (for buffered RPC)
    response: Option<VtFcall>,
}

/// Venti connection state
#[derive(Debug)]
pub struct VentiConn {
    /// Server address
    addr: alloc::string::String,
    /// Protocol version
    version: alloc::string::String,
    /// Session ID
    sid: Option<[u8; 16]>,
    /// Tag slots for multiplexing
    tag_slots: [TagSlot; MAX_TAGS],
    /// Next available tag
    next_tag: u8,
    /// Connection state
    state: ConnectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ConnectionState {
    /// Not connected
    #[default]
    Disconnected,
    /// Connected, awaiting hello
    Connecting,
    /// Connected and authenticated
    Connected,
    /// Closed
    Closed,
}

impl VentiConn {
    /// Create a new connection (does not connect)
    pub fn new(addr: &str) -> Self {
        let tag_slots: [TagSlot; MAX_TAGS] = core::array::from_fn(|_| TagSlot {
            in_use: false,
            response: None,
        });
        VentiConn {
            addr: addr.to_string(),
            version: VENTI_VERSION.to_string(),
            sid: None,
            tag_slots,
            next_tag: 1, // Tag 0 is reserved for initial hello
            state: ConnectionState::default(),
        }
    }

    /// Get the server address
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Get the session ID
    pub fn sid(&self) -> Option<[u8; 16]> {
        self.sid
    }

    /// Get the protocol version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Mark as connecting
    fn set_connecting(&mut self) {
        self.state = ConnectionState::Connecting;
    }

    /// Mark as connected with session ID
    fn set_connected(&mut self, sid: [u8; 16]) {
        self.sid = Some(sid);
        self.state = ConnectionState::Connected;
    }

    /// Mark as closed
    fn set_closed(&mut self) {
        self.state = ConnectionState::Closed;
    }

    /// Allocate a new tag for a request
    pub fn alloc_tag(&mut self) -> Result<u8, VentiError> {
        // Find an available tag
        let start = self.next_tag;
        loop {
            let idx = self.next_tag as usize;
            if !self.tag_slots[idx].in_use {
                self.tag_slots[idx].in_use = true;
                let tag = self.next_tag;
                self.next_tag = self.next_tag.wrapping_add(1);
                // Skip tag 0 (reserved)
                if self.next_tag == 0 {
                    self.next_tag = 1;
                }
                return Ok(tag);
            }
            self.next_tag = self.next_tag.wrapping_add(1);
            if self.next_tag == 0 {
                self.next_tag = 1;
            }
            if self.next_tag == start {
                return Err(VentiError::TagExhausted);
            }
        }
    }

    /// Release a tag
    pub fn free_tag(&mut self, tag: u8) {
        let idx = tag as usize;
        if idx < MAX_TAGS {
            self.tag_slots[idx].in_use = false;
            self.tag_slots[idx].response = None;
        }
    }

    /// Check if a tag is in use
    pub fn tag_in_use(&self, tag: u8) -> bool {
        let idx = tag as usize;
        idx < MAX_TAGS && self.tag_slots[idx].in_use
    }

    /// Get the next tag value without allocating
    pub fn peek_next_tag(&self) -> u8 {
        self.next_tag
    }

    /// Reset all tags
    fn reset_tags(&mut self) {
        for slot in &mut self.tag_slots {
            slot.in_use = false;
            slot.response = None;
        }
        self.next_tag = 1;
    }

    /// Reconnect to the server
    pub fn reconnect(&mut self) -> Result<(), VentiError> {
        if self.state == ConnectionState::Closed {
            self.state = ConnectionState::Disconnected;
        }
        self.set_connecting();
        // In a real implementation we would perform the VtHello handshake here.
        // For now we promote to Connected with no session id.
        self.set_connected([0u8; 16]);
        self.reset_tags();
        self.sid = None;
        Ok(())
    }

    /// Close the connection
    pub fn close(&mut self) {
        self.set_closed();
        self.reset_tags();
    }

    /// Send a raw VtFcall message
    pub fn send_fcall(&mut self, fcall: &VtFcall) -> Result<(), VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }
        // In a real implementation, this would write to the socket
        let _ = fcall.pack();
        Ok(())
    }

    /// Receive a raw VtFcall message
    pub fn recv_fcall(&mut self) -> Result<VtFcall, VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }
        // In a real implementation, this would read from the socket
        Err(VentiError::NotConnected)
    }

    /// Read a block by score
    pub fn read(&mut self, score: &Score, block_type: u32) -> Result<Vec<u8>, VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }
        // Allocate a tag
        let tag = self.alloc_tag()?;

        // Create read request
        let _request = VtFcall::read_request(tag, *score, block_type);

        // In a real implementation:
        // 1. Send the request
        // 2. Wait for response with matching tag
        // 3. Parse the response and return data

        // For now, return NotConnected to indicate real implementation needed
        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }

    /// Write a block and return its score
    pub fn write(&mut self, data: &[u8], block_type: u32) -> Result<Score, VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }

        // Calculate the score of the data
        let score = Score::from_data(data);

        // Allocate a tag
        let tag = self.alloc_tag()?;

        // Create write request
        let _request = VtFcall::write_request(tag, score, block_type, data.to_vec());

        // In a real implementation:
        // 1. Send the request
        // 2. Wait for response with matching tag
        // 3. Return the score

        // For now, return the calculated score (this is what the server would return)
        self.free_tag(tag);
        Ok(score)
    }

    /// Ping the server
    pub fn ping(&mut self) -> Result<(), VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }

        let tag = self.alloc_tag()?;
        let _request = VtFcall::ping(tag);

        // In a real implementation, send ping and wait for response
        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }

    /// Sync with the server
    pub fn sync(&mut self) -> Result<(), VentiError> {
        if self.state != ConnectionState::Connected {
            return Err(VentiError::NotConnected);
        }

        let tag = self.alloc_tag()?;
        let _request = VtFcall::sync(tag);

        // In a real implementation, send sync and wait for response
        self.free_tag(tag);
        Err(VentiError::NotConnected)
    }
}

impl Default for VentiConn {
    fn default() -> Self {
        Self::new("localhost:17034")
    }
}

impl core::fmt::Display for VentiConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VtConn({}, state={:?})", self.addr, self.state)
    }
}

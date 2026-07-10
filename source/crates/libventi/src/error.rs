//! Venti Error Types

use alloc::string::String;

/// Venti error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VentiError {
    /// Not connected to server
    NotConnected,
    /// Connection timeout
    Timeout,
    /// Block not found
    NotFound,
    /// I/O error
    IoError,
    /// Invalid score format
    InvalidScore,
    /// Protocol error
    ProtocolError(String),
    /// Tag exhausted (no available tags)
    TagExhausted,
    /// Invalid message
    InvalidMessage,
    /// Server error
    ServerError(String),
    /// Write error
    WriteError,
    /// Read error
    ReadError,
}

impl VentiError {
    /// Create a protocol error with a message
    pub fn protocol(msg: impl Into<String>) -> Self {
        VentiError::ProtocolError(msg.into())
    }

    /// Create a server error with a message
    pub fn server(msg: impl Into<String>) -> Self {
        VentiError::ServerError(msg.into())
    }
}

impl core::fmt::Display for VentiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VentiError::NotConnected => write!(f, "not connected to Venti server"),
            VentiError::Timeout => write!(f, "connection timeout"),
            VentiError::NotFound => write!(f, "block not found"),
            VentiError::IoError => write!(f, "I/O error"),
            VentiError::InvalidScore => write!(f, "invalid score format"),
            VentiError::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
            VentiError::TagExhausted => write!(f, "no available tags"),
            VentiError::InvalidMessage => write!(f, "invalid message format"),
            VentiError::ServerError(msg) => write!(f, "server error: {}", msg),
            VentiError::WriteError => write!(f, "write error"),
            VentiError::ReadError => write!(f, "read error"),
        }
    }
}

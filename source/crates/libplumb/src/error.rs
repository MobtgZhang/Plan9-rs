//! Plumb Error Types

use alloc::string::String;

/// Plumb error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlumbError {
    /// Not connected to plumb server
    NotConnected,
    /// Port not found
    PortNotFound,
    /// I/O error
    IoError,
    /// Unpack error
    UnpackError,
    /// Pack error
    PackError,
    /// Invalid message
    InvalidMessage(String),
    /// Invalid format
    InvalidFormat(String),
    /// Port busy
    PortBusy,
    /// Permission denied
    PermissionDenied,
    /// Operation would block
    WouldBlock,
    /// Operation timed out
    Timeout,
    /// Attribute not found
    AttributeNotFound,
    /// Destination not found
    DestinationNotFound(String),
}

impl PlumbError {
    /// Get error message
    pub fn as_str(&self) -> alloc::string::String {
        match self {
            PlumbError::NotConnected => alloc::string::String::from("not connected to plumb server"),
            PlumbError::PortNotFound => alloc::string::String::from("port not found"),
            PlumbError::IoError => alloc::string::String::from("I/O error"),
            PlumbError::UnpackError => alloc::string::String::from("failed to unpack message"),
            PlumbError::PackError => alloc::string::String::from("failed to pack message"),
            PlumbError::InvalidMessage(s) => alloc::string::String::from("invalid message format: ") + s,
            PlumbError::InvalidFormat(s) => alloc::string::String::from("invalid format: ") + s,
            PlumbError::PortBusy => alloc::string::String::from("port is busy"),
            PlumbError::PermissionDenied => alloc::string::String::from("permission denied"),
            PlumbError::WouldBlock => alloc::string::String::from("operation would block"),
            PlumbError::Timeout => alloc::string::String::from("operation timed out"),
            PlumbError::AttributeNotFound => alloc::string::String::from("attribute not found"),
            PlumbError::DestinationNotFound(s) => alloc::string::String::from("destination not found: ") + s,
        }
    }
}

impl core::fmt::Display for PlumbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<core::fmt::Error> for PlumbError {
    fn from(_: core::fmt::Error) -> Self {
        PlumbError::PackError
    }
}

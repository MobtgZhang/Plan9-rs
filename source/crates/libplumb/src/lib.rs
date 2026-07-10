//! Plumb Message Library
//!
//! Implements the Plan 9 inter-application message system.
//!
//! The plumber is a system for routing messages between applications
//! based on their destination port.

#![no_std]

extern crate alloc;


pub mod attr;
pub mod message;
pub mod pack;
pub mod unpack;
pub mod port;
pub mod error;
pub mod event;
pub mod attr_helpers;
pub mod rules;     // Plumber rules parser
pub mod matcher;   // Plumber rule matching engine
pub mod plumber;   // Plumber daemon

// Re-export commonly used types
pub use attr::Plumbattr;
pub use message::Plumbmsg;
pub use port::{Port, RecvBuffer, PLUMB_MOUNT_POINT, MAX_MESSAGE_SIZE};
pub use error::PlumbError;
pub use pack::plumbpack;
pub use unpack::{plumbunpack, plumbunpackpartial, plumbneedmore};
pub use event::{eplumb, PlumbEventLoop, PlumbLoopControl};
pub use attr_helpers::{plumbaddattr, plumbdelattr, plumblook,
    plumbaddattr_link, plumbdelattr_link};

/// Result type for plumb operations
pub type PlumbResult<T> = core::result::Result<T, PlumbError>;

/// Message type constants
pub mod msgtype {
    /// Text message
    pub const TEXT: &str = "text";
    /// Display message (for sending to the window system)
    pub const DISPLAY: &str = "display";
    /// Send file message
    pub const SENDFILE: &str = "sendfile";
    /// Edit message
    pub const EDIT: &str = "edit";
    /// Snarf message (clipboard)
    pub const SNARF: &str = "snarf";
    /// Acme custom message
    pub const ACME: &str = "acme";
}

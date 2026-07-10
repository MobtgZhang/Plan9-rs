//! Plan 9 String Library
//!
//! Provides Plan 9 style string operations. In Rust, these functions are largely
//! superseded by the standard library, but they are provided for compatibility
//! with Plan 9 code.
//!
//! Reference: sys/src/libString/

#![no_std]

extern crate alloc;

pub mod s_string;
pub mod s_alloc;
pub mod s_copy;
pub mod s_append;
pub mod s_grow;
pub mod s_reset;
pub mod s_read;
pub mod s_parse;
pub mod s_tolower;

// Re-exports
pub use s_string::S;
pub use s_alloc::{s_alloc, s_free};
pub use s_copy::s_copy;
pub use s_append::s_append;
pub use s_grow::s_grow;
pub use s_reset::s_reset;
pub use s_read::s_read;
pub use s_parse::s_parse;
pub use s_tolower::s_tolower;

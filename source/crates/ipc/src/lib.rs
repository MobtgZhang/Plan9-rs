//! IPC
//!
//! Inter-process and inter-thread communication primitives for Plan 9 style
//! threading. Includes channels, rendezvous, pipes, and message passing.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod pipe;
pub mod msg;
pub mod rendez;

pub use pipe::Pipe;

// Channel and ALT implementation (Plan 9 libthread style)
pub mod channel;
pub mod channel_impl;

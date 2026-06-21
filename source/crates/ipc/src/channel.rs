//! Channel API re-exports and wrappers
//!
//! This module provides a clean API for the channel implementation.

pub use super::channel_impl::{
    // Core functions
    chancreate, chaninit, chanclose, chanisclosed,
    
    // Operations
    send, recv, nbsend, nbrecv,
    
    // Typed operations
    sendul, recvul, nbsendul, nbrecvul,
    sendp, recvp,
    
    // ALT
    alt, AltEntry, AltOpType, ChanState,
    
    // Types
    Channel,
    
    // Builder
    ChanBuilder,
    
    // Type-safe channel
    chan,
};

// Re-export rendezvous functions
pub use super::rendez::{
    _threadrendezvous, _threadflagrendez, _threadbreakrendez,
    ThreadState,
};

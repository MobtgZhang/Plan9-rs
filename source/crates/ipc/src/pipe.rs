//! Pipe implementation (Plan 9 style)
//!
//! Implements pipes for inter-process communication.
//! Based on Plan 9's libthread/pipe.c

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::channel_impl::{
    Channel, chancreate, nbsend, nbrecv,
};

/// A bidirectional pipe
/// 
/// In Plan 9, pipes are unidirectional. This implementation provides
/// a simple buffered pipe that can be used for IPC.
pub struct Pipe {
    /// The channel for data
    channel: Channel,
    /// Flag indicating pipe is closed
    closed: AtomicBool,
}

impl Pipe {
    /// Create a new pipe with the given buffer size
    pub fn new(capacity: usize) -> Option<Self> {
        let channel = chancreate(1, capacity)?;
        Some(Self {
            channel,
            closed: AtomicBool::new(false),
        })
    }
    
    /// Write data to the pipe
    /// Returns true if data was written
    pub fn write(&self, data: &[u8]) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        
        for &byte in data {
            if !nbsend(&self.channel, &byte) {
                return false;
            }
        }
        true
    }
    
    /// Read data from the pipe
    /// Returns the number of bytes read
    pub fn read(&self, buf: &mut [u8]) -> usize {
        if self.closed.load(Ordering::Acquire) && self.channel.len() == 0 {
            return 0;
        }
        
        let mut count = 0;
        for byte in buf.iter_mut() {
            if !nbrecv(&self.channel, byte) {
                break;
            }
            count += 1;
        }
        count
    }
    
    /// Check if pipe is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    
    /// Close the pipe
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

impl Default for Pipe {
    fn default() -> Self {
        Self::new(64).unwrap()
    }
}

/// Create a pipe pair (read end, write end)
/// 
/// Returns (read_pipe, write_pipe)
pub fn pipe() -> Option<(Arc<Pipe>, Arc<Pipe>)> {
    let write_pipe = Arc::new(Pipe::new(64)?);
    let read_pipe = Arc::new(Pipe::new(64)?);
    Some((read_pipe, write_pipe))
}

//! Pipe Device Implementation
//!
//! Implements the Plan 9 pipe device (#|) for inter-process communication.
//!
//! ## Overview
//!
//! Pipes provide a unidirectional data channel between two processes.
//! Data written to one end can be read from the other end.
//!
//! ## Namespace Structure
//!
//! ```
//! #|/                    (pipe directory - created on attach)
//! ├── data              (read end)
//! └── data1             (write end)
//! ## Safety
//! This module uses `extern crate alloc` for `vec!` and `format!` macros.


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Dirtab, Error as DevError, qidtype};
use crate::plan9_common::sync::{ Spinlock };// use crate::sched::scheduler;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Pipe device constants
const PIPE_BUF_SIZE: usize = 4096;
const MAX_PIPE_READERS: usize = 16;

/// Qid types for pipe directories
mod pipe_qid {
    pub const QDIR: u64 = 0;
    pub const QDATA0: u64 = 1;  // Read end (odd)
    pub const QDATA1: u64 = 2;  // Write end (even)
}

/// Directory entries for pipe
const PIPE_DIRTAB: &[Dirtab] = &[
    Dirtab { name: ".", qid: Qid { path: 0, vers: 0, type_: qidtype::DIR }, length: 0, perm: 0x16D | 0x4000 },
    Dirtab { name: "data", qid: Qid { path: 1, vers: 0, type_: 0 }, length: 0, perm: 0x1B6 },
    Dirtab { name: "data1", qid: Qid { path: 2, vers: 0, type_: 0 }, length: 0, perm: 0x1B6 },
];

/// Pipe buffer state - lock-free circular buffer
pub struct PipeBuffer {
    /// Data buffer
    data: Vec<u8>,
    /// Read position
    read_pos: AtomicUsize,
    /// Write position  
    write_pos: AtomicUsize,
    /// Flag indicating a write occurred (for waking readers)
    write_event: AtomicBool,
    /// Flag indicating a read occurred (for waking writers)
    read_event: AtomicBool,
    /// Number of readers still open
    reader_count: AtomicUsize,
    /// Number of writers still open
    writer_count: AtomicUsize,
}

// SAFETY: PipeBuffer uses atomic operations for all shared state and is designed
// to be shared between threads for inter-process communication.
unsafe impl Send for PipeBuffer {}
unsafe impl Sync for PipeBuffer {}

impl PipeBuffer {
    /// Create a new pipe buffer
    pub fn new() -> Self {
        Self {
            data: vec![0u8; PIPE_BUF_SIZE],
            read_pos: AtomicUsize::new(0),
            write_pos: AtomicUsize::new(0),
            write_event: AtomicBool::new(false),
            read_event: AtomicBool::new(false),
            reader_count: AtomicUsize::new(1),
            writer_count: AtomicUsize::new(1),
        }
    }

    /// Calculate available bytes (write_pos - read_pos) mod SIZE
    fn available(&self) -> usize {
        let read = self.read_pos.load(Ordering::Relaxed);
        let write = self.write_pos.load(Ordering::Relaxed);
        if write >= read {
            write - read
        } else {
            PIPE_BUF_SIZE - read + write
        }
    }

    /// Calculate free space
    fn free_space(&self) -> usize {
        let read = self.read_pos.load(Ordering::Relaxed);
        let write = self.write_pos.load(Ordering::Relaxed);
        let available = if write >= read {
            write - read
        } else {
            PIPE_BUF_SIZE - read + write
        };
        PIPE_BUF_SIZE - 1 - available
    }

    /// Write data to the pipe
    /// Returns the number of bytes written
    pub fn write(&self, buf: &[u8]) -> usize {
        let mut written = 0;
        let read = self.read_pos.load(Ordering::Relaxed);
        let mut write = self.write_pos.load(Ordering::Relaxed);
        
        // Get pointer to data buffer for mutation
        let data_ptr = self.data.as_ptr() as *mut u8;
        
        for &byte in buf {
            let next_write = (write + 1) % PIPE_BUF_SIZE;
            if next_write == read {
                break; // Pipe full
            }
            
            unsafe { *data_ptr.add(write) = byte; }
            write = next_write;
            written += 1;
        }
        
        // Only update write_pos once
        if written > 0 {
            self.write_pos.store(write, Ordering::Release);
        }
        
        written
    }

    /// Read data from the pipe
    /// Returns the number of bytes read
    pub fn read(&self, buf: &mut [u8]) -> usize {
        let mut read = self.read_pos.load(Ordering::Relaxed);
        let write = self.write_pos.load(Ordering::Acquire);
        
        let mut read_count = 0;
        for byte in buf.iter_mut() {
            if read == write {
                break; // Pipe empty
            }
            
            *byte = self.data[read];
            read = (read + 1) % PIPE_BUF_SIZE;
            read_count += 1;
        }
        
        // Only update read_pos once
        if read_count > 0 {
            self.read_pos.store(read, Ordering::Release);
        }
        
        read_count
    }

    /// Get the number of bytes available to read
    pub fn get_available(&self) -> usize {
        let read = self.read_pos.load(Ordering::Relaxed);
        let write = self.write_pos.load(Ordering::Relaxed);
        if write >= read {
            write - read
        } else {
            PIPE_BUF_SIZE - read + write
        }
    }

    /// Check if pipe is full
    pub fn is_full(&self) -> bool {
        self.free_space() == 0
    }

    /// Check if pipe is empty
    pub fn is_empty(&self) -> bool {
        self.get_available() == 0
    }

    /// Decrement reader count
    pub fn close_reader(&self) {
        self.reader_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Decrement writer count
    pub fn close_writer(&self) {
        self.writer_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Check if all writers are closed
    pub fn all_writers_closed(&self) -> bool {
        self.writer_count.load(Ordering::SeqCst) == 0
    }

    /// Check if all readers are closed
    pub fn all_readers_closed(&self) -> bool {
        self.reader_count.load(Ordering::SeqCst) == 0
    }

    /// Check and clear write event flag (used for wakeup)
    pub fn check_and_clear_write_event(&self) -> bool {
        self.write_event.load(Ordering::SeqCst)
    }

    /// Set write event flag (called after write)
    pub fn set_write_event(&self) {
        self.write_event.store(true, Ordering::SeqCst);
    }

    /// Check and clear read event flag (used for wakeup)
    pub fn check_and_clear_read_event(&self) -> bool {
        self.read_event.load(Ordering::SeqCst)
    }

    /// Set read event flag (called after read)
    pub fn set_read_event(&self) {
        self.read_event.store(true, Ordering::SeqCst);
    }
}

/// Sleep channel for blocking I/O on pipes
pub struct PipeSleepChannel {
    /// Pointer to the pipe buffer (for wakeup matching)
    buffer: Arc<PipeBuffer>,
}

// SAFETY: PipeSleepChannel is safe to share between threads because the underlying
// Arc<PipeBuffer> is already marked as Send + Sync.
unsafe impl Send for PipeSleepChannel {}
unsafe impl Sync for PipeSleepChannel {}

impl PipeSleepChannel {
    /// Create a new sleep channel for a pipe buffer
    pub fn new(buffer: Arc<PipeBuffer>) -> Self {
        Self { buffer }
    }

    /// Check if data is available to read (non-blocking)
    pub fn can_read(&self) -> bool {
        self.buffer.available() > 0 || self.buffer.all_writers_closed()
    }

    /// Check if pipe can accept data (non-blocking)
    pub fn can_write(&self) -> bool {
        !self.buffer.is_full()
    }
}

/// Pipe end state - represents one end of a pipe
pub struct PipeEnd {
    /// Buffer reference (shared between both ends)
    buffer: Arc<PipeBuffer>,
    /// Is this the read end?
    is_read_end: bool,
    /// Reference count
    refcount: AtomicUsize,
}

impl Clone for PipeEnd {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            is_read_end: self.is_read_end,
            refcount: AtomicUsize::new(self.refcount.load(Ordering::Relaxed)),
        }
    }
}

impl PipeEnd {
    /// Create a new pipe end
    pub fn new(buffer: Arc<PipeBuffer>, is_read_end: bool) -> Self {
        Self {
            buffer,
            is_read_end,
            refcount: AtomicUsize::new(1),
        }
    }
    
    /// Write data to the pipe (non-blocking)
    /// Returns the number of bytes written
    pub fn write(&self, buf: &[u8]) -> Result<usize, DevError> {
        if self.is_read_end {
            return Err(DevError::Eperm); // Can't write to read end
        }
        Ok(self.buffer.write(buf))
    }

    /// Write data to the pipe with blocking
    /// Returns the number of bytes written
    pub fn write_blocking(&self, buf: &[u8]) -> Result<usize, DevError> {
        if self.is_read_end {
            return Err(DevError::Eperm);
        }

        let mut total_written = 0;
        let mut offset = 0;

        while offset < buf.len() {
            // Try to write
            let remaining = &buf[offset..];
            let written = self.buffer.write(remaining);
            total_written += written;
            offset += written;

            if offset >= buf.len() {
                break; // All data written
            }

            if written == 0 {
                // Pipe is full
                if self.buffer.all_readers_closed() {
                    // No readers left - return error
                    break;
                }
                // Would block - in a real implementation, sleep here
                // For now, busy wait
                while self.buffer.is_full() && !self.buffer.all_readers_closed() {
                    core::hint::spin_loop();
                }
            }
        }

        // Set write event to wake up readers
        self.buffer.set_write_event();

        Ok(total_written)
    }

    /// Read data from the pipe (non-blocking)
    /// Returns the number of bytes read
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, DevError> {
        if !self.is_read_end {
            return Err(DevError::Eperm); // Can't read from write end
        }
        Ok(self.buffer.read(buf))
    }

    /// Read data from the pipe with blocking
    /// Returns the number of bytes read, or 0 if pipe is closed
    pub fn read_blocking(&self, buf: &mut [u8]) -> Result<usize, DevError> {
        if !self.is_read_end {
            return Err(DevError::Eperm);
        }

        let mut total_read = 0;
        let mut offset = 0;

        while offset < buf.len() {
            // Try to read
            let remaining = &mut buf[offset..];
            let read = self.buffer.read(remaining);
            total_read += read;
            offset += read;

            if read > 0 || self.buffer.all_writers_closed() {
                break; // Got data or pipe closed
            }

            // Would block
            if self.buffer.all_writers_closed() {
                break; // No more writers, EOF
            }

            // Busy wait - in real implementation would sleep
            while self.buffer.is_empty() && !self.buffer.all_writers_closed() {
                core::hint::spin_loop();
            }
        }

        // Set read event to wake up writers
        self.buffer.set_read_event();

        Ok(total_read)
    }

    /// Check if pipe is empty (for read end)
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Check if pipe is full (for write end)
    pub fn is_full(&self) -> bool {
        self.buffer.is_full()
    }

    /// Get available bytes
    pub fn available(&self) -> usize {
        self.buffer.available()
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn decref(&self) -> usize {
        self.refcount.fetch_sub(1, Ordering::Relaxed)
    }

    /// Check if all writers are closed
    pub fn all_writers_closed(&self) -> bool {
        self.buffer.all_writers_closed()
    }

    /// Check if all readers are closed
    pub fn all_readers_closed(&self) -> bool {
        self.buffer.all_readers_closed()
    }
}

/// Pipe pair - contains both ends of a pipe
pub struct PipePair {
    /// The shared buffer
    buffer: Arc<PipeBuffer>,
    /// Read end
    read_end: Arc<PipeEnd>,
    /// Write end
    write_end: Arc<PipeEnd>,
    /// Reference count for read end
    read_refcount: AtomicUsize,
    /// Reference count for write end
    write_refcount: AtomicUsize,
    /// Path for this pipe
    path: u64,
}

impl Clone for PipePair {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            read_end: self.read_end.clone(),
            write_end: self.write_end.clone(),
            read_refcount: AtomicUsize::new(self.read_refcount.load(Ordering::Relaxed)),
            write_refcount: AtomicUsize::new(self.write_refcount.load(Ordering::Relaxed)),
            path: self.path,
        }
    }
}

impl PipePair {
    /// Create a new pipe pair
    pub fn new(path: u64) -> Self {
        // Create buffer wrapped in Arc for safe sharing
        let buffer = Arc::new(PipeBuffer::new());
        
        let read_end = Arc::new(PipeEnd::new(buffer.clone(), true));
        let write_end = Arc::new(PipeEnd::new(buffer.clone(), false));
        
        Self {
            buffer,
            read_end,
            write_end,
            read_refcount: AtomicUsize::new(1),
            write_refcount: AtomicUsize::new(1),
            path,
        }
    }

    /// Get read end
    pub fn read_end(&self) -> &PipeEnd {
        &self.read_end
    }

    /// Get write end
    pub fn write_end(&self) -> &PipeEnd {
        &self.write_end
    }

    /// Get the buffer
    pub fn buffer(&self) -> &PipeBuffer {
        &self.buffer
    }

    /// Get the path for this pipe
    pub fn path(&self) -> u64 {
        self.path
    }

    /// Get qid for a specific end
    pub fn data_qid(&self, is_data1: bool) -> Qid {
        let qpath = if is_data1 {
            (self.path << 1) | pipe_qid::QDATA1
        } else {
            (self.path << 1) | pipe_qid::QDATA0
        };
        Qid::new(qpath, 0, 0)
    }

    /// Get dir qid
    pub fn dir_qid(&self) -> Qid {
        Qid::new(self.path << 1, 0, qidtype::DIR)
    }

    /// Increment read end reference
    pub fn add_reader(&self) {
        self.read_refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement read end reference
    pub fn remove_reader(&self) {
        let prev = self.read_refcount.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            // Last reader closed
            self.buffer.close_reader();
        }
    }

    /// Increment write end reference
    pub fn add_writer(&self) {
        self.write_refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement write end reference
    pub fn remove_writer(&self) {
        let prev = self.write_refcount.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            // Last writer closed
            self.buffer.close_writer();
        }
    }

    /// Check if both ends are closed
    pub fn is_closed(&self) -> bool {
        self.read_refcount.load(Ordering::SeqCst) == 0 && 
        self.write_refcount.load(Ordering::SeqCst) == 0
    }

    /// Get number of readers
    pub fn reader_count(&self) -> usize {
        self.read_refcount.load(Ordering::Relaxed)
    }

    /// Get number of writers
    pub fn writer_count(&self) -> usize {
        self.write_refcount.load(Ordering::Relaxed)
    }
}

/// Pipe device structure
pub struct PipeDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Pipe pairs indexed by ID
    pipes: Spinlock<Vec<Option<Box<PipePair>>>>,
    /// Next pipe ID (global counter)
    next_id: AtomicU64,
    /// Global path counter
    global_path: AtomicU64,
}

impl PipeDev {
    /// Create a new pipe device
    pub fn new() -> Self {
        Self {
            name: "pipe",
            dev_char: '|',
            pipes: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            global_path: AtomicU64::new(1),
        }
    }

    /// Create a new pipe pair
    /// Returns the path for the pipe directory
    fn create_pipe(&self) -> u64 {
        let mut pipes = self.pipes.lock();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let path = self.global_path.fetch_add(1, Ordering::Relaxed);
        
        // Ensure vector is large enough
        while pipes.len() <= id as usize {
            pipes.push(None);
        }
        
        pipes[id as usize] = Some(Box::new(PipePair::new(path)));
        path
    }

/// Get pipe pair by path
    fn get_pipe(&self, path: u64) -> Option<usize> {
        let pipes = self.pipes.lock();
        for (i, pair) in pipes.iter().enumerate() {
            if let Some(ref p) = pair {
                if p.path() == path {
                    return Some(i);
                }
            }
        }
        None
    }
    
    /// Get pipe pair by index
    fn get_pipe_at(&self, idx: usize) -> Option<Arc<PipePair>> {
        let pipes = self.pipes.lock();
        if let Some(Some(ref pipe)) = pipes.get(idx) {
            Some(Arc::new((**pipe).clone()))
        } else {
            None
        }
    }

    /// Extract path from qid (remove lower bits)
    fn path_from_qid(qid: &Qid) -> u64 {
        qid.path >> 1
    }

    /// Check if qid is data1 (write end)
    fn is_data1(qid: &Qid) -> bool {
        (qid.path & 1) == pipe_qid::QDATA1
    }
}

impl Dev for PipeDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        // Create a new pipe
        let path = self.create_pipe();
        
        // Create channel for pipe directory
        Ok(Chan::new(
            dev::devtype::PIPE,
            Qid::new(path << 1, 0, qidtype::DIR),
            0, // Default to read for directory
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        // Only allow walking to data or data1
        let base_path = Self::path_from_qid(&ch.qid);
        
        if name == "data" {
            // Read end - odd path
            ch.qid = Qid::new((base_path << 1) | pipe_qid::QDATA0, 0, 0);
            Ok(Some(ch.qid))
        } else if name == "data1" {
            // Write end - even path
            ch.qid = Qid::new((base_path << 1) | pipe_qid::QDATA1, 0, 0);
            Ok(Some(ch.qid))
        } else if name.is_empty() {
            Ok(Some(ch.qid))
        } else {
            Err(DevError::Enoent)
        }
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        // Track which end is being opened
        let path = Self::path_from_qid(&ch.qid);
        let is_data1 = Self::is_data1(&ch.qid);
        
        // Find the pipe and modify atomically
        let mut pipes = self.pipes.lock();
        for pair_opt in pipes.iter_mut() {
            if let Some(ref mut pair) = pair_opt {
                if pair.path() == path {
                    if is_data1 {
                        pair.add_writer();
                    } else {
                        pair.add_reader();
                    }
                    break;
                }
            }
        }
        drop(pipes);
        
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        // Pipes are created by attach, not create
        Err(DevError::Eperm)
    }

    fn close(&mut self, ch: &mut Chan) {
        let path = Self::path_from_qid(&ch.qid);
        let is_data1 = Self::is_data1(&ch.qid);
        
        // Find the pipe and modify atomically
        let mut pipes = self.pipes.lock();
        for pair_opt in pipes.iter_mut() {
            if let Some(ref mut pair) = pair_opt {
                if pair.path() == path {
                    if is_data1 {
                        pair.remove_writer();
                    } else {
                        pair.remove_reader();
                    }
                    break;
                }
            }
        }
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        let path = Self::path_from_qid(&ch.qid);
        let is_data1 = Self::is_data1(&ch.qid);
        
        if let Some(idx) = self.get_pipe(path) {
            if let Some(pipe) = self.get_pipe_at(idx) {
                if is_data1 {
                    // data1 - writing end, but read from read end
                    Ok(pipe.read_end().read(buf)?)
                } else {
                    // data - reading end
                    Ok(pipe.read_end().read(buf)?)
                }
            } else {
                Err(DevError::Enoent)
            }
        } else {
            Err(DevError::Enoent)
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let path = Self::path_from_qid(&ch.qid);
        let is_data1 = Self::is_data1(&ch.qid);
        
        if let Some(idx) = self.get_pipe(path) {
            if let Some(pipe) = self.get_pipe_at(idx) {
                if is_data1 {
                    // data1 - writing end
                    Ok(pipe.write_end().write(buf)?)
                } else {
                    // data - reading end, but write to write end
                    Ok(pipe.write_end().write(buf)?)
                }
            } else {
                Err(DevError::Enoent)
            }
        } else {
            Err(DevError::Enoent)
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let path = Self::path_from_qid(&ch.qid);
        let is_data1 = Self::is_data1(&ch.qid);
        
        let (name, mode, _qid_type) = if path == 0 {
            ("pipe".as_bytes().to_vec(), 0x16D | 0x4000, qidtype::DIR)
        } else if is_data1 {
            ("data1".as_bytes().to_vec(), 0x29E, 0)
        } else {
            ("data".as_bytes().to_vec(), 0x29E, 0)
        };
        
        let length = if is_data1 {
            0 // data1 length not tracked
        } else {
            0 // data length not tracked
        };
        
        Ok(DirEntry {
            dev: dev::devtype::PIPE,
            qid: ch.qid,
            mode: mode | 0o120000, // S_IFIFO
            atime: 0,
            mtime: 0,
            length,
            name,
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        // Pipe permissions are not modifiable
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        // Remove is not typically called on pipes
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Global pipe device instance
static PIPE_DEV: Spinlock<Option<PipeDev>> = Spinlock::new(None);

/// Initialize the global pipe device
pub fn init_pipe_dev() {
    let dev = PipeDev::new();
    *PIPE_DEV.lock() = Some(dev);
    crate::dev::register_device(Box::new(PipeDev::new()));
}

/// Create a pipe pair
/// Returns file descriptors for read and write ends
pub fn pipe_create() -> Result<(u64, u64), DevError> {
    let dev = PipeDev::new();
    
    // Create pipe via attach
    let mut dev = dev;
    let read_chan = dev.attach(None)?;
    let write_chan = dev.attach(None)?;
    
    Ok((read_chan.qid.path, write_chan.qid.path))
}

// ============================================================================
// Sleep/Wakeup Synchronization for Pipes
// ============================================================================


/// Global sleep channel table for pipe synchronization
struct SleepChannelTable {
    channels: Spinlock<Vec<Option<Arc<PipeSleepChannel>>>>,
}

static SLEEP_CHANNEL_TABLE: SleepChannelTable = SleepChannelTable {
    channels: Spinlock::new(Vec::new()),
};

impl SleepChannelTable {
    fn new() -> Self {
        Self {
            channels: Spinlock::new(Vec::new()),
        }
    }

    /// Register a sleep channel for a pipe buffer
    fn register(&self, buffer: Arc<PipeBuffer>) -> usize {
        let mut channels = self.channels.lock();
        let channel = Arc::new(PipeSleepChannel::new(buffer));
        
        // Find empty slot or push new
        for (i, slot) in channels.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(channel.clone());
                return i;
            }
        }
        
        let idx = channels.len();
        channels.push(Some(channel.clone()));
        idx
    }

    /// Unregister a sleep channel
    fn unregister(&self, id: usize) {
        let mut channels = self.channels.lock();
        if id < channels.len() {
            channels[id] = None;
        }
    }

    /// Get a sleep channel by ID
    fn get(&self, id: usize) -> Option<Arc<PipeSleepChannel>> {
        let channels = self.channels.lock();
        channels.get(id).and_then(|c| c.clone())
    }
}

/// Sleep on a pipe until data is available or pipe is closed
/// Returns true if data is available, false if pipe is closed
pub fn pipe_sleep_read(buffer: *const PipeBuffer) {
    // In a real implementation, this would:
    // 1. Register the process with the sleep channel
    // 2. Set process state to Wakeme
    // 3. Call scheduler to switch to another process
    // 4. Be woken up by a writer calling wakeup
    
    // For now, busy wait
    while unsafe {
        (*buffer).available() == 0 && !(*buffer).all_writers_closed()
    } {
        core::hint::spin_loop();
    }
}

/// Sleep on a pipe until space is available
/// Returns true if space is available, false if all readers closed
pub fn pipe_sleep_write(buffer: *const PipeBuffer) {
    // Similar to read sleep but for writers
    while unsafe {
        (*buffer).is_full() && !(*buffer).all_readers_closed()
    } {
        core::hint::spin_loop();
    }
}

/// Wakeup processes waiting to read from a pipe
pub fn pipe_wakeup_read(buffer: *const PipeBuffer) {
    // Wake up sleeping readers
    unsafe {
        if (*buffer).available() > 0 {
            (*buffer).set_write_event();
        }
    }
}

/// Wakeup processes waiting to write to a pipe
pub fn pipe_wakeup_write(buffer: *const PipeBuffer) {
    // Wake up sleeping writers
    unsafe {
        if !(*buffer).is_full() {
            (*buffer).set_read_event();
        }
    }
}

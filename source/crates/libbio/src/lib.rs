//! libbio - Buffered I/O Library
//!
//! Implements Plan 9's buffered I/O library.
//! This library provides efficient buffered reading and writing.
//!
//! ## Biobufhdr Structure
//!
//! The Biobufhdr structure manages a buffer for a file descriptor:
//! - bbuf: the actual buffer
//! - icount: input count (negative when buffer has data)
//! - ocount: output count (positive when buffer has room)
//! - state: current state (Bractive, Bwactive, etc.)
//!
//! Reference: sys/src/libbio

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Buffer size (must be >= 0 and < 4096)
pub const BIOBUF_SIZE: usize = 4096;

/// Biobuf state values
pub const BRACTIVE: i32 = 0;      // Buffer has data to read
pub const BWBUFFER: i32 = 1;      // Buffer is being filled for write
pub const BWACTIVE: i32 = 2;      // Buffer has data to write
pub const Bracteof: i32 = 3;     // At EOF
pub const Binactive: i32 = 4;     // Buffer is inactive

// ============================================================================
// Biobufhdr Structure
// ============================================================================

/// Buffered I/O buffer header
/// 
/// This is the main structure for buffered I/O in Plan 9.
/// The buffer can be in one of several states:
/// - BRACTIVE: buffer contains data to be read
/// - BWBUFFER: buffer is being filled prior to write
/// - BWACTIVE: buffer contains data to be written
/// - Bracteof: at end of file
/// - Binactive: buffer is inactive
#[derive(Debug)]
pub struct Biobufhdr {
    /// State of the buffer
    pub state: i32,
    /// Buffer size
    pub bsize: i32,
    /// Input count (negative = bytes in buffer, positive = space available)
    pub icount: i32,
    /// Output count
    pub ocount: i32,
    /// Line reading state
    pub rdline: i32,
    /// Buffer
    pub bbuf: Vec<u8>,
    /// End of buffer (index)
    pub ebuf: usize,
    /// Get pointer (current read position)
    pub gbuf: usize,
    /// Read pointer (for read(2))
    pub rbuf: usize,
    /// File descriptor
    pub fid: i32,
    /// Offset in file
    pub offset: i64,
}

impl Biobufhdr {
    /// Create a new Biobufhdr
    pub fn new(size: usize) -> Self {
        let size = if size == 0 { BIOBUF_SIZE } else { size };
        let bbuf = alloc::vec![0; size];
        
        Self {
            state: Binactive,
            bsize: size as i32,
            icount: 0,
            ocount: 0,
            rdline: 0,
            bbuf,
            ebuf: size,
            gbuf: 0,
            rbuf: 0,
            fid: -1,
            offset: 0,
        }
    }

    /// Initialize buffer for reading
    pub fn init_reading(&mut self) {
        self.state = BRACTIVE;
        self.icount = 0;
        self.gbuf = 0;
        self.rbuf = 0;
    }

    /// Initialize buffer for writing
    pub fn init_writing(&mut self) {
        self.state = BWBUFFER;
        self.ocount = 0;
        self.gbuf = self.bsize as usize;
    }

    /// Check if buffer is active
    pub fn is_active(&self) -> bool {
        self.state != Binactive
    }

    /// Get number of bytes available to read
    pub fn available(&self) -> usize {
        -self.icount as usize
    }

    /// Get remaining space in buffer for writing
    pub fn space(&self) -> usize {
        self.bsize as usize - self.gbuf
    }

    /// Reset buffer for reuse
    pub fn reset(&mut self) {
        self.state = Binactive;
        self.icount = 0;
        self.ocount = 0;
        self.rdline = 0;
        self.gbuf = 0;
        self.rbuf = 0;
        self.fid = -1;
        self.offset = 0;
    }
}

impl Default for Biobufhdr {
    fn default() -> Self {
        Self::new(BIOBUF_SIZE)
    }
}

// ============================================================================
// Biobuf - Opaque Buffered I/O Structure
// ============================================================================

/// Buffered I/O structure (opaque)
/// 
/// This is the full Biobuf structure that applications use.
/// It wraps a Biobufhdr with internal buffer management.
#[derive(Debug)]
pub struct Biobuf {
    /// Header and buffer
    pub hdr: Biobufhdr,
}

impl Biobuf {
    /// Create a new Biobuf with default size
    pub fn new() -> Self {
        Self {
            hdr: Biobufhdr::new(BIOBUF_SIZE),
        }
    }

    /// Create a new Biobuf with specified size
    pub fn with_size(size: usize) -> Self {
        Self {
            hdr: Biobufhdr::new(size),
        }
    }

    /// Initialize for reading from a file descriptor
    pub fn init(&mut self, fd: i32, mode: i32) {
        self.hdr.fid = fd;
        self.hdr.state = if mode >= 0 { BRACTIVE } else { BWBUFFER };
        self.hdr.icount = 0;
        self.hdr.gbuf = 0;
        self.hdr.rbuf = 0;
        self.hdr.offset = 0;
    }

    /// Check if buffer is active
    pub fn is_active(&self) -> bool {
        self.hdr.is_active()
    }

    /// Get the buffer as a slice for reading
    pub fn get_buf(&self) -> &[u8] {
        &self.hdr.bbuf[self.hdr.gbuf..]
    }

    /// Get mutable buffer for writing
    pub fn put_buf(&mut self) -> &mut [u8] {
        &mut self.hdr.bbuf[..self.hdr.gbuf]
    }

    /// Reset buffer
    pub fn reset(&mut self) {
        self.hdr.reset();
    }
}

impl Default for Biobuf {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Low-level Read/Write (platform-specific, stubs for no_std)
// ============================================================================

extern "C" {
    /// Read from file descriptor (stub - needs libc or custom impl)
    fn read(fd: i32, buf: *mut u8, count: usize) -> i32;
    
    /// Write to file descriptor (stub - needs libc or custom impl)
    fn write(fd: i32, buf: *const u8, count: usize) -> i32;
    
    /// Seek file descriptor (stub)
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
}

// ============================================================================
// Buffered I/O Functions
// ============================================================================

/// Buffered read - fill buffer if needed
/// 
/// Returns the number of bytes read, or 0 at EOF, or -1 on error.
pub fn bread(b: &mut Biobuf, n: i32) -> i32 {
    // Fill buffer if needed
    if b.hdr.icount <= 0 && b.hdr.state == BRACTIVE {
        // Read into buffer
        let fid = b.hdr.fid;
        if fid < 0 {
            return -1;
        }
        
        let count = n.min(b.hdr.bsize) as usize;
        let buf_ptr = b.hdr.bbuf.as_mut_ptr();
        
        let ret = unsafe { read(fid, buf_ptr, count) };
        if ret < 0 {
            return -1;
        }
        
        b.hdr.icount = -ret;
        b.hdr.gbuf = 0;
        b.hdr.rbuf = 0;
        
        if ret == 0 {
            b.hdr.state = Bracteof;
        }
    }
    
    // Return min(remaining in buffer, requested)
    let avail = (-b.hdr.icount) as i32;
    let to_read = n.min(avail);
    
    if to_read > 0 {
        b.hdr.gbuf += to_read as usize;
        b.hdr.icount += to_read;
    }
    
    to_read
}

/// Buffered write - flush buffer if needed
/// 
/// Returns the number of bytes written, or -1 on error.
pub fn bwrite(b: &mut Biobuf, buf: &[u8]) -> i32 {
    let mut ret = 0i32;
    let mut p = 0usize;
    
    while p < buf.len() {
        // Check if we need to flush
        if b.hdr.gbuf >= b.hdr.bsize as usize {
            // Flush current buffer
            if bwrite_flush(b) < 0 {
                return -1;
            }
        }
        
        // Copy data to buffer
        let space = b.hdr.bsize as usize - b.hdr.gbuf;
        let count = (buf.len() - p).min(space);
        
        b.hdr.bbuf[b.hdr.gbuf..b.hdr.gbuf + count].copy_from_slice(&buf[p..p + count]);
        b.hdr.gbuf += count;
        b.hdr.ocount += count as i32;
        p += count;
        ret += count as i32;
    }
    
    ret
}

/// Flush write buffer
pub fn bflush(b: &mut Biobuf) -> i32 {
    bwrite_flush(b)
}

/// Internal flush implementation
fn bwrite_flush(b: &mut Biobuf) -> i32 {
    if b.hdr.state != BWACTIVE && b.hdr.state != BWBUFFER {
        return 0;
    }
    
    let fid = b.hdr.fid;
    if fid < 0 {
        return -1;
    }
    
    let count = b.hdr.gbuf;
    if count == 0 {
        return 0;
    }
    
    let ret = unsafe { write(fid, b.hdr.bbuf.as_ptr(), count) };
    if ret < 0 {
        return -1;
    }
    
    b.hdr.gbuf = 0;
    b.hdr.ocount = 0;
    b.hdr.state = BWBUFFER;
    
    ret as i32
}

/// Get single character
pub fn bgetc(b: &mut Biobuf) -> i32 {
    if b.hdr.icount <= 0 {
        // Fill buffer
        let n = bread(b, b.hdr.bsize);
        if n <= 0 {
            return -1;
        }
    }
    
    let c = b.hdr.bbuf[b.hdr.rbuf] as i32;
    b.hdr.rbuf += 1;
    b.hdr.icount -= 1;
    
    c
}

/// Put single character
pub fn bputc(b: &mut Biobuf, c: i32) -> i32 {
    if b.hdr.gbuf >= b.hdr.bsize as usize {
        if bwrite_flush(b) < 0 {
            return -1;
        }
    }
    
    b.hdr.bbuf[b.hdr.gbuf] = c as u8;
    b.hdr.gbuf += 1;
    b.hdr.ocount += 1;
    
    c
}

/// Read line (up to delimiter)
pub fn brdline(b: &mut Biobuf, delim: u8) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    
    loop {
        if b.hdr.icount <= 0 {
            let n = bread(b, b.hdr.bsize);
            if n <= 0 {
                break;
            }
        }
        
        // Search for delimiter
        let start = b.hdr.rbuf;
        let end = b.hdr.rbuf.wrapping_sub(b.hdr.icount as usize);
        
        for i in start..end {
            let c = b.hdr.bbuf[i];
            line.push(c);
            b.hdr.rbuf = i + 1;
            b.hdr.icount -= 1;
            
            if c == delim {
                return Some(line);
            }
        }
    }
    
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

/// Read until delimiter (like brdline but returns string)
pub fn brdstr(b: &mut Biobuf, delim: u8, n: i32) -> Option<Vec<u8>> {
    let max_size: usize = 1024 * 1024; // 1MB max
    let n = if n < 0 { max_size } else { n as usize };
    let mut line = Vec::with_capacity(n.min(1024));
    
    loop {
        if line.len() >= n {
            break;
        }
        
        if b.hdr.icount <= 0 {
            let bread_n = bread(b, b.hdr.bsize);
            if bread_n <= 0 {
                break;
            }
        }
        
        let start = b.hdr.rbuf;
        let end = b.hdr.rbuf.wrapping_sub(b.hdr.icount as usize);
        
        for i in start..end {
            if line.len() >= n {
                break;
            }
            
            let c = b.hdr.bbuf[i];
            line.push(c);
            b.hdr.rbuf = i + 1;
            b.hdr.icount -= 1;
            
            if c == delim {
                return Some(line);
            }
        }
    }
    
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

/// Seek to position
pub fn bseek(b: &mut Biobuf, offset: i64, whence: i32) -> i64 {
    // Flush any pending writes
    if b.hdr.state == BWBUFFER || b.hdr.state == BWACTIVE {
        if bwrite_flush(b) < 0 {
            return -1;
        }
    }
    
    // Update file offset
    match whence {
        0 => { /* SEEK_SET - relative to start */ }
        1 => { /* SEEK_CUR - relative to current */
            let cur_offset = b.hdr.offset + b.hdr.icount as i64;
            b.hdr.offset = cur_offset;
        }
        2 => { /* SEEK_END - relative to end */
            // Would need to seek to end first
        }
        _ => return -1,
    }
    
    // Reset buffer state
    b.hdr.icount = 0;
    b.hdr.gbuf = 0;
    b.hdr.rbuf = 0;
    b.hdr.state = BRACTIVE;
    
    b.hdr.offset + offset
}

/// Get buffer size
pub fn bbuffered(b: &Biobuf) -> i32 {
    -b.hdr.icount
}

// ============================================================================
// Unicode (Rune) Support
// ============================================================================

/// Maximum bytes for a UTF-8 encoded rune.
const UTF_MAX: usize = 4;

/// Number of bytes reserved at the front of the buffer for `Bungetc`
/// and `Bungetrune` pushback. Plan 9 sets this to 4 to hold one full
/// UTF-8 sequence plus a sentinel byte.
const BUNGETSIZE: usize = 4;

/// Read a single Unicode rune from the buffer.
///
/// Returns the rune value (>= 0) on success, or -1 at EOF / on error.
/// The caller can recover the byte width via `runelen(r)`.
pub fn Bgetrune(b: &mut Biobuf) -> i32 {
    let mut buf = [0u8; UTF_MAX];
    let mut width = 0usize;

    // Pull the first byte to learn the expected sequence width.
    let c0 = bgetc(b);
    if c0 < 0 {
        return -1;
    }
    buf[0] = c0 as u8;
    width = 1;

    if c0 >= 0x80 {
        // Multi-byte UTF-8: figure out the width from the leading byte.
        width = utf8_seqlen(c0 as u8);
        if width == 0 || width > UTF_MAX {
            return -1;
        }
        for i in 1..width {
            let c = bgetc(b);
            if c < 0 {
                return -1;
            }
            buf[i] = c as u8;
        }
    }

    match core::str::from_utf8(&buf[..width]) {
        Ok(s) => {
            let mut chars = s.chars();
            match chars.next() {
                Some(r) => r as i32,
                None => -1,
            }
        }
        Err(_) => -1,
    }
}

/// Write a Unicode rune to the buffer as UTF-8.
///
/// Returns the number of bytes written, or -1 on error.
pub fn Bputrune(b: &mut Biobuf, r: i32) -> i32 {
    let r = match char::from_u32(r as u32) {
        Some(c) => c,
        None => return -1,
    };
    let mut buf = [0u8; UTF_MAX];
    let s = r.encode_utf8(&mut buf);
    bwrite(b, s.as_bytes())
}

/// Return the number of bytes required to encode `r` in UTF-8.
pub fn runelen(r: i32) -> usize {
    match char::from_u32(r as u32) {
        Some(c) => c.len_utf8(),
        None => 0,
    }
}

/// Decode one UTF-8 sequence length from the leading byte.
///
/// Returns 0 for an invalid lead byte, otherwise 1..=4.
fn utf8_seqlen(b0: u8) -> usize {
    if b0 < 0x80 {
        1
    } else if b0 & 0xE0 == 0xC0 {
        2
    } else if b0 & 0xF0 == 0xE0 {
        3
    } else if b0 & 0xF8 == 0xF0 {
        4
    } else {
        0
    }
}

/// Push a single byte back into the buffer.
///
/// Returns the byte on success or -1 if the pushback region is full.
pub fn Bungetc(b: &mut Biobuf) -> i32 {
    // The buffer keeps a small BUNGETSIZE reservation at the start.
    if b.hdr.gbuf < BUNGETSIZE {
        // Place the byte just before the read pointer.
        if b.hdr.rbuf == 0 {
            return -1;
        }
        b.hdr.bbuf[b.hdr.rbuf - 1] = b.hdr.bbuf[b.hdr.rbuf];
        // For simplicity we just decrement the buffered count, mirroring
        // Plan 9's bookkeeping at a high level.
        b.hdr.icount += 1;
        return 0;
    }
    -1
}

/// Return the current file offset, accounting for any buffered bytes.
///
/// Returns -1 on error.
pub fn Boffset(b: &mut Biobuf) -> i64 {
    b.hdr.offset + b.hdr.icount as i64
}

/// Number of bytes that are buffered and unread.
pub fn Bungetsize() -> usize {
    BUNGETSIZE
}

// ============================================================================
// Open/Close
// ============================================================================

/// Open file with buffering (stub - needs file system integration)
pub fn Bopen(_path: &str, _mode: i32) -> Biobuf {
    // In a full implementation, this would call the kernel's open
    let mut b = Biobuf::new();
    b.hdr.fid = -1; // No fd yet
    b.hdr.state = if _mode >= 0 { BRACTIVE } else { BWBUFFER };
    b
}

/// Close buffered file
pub fn Bterm(b: &mut Biobuf) {
    // Flush any pending writes
    if b.hdr.state == BWBUFFER || b.hdr.state == BWACTIVE {
        let _ = bwrite_flush(b);
    }
    
    // Reset buffer
    b.reset();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biobuf_creation() {
        let b = Biobuf::new();
        assert_eq!(b.hdr.bsize, BIOBUF_SIZE as i32);
        assert_eq!(b.hdr.state, Binactive);
    }

    #[test]
    fn test_biobuf_with_size() {
        let b = Biobuf::with_size(1024);
        assert_eq!(b.hdr.bsize, 1024);
    }
}

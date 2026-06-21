//! Kernel Message Buffer
//!
//! Implements the Plan 9 style kernel message buffer (/dev/kmesg).
//! This provides a circular buffer for kernel log messages that can be
//! read by userspace programs.
//!
//! ## Reference
//! - Plan 9: `/sys/src/9/port/kmesg.c`

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

/// Size of the kernel message buffer (16KB)
pub const KMESG_SIZE: usize = 16384;

/// Kernel message buffer
pub struct KMesg {
    /// Circular buffer
    buf: [u8; KMESG_SIZE],
    /// Read pointer
    rptr: AtomicUsize,
    /// Write pointer
    wptr: AtomicUsize,
    /// Number of times the buffer has wrapped
    seq: AtomicUsize,
}

impl KMesg {
    /// Create a new kernel message buffer
    pub fn new() -> Self {
        Self {
            buf: [0u8; KMESG_SIZE],
            rptr: AtomicUsize::new(0),
            wptr: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
        }
    }

    /// Write a byte to the buffer
    /// Returns the number of bytes written (1)
    pub fn putc(&self, c: u8) {
        let w = self.wptr.load(Ordering::Relaxed);
        let r = self.rptr.load(Ordering::Relaxed);

        // Calculate available space
        let space = if w >= r {
            KMESG_SIZE - (w - r) - 1
        } else {
            r - w - 1
        };

        if space == 0 {
            // Buffer full, advance read pointer to make room
            let new_r = (r + 1) % KMESG_SIZE;
            self.rptr.store(new_r, Ordering::Relaxed);
            self.seq.fetch_add(1, Ordering::Relaxed);
        }

        let w = self.wptr.load(Ordering::Relaxed);
        self.buf[w] = c;
        self.wptr.store((w + 1) % KMESG_SIZE, Ordering::Relaxed);
    }

    /// Write a string to the buffer
    pub fn puts(&self, s: &[u8]) {
        for &c in s {
            self.putc(c);
        }
    }

    /// Read from the buffer
    /// Returns the number of bytes read
    pub fn read(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        let r = self.rptr.load(Ordering::Relaxed);
        let w = self.wptr.load(Ordering::Relaxed);

        // Buffer is empty if r == w
        if r == w {
            return 0;
        }

        // Calculate number of bytes available
        let available = if w > r {
            w - r
        } else {
            KMESG_SIZE - r + w
        };

        for byte in buf.iter_mut() {
            if count >= available {
                break;
            }
            *byte = self.buf[r];
            self.buf[r] = 0; // Clear for debugging
            self.rptr.store((r + 1) % KMESG_SIZE, Ordering::Relaxed);
            count += 1;
            // Safe to re-read r now that we've updated it
            let new_r = self.rptr.load(Ordering::Relaxed);
            // Check if we've caught up to writer
            if new_r == w && count < available {
                // Writer may have written more, but we can't safely read it without locking
                break;
            }
        }

        count
    }

    /// Get the number of bytes available to read
    pub fn available(&self) -> usize {
        let r = self.rptr.load(Ordering::Relaxed);
        let w = self.wptr.load(Ordering::Relaxed);

        if r == w {
            0
        } else if w > r {
            w - r
        } else {
            KMESG_SIZE - r + w
        }
    }

    /// Get the sequence number (number of times buffer wrapped)
    pub fn sequence(&self) -> usize {
        self.seq.load(Ordering::Relaxed)
    }

    /// Clear the buffer
    pub fn clear(&self) {
        self.rptr.store(0, Ordering::Relaxed);
        self.wptr.store(0, Ordering::Relaxed);
        self.seq.store(0, Ordering::Relaxed);
        // Note: We don't zero the buffer for performance
    }
}

// ============================================================================
// Global Kernel Message Buffer
// ============================================================================

use core::sync::atomic::AtomicPtr;

static KMESG: AtomicPtr<KMesg> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the kernel message buffer
pub fn init_kmesg() {
    let km = Box::new(KMesg::new());
    KMESG.store(Box::into_raw(km), Ordering::SeqCst);
}

/// Get the global kernel message buffer
pub fn kmesg() -> &'static KMesg {
    unsafe { &*KMESG.load(Ordering::SeqCst) }
}

/// Write a character to the kernel message buffer
pub fn kmesg_putc(c: u8) {
    kmesg().putc(c);
}

/// Write a string to the kernel message buffer
pub fn kmesg_puts(s: &[u8]) {
    kmesg().puts(s);
}

/// Print a formatted kernel message (simplified version)
pub fn kmesg_printf(fmt: &core::fmt::Arguments) {
    // Simple implementation using the buffer
    // For a full implementation, we would parse the format string
    let _ = fmt;
    // This is a placeholder - a full printf would need va_list support
}

// ============================================================================
// Kmesg Device (Plan 9 style)
// ============================================================================

/// Kernel message device
pub struct KmesgDev {
    name: &'static str,
    dev_char: char,
}

impl KmesgDev {
    /// Create a new kmesg device
    pub fn new() -> Self {
        Self {
            name: "kmesg",
            dev_char: 'K',  // 'K' for kernel messages
        }
    }
}

impl Dev for KmesgDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Err(Error::Enoent)
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), Error> {
        Err(Error::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // Nothing to clean up
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        let km = kmesg();
        let n = km.read(buf);
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        let km = kmesg();
        km.puts(buf);
        Ok(buf.len())
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length: kmesg().available() as u64,
            name: b"kmesg".to_vec(),
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), Error> {
        // Allow clearing the buffer via wstat
        if _dir.length == 0 {
            kmesg().clear();
            Ok(())
        } else {
            Err(Error::Eperm)
        }
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), Error> {
        Err(Error::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Global Console Output with Kmesg Integration
// ============================================================================

/// Print character to both console and kmesg buffer
pub fn console_putc(c: u8) {
    // Write to kmesg buffer
    kmesg_putc(c);
    // Also write to hardware console
    crate::cons::putchar(c);
}

/// Print string to both console and kmesg buffer
pub fn console_puts(s: &[u8]) {
    // Write to kmesg buffer
    kmesg_puts(s);
    // Also write to hardware console
    crate::cons::puts(s);
}



//! Device Driver Framework
//!
//! Implements the Plan 9 device driver framework including:
//! - Dev trait for device operations
//! - DevTable for device registration
//! - Basic device implementations (console, null, etc.)
//!
//! ## Plan 9 Device Architecture
//!
//! In Plan 9, everything is a file and accessed through the VFS.
//! Each device implements the Dev trait which provides:
//! - attach(): Create a channel to the root of the device
//! - walk(): Navigate the device namespace
//! - open/create/close: File operations
//! - read/write: Data transfer
//! - stat/wstat: Metadata operations

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
// use alloc::string::String;
use alloc::boxed::Box;
use crate::plan9_common::sync::{Spinlock, Mutex};

// Spinlock is generic over its data; in this file we use Spinlock<()> as a
// stateless "owned" lock.
type ConsoleLock = Spinlock<()>;

// Re-export Qid from chan module for use throughout the kernel
pub use crate::chan::Qid;

// Import block module for Block type
use crate::block::{Block, allocb};

// ============================================================================
// Device Constants
// ============================================================================

/// Maximum number of devices
pub const NDEV: usize = 32;

/// Device types (device characters)
pub mod devtype {
    pub const NONE: usize = 0;
    pub const CONS: usize = 1;      // 'c' - console
    pub const ENV: usize = 2;      // 'e' - environment
    pub const DRAW: usize = 3;     // 'd' - graphics
    pub const IP: usize = 4;       // 'i' - IP/network
    pub const BRIDGE: usize = 5;   // 'l' - bridge
    pub const AUDIO: usize = 6;    // 'a' - audio
    pub const MOUSE: usize = 7;    // 'm' - mouse
    pub const KB: usize = 8;       // 'k' - keyboard
    pub const PROC: usize = 9;     // 'p' - proc fs
    pub const FS: usize = 10;      // 'f' - file system
    pub const PIPE: usize = 11;    // '|' - pipe
    pub const TLS: usize = 12;     // 'I' - TLS/SSL
    pub const SD: usize = 13;     // 's' - storage/disk
    pub const AOE: usize = 14;    // 'A' - AoE
    pub const CAP: usize = 15;    // 'C' - capability
    pub const SEC: usize = 16;    // 's' - security
    pub const ROOT: usize = 17;   // '/' - root fs
    pub const SRV: usize = 18;    // '#s' - service
    pub const MNT: usize = 19;    // '#M' - mount
    pub const DOS: usize = 20;    // '#d' - DOS
    pub const VIRTIO: usize = 21; // virtio

    /// User mountable devices start here
    pub const USER: usize = 64;
}

// ============================================================================
// Qid type flags (re-exported from chan module for convenience)
// ============================================================================

/// Qid type flags
pub mod qidtype {
    pub const NONE: u8 = 0;
    pub const EXEC: u8 = 0x80;    // executable
    pub const EXCL: u8 = 0x40;   // exclusive use
    pub const APPEND: u8 = 0x20;  // append-only
    pub const MOUNT: u8 = 0x10;   // mounted channel
    pub const AUTH: u8 = 0x08;    // authentication file
    pub const TMP: u8 = 0x04;     // temporary file
    pub const LINK: u8 = 0x02;     // symbolic link
    pub const FILE: u8 = 0x00;     // regular file
    pub const DIR: u8 = 0x80;     // directory
}

// ============================================================================
// Channel - Open File/Device
// ============================================================================

/// Channel - represents an open file or device
pub struct Chan {
    /// Device type
    pub dev: usize,
    /// Qid for this channel
    pub qid: Qid,
    /// Mode (read/write)
    pub mode: u8,
    /// Channel flags
    pub flag: u32,
    /// Offset in file
    pub offset: u64,
    /// Device-specific data
    pub aux: Option<Box<dyn Send + Sync>>,
    /// Reference count (made pub for internal cloning)
    pub refcount: Mutex<u32>,
}

impl Clone for Chan {
    fn clone(&self) -> Self {
        self.incref();
        Self {
            dev: self.dev,
            qid: self.qid,
            mode: self.mode,
            flag: self.flag,
            offset: self.offset,
            aux: None,
            refcount: Mutex::new(*self.refcount.lock()),
        }
    }
}

impl Chan {
    /// Create new channel
    pub fn new(dev: usize, qid: Qid, mode: u8) -> Self {
        Self {
            dev,
            qid,
            mode,
            flag: 0,
            offset: 0,
            aux: None,
            refcount: Mutex::new(1),
        }
    }

    /// Increment reference count
    pub fn incref(&self) {
        *self.refcount.lock() += 1;
    }

    /// Decrement reference count
    pub fn decref(&self) -> u32 {
        let mut count = self.refcount.lock();
        *count = count.saturating_sub(1);
        *count
    }

    /// Get reference count
    pub fn refcount(&self) -> u32 {
        *self.refcount.lock()
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// Directory entry for readdir
#[derive(Debug)]
pub struct DirEntry {
    /// Device number
    pub dev: usize,
    /// Qid
    pub qid: Qid,
    /// Mode (permissions + type)
    pub mode: u32,
    /// Last access time
    pub atime: u32,
    /// Last modification time
    pub mtime: u32,
    /// Length (for files)
    pub length: u64,
    /// Name
    pub name: Vec<u8>,
    /// Owning user id
    pub uid: u32,
    /// Owning group id
    pub gid: u32,
}

impl Clone for DirEntry {
    fn clone(&self) -> Self {
        Self {
            dev: self.dev,
            qid: self.qid,
            mode: self.mode,
            atime: self.atime,
            mtime: self.mtime,
            length: self.length,
            name: self.name.clone(),
            uid: self.uid,
            gid: self.gid,
        }
    }
}

/// Directory entry for Dirtab
#[derive(Debug)]
pub struct Dirtab {
    /// Name
    pub name: &'static str,
    /// Qid
    pub qid: Qid,
    /// Length (0 for commands)
    pub length: u64,
    /// Permissions
    pub perm: u32,
}

impl Dirtab {
    /// Create new directory entry
    pub fn new(name: &'static str, path: u64, vers: u32, type_: u8, 
               length: u64, perm: u32) -> Self {
        Self {
            name,
            qid: Qid::new(path, vers, type_),
            length,
            perm,
        }
    }
}

// ============================================================================
// Walk Result
// ============================================================================

/// Walk result - returned by walk operations
#[derive(Debug)]
pub struct Walkqid {
    /// Qids for walked path components
    pub qids: Vec<Qid>,
}

impl Walkqid {
    /// Create empty walk result
    pub fn new() -> Self {
        Self { qids: Vec::new() }
    }

    /// Create from array
    pub fn from_slice(qids: &[Qid]) -> Self {
        Self { qids: qids.to_vec() }
    }
}

// ============================================================================
// Device Operations Trait
// ============================================================================

/// Device operations trait - all Plan 9 devices implement this
pub trait Dev: Send + Sync {
    /// Reset device
    fn reset(&mut self) {}
    
    /// Initialize device
    fn init(&mut self) {}
    
    /// Attach to device tree
    fn attach(&mut self, spec: Option<&str>) -> Result<Chan, Error>;
    
    /// Walk directory
    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        let _ = (ch, name);
        Err(Error::Enoent)
    }
    
    /// Open file/device
    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), Error> {
        let _ = (ch, mode);
        Ok(())
    }
    
    /// Create file
    fn create(&mut self, ch: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), Error> {
        let _ = (ch, name, mode, perm);
        Err(Error::Eperm)
    }
    
    /// Close channel
    fn close(&mut self, _ch: &mut Chan) {}
    
    /// Read data
    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        let _ = (ch, buf, offset);
        Err(Error::Eperm)
    }
    
    /// Write data
    fn write(&mut self, ch: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, Error> {
        let _ = (ch, buf, offset);
        Err(Error::Eperm)
    }
    
    /// Get file status
    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, Error> {
        let _ = ch;
        Err(Error::Eperm)
    }
    
    /// Set file status
    fn wstat(&mut self, ch: &mut Chan, dir: &DirEntry) -> Result<(), Error> {
        let _ = (ch, dir);
        Err(Error::Eperm)
    }

    /// Truncate a file to zero length.
    ///
    /// Devices that model a byte-addressable file override this; the
    /// default is a no-op success so that opening a device (console, pipe,
    /// clock) for writing never fails because of a truncation request.
    fn truncate(&mut self, ch: &mut Chan) -> Result<(), Error> {
        let _ = ch;
        Ok(())
    }
    
    /// Remove file
    fn remove(&mut self, ch: &mut Chan) -> Result<(), Error> {
        let _ = ch;
        Err(Error::Eperm)
    }
    
    /// Get device character
    fn dev_char(&self) -> char;
    
    /// Get device name
    fn name(&self) -> &'static str;

    /// Downcast self to `&dyn Any` for runtime type inspection.
    ///
    /// Default implementation returns a no-op `&dyn Any`. Concrete device
    /// types that want to participate in downcasting should override this
    /// (typically by returning `self`).
    fn as_any(&self) -> &dyn core::any::Any {
        &()
    }

    /// Downcast self to `&mut dyn Any` for runtime type inspection.
    ///
    /// Default implementation returns `None`. Concrete device
    /// types that want to participate in downcasting should override this
    /// (typically by returning `Some(self)`).
    fn as_any_mut(&mut self) -> Option<&mut dyn core::any::Any> {
        None
    }

    // === Block I/O Operations ===
    
    /// Read a block of data (buffered I/O)
    /// 
    /// # Arguments
    /// * `ch` - Channel to read from
    /// * `n` - Number of bytes to read
    /// * `offset` - Block offset (usually 0)
    /// 
    /// # Returns
    /// * `Some(Block)` - The read block
    /// * `None` - Error or EOF
    fn bread(&mut self, _ch: &mut Chan, _n: i64, _offset: u32) -> Option<Box<Block> > {
        // Default implementation using read()
        let mut buf = vec![0u8; _n as usize];
        match self.read(_ch, &mut buf, _offset as u64) {
            Ok(len) => {
                if len > 0 {
                    // Wrap in block
                    if let Some(mut block) = allocb(len) {
                        block.wp = block.base;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                buf.as_ptr(),
                                block.wp as *mut u8,
                                len
                            );
                        }
                        block.wp += len;
                        Some(block)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
    
    /// Write a block of data (buffered I/O)
    /// 
    /// # Arguments
    /// * `ch` - Channel to write to
    /// * `block` - Block containing data to write
    /// * `offset` - Block offset (usually 0)
    /// 
    /// # Returns
    /// * Number of bytes written, or error
    fn bwrite(&mut self, ch: &mut Chan, block: Box<Block>, _offset: u32) -> Result<i32, Error> {
        // Default implementation using write()
        let len = block.len();
        let data = unsafe {
            core::slice::from_raw_parts(block.rp as *const u8, len)
        };
        let result = self.write(ch, data, _offset as u64)?;
        Ok(result as i32)
    }

    // === Power Management ===
    
    /// Power management
    /// 
    /// # Arguments
    /// * `state` - 1 = power on, 0 = power off
    fn power(&mut self, _state: i32) {}
    
    /// Configuration
    /// 
    /// # Arguments
    /// * `cf` - Configuration type
    /// * `spec` - Device specification
    /// * `conf` - Configuration data
    /// 
    /// # Returns
    /// * 0 on success, -1 on error
    fn config(&mut self, _cf: i32, _spec: Option<&str>, _conf: Option<&DevConf>) -> Result<i32, Error> {
        let _ = (_cf, _spec, _conf);
        Ok(0)
    }
}

/// Default implementations for devices
impl dyn Dev {
    /// Default read implementation that returns EOF
    pub fn read_eof(_ch: &mut Chan, _buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        Ok(0)
    }
    
    /// Default write implementation that discards data
    pub fn write_discard(_ch: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, Error> {
        Err(Error::Eio)
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Device error
#[derive(Debug)]
pub enum Error {
    /// Operation succeeded
    Ok,
    /// No such file or directory
    Enoent,
    /// Permission denied
    Eperm,
    /// Out of memory
    Enomem,
    /// Bad address
    Ebadaddr,
    /// Bad path
    Ebadpath,
    /// No space left
    Enospace,
    /// Already exists
    Eexists,
    /// Not a directory
    Enotdir,
    /// Not a directory (alias)
    Enottdir,
    /// Is a directory
    Eisdir,
    /// Bad file descriptor
    Ebadfd,
    /// I/O error
    Eio,
    /// Invalid argument
    Einval,
    /// Operation not supported
    Enotsup,
    /// Closed
    Eclosed,
    /// Unknown error
    Unknown,
}

/// Type alias for Error (for compatibility)
pub type DevError = Error;

impl Error {
    pub fn to_isize(&self) -> isize {
        match self {
            Error::Ok => 0,
            Error::Enoent => -12,
            Error::Eperm => -6,
            Error::Enomem => -2,
            Error::Ebadaddr => -1,
            Error::Ebadpath => -1,
            Error::Enospace => -1,
            Error::Eexists => -7,
            Error::Enotdir => -20,
            Error::Enottdir => -20,
            Error::Eisdir => -21,
            Error::Ebadfd => -4,
            Error::Eio => -3,
            Error::Einval => -10,
            Error::Enotsup => -1,
            Error::Eclosed => -1,
            Error::Unknown => -1,
        }
    }
}

// ============================================================================
// Null Device
// ============================================================================

/// Null device - /dev/null equivalent
pub struct NullDev {
    name: &'static str,
    dev_char: char,
}

impl NullDev {
    pub fn new() -> Self {
        Self {
            name: "null",
            dev_char: '#',
        }
    }
}

impl Dev for NullDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::empty(), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn read(&mut self, _ch: &mut Chan, _buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Return EOF (0 bytes read)
        Ok(0)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // Discard data
        Ok(buf.len())
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Zero Device
// ============================================================================

/// Zero device - /dev/zero equivalent
pub struct ZeroDev {
    name: &'static str,
}

impl ZeroDev {
    pub fn new() -> Self {
        Self { name: "zero" }
    }
}

impl Dev for ZeroDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::empty(), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Return zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&mut self, _ch: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, Error> {
        Ok(0)
    }

    fn dev_char(&self) -> char {
        'z'
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Console Device
// ============================================================================

/// Console device - handles keyboard input and screen output
/// This is the #c device that provides the main terminal interface
pub struct ConsDev {
    name: &'static str,
    /// Console input buffer
    input_buffer: Mutex<Vec<u8>>,
    /// Bytes produced by a single PS/2 key press but not yet delivered
    /// (escape sequences are several bytes long).
    pending_input: Mutex<Vec<u8>>,
    /// Console output state
    output_lock: ConsoleLock,
    /// VGA availability flag - set to true when VGA is initialized
    vga_available: Spinlock<bool>,
}

impl ConsDev {
    /// Create new console device
    pub fn new() -> Self {
        Self {
            name: "cons",
            input_buffer: Mutex::new(Vec::new()),
            pending_input: Mutex::new(Vec::new()),
            output_lock: Spinlock::new(()),
            // VGA starts as unavailable, will be enabled when VGA is initialized
            vga_available: Spinlock::new(false),
        }
    }

    /// Mark VGA as available (called during VGA initialization)
    ///
    /// This should be called by the VGA subsystem once it has been
    /// successfully initialized and is ready to accept output.
    pub fn set_vga_available(&self, available: bool) {
        *self.vga_available.lock() = available;
    }

    /// Check if VGA is available
    pub fn is_vga_available(&self) -> bool {
        *self.vga_available.lock()
    }

    /// Add characters to input buffer (from keyboard interrupt)
    pub fn add_input(&self, data: &[u8]) {
        let mut buf = self.input_buffer.lock();
        buf.extend_from_slice(data);
    }

    /// Read a single character from input buffer.
    ///
    /// If the buffer is empty we poll the PS/2 keyboard data port directly
    /// so that typed characters are available even when the IRQ path has not
    /// delivered them (e.g. QEMU `sendkey` via the monitor does not raise a
    /// real PS/2 interrupt).
    ///
    /// QEMU mirrors a keystroke to both the emulated PS/2 keyboard and the
    /// serial port when `-serial stdio` is used together with a display, so
    /// the same key can arrive twice.  We therefore sample both transports
    /// and, when they carry the same byte, consume both and deliver it once.
    fn get_char(&self) -> Option<u8> {
        // virtio keyboard (e.g. aarch64's graphical-window input): the
        // polling driver translates Linux keycodes into the same byte
        // stream the PS/2 and serial transports deliver.
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
        if let Some(b) = crate::vkey::get_byte() {
            return Some(b);
        }

        {
            let mut buf = self.input_buffer.lock();
            if !buf.is_empty() {
                let b = buf.remove(0);
                // QEMU mirrors a keystroke to both PS/2 (→ input_buffer via IRQ)
                // and serial.  If the serial mirror is already buffered,
                // consume and collapse it so it is not delivered again on
                // the next get_char() call.
                if let Some(s) = crate::cons::serial_getchar() {
                    if s != b {
                        crate::cons::unread_serial(s);
                    }
                }
                return Some(b);
            }
        }

        // QEMU mirrors every keystroke to *both* transports (PS/2 keyboard
        // and serial port) when a display is attached.  Always sample both
        // before deciding, otherwise the serial mirror of one key lingers
        // in the UART buffer and is later delivered again as a "new" key —
        // the classic `dir` -> `dirr` double-typing.
        let ps2 = self.poll_ps2();
        let ser = crate::cons::serial_getchar();

        // QEMU mirrors one keystroke to both transports with a small skew:
        // the serial byte may trail the PS/2 byte by several interrupts.
        // When only one transport delivered, peek at the other (draining
        // its FIFO first) to catch a lagging mirror before returning.
        let ser = match ser {
            Some(b) => Some(b),
            None => {
                crate::cons::poll_serial_rx();
                match crate::cons::serial_peek() {
                    Some(b) if Some(b) == ps2 => {
                        // Mirror caught up: consume and collapse.
                        let _ = crate::cons::serial_getchar();
                        None
                    }
                    _ => None,
                }
            }
        };

        match (ps2, ser) {
            (Some(a), Some(b)) => {
                // Mirror of the same keystroke: collapse to one character.
                // If they differ, keep the serial byte for the next read so
                // no input is lost.
                if a != b {
                    crate::cons::unread_serial(b);
                }
                Some(a)
            }
            (Some(a), None) => Some(a),
            (None, s) => s,
        }
    }

    /// Poll the PS/2 keyboard controller and translate one complete key.
    ///
    /// A single key can produce several bytes (an escape sequence) or none
    /// at all (a modifier), so translated output is staged in
    /// `pending_input` and drained one byte at a time.
    fn poll_ps2(&self) -> Option<u8> {
        {
            let mut staged = self.pending_input.lock();
            if !staged.is_empty() {
                return Some(staged.remove(0));
            }
        }

        // The interrupt path may have just consumed this keystroke and
        // queued it in `input_buffer`; QEMU keeps the scancode port
        // readable for a short while after the IRQ, so a naive poll here
        // would deliver the key a second time.  Stand down once per
        // delivered IRQ — the data is already in `input_buffer` and will
        // be returned by the buffered read above on the next call.
        if crate::keymap::irq_delivered_pending() {
            crate::keymap::clear_irq_delivered();
            return None;
        }

        // On port-I/O architectures the keyboard IRQ handler is the sole
        // reader of port 0x60 (see `keyboard_interrupt` in trap.rs).
        // QEMU keeps the scancode port readable after the IRQ, so polling
        // it here would deliver the same key a second time.  Do not read
        // port 0x60 from the polling path; input arrives exclusively
        // through the IRQ → `input_buffer` path above.
        #[cfg(target_arch = "x86_64")]
        return None;

        // Non-port-I/O architectures have no PS/2 controller; console
        // input arrives through the serial transport in `get_char`.
        #[cfg(not(target_arch = "x86_64"))]
        return None;
    }

    /// Write characters to output (screen/serial)
    ///
    /// This method writes to both serial console and VGA text buffer.
    /// If VGA is not available (not initialized), the VGA write is skipped
    /// gracefully without error.
    fn put_chars(&self, data: &[u8]) {
        let _guard = self.output_lock.lock();

        // Prefer the graphical text console (the Ring3 terminal page) when
        // the GPU framebuffer console is available.  Serial output is still
        // mirrored so the QEMU serial log remains a complete diagnostic
        // transcript.  VGA text is the fallback when no graphical console
        // exists.
        if crate::console::is_initialised() {
            crate::console::puts_bytes(data);
        }

        crate::cons::serial_puts(data);

        if *self.vga_available.lock() {
            crate::vga::vga_puts(data);
        }
    }
}

impl Dev for ConsDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        // Return channel to console root
        // Qid path 0 is the console root directory
        Ok(Chan::new(devtype::CONS, Qid::new(0, 0, qidtype::DIR), 0))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        // Console is a flat namespace - only allow empty name for root
        if name.is_empty() {
            return Ok(Some(ch.qid));
        }
        Err(Error::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), Error> {
        // Store mode in channel
        ch.mode = mode;
        Ok(())
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        let _ = offset; // Offset not used for console
        let mut count = 0;

        for byte in buf.iter_mut() {
            if let Some(c) = self.get_char() {
                *byte = c;
                count += 1;

                // Break on newline for line-based input
                if c == b'\n' || c == b'\r' {
                    break;
                }
            } else {
                break;
            }
        }

        if count > 0 {
            Ok(count)
        } else {
            // No input available
            Ok(0)
        }
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        self.put_chars(buf);
        Ok(buf.len())
    }

    fn dev_char(&self) -> char {
        'c'
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn core::any::Any> {
        Some(self)
    }
}

// ============================================================================
// Root Device
// ============================================================================

/// Root device - the root of the file system tree
/// This is the '/' device that provides access to the entire namespace
pub struct RootDev {
    name: &'static str,
    /// Root channel (initialized during boot)
    root_chan: Spinlock<Option<Chan>>,
}

impl RootDev {
    /// Create new root device
    pub fn new() -> Self {
        Self {
            name: "root",
            root_chan: Spinlock::new(None),
        }
    }

    /// Set the root channel
    pub fn set_root(&self, chan: Chan) {
        *self.root_chan.lock() = Some(chan);
    }

    /// Get the root channel
    pub fn get_root(&self) -> Option<Chan> {
        self.root_chan.lock().as_ref().map(|c| c.dup())
    }
}

impl RootDev {
    /// Standard directories in Plan 9 root
    const ROOT_DIRS: &'static [(u64, &'static str)] = &[
        (0, "bin"),      // Executables
        (1, "dev"),      // Devices
        (2, "env"),      // Environment
        (3, "lib"),      // Libraries
        (4, "mnt"),      // Mount points
        (5, "net"),      // Network
        (6, "proc"),     // Process info
        (7, "root"),     // Root home
        (8, "srv"),      // Services
        (9, "tmp"),      // Temporary files
        (10, "appl"),    // Applications
    ];

    /// Check if a name is a valid root directory
    fn lookup_dir(name: &str) -> Option<Qid> {
        for (path, dir_name) in Self::ROOT_DIRS {
            if *dir_name == name {
                return Some(Qid::new(*path, 0, qidtype::DIR));
            }
        }
        None
    }
}

impl Dev for RootDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        // Return the root channel
        if let Some(ref root) = *self.root_chan.lock() {
            Ok(root.dup())
        } else {
            // No root set yet - return an error or empty root
            Err(Error::Enoent)
        }
    }

    fn walk(&mut self, _ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        // Look up standard root directories
        // The actual navigation is handled by the mounted file system
        if let Some(qid) = RootDev::lookup_dir(name) {
            Ok(Some(qid))
        } else {
            // Not a standard directory in root
            // Delegate to mounted filesystem if any
            if let Some(ref root) = *self.root_chan.lock() {
                // Root has a channel - try to walk it
                // This is a simplified implementation
                let _ = root;
                Err(Error::Enoent)
            } else {
                Err(Error::Enoent)
            }
        }
    }

    fn open(&mut self, ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        // Can only open directories
        if !ch.qid.is_dir() {
            return Err(Error::Enottdir);
        }
        Ok(())
    }

    fn dev_char(&self) -> char {
        '/'
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// ============================================================================
// RAM File System Device
// ============================================================================

/// RAM file system device - provides an in-memory file system
/// Used for /dev, /tmp, and other volatile directories
pub struct RamDev {
    name: &'static str,
    /// Root directory entries
    entries: Mutex<Vec<DirEntry>>,
    /// Next qid path to allocate
    next_qid: Mutex<u64>,
}

impl RamDev {
    /// Create new RAM device
    pub fn new() -> Self {
        let mut entries = Vec::new();

        // Create standard directories
        entries.push(DirEntry {
            dev: devtype::SD,
            qid: Qid::new(1, 0, qidtype::DIR),
            mode: 0o755 | 0o40000, // Directory + rwxr-xr-x
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"dev".to_vec(),
            uid: 0,
            gid: 0,
});

        entries.push(DirEntry {
            dev: devtype::SD,
            qid: Qid::new(2, 0, qidtype::DIR),
            mode: 0o755 | 0o40000,
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"tmp".to_vec(),
            uid: 0,
            gid: 0,
});

        Self {
            name: "ram",
            entries: Mutex::new(entries),
            next_qid: Mutex::new(3),
        }
    }

    /// Add an entry to the RAM device
    pub fn add_entry(&self, name: &str, mode: u32, is_dir: bool) {
        let mut entries = self.entries.lock();
        let qid_path = {
            let mut next = self.next_qid.lock();
            let path = *next;
            *next += 1;
            path
        };

        entries.push(DirEntry {
            dev: devtype::SD,
            qid: Qid::new(qid_path, 0, if is_dir { qidtype::DIR } else { qidtype::FILE }),
            mode,
            atime: 0,
            mtime: 0,
            length: 0,
            name: name.as_bytes().to_vec(),
            uid: 0,
            gid: 0,
});
    }

    /// Find an entry by name
    fn find_entry(&self, name: &str) -> Option<DirEntry> {
        let entries = self.entries.lock();
        entries.iter().find(|e| e.name == name.as_bytes()).cloned()
    }
}

impl Dev for RamDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::SD, Qid::new(0, 0, qidtype::DIR), 0))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        if let Some(entry) = self.find_entry(name) {
            ch.qid = entry.qid;
            Ok(Some(entry.qid))
        } else {
            Err(Error::Enoent)
        }
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if ch.qid.type_ == qidtype::DIR {
            // Read directory entries
            self.readdir(buf, offset)
        } else {
            Err(Error::Enoent)
        }
    }

    fn write(&mut self, _ch: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, Error> {
        Err(Error::Eperm)
    }

    fn dev_char(&self) -> char {
        // Plan 9 uses `#s` for the SD/storage device.  This RAM namespace
        // device must not shadow it, so use `#r` (RAM disk).
        'r'
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

impl RamDev {
    /// Read directory entries
    fn readdir(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
//         use core::mem::size_of;

        let entries = self.entries.lock();
        let entry_size = 64; // Plan 9 dir entry size
        let start = (offset / entry_size as u64) as usize;

        let mut pos = 0;
        for (i, entry) in entries.iter().enumerate().skip(start) {
            if pos + entry_size > buf.len() {
                break;
            }

            // Pack directory entry (Plan 9 format)
            // struct DirEntry {
            //     u64 qid_path;
            //     u32 qid_vers;
            //     u8 qid_type;
            //     u32 mode;
            //     u32 atime;
            //     u32 mtime;
            //     u64 length;
            //     char name[];
            // }
            let name_len = entry.name.len().min(28);
            let total_len = 39 + name_len; // Fixed part + name

            if pos + total_len > buf.len() {
                break;
            }

            // Write qid
            buf[pos..pos + 8].copy_from_slice(&entry.qid.path.to_le_bytes());
            pos += 8;
            buf[pos..pos + 4].copy_from_slice(&entry.qid.vers.to_le_bytes());
            pos += 4;
            buf[pos] = entry.qid.type_;
            pos += 1;
            // Skip padding
            pos += 3;

            // Write mode, times, length
            buf[pos..pos + 4].copy_from_slice(&entry.mode.to_le_bytes());
            pos += 4;
            buf[pos..pos + 4].copy_from_slice(&entry.atime.to_le_bytes());
            pos += 4;
            buf[pos..pos + 4].copy_from_slice(&entry.mtime.to_le_bytes());
            pos += 4;
            buf[pos..pos + 8].copy_from_slice(&entry.length.to_le_bytes());
            pos += 8;

            // Write name length and name
            buf[pos] = name_len as u8;
            pos += 1;
            buf[pos..pos + name_len].copy_from_slice(&entry.name[..name_len]);
            pos += name_len;

            // Skip remaining of 28-byte name field
            pos += 28 - name_len;

            if i == start {
                // First entry is special
            }
        }

        Ok(pos)
    }
}

// ============================================================================
// Device Table
// ============================================================================

/// Device table - manages all registered devices
pub struct DevTable {
    /// Array of devices
    devices: [Option<Box<dyn Dev>>; NDEV],
    /// Number of registered devices
    count: usize,
}

impl DevTable {
    /// Create new device table
    pub fn new() -> Self {
        Self {
            devices: [const { None }; NDEV],
            count: 0,
        }
    }

    /// Register a device
    pub fn register(&mut self, dev: Box<dyn Dev>) -> Option<usize> {
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(dev);
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.count
    }

    /// Get device by index
    pub fn get(&self, index: usize) -> Option<&dyn Dev> {
        self.devices.get(index).and_then(|d| d.as_ref().map(|b| b.as_ref()))
    }

    /// Get mutable device by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut dyn Dev> {
        self.devices.get_mut(index).and_then(|d| d.as_mut().map(|b| b.as_mut() as &mut dyn Dev))
    }

    /// Find device by character
    pub fn find_by_char(&self, c: char) -> Option<usize> {
        for (i, dev) in self.devices.iter().enumerate() {
            if let Some(d) = dev {
                if d.dev_char() == c {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find device by character, searching by name
    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        for (i, dev) in self.devices.iter().enumerate() {
            if let Some(d) = dev {
                if d.name() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Initialize with default devices
    pub fn init_defaults(&mut self) {
        // Register null device (#n)
        self.register(Box::new(NullDev::new()));
        // Register zero device (#z)
        self.register(Box::new(ZeroDev::new()));
        // Register root device ('/') — the RAM root file system.
        self.register(Box::new(crate::rootfs::RootFsDev::new()));
        // Register console device (#c)
        self.register(Box::new(ConsDev::new()));
        // Register RAM device for /sd
        self.register(Box::new(RamDev::new()));
        // Register kmesg device (#K) - kernel message buffer
        self.register(Box::new(crate::kmesg::KmesgDev::new()));
        // Register proc device (#p) - process filesystem
        self.register(Box::new(crate::procfs::ProcFsDev::new()));
        // Register pipe device (#|) - inter-process pipes
        self.register(Box::new(crate::devpipe::PipeDev::new()));
        // Register SD device (#s) - storage/disk
        self.register(Box::new(crate::devsd::SdDev::new()));
        // Register filesystem device (#f) - EXT/NTFS/FAT/XFS images
        self.register(Box::new(crate::devfs::FsDev::new()));
        // Register UART device (#U) - serial ports
        self.register(Box::new(crate::devuart::UartDev::new()));
        // Register mouse device (#m) - PS/2 mouse
        self.register(Box::new(crate::devmouse::MouseDev::new()));
        // Register keyboard device (#k) - PS/2 keyboard
        self.register(Box::new(crate::devkb::KbdDev::new()));
        // Register draw device (#d) - graphics
        self.register(Box::new(crate::devdraw::DrawDev::new()));
        // Register audio device (#a) - audio playback/recording
        self.register(Box::new(crate::devaudio::AudioDev::new()));
        // Register mnt device (#M) - mount driver
        self.register(Box::new(crate::devmnt::MntDev::new()));
        // Register TLS device (#T) - TLS/SSL
        self.register(Box::new(crate::devtls::TlsDev::new()));
        // Register bridge device (#l) - Ethernet bridge
        self.register(Box::new(crate::devbridge::BridgeDev::new()));
        // Register USB device (#u) - USB host
        self.register(Box::new(crate::devusb::UsbDev::new()));
        // Register network device (#I) - the Plan 9 /net tree
        self.register(Box::new(crate::netfs::NetFs::new()));
        // Register srv device - service access device
        self.register(Box::new(crate::devsrv::SrvDev::new()));
    }
}

// ============================================================================
// Device Configuration
// ============================================================================

/// Device configuration structure
///
/// Used by the config() method to pass device-specific configuration.
pub struct DevConf {
    /// Number of interrupt vectors used
    pub nirq: u32,
    /// DMA channel (if any)
    pub dma: u32,
    /// Port I/O base address
    pub portbase: u32,
    /// Memory-mapped I/O base address
    pub membase: u32,
    /// Memory-mapped I/O length
    pub memlen: u32,
    /// IRQ number
    pub irq: u32,
    /// DMA channel
    pub dmarq: u32,
    /// Clock frequency in Hz
    pub freq: u32,
    /// Clock divisor
    pub div: u32,
    /// Device type (vendor-specific)
    pub type_: u32,
    /// Device-specific data
    pub data: Option<Box<dyn Send + Sync>>,
}

impl DevConf {
    /// Create a new device configuration
    pub fn new() -> Self {
        Self {
            nirq: 0,
            dma: 0,
            portbase: 0,
            membase: 0,
            memlen: 0,
            irq: 0,
            dmarq: 0,
            freq: 0,
            div: 0,
            type_: 0,
            data: None,
        }
    }
}

impl core::fmt::Debug for DevConf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevConf")
            .field("nirq", &self.nirq)
            .field("dma", &self.dma)
            .field("portbase", &self.portbase)
            .field("membase", &self.membase)
            .field("memlen", &self.memlen)
            .field("irq", &self.irq)
            .field("dmarq", &self.dmarq)
            .field("freq", &self.freq)
            .field("div", &self.div)
            .field("type_", &self.type_)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Chan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chan")
            .field("dev", &self.dev)
            .field("qid", &self.qid)
            .field("mode", &self.mode)
            .field("flag", &self.flag)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Global Device Table
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static DEV_TABLE: AtomicPtr<DevTable> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize device table
pub fn init_devs() {
    let mut table = Box::new(DevTable::new());
    table.init_defaults();
    DEV_TABLE.store(Box::into_raw(table), Ordering::SeqCst);
}

/// Get device table reference
pub fn devs() -> &'static DevTable {
    unsafe { &*DEV_TABLE.load(Ordering::SeqCst) }
}

/// Get mutable device table reference
pub fn devs_mut() -> &'static mut DevTable {
    unsafe { &mut *DEV_TABLE.load(Ordering::SeqCst) }
}

/// Register a device
pub fn register_device(dev: Box<dyn Dev>) -> Option<usize> {
    devs_mut().register(dev)
}

/// Set the root device's root channel.
///
/// The device is looked up via `dev_char('/')`. The channel is stored inside
/// the device's auxiliary data, which is keyed by the `'/'` device character.
///
/// In a no-downcast environment we keep a parallel static map of `RootDev`
/// pointers. The kernel registers the `RootDev` via [`set_root_device`] and
/// this function pushes the supplied channel into it.
pub fn set_root_device_chan(chan: Chan) {
    // Try the per-table slot first: the global table contains a `RootDev`
    // entry registered via `set_root_device` below.
    if let Some(idx) = devs().find_by_char('/') {
        if let Some(dev) = devs().get(idx) {
            if let Some(root_dev) = dev.as_any().downcast_ref::<RootDev>() {
                root_dev.set_root(chan);
                return;
            }
        }
    }
    // Fallback: keep a side-table of recently set channels so that
    // `lookup_root` can find them even before a RootDev is registered.
    ROOT_CHAN_FALLBACK.lock().replace(chan);
}

/// Fallback storage for the root channel when no RootDev is registered.
static ROOT_CHAN_FALLBACK: crate::plan9_common::sync::Mutex<Option<Chan>> =
    crate::plan9_common::sync::Mutex::new(None);

/// Look up the root channel used for path resolution at `/`.
///
/// This returns the channel set via `set_root_device_chan`, opening a fresh
/// dup of the registered root.
pub fn lookup_root() -> Result<Chan, Error> {
    if let Some(idx) = devs().find_by_char('/') {
        if let Some(dev) = devs().get(idx) {
            if let Some(root_dev) = dev.as_any().downcast_ref::<RootDev>() {
                if let Some(c) = root_dev.get_root() {
                    return Ok(c);
                }
            }
        }
    }
    if let Some(c) = ROOT_CHAN_FALLBACK.lock().as_ref() {
        return Ok(c.dup());
    }
    Err(Error::Enoent)
}

// ============================================================================
// Device Helper Functions
// ============================================================================

/// Minimal PCI device description used by devices that want to probe the
/// PCI bus. This intentionally mirrors the fields of
/// `plan9_drivers::pci::PciDevice` so the kernel can keep its own
/// dependency-free view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDeviceInfo {
    /// PCI bus number
    pub bus: u8,
    /// PCI device number
    pub dev: u8,
    /// PCI function number
    pub func: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Class code (e.g. 0x0C for Serial Bus)
    pub class_code: u8,
    /// Subclass (e.g. 0x03 for USB)
    pub subclass: u8,
    /// Programming interface (e.g. 0x20 for EHCI)
    pub prog_if: u8,
    /// Revision
    pub revision: u8,
}

/// A PCI device iterator. The default implementation returns no devices;
/// drivers that have access to a real PCI bus can install an iterator
/// via [`set_pci_iterator`].
pub type PciIterator = alloc::vec::IntoIter<PciDeviceInfo>;

/// Install a custom PCI iterator. Drivers with access to a real PCI bus
/// should call this once during initialization.
pub fn set_pci_iterator(iter: Option<alloc::vec::Vec<PciDeviceInfo>>) {
    if let Some(items) = iter {
        *PCI_BUFFER.lock() = Some(items);
    } else {
        *PCI_BUFFER.lock() = None;
    }
}

/// Iterate over a fresh copy of the PCI devices known to the kernel.  Each
/// call starts from the beginning, so multiple drivers can consume the list.
pub fn pci_iter() -> PciIteratorGuard {
    let items = PCI_BUFFER.lock().clone();
    PciIteratorGuard {
        iter: items.map(|v| v.into_iter()),
    }
}

pub struct PciIteratorGuard {
    iter: Option<alloc::vec::IntoIter<PciDeviceInfo>>,
}

impl Iterator for PciIteratorGuard {
    type Item = PciDeviceInfo;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.iter {
            Some(it) => it.next(),
            None => None,
        }
    }
}

static PCI_BUFFER: Mutex<Option<alloc::vec::Vec<PciDeviceInfo>>> = Mutex::new(None);

/// Install a fixed list of PCI devices (for tests and stub environments).
pub fn install_test_pci_devices(devices: alloc::vec::Vec<PciDeviceInfo>) {
    set_pci_iterator(Some(devices));
}

/// Open a file on a specific device
pub fn dev_open(dev_char: char, path: &str, mode: u8) -> Result<Chan, Error> {
    let dev_idx = devs_mut().find_by_char(dev_char)
        .ok_or(Error::Enoent)?;

    let dev = devs_mut().get_mut(dev_idx)
        .ok_or(Error::Enoent)?;

    let mut chan = dev.attach(Some(path))
        .map_err(|_| Error::Eio)?;

    if mode != 0 {
        dev.open(&mut chan, mode).map_err(|_| Error::Eio)?;
    }

    Ok(chan)
}

/// Read from a device channel
pub fn dev_read(chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.read(chan, buf, offset)
}

/// Write to a device channel
pub fn dev_write(chan: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.write(chan, buf, offset)
}

/// Close a device channel
pub fn dev_close(chan: &mut Chan) -> Result<(), Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.close(chan);
    Ok(())
}

/// Truncate the file behind `chan` to zero length.
pub fn dev_truncate(chan: &mut Chan) -> Result<(), Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.truncate(chan)
}

/// Get device channel status

pub fn dev_stat(chan: &mut Chan) -> Result<DirEntry, Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.stat(chan)
}

/// Apply a directory-entry update to the file behind `chan`.
pub fn dev_wstat(chan: &mut Chan, dir: &DirEntry) -> Result<(), Error> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(Error::Enoent)?;
    dev.wstat(chan, dir)
}

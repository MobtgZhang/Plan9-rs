//! Console Device
//!
//! Implements the Plan 9 console device for text input/output.

use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};
use crate::plan9_common::sync::{ Mutex };
// ============================================================================
// Console Device State
// ============================================================================

/// Console device state
pub struct ConsoleDev {
    /// Console name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Input buffer (for keyboard)
    input: Mutex<Vec<u8>>,
    /// Output buffer
    output: Mutex<Vec<u8>>,
}

impl ConsoleDev {
    /// Create a new console device
    pub fn new() -> Self {
        Self {
            name: "cons",
            dev_char: 'c',
            input: Mutex::new(Vec::new()),
            output: Mutex::new(Vec::new()),
        }
    }
    
    /// Add input to the console buffer
    pub fn add_input(&self, byte: u8) {
        self.input.lock().push(byte);
    }
    
    /// Add multiple bytes to input buffer
    pub fn add_input_str(&self, s: &[u8]) {
        let mut input = self.input.lock();
        input.extend_from_slice(s);
    }
}

impl Dev for ConsoleDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::CONS, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Ok(None)
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), Error> {
        Err(Error::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // Nothing to clean up
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        let mut input = self.input.lock();
        
        if input.is_empty() {
            return Ok(0);
        }
        
        let n = input.len().min(buf.len());
        for (i, byte) in input.drain(..n).enumerate() {
            buf[i] = byte;
        }
        
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // In a real implementation, this would write to the VGA display or serial port
        // For now, just succeed
        Ok(buf.len())
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        Ok(DirEntry {
            dev: devtype::CONS,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"cons".to_vec(),
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), Error> {
        Err(Error::Eperm)
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
// Keyboard Device
// ============================================================================

/// Keyboard device state
pub struct KbdDev {
    /// Keyboard name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Keyboard buffer
    buffer: Mutex<Vec<u8>>,
    /// Shift state
    shift: bool,
    /// Caps lock
    caps_lock: bool,
}

impl KbdDev {
    /// Create a new keyboard device
    pub fn new() -> Self {
        Self {
            name: "kbd",
            dev_char: 'k',
            buffer: Mutex::new(Vec::new()),
            shift: false,
            caps_lock: false,
        }
    }
    
    /// Handle a keyboard scancode
    pub fn handle_scancode(&self, scancode: u8) {
        if let Some(c) = self.scancode_to_ascii(scancode) {
            self.buffer.lock().push(c);
        }
    }
    
    /// Read a byte from the keyboard buffer
    pub fn read_byte(&self) -> Option<u8> {
        self.buffer.lock().pop()
    }
    
    /// Convert PS/2 scancode to ASCII
    fn scancode_to_ascii(&self, scancode: u8) -> Option<u8> {
        match scancode {
            // Letters (without modifiers)
            0x1E..=0x26 if !self.shift && !self.caps_lock => {
                Some(scancode + 0x61 - 0x1E) // 'a' - 'z'
            }
            0x1E..=0x26 => {
                Some(scancode + 0x41 - 0x1E) // 'A' - 'Z'
            }
            // Numbers with shift
            0x02..=0x0A if self.shift => {
                let shifted = match scancode {
                    0x02 => b'!',
                    0x03 => b'@',
                    0x04 => b'#',
                    0x05 => b'$',
                    0x06 => b'%',
                    0x07 => b'^',
                    0x08 => b'&',
                    0x09 => b'*',
                    0x0A => b'(',
                    _ => 0,
                };
                if shifted != 0 { Some(shifted) } else { None }
            }
            // Numbers without shift
            0x02..=0x0A => Some(scancode + 0x30 - 0x02 + b'1'), // '1' - '9'
            // Special keys
            0x0D => Some(b'\n'),  // Enter
            0x0E => Some(0x7F),    // Backspace
            0x39 => Some(b' '),     // Space
            // Function keys (return as escape sequences)
            0x3B..=0x44 => None, // F1-F10 - could be escape sequences
            // Toggle keys
            0x3A => {
                // Caps lock toggle handled at hardware level
                None
            }
            0x2A | 0x36 => {
                // Shift key
                None
            }
            _ => None,
        }
    }
}

impl Dev for KbdDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::KB, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Ok(None)
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        let mut buffer = self.buffer.lock();
        
        if buffer.is_empty() {
            return Ok(0);
        }
        
        let n = buffer.len().min(buf.len());
        for (i, byte) in buffer.drain(..n).enumerate() {
            buf[i] = byte;
        }
        
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, Error> {
        Err(Error::Eio)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Serial Console Device
// ============================================================================

/// Serial port device
#[cfg(target_arch = "x86_64")]
pub struct SerialDev {
    /// Port I/O address
    port: u16,
    /// Device name
    name: &'static str,
}

/// Stub serial device for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub struct SerialDev {
    /// Port I/O address (unused on non-x86_64)
    _port: u16,
    /// Device name
    name: &'static str,
}

#[cfg(target_arch = "x86_64")]
impl SerialDev {
    /// Create a new serial device
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            name: if port == 0x3F8 { "com1" } else { "com2" },
        }
    }
    
    /// Initialize the serial port
    pub fn init(&self) {
        // Disable interrupts
        self.write_reg(1, 0x00);
        
        // Set baud rate divisor
        self.write_reg(3, 0x80); // Enable DLAB
        self.write_reg(0, 0x03); // 115200 baud
        self.write_reg(1, 0x00);
        
        // 8 bits, no parity, one stop bit
        self.write_reg(3, 0x03);
        
        // Enable FIFO, clear, 14-byte threshold
        self.write_reg(2, 0xC7);
        
        // Enable IRQs, RTS/DSR set
        self.write_reg(4, 0x0F);
    }
    
    /// Read a byte from the serial port (non-blocking)
    pub fn read_byte(&self) -> Option<u8> {
        // Check if data is ready
        if self.read_reg(5) & 0x01 == 0 {
            return None;
        }
        Some(self.read_reg(0))
    }

    /// Current line-status register, used by the diagnostic path.
    pub fn lsr(&self) -> u8 {
        self.read_reg(5)
    }
    
    /// Write a byte to the serial port.
    /// The TX-empty wait is bounded: an absent or unusual UART must not
    /// wedge kernel output forever.
    pub fn write_byte(&self, byte: u8) {
        for _ in 0..0x10000 {
            if self.read_reg(5) & 0x20 != 0 {
                break;
            }
        }
        self.write_reg(0, byte);
    }
    
    /// Read from a register
    fn read_reg(&self, reg: u8) -> u8 {
        let port = self.port + reg as u16;
        let result: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                inout("dx") port => _,
                out("al") result,
            );
        }
        result
    }
    
    /// Write to a register
    fn write_reg(&self, reg: u8, val: u8) {
        let port = self.port + reg as u16;
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
            );
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl SerialDev {
    /// Create a new serial device
    pub const fn new(port: u16) -> Self {
        Self {
            _port: port,
            name: if port == 0x3F8 { "com1" } else { "com2" },
        }
    }
    
    /// Initialize the serial port (stub for non-x86_64)
    pub fn init(&self) {
        // No serial port on non-x86_64 architectures
    }
    
    /// Read a byte from the serial port (stub for non-x86_64)
    pub fn read_byte(&self) -> Option<u8> {
        None
    }
    
    /// Write a byte to the serial port (stub for non-x86_64)
    pub fn write_byte(&self, _byte: u8) {
        // No serial port on non-x86_64 architectures
    }
}

#[cfg(target_arch = "x86_64")]
impl Dev for SerialDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        self.init();
        Ok(Chan::new(devtype::CONS, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Read available bytes
        let mut n = 0;
        for byte in buf.iter_mut() {
            if let Some(c) = self.read_byte() {
                *byte = c;
                n += 1;
            } else {
                break;
            }
        }
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        for &byte in buf {
            self.write_byte(byte);
        }
        Ok(buf.len())
    }

    fn dev_char(&self) -> char {
        #[cfg(target_arch = "x86_64")]
        {
            if self.port == 0x3F8 { 'c' } else { 'c' }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            'c'
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Global Console Output
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

/// Global console instance
static CONSOLE: AtomicPtr<ConsoleDev> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the console
pub fn init_console() {
    let console = Box::new(ConsoleDev::new());
    CONSOLE.store(Box::into_raw(console), Ordering::SeqCst);
}

/// Print a single character to the console.
///
/// Output goes to every available sink so kernel log messages remain
/// visible after the system switches to the graphical Ring-3 terminal:
///   * the graphical text console (when `console::init_console()` ran),
///   * the serial port (for QEMU `-serial` capture),
///   * the `ConsoleDev` output buffer (for `/dev/kmesg` readers).
pub fn putchar(c: u8) {
    // Graphical console first — this is what the Ring-3 terminal shows.
    if crate::console::is_initialised() {
        crate::console::putchar(c);
    }
    // Serial mirror for headless / debug captures.
    serial_putchar(c);
    // Buffer for /dev/kmesg readers.
    unsafe {
        if let Some(console) = CONSOLE.load(Ordering::SeqCst).as_ref() {
            console.output.lock().push(c);
        }
    }
}

/// Print a string to the console.
pub fn puts(s: &[u8]) {
    for &c in s {
        putchar(c);
    }
}

/// Global serial port instance
static SERIAL: AtomicPtr<SerialDev> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize serial console.
/// The device is heap-allocated: a pointer to a stack local would dangle
/// as soon as `init_serial` returns and could make input reads use a
/// corrupted port.
pub fn init_serial() {
    let serial = Box::new(SerialDev::new(0x3F8)); // COM1
    serial.init();
    SERIAL.store(Box::into_raw(serial), Ordering::SeqCst);
}

/// Write a byte to serial port.  If the full SerialDev has not been
/// initialised yet, fall back to the early-boot direct COM1 driver so
/// user-space `puts`/`write` output is visible during boot.
pub fn serial_putchar(c: u8) {
    // Output goes through the early serial driver.  The SerialDev output
    // path waits indefinitely for QEMU's LSR TX-empty bit, which can wedge
    // the syscall before any characters appear; the boot driver uses a
    // bounded wait and is reliable on both hardware and emulation.
    crate::serial::putc(c);
}

/// Write a string to serial port
pub fn serial_puts(s: &[u8]) {
    crate::serial::put_bytes(s);
}

/// Read a byte from serial port (non-blocking)
///
/// Bytes are served from the software RX buffer first (see `poll_serial_rx`),
/// then straight from the UART.
pub fn serial_getchar() -> Option<u8> {
    {
        let mut buf = SER_RX.lock();
        if !buf.is_empty() {
            return Some(buf.remove(0));
        }
    }
    unsafe {
        if let Some(serial) = SERIAL.load(Ordering::SeqCst).as_ref() {
            serial.read_byte()
        } else {
            None
        }
    }
}

/// Software buffer for serial receive bytes.
///
/// The 16550 FIFO holds only 16 bytes and nothing polls it while the
/// graphical console is busy rendering output inside a `write` syscall, so
/// fast typists would lose keystrokes.  Every console interaction drains
/// the UART into this buffer first.
static SER_RX: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Move every byte waiting in the UART FIFO into the software RX buffer.
///
/// Cheap when idle (one LSR port read); call it from any code that runs for
/// a long time without servicing input, e.g. the console render path.
pub fn poll_serial_rx() {
    let mut guard = SER_RX.lock();
    loop {
        let byte = unsafe {
            match SERIAL.load(Ordering::SeqCst).as_ref() {
                Some(s) => s.read_byte(),
                None => None,
            }
        };
        match byte {
            Some(b) => {
                if guard.len() < 4096 {
                    guard.push(b);
                }
            }
            None => break,
        }
    }
}

/// Diagnostic line-status register for terminal input debugging.
pub fn serial_lsr() -> Option<u8> {
    unsafe {
        SERIAL.load(Ordering::SeqCst)
            .as_ref()
            .map(|serial| serial.lsr())
    }
}

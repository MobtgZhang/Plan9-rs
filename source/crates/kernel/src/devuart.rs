

//! UART Device Implementation
//!
//! Implements the Plan 9 UART device (#U) for serial communication.
//!
//! ## Overview
//!
//! The UART device provides access to serial ports (16550-compatible).
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! ├── eia0/              (first UART port)
//! │   ├── ctl           (control - configuration)
//! │   ├── data          (read/write serial data)
//! │   └── status        (modem status)
//! ├── eia1/              (second UART port, etc.)
//! └── tty                (default TTY - console)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};

use crate::plan9_common::sync::{Spinlock, Mutex};
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{ AtomicBool, Ordering };
/// Maximum number of UART ports
const UART_MAX_PORTS: usize = 4;

/// UART I/O port addresses (PC architecture)
const UART_PORT_COM1: u16 = 0x3F8;
const UART_PORT_COM2: u16 = 0x2F8;
const UART_PORT_COM3: u16 = 0x3E8;
const UART_PORT_COM4: u16 = 0x2E8;

/// UART registers (offset from base port)
mod uart_reg {
    pub const UART_RBR: u16 = 0;  // Receive Buffer (read)
    pub const UART_THR: u16 = 0;  // Transmit Hold (write)
    pub const UART_IER: u16 = 1;  // Interrupt Enable
    pub const UART_IIR: u16 = 2;  // Interrupt Identification (read)
    pub const UART_FCR: u16 = 2;  // FIFO Control (write)
    pub const UART_LCR: u16 = 3;  // Line Control
    pub const UART_MCR: u16 = 4;  // Modem Control
    pub const UART_LSR: u16 = 5;  // Line Status
    pub const UART_MSR: u16 = 6;  // Modem Status
    pub const UART_SCR: u16 = 7;  // Scratch
    pub const UART_DLL: u16 = 0;  // Divisor LSB (when DLAB=1)
    pub const UART_DLM: u16 = 1;  // Divisor MSB (when DLAB=1)
    
    // LSR bits
    pub const LSR_DATA_READY: u8 = 1 << 0;
    pub const LSR_OVERRUN_ERR: u8 = 1 << 1;
    pub const LSR_PARITY_ERR: u8 = 1 << 2;
    pub const LSR_FRAMING_ERR: u8 = 1 << 3;
    pub const LSR_BREAK_INT: u8 = 1 << 4;
    pub const LSR_TRANS_EMPTY: u8 = 1 << 5;
    pub const LSR_IDLE: u8 = 1 << 6;
    
    // LCR bits
    pub const LCR_5_BITS: u8 = 0;
    pub const LCR_6_BITS: u8 = 1;
    pub const LCR_7_BITS: u8 = 2;
    pub const LCR_8_BITS: u8 = 3;
    pub const LCR_STOP_1: u8 = 0;
    pub const LCR_STOP_2: u8 = 1 << 2;
    pub const LCR_NOPARITY: u8 = 0;
    pub const LCR_PARITY: u8 = 1 << 3;
    pub const LCR_ODDPARITY: u8 = 3 << 3;
    pub const LCR_EVENPARITY: u8 = 3 << 3 | 1 << 4;
    pub const LCR_DLAB: u8 = 1 << 7;
    
    // MCR bits
    pub const MCR_DTR: u8 = 1 << 0;
    pub const MCR_RTS: u8 = 1 << 1;
    pub const MCR_OUT1: u8 = 1 << 2;
    pub const MCR_OUT2: u8 = 1 << 3;  // Required for interrupts
    pub const MCR_LOOP: u8 = 1 << 4;
}

/// Qid structure for UART device
mod uart_qid {
    /// Top-level directory
    pub const QDIR: u64 = 0;
    /// Control file
    pub const QCTL: u64 = 1;
    /// Data file
    pub const QDATA: u64 = 2;
    /// Status file
    pub const QSTATUS: u64 = 3;
    
    /// Calculate port-specific qid
    pub fn port_qid(port: usize, file: u64) -> u64 {
        ((port as u64) << 4) | file
    }
    
    /// Extract port from qid
    pub fn port(qid: u64) -> usize {
        ((qid >> 4) & 0xF) as usize
    }
    
    /// Extract file type from qid
    pub fn file(qid: u64) -> u64 {
        qid & 0xF
    }
}

/// UART configuration
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Baud rate
    pub baud: u32,
    /// Data bits (5-8)
    pub data_bits: u8,
    /// Stop bits (1 or 2)
    pub stop_bits: u8,
    /// Parity (0=none, 1=odd, 2=even)
    pub parity: u8,
}

impl Default for UartConfig {
    fn default() -> Self {
        Self {
            baud: 115200,
            data_bits: 8,
            stop_bits: 1,
            parity: 0,
        }
    }
}

/// UART port state
pub struct UartPort {
    /// Base I/O port
    base: u16,
    /// Port is enabled
    enabled: AtomicBool,
    /// Configuration
    config: Mutex<UartConfig>,
    /// Input buffer
    input: Spinlock<Vec<u8>>,
    /// Output buffer
    output: Spinlock<Vec<u8>>,
}

impl UartPort {
    /// Create a new UART port
    pub fn new(base: u16) -> Self {
        Self {
            base,
            enabled: AtomicBool::new(false),
            config: Mutex::new(UartConfig::default()),
            input: Spinlock::new(Vec::new()),
            output: Spinlock::new(Vec::new()),
        }
    }
    
    /// Initialize the UART port
    pub fn init(&self) {
        let base = self.base;
        
        // Disable interrupts
        outb(base + uart_reg::UART_IER, 0x00);
        
        // Set DLAB to access divisor
        outb(base + uart_reg::UART_LCR, uart_reg::LCR_DLAB);
        
        // Set baud rate divisor (115200 / baud)
        let config = *self.config.lock();
        let divisor = 115200 / config.baud;
        outb(base + uart_reg::UART_DLL, (divisor & 0xFF) as u8);
        outb(base + uart_reg::UART_DLM, ((divisor >> 8) & 0xFF) as u8);
        
        // Set line control (8N1 by default)
        let lcr = match (config.data_bits, config.stop_bits, config.parity) {
            (8, 1, 0) => uart_reg::LCR_8_BITS,
            (8, 1, 1) => uart_reg::LCR_8_BITS | uart_reg::LCR_PARITY | uart_reg::LCR_ODDPARITY,
            (8, 1, 2) => uart_reg::LCR_8_BITS | uart_reg::LCR_PARITY | uart_reg::LCR_EVENPARITY,
            (7, 1, 0) => uart_reg::LCR_7_BITS,
            _ => uart_reg::LCR_8_BITS,
        };
        outb(base + uart_reg::UART_LCR, lcr);
        
        // Enable FIFO, clear receiver/transmitter
        outb(base + uart_reg::UART_FCR, 0xC7);
        
        // Enable IRQs (OUT2 required for interrupts)
        outb(base + uart_reg::UART_MCR, uart_reg::MCR_OUT2 | uart_reg::MCR_DTR | uart_reg::MCR_RTS);
        
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// Check if data is ready
    pub fn data_ready(&self) -> bool {
        if !self.enabled.load(Ordering::SeqCst) {
            return false;
        }
        (inb(self.base + uart_reg::UART_LSR) & uart_reg::LSR_DATA_READY) != 0
    }
    
    /// Check if transmit buffer is empty
    pub fn transmit_empty(&self) -> bool {
        if !self.enabled.load(Ordering::SeqCst) {
            return false;
        }
        (inb(self.base + uart_reg::UART_LSR) & uart_reg::LSR_TRANS_EMPTY) != 0
    }
    
    /// Read a byte (non-blocking)
    pub fn read_byte(&self) -> Option<u8> {
        if self.data_ready() {
            Some(inb(self.base + uart_reg::UART_RBR))
        } else {
            None
        }
    }
    
    /// Write a byte
    pub fn write_byte(&self, byte: u8) -> bool {
        if !self.enabled.load(Ordering::SeqCst) {
            return false;
        }
        if self.transmit_empty() {
            outb(self.base + uart_reg::UART_THR, byte);
            true
        } else {
            false
        }
    }
    
    /// Read multiple bytes
    pub fn read(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for byte in buf.iter_mut() {
            if let Some(b) = self.read_byte() {
                *byte = b;
                count += 1;
            } else {
                break;
            }
        }
        count
    }
    
    /// Write multiple bytes
    pub fn write(&self, buf: &[u8]) -> usize {
        let mut count = 0;
        for &byte in buf {
            if self.write_byte(byte) {
                count += 1;
            } else {
                break;
            }
        }
        count
    }
    
    /// Get modem status
    pub fn modem_status(&self) -> u8 {
        if !self.enabled.load(Ordering::SeqCst) {
            return 0;
        }
        inb(self.base + uart_reg::UART_MSR)
    }
    
    /// Get line status
    pub fn line_status(&self) -> u8 {
        if !self.enabled.load(Ordering::SeqCst) {
            return 0;
        }
        inb(self.base + uart_reg::UART_LSR)
    }
}

/// UART Device structure
pub struct UartDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// UART ports
    ports: [Option<UartPort>; UART_MAX_PORTS],
    /// Port base addresses
    port_bases: [u16; UART_MAX_PORTS],
}

impl UartDev {
    /// Create a new UART device
    pub fn new() -> Self {
        Self {
            name: "uart",
            dev_char: 'U',
            ports: [
                Some(UartPort::new(UART_PORT_COM1)),
                Some(UartPort::new(UART_PORT_COM2)),
                Some(UartPort::new(UART_PORT_COM3)),
                Some(UartPort::new(UART_PORT_COM4)),
            ],
            port_bases: [
                UART_PORT_COM1,
                UART_PORT_COM2,
                UART_PORT_COM3,
                UART_PORT_COM4,
            ],
        }
    }
    
    /// Get port by number
    pub fn get_port(&self, port: usize) -> Option<&UartPort> {
        self.ports.get(port)?.as_ref()
    }
}

impl Dev for UartDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        // Attach to top-level /dev directory
        Ok(Chan::new(
            dev::devtype::AUDIO,  // Use audio type since there's no specific UART type
            Qid::new(uart_qid::QDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid;
        
        if uart_qid::file(qid.path) == uart_qid::QDIR {
            // At top level - look for eiaN or tty
            if let Some(port) = parse_eia_name(name) {
                if port < UART_MAX_PORTS && self.ports[port].is_some() {
                    // Walk to port directory
                    ch.qid = Qid::new(uart_qid::port_qid(port, uart_qid::QDIR), 0, qidtype::DIR);
                    return Ok(Some(ch.qid));
                }
            } else if name == "tty" || name.is_empty() {
                // Default to tty (COM1)
                ch.qid = Qid::new(uart_qid::port_qid(0, uart_qid::QDATA), 0, 0);
                return Ok(Some(ch.qid));
            }
        } else {
            // At port level
            let port = uart_qid::port(qid.path);
            match name {
                "ctl" => {
                    ch.qid = Qid::new(uart_qid::port_qid(port, uart_qid::QCTL), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "data" => {
                    ch.qid = Qid::new(uart_qid::port_qid(port, uart_qid::QDATA), 0, 0);
                    return Ok(Some(ch.qid));
                }
                "status" => {
                    ch.qid = Qid::new(uart_qid::port_qid(port, uart_qid::QSTATUS), 0, 0);
                    return Ok(Some(ch.qid));
                }
                _ => {}
            }
        }
        
        Err(DevError::Enoent)
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        let port = uart_qid::port(ch.qid.path);
        if let Some(uart) = self.get_port(port) {
            if !uart.enabled.load(Ordering::SeqCst) {
                uart.init();
            }
        }
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        let port = uart_qid::port(ch.qid.path);
        let file = uart_qid::file(ch.qid.path);
        
        let uart = self.get_port(port).ok_or(DevError::Enoent)?;
        
        match file {
            uart_qid::QDATA => {
                // Read serial data
                Ok(uart.read(buf))
            }
            uart_qid::QSTATUS => {
                // Read status (modem status byte)
                let msr = uart.modem_status();
                let lsr = uart.line_status();
                let status = format!(
                    "modem {:02x} line {:02x}\n",
                    msr, lsr
                );
                let len = status.len().min(buf.len());
                buf[..len].copy_from_slice(&status.as_bytes()[..len]);
                Ok(len)
            }
            uart_qid::QCTL => {
                // Read configuration
                let config = *uart.config.lock();
                let info = format!(
                    "baud {} dats {} stop {} parity {}\n",
                    config.baud, config.data_bits, config.stop_bits, config.parity
                );
                let len = info.len().min(buf.len());
                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                Ok(len)
            }
            _ => Err(DevError::Enoent),
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let port = uart_qid::port(ch.qid.path);
        let file = uart_qid::file(ch.qid.path);
        
        let uart = self.get_port(port).ok_or(DevError::Enoent)?;
        
        match file {
            uart_qid::QDATA => {
                // Write serial data
                Ok(uart.write(buf))
            }
            uart_qid::QCTL => {
                // Parse configuration commands
                let cmd = String::from_utf8_lossy(buf);
                
                // Parse "baud N" command
                if cmd.starts_with("baud ") {
                    if let Ok(baud) = cmd[5..].trim().parse::<u32>() {
                        let mut config = uart.config.lock();
                        config.baud = baud;
                        drop(config);
                        uart.init();  // Re-initialize with new baud rate
                        return Ok(buf.len());
                    }
                }
                
                Err(DevError::Einval)
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let port = uart_qid::port(ch.qid.path);
        let file = uart_qid::file(ch.qid.path);
        
        let (name, mode) = if file == uart_qid::QDIR {
            if port == 0 {
                ("eia".as_bytes().to_vec(), 0o555 | 0o40000)
            } else {
                (format!("eia{}", port).into_bytes(), 0o555 | 0o40000)
            }
        } else {
            match file {
                uart_qid::QCTL => (b"ctl".to_vec(), 0o666),
                uart_qid::QDATA => (b"data".to_vec(), 0o666),
                uart_qid::QSTATUS => (b"status".to_vec(), 0o444),
                _ => return Err(DevError::Enoent),
            }
        };
        
        Ok(DirEntry {
            dev: dev::devtype::AUDIO,
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR (character device)
            atime: 0,
            mtime: 0,
            length: 0,
            name,
        })
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Parse eia name like "eia0" to port number
fn parse_eia_name(name: &str) -> Option<usize> {
    if name.starts_with("eia") {
        name[3..].parse().ok()
    } else {
        None
    }
}

/// I/O port operations (architecture-specific)
fn inb(port: u16) -> u8 {
    plan9_arch::hal::inb(port)
}

fn outb(port: u16, value: u8) {
    plan9_arch::hal::outb(port, value);
}

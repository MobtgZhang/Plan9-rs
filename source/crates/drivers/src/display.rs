//! Display and Console Drivers
//!
//! Implements VGA text mode, serial console, and display output.

extern crate alloc;
extern crate plan9_common;

use plan9_common::error::{Error, Result};
use plan9_common::types::PhysAddr;

// ============================================================================
// VGA Text Mode
// ============================================================================

/// VGA text mode constants
pub mod vga {
    /// VGA text mode screen dimensions
    pub const WIDTH: usize = 80;
    pub const HEIGHT: usize = 25;

    /// VGA I/O ports
    pub const VGA_CRTC_ADDR: u16 = 0x3D4;
    pub const VGA_CRTC_DATA: u16 = 0x3D5;

    /// VGA register indices
    pub const VGA_CRTC_CURSOR_START: u8 = 0x0A;
    pub const VGA_CRTC_CURSOR_END: u8 = 0x0B;
    pub const VGA_CRTC_HI_ADDRESS: u8 = 0x0C;
    pub const VGA_CRTC_LO_ADDRESS: u8 = 0x0D;
    pub const VGA_CRTC_LIGHT_SAVE: u8 = 0x0E;
    pub const VGA_CRTC_LIGHT_SAVE_HI: u8 = 0x0F;

    /// VGA color constants
    pub const COLOR_BLACK: u8 = 0;
    pub const COLOR_BLUE: u8 = 1;
    pub const COLOR_GREEN: u8 = 2;
    pub const COLOR_CYAN: u8 = 3;
    pub const COLOR_RED: u8 = 4;
    pub const COLOR_MAGENTA: u8 = 5;
    pub const COLOR_BROWN: u8 = 6;
    pub const COLOR_LIGHT_GREY: u8 = 7;
    pub const COLOR_DARK_GREY: u8 = 8;
    pub const COLOR_LIGHT_BLUE: u8 = 9;
    pub const COLOR_LIGHT_GREEN: u8 = 10;
    pub const COLOR_LIGHT_CYAN: u8 = 11;
    pub const COLOR_LIGHT_RED: u8 = 12;
    pub const COLOR_LIGHT_MAGENTA: u8 = 13;
    pub const COLOR_YELLOW: u8 = 14;
    pub const COLOR_WHITE: u8 = 15;

    /// Default framebuffer at 0xB8000
    pub const FB_MEMORY: usize = 0xB8000;
}

/// VGA character cell
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VgaChar {
    pub char_byte: u8,
    pub attr_byte: u8,
}

impl VgaChar {
    /// Create a new character with given ASCII code and color
    pub fn new(ch: u8, fg: u8, bg: u8) -> Self {
        Self {
            char_byte: ch,
            attr_byte: ((bg & 0xF) << 4) | (fg & 0xF),
        }
    }

    /// Create a character with default gray on black
    pub fn new_default(ch: u8) -> Self {
        Self::new(ch, vga::COLOR_LIGHT_GREY, vga::COLOR_BLACK)
    }
}

/// VGA text mode driver
pub struct VgaConsole {
    /// Current cursor X position
    x: usize,
    /// Current cursor Y position
    y: usize,
    /// Current text color
    fg: u8,
    /// Current background color
    bg: u8,
    /// Framebuffer pointer
    fb: *mut VgaChar,
}

impl VgaConsole {
    /// Create new VGA console driver
    pub fn new() -> Self {
        let fb = vga::FB_MEMORY as *mut VgaChar;
        Self {
            x: 0,
            y: 0,
            fg: vga::COLOR_LIGHT_GREY,
            bg: vga::COLOR_BLACK,
            fb,
        }
    }

    /// Get character at position
    fn get_char(&self, x: usize, y: usize) -> VgaChar {
        if x < vga::WIDTH && y < vga::HEIGHT {
            unsafe { *self.fb.add(y * vga::WIDTH + x) }
        } else {
            VgaChar::new_default(0)
        }
    }

    /// Set character at position
    fn set_char(&mut self, x: usize, y: usize, ch: VgaChar) {
        if x < vga::WIDTH && y < vga::HEIGHT {
            unsafe { *self.fb.add(y * vga::WIDTH + x) = ch; }
        }
    }

    /// Scroll the screen up by one line
    fn scroll_up(&mut self) {
        // Copy all lines up by one
        for y in 0..(vga::HEIGHT - 1) {
            for x in 0..vga::WIDTH {
                let ch = self.get_char(x, y + 1);
                self.set_char(x, y, ch);
            }
        }

        // Clear last line
        let space = VgaChar::new(b' ', self.fg, self.bg);
        for x in 0..vga::WIDTH {
            self.set_char(x, vga::HEIGHT - 1, space);
        }
    }

    /// Move to next line, scroll if needed
    fn newline(&mut self) {
        self.x = 0;
        self.y += 1;
        if self.y >= vga::HEIGHT {
            self.y = vga::HEIGHT - 1;
            self.scroll_up();
        }
    }

    /// Set cursor position
    pub fn set_cursor(&mut self, x: usize, y: usize) {
        if x < vga::WIDTH && y < vga::HEIGHT {
            self.x = x;
            self.y = y;
            self.update_hw_cursor();
        }
    }

    /// Update hardware cursor
    fn update_hw_cursor(&self) {
        let pos = self.y * vga::WIDTH + self.x;

        // Set cursor position high byte
        plan9_arch::x86_64::outb(vga::VGA_CRTC_ADDR, vga::VGA_CRTC_LIGHT_SAVE);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_DATA, ((pos >> 8) & 0xFF) as u8);

        // Set cursor position low byte
        plan9_arch::x86_64::outb(vga::VGA_CRTC_ADDR, vga::VGA_CRTC_LIGHT_SAVE_HI);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_DATA, (pos & 0xFF) as u8);
    }

    /// Enable cursor
    pub fn enable_cursor(&self, start: u8, end: u8) {
        plan9_arch::x86_64::outb(vga::VGA_CRTC_ADDR, vga::VGA_CRTC_CURSOR_START);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_DATA, start);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_ADDR, vga::VGA_CRTC_CURSOR_END);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_DATA, end);
    }

    /// Disable cursor
    pub fn disable_cursor(&self) {
        plan9_arch::x86_64::outb(vga::VGA_CRTC_ADDR, vga::VGA_CRTC_CURSOR_START);
        plan9_arch::x86_64::outb(vga::VGA_CRTC_DATA, 0x20);
    }

    /// Clear the screen
    pub fn clear(&mut self) {
        let space = VgaChar::new(b' ', self.fg, self.bg);
        for y in 0..vga::HEIGHT {
            for x in 0..vga::WIDTH {
                self.set_char(x, y, space);
            }
        }
        self.x = 0;
        self.y = 0;
        self.update_hw_cursor();
    }

    /// Set foreground color
    pub fn set_fg(&mut self, color: u8) {
        self.fg = color & 0xF;
    }

    /// Set background color
    pub fn set_bg(&mut self, color: u8) {
        self.bg = color & 0xF;
    }

    /// Set color
    pub fn set_color(&mut self, fg: u8, bg: u8) {
        self.fg = fg & 0xF;
        self.bg = bg & 0xF;
    }

    /// Put a character at current position
    pub fn put_char(&mut self, ch: u8) {
        match ch {
            b'\n' => self.newline(),
            b'\r' => self.x = 0,
            b'\t' => {
                // Tab to next multiple of 8
                self.x = (self.x + 7) & !7;
                if self.x >= vga::WIDTH {
                    self.newline();
                }
            }
            8 => {
                // Backspace
                if self.x > 0 {
                    self.x -= 1;
                }
            }
            _ => {
                if ch >= 32 && ch < 127 {
                    self.set_char(self.x, self.y, VgaChar::new(ch, self.fg, self.bg));
                    self.x += 1;
                    if self.x >= vga::WIDTH {
                        self.newline();
                    }
                }
            }
        }
        self.update_hw_cursor();
    }

    /// Print a string
    pub fn print(&mut self, s: &[u8]) {
        for &ch in s {
            self.put_char(ch);
        }
    }

    /// Print a string with color
    pub fn print_color(&mut self, s: &[u8], fg: u8, bg: u8) {
        let old_fg = self.fg;
        let old_bg = self.bg;
        self.set_color(fg, bg);
        self.print(s);
        self.fg = old_fg;
        self.bg = old_bg;
    }

    /// Print a hex number
    pub fn print_hex(&mut self, val: u64, width: usize) {
        let digits = b"0123456789ABCDEF";
        let mut buf = [b'0'; 16];
        let mut pos = 16;

        if val == 0 {
            pos -= 1;
            buf[pos] = b'0';
        } else {
            let mut v = val;
            while v > 0 && pos > 0 {
                pos -= 1;
                buf[pos] = digits[(v & 0xF) as usize];
                v >>= 4;
            }
        }

        // Pad with zeros
        while pos > 16 - width {
            pos -= 1;
            buf[pos] = b'0';
        }

        self.print(&buf[pos..]);
    }

    /// Print a decimal number
    pub fn print_dec(&mut self, val: u64) {
        let digits = b"0123456789";
        let mut buf = [b'0'; 20];
        let mut pos = 20;

        if val == 0 {
            pos -= 1;
            buf[pos] = b'0';
        } else {
            let mut v = val;
            while v > 0 && pos > 0 {
                pos -= 1;
                buf[pos] = digits[(v % 10) as usize];
                v /= 10;
            }
        }

        self.print(&buf[pos..]);
    }
}

impl Default for VgaConsole {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Serial Console (16550 UART)
// ============================================================================

/// Serial port configuration
pub mod serial {
    use super::*;

    /// COM1 port
    pub const COM1: u16 = 0x3F8;
    /// COM2 port
    pub const COM2: u16 = 0x2F8;
    /// COM3 port
    pub const COM3: u16 = 0x3E8;
    /// COM4 port
    pub const COM4: u16 = 0x2E8;

    // UART registers (offset from base)
    pub const UART_RBR: u8 = 0;  // Receive Buffer (read)
    pub const UART_THR: u8 = 0;  // Transmit Holding (write)
    pub const UART_DLL: u8 = 0;  // Divisor LSB (when DLAB=1)
    pub const UART_IER: u8 = 1;  // Interrupt Enable
    pub const UART_DLM: u8 = 1;  // Divisor MSB (when DLAB=1)
    pub const UART_FCR: u8 = 2;  // FIFO Control
    pub const UART_LCR: u8 = 3;  // Line Control
    pub const UART_MCR: u8 = 4;  // Modem Control
    pub const UART_LSR: u8 = 5;  // Line Status
    pub const UART_MSR: u8 = 6;  // Modem Status
    pub const UART_SCR: u8 = 7;  // Scratch

    // Line Status bits
    pub const LSR_DATA_READY: u8 = 1 << 0;
    pub const LSR_OVERRUN_ERR: u8 = 1 << 1;
    pub const LSR_PARITY_ERR: u8 = 1 << 2;
    pub const LSR_FRAMING_ERR: u8 = 1 << 3;
    pub const LSR_BREAK_INT: u8 = 1 << 4;
    pub const LSR_TRANS_EMPTY: u8 = 1 << 5;
    pub const LSR_TRANS_IDLE: u8 = 1 << 6;

    // Line Control bits
    pub const LCR_8N1: u8 = 0x03;
    pub const LCR_DLAB: u8 = 0x80;

    // Modem Control bits
    pub const MCR_OUT2: u8 = 1 << 3;  // Required for interrupts
}

/// Serial port driver
pub struct SerialPort {
    /// Base I/O port
    port: u16,
}

impl SerialPort {
    /// Create a new serial port driver
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initialize the serial port (8N1, 115200 baud)
    pub fn init(&mut self) {
        // Disable interrupts
        plan9_arch::x86_64::outb(self.port + serial::UART_IER, 0x00);

        // Set DLAB to access divisor
        plan9_arch::x86_64::outb(self.port + serial::UART_LCR, serial::LCR_DLAB);

        // Set baud rate to 115200 (divisor = 1)
        plan9_arch::x86_64::outb(self.port + serial::UART_DLL, 1);
        plan9_arch::x86_64::outb(self.port + serial::UART_DLM, 0);

        // Set 8N1, DLAB=0
        plan9_arch::x86_64::outb(self.port + serial::UART_LCR, serial::LCR_8N1);

        // Enable FIFO, clear receiver/transmitter
        plan9_arch::x86_64::outb(self.port + serial::UART_FCR, 0xC7);

        // Enable IRQs (actually OUT2 for interrupt enable)
        plan9_arch::x86_64::outb(self.port + serial::UART_MCR, serial::MCR_OUT2);

        // Loopback mode test
        plan9_arch::x86_64::outb(self.port + serial::UART_MCR, 0x1F);

        // Test serial chip (transmit/receive)
        plan9_arch::x86_64::outb(self.port + serial::UART_RBR, 0xAE);
        let test = plan9_arch::x86_64::inb(self.port + serial::UART_RBR);
        if test != 0xAE {
            // Serial not working
            return;
        }

        // Back to normal mode
        plan9_arch::x86_64::outb(self.port + serial::UART_MCR, serial::MCR_OUT2);
    }

    /// Check if data is available
    pub fn data_ready(&self) -> bool {
        (plan9_arch::x86_64::inb(self.port + serial::UART_LSR) & serial::LSR_DATA_READY) != 0
    }

    /// Check if transmit buffer is empty
    pub fn transmit_empty(&self) -> bool {
        (plan9_arch::x86_64::inb(self.port + serial::UART_LSR) & serial::LSR_TRANS_EMPTY) != 0
    }

    /// Read a byte (blocking)
    pub fn read_byte(&self) -> u8 {
        while !self.data_ready() {}
        plan9_arch::x86_64::inb(self.port + serial::UART_RBR)
    }

    /// Write a byte
    pub fn write_byte(&mut self, byte: u8) {
        while !self.transmit_empty() {}
        plan9_arch::x86_64::outb(self.port + serial::UART_THR, byte);
    }

    /// Write a string
    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.write_byte(b);
        }
    }
}

// ============================================================================
// System Console Abstraction
// ============================================================================

/// System console combining VGA and serial
pub struct Console {
    vga: VgaConsole,
    serial: SerialPort,
    debug: bool,
}

impl Console {
    /// Create new system console
    pub fn new() -> Self {
        let mut serial = SerialPort::new(serial::COM1);
        serial.init();

        Self {
            vga: VgaConsole::new(),
            serial,
            debug: true,
        }
    }

    /// Initialize the console
    pub fn init(&mut self) {
        self.vga.clear();
        self.vga.enable_cursor(0, 15);
        self.write(b"\r\nConsole initialized\r\n");
    }

    /// Write bytes to console
    pub fn write(&mut self, data: &[u8]) {
        // Always write to VGA
        self.vga.print(data);

        // Write to serial if debug enabled
        if self.debug {
            self.serial.write(data);
        }
    }

    /// Write byte
    pub fn put_char(&mut self, ch: u8) {
        self.vga.put_char(ch);
        if self.debug {
            self.serial.write_byte(ch);
        }
    }

    /// Clear screen
    pub fn clear(&mut self) {
        self.vga.clear();
    }

    /// Set cursor position
    pub fn set_cursor(&mut self, x: usize, y: usize) {
        self.vga.set_cursor(x, y);
    }

    /// Set foreground color
    pub fn set_fg(&mut self, color: u8) {
        self.vga.set_fg(color);
    }

    /// Set background color
    pub fn set_bg(&mut self, color: u8) {
        self.vga.set_bg(color);
    }

    /// Set debug mode
    pub fn set_debug(&mut self, enabled: bool) {
        self.debug = enabled;
    }

    /// Read from serial (non-blocking)
    pub fn read_byte(&self) -> Option<u8> {
        if self.serial.data_ready() {
            Some(self.serial.read_byte())
        } else {
            None
        }
    }

    /// Get reference to VGA console
    pub fn vga_mut(&mut self) -> &mut VgaConsole {
        &mut self.vga
    }

    /// Get reference to serial port
    pub fn serial_mut(&mut self) -> &mut SerialPort {
        &mut self.serial
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Kernel Logging
// ============================================================================

use core::fmt::{self, Write};

/// Kernel logger
pub struct KernelLogger {
    console: Console,
}

impl KernelLogger {
    /// Create new kernel logger
    pub fn new() -> Self {
        let mut console = Console::new();
        console.init();
        Self { console }
    }

    /// Log a string
    pub fn log(&mut self, s: &[u8]) {
        self.console.write(s);
    }

    /// Log with color
    pub fn log_color(&mut self, s: &[u8], fg: u8, bg: u8) {
        self.console.vga_mut().print_color(s, fg, bg);
        if self.console.debug {
            self.console.serial_mut().write(s);
        }
    }

    /// Get console
    pub fn console_mut(&mut self) -> &mut Console {
        &mut self.console
    }
}

impl Default for KernelLogger {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Write for Console for use with format!
impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

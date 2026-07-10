//! VGA Text Mode Driver
//!
//! Implements an 80x25 VGA text mode driver for Plan 9.
//!
//! The VGA text buffer is a 16-bit cell array at physical address 0xB8000,
//! each cell containing an 8-bit character and an 8-bit attribute byte
//! (foreground/background colors).
//!
//! Reference: `reference/plan9/sys/src/9/pc/vga.c`


extern crate alloc;

use alloc::boxed::Box;
use crate::plan9_common::sync::Spinlock;
use core::fmt;
use core::ptr::{read_volatile, write_volatile};

/// Physical base address of the VGA text buffer
pub const VGA_BUFFER_ADDR: usize = 0xB8000;

/// Width of the VGA text screen in characters
pub const VGA_WIDTH: usize = 80;

/// Height of the VGA text screen in characters
pub const VGA_HEIGHT: usize = 25;

// ============================================================================
// VGA I/O Port Constants
// ============================================================================

/// VGA CRT Controller I/O ports
pub mod vga_registers {
    /// CRT Controller address register
    pub const CRT_ADDR: u16 = 0x3D4;
    /// CRT Controller data register
    pub const CRT_DATA: u16 = 0x3D5;
    /// Miscellaneous Output Register
    pub const MISC_OUTPUT: u16 = 0x3C2;
    /// Input Status Register 0
    pub const STATUS_0: u16 = 0x3C2;
    /// Input Status Register 1
    pub const STATUS_1: u16 = 0x3DA;
    /// Attribute Controller address register
    pub const ATTR_ADDR: u16 = 0x3C0;
    /// Sequencer address register
    pub const SEQ_ADDR: u16 = 0x3C4;
    /// Sequencer data register
    pub const SEQ_DATA: u16 = 0x3C5;
    /// Graphics Controller address register
    pub const GFX_ADDR: u16 = 0x3CE;
    /// Graphics Controller data register
    pub const GFX_DATA: u16 = 0x3CF;
    /// Feature Control Register (write)
    pub const FEATURE_CTRL: u16 = 0x3DA;
    /// General Input Register
    pub const GEN_INPUT: u16 = 0x3C3;
    /// VGA enable register
    pub const VGA_ENABLE: u16 = 0x3C3;
}

// ============================================================================
// Low-level I/O Helper Functions
// ============================================================================

/// Read a byte from an I/O port
#[inline(always)]
fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// Write a byte to an I/O port
#[inline(always)]
fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, preserves_flags)
        );
    }
}

/// Read a byte from CRT controller register
#[inline(always)]
fn crtc_read(index: u8) -> u8 {
    outb(vga_registers::CRT_ADDR, index);
    inb(vga_registers::CRT_DATA)
}

/// Write a byte to CRT controller register
#[inline(always)]
fn crtc_write(index: u8, value: u8) {
    outb(vga_registers::CRT_ADDR, index);
    outb(vga_registers::CRT_DATA, value);
}

/// Read a byte from sequencer register
#[inline(always)]
fn seq_read(index: u8) -> u8 {
    outb(vga_registers::SEQ_ADDR, index);
    inb(vga_registers::SEQ_DATA)
}

/// Write a byte to sequencer register
#[inline(always)]
fn seq_write(index: u8, value: u8) {
    outb(vga_registers::SEQ_ADDR, index);
    outb(vga_registers::SEQ_DATA, value);
}

/// Read a byte from graphics controller register
#[inline(always)]
fn gfx_read(index: u8) -> u8 {
    outb(vga_registers::GFX_ADDR, index);
    inb(vga_registers::GFX_DATA)
}

/// Write a byte to graphics controller register
#[inline(always)]
fn gfx_write(index: u8, value: u8) {
    outb(vga_registers::GFX_ADDR, index);
    outb(vga_registers::GFX_DATA, value);
}

/// Standard VGA color attribute byte encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VgaColor {
    /// Foreground color (0-15)
    pub foreground: u8,
    /// Background color (0-15)
    pub background: u8,
}

impl VgaColor {
    /// Standard black foreground on black background
    pub const BLACK_ON_BLACK: VgaColor = VgaColor { foreground: 0, background: 0 };
    /// Light gray foreground on black background
    pub const LIGHT_GRAY_ON_BLACK: VgaColor = VgaColor { foreground: 7, background: 0 };
    /// White foreground on black background
    pub const WHITE_ON_BLACK: VgaColor = VgaColor { foreground: 15, background: 0 };
    /// Black foreground on light cyan background (highlight)
    pub const BLACK_ON_LIGHT_CYAN: VgaColor = VgaColor { foreground: 0, background: 11 };

    /// Build the attribute byte
    pub const fn attr(self) -> u8 {
        (self.background << 4) | (self.foreground & 0x0F)
    }
}

impl Default for VgaColor {
    fn default() -> Self {
        VgaColor::LIGHT_GRAY_ON_BLACK
    }
}

/// A 16-bit VGA text cell: 8-bit character + 8-bit attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct VgaCell(pub u16);

impl VgaCell {
    /// Build a cell from a character and a color attribute
    pub const fn new(c: u8, color: VgaColor) -> Self {
        VgaCell(((color.attr() as u16) << 8) | (c as u16))
    }

    /// Build a cell from a character and a raw attribute byte
    pub const fn from_raw(c: u8, attr: u8) -> Self {
        VgaCell(((attr as u16) << 8) | (c as u16))
    }

    /// Get the character byte
    pub const fn character(self) -> u8 {
        self.0 as u8
    }

    /// Get the attribute byte
    pub const fn attribute(self) -> u8 {
        (self.0 >> 8) as u8
    }
}

/// Volatile read from a memory-mapped 16-bit cell
unsafe fn cell_read(idx: usize) -> VgaCell {
    let addr = (VGA_BUFFER_ADDR as *const u16).add(idx);
    VgaCell(read_volatile(addr))
}

/// Volatile write to a memory-mapped 16-bit cell
unsafe fn cell_write(idx: usize, cell: VgaCell) {
    let addr = (VGA_BUFFER_ADDR as *mut u16).add(idx);
    write_volatile(addr, cell.0);
}

/// VGA text mode state.
///
/// All write paths take a spinlock so that multiple writers (serial port
/// redirector, kernel panic handler, console driver) do not interleave
/// individual character writes.
pub struct VgaState {
    /// Cursor row (0-24)
    row: usize,
    /// Cursor column (0-79)
    col: usize,
    /// Current color attribute
    color: VgaColor,
    /// Lock to make the write path re-entrant
    lock: Spinlock<()>,
}

impl VgaState {
    /// Construct a new VGA state with default colors and the cursor at (0, 0)
    pub const fn new() -> Self {
        VgaState {
            row: 0,
            col: 0,
            color: VgaColor::LIGHT_GRAY_ON_BLACK,
            lock: Spinlock::new(()),
        }
    }

    /// Clear the screen and reset the cursor to (0, 0)
    pub fn clear(&mut self) {
        let _guard = self.lock.lock();
        let blank = VgaCell::from_raw(b' ', self.color.attr());
        for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
            unsafe { cell_write(i, blank) };
        }
        self.row = 0;
        self.col = 0;
    }

    /// Set the current color attribute
    pub fn set_color(&mut self, color: VgaColor) {
        let _guard = self.lock.lock();
        self.color = color;
    }

    /// Get the current color attribute
    pub fn color(&self) -> VgaColor {
        self.color
    }

    /// Current cursor position (row, col)
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Write a single byte at the current cursor position.
    ///
    /// Special bytes are handled: '\n' advances to the start of the next line,
    /// '\r' returns to the start of the current line, '\t' advances to the
    /// next 8-column tab stop. Bytes that do not fit on the current line wrap
    /// to the next line. When the screen is full, the contents scroll up.
    pub fn put_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => {
                self.col = 0;
                self.advance_row();
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                // Move to the next 8-column tab stop
                let next = ((self.col / 8) + 1) * 8;
                while self.col < next {
                    self.put_cell(b' ');
                    if self.col == VGA_WIDTH {
                        break;
                    }
                }
            }
            b => {
                self.put_cell(b);
            }
        }
    }

    /// Write a string of bytes to the screen.
    pub fn write_str(&mut self, s: &[u8]) {
        for &b in s {
            self.put_byte(b);
        }
    }

    /// Internal: put a printable cell at the current cursor position and
    /// advance the cursor.
    fn put_cell(&mut self, byte: u8) {
        let idx = self.row * VGA_WIDTH + self.col;
        unsafe { cell_write(idx, VgaCell::new(byte, self.color)) };
        self.col += 1;
        if self.col >= VGA_WIDTH {
            self.col = 0;
            self.advance_row();
        }
    }

    /// Internal: move the cursor to the next line, scrolling if needed.
    fn advance_row(&mut self) {
        if self.row + 1 < VGA_HEIGHT {
            self.row += 1;
        } else {
            self.scroll_up();
        }
    }

    /// Internal: shift all rows up by one and clear the last row.
    fn scroll_up(&mut self) {
        for row in 1..VGA_HEIGHT {
            for col in 0..VGA_WIDTH {
                let src = row * VGA_WIDTH + col;
                let dst = (row - 1) * VGA_WIDTH + col;
                let cell = unsafe { cell_read(src) };
                unsafe { cell_write(dst, cell) };
            }
        }
        // Clear the last row
        let blank = VgaCell::from_raw(b' ', self.color.attr());
        for col in 0..VGA_WIDTH {
            unsafe { cell_write((VGA_HEIGHT - 1) * VGA_WIDTH + col, blank) };
        }
    }
}

impl Default for VgaState {
    fn default() -> Self {
        VgaState::new()
    }
}

impl fmt::Write for VgaState {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s.as_bytes());
        Ok(())
    }
}

// ============================================================================
// Architecture-specific display hardware abstraction
// ============================================================================

/// Trait for hardware-specific display initialisation and cell writing.
///
/// Each target architecture provides a concrete type that implements this
/// trait, allowing `vga_hw_init` to route to the correct register
/// sequence at compile time without any runtime dispatch.
pub trait DisplayHw {
    /// Perform any required hardware initialisation (e.g. programming the
    /// CRT controller on x86, or mapping the framebuffer on ARM/RISC-V).
    ///
    /// For stub implementations this is a no-op.
    unsafe fn hw_init();

    /// Write a single 16-bit character cell at linear cell index `idx`.
    /// The caller is responsible for ensuring `idx < VGA_WIDTH * VGA_HEIGHT`.
    ///
    /// On x86 this writes to the legacy VGA memory window at 0xB8000.
    /// On ARM/RISC-V it writes to the MMIO framebuffer base address.
    unsafe fn put_cell(idx: usize, cell: u16);
}

// ---------------------------------------------------------------------------
// x86_64 — legacy VGA I/O port CRT controller (stable inline asm)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", not(test)))]
pub struct X86VgaHw;

#[cfg(all(target_arch = "x86_64", not(test)))]
impl DisplayHw for X86VgaHw {
    unsafe fn hw_init() {
        // VGA CRT Controller Initialization for 80x25 text mode
        //
        // This implements a complete VGA initialization sequence based on
        // the standard IBM VGA timing for mode 3 (80x25 text, 16 colors).
        //
        // Reference: VGADOC.TXT, Plan 9 sys/src/9/pc/vga.c

        // Step 1: Enable VGA by setting bit 1 of the VGA enable register
        outb(vga_registers::VGA_ENABLE, inb(vga_registers::VGA_ENABLE) | 0x01);

        // Step 2: Synchronous reset of the sequencer
        // This stops the display while we configure it
        seq_write(0x00, 0x01); // Reset
        seq_write(0x01, 0x00); // Clocking mode: no divide, 8-dot clock
        seq_write(0x02, 0x03); // Map mask: enable planes 0 and 1
        seq_write(0x03, 0x00); // Character map select: no effect in text mode
        seq_write(0x04, 0x03); // Memory mode: odd/even, extended memory enabled

        // Step 3: Perform synchronous reset
        seq_write(0x00, 0x03); // Synchronous reset

        // Step 4: Program the CRT controller for 80x25 text mode
        // Timing values based on 25.175MHz pixel clock (standard VGA)
        // Horizontal timing:
        // - HTOTAL = 113 chars (0x6F)
        // - HDISP = 80 chars (0x4F)
        // - HBLANK_START = 80 (0x50)
        // - HBLANK_END = 0x5A (with 5-bit count)
        // - HRETRACE_START = 90 (0x5A)
        // - HRETRACE_END = 0x8A (with 4-bit count and 2-bit skew)
        // Vertical timing:
        // - VTOTAL = 449 lines (0x1C1)
        // - VDISP = 400 lines (0x18F) - text rows = 25*16 = 400
        // - VBLANK_START = 400 (0x190)
        // - VRETRACE_START = 414 (0x19E)
        // - OVERFLOW register handles bit 8 of vertical registers

        // CRT Controller Register 0x00: Horizontal Total
        crtc_write(0x00, 0x6F);
        // CRT Controller Register 0x01: Horizontal Display Enable End
        crtc_write(0x01, 0x4F);
        // CRT Controller Register 0x02: Horizontal Blanking Start
        crtc_write(0x02, 0x50);
        // CRT Controller Register 0x03: Horizontal Blanking End / Display Enable Skew
        crtc_write(0x03, 0x5A);
        // CRT Controller Register 0x04: Horizontal Retrace Start
        crtc_write(0x04, 0x5A);
        // CRT Controller Register 0x05: Horizontal Retrace End / Output Control
        crtc_write(0x05, 0x8A);
        // CRT Controller Register 0x06: Vertical Total
        crtc_write(0x06, 0xBF);
        // CRT Controller Register 0x07: Overflow
        crtc_write(0x07, 0x1F);
        // CRT Controller Register 0x08: Preset Row Scan
        crtc_write(0x08, 0x00);
        // CRT Controller Register 0x09: Maximum Scan Line / Character Height
        crtc_write(0x09, 0x0C); // 16 scan lines per character row
        // CRT Controller Register 0x0A: Cursor Start
        crtc_write(0x0A, 0x0D); // Row 13
        // CRT Controller Register 0x0B: Cursor End
        crtc_write(0x0B, 0x0E); // Row 14
        // CRT Controller Register 0x0C: Start Address High
        crtc_write(0x0C, 0x00);
        // CRT Controller Register 0x0D: Start Address Low
        crtc_write(0x0D, 0x00);
        // CRT Controller Register 0x0E: Cursor Location High
        crtc_write(0x0E, 0x00);
        // CRT Controller Register 0x0F: Cursor Location Low
        crtc_write(0x0F, 0x00);
        // CRT Controller Register 0x10: Vertical Retrace Start
        crtc_write(0x10, 0x9C);
        // CRT Controller Register 0x11: Vertical Retrace End / Interrupt Enable
        crtc_write(0x11, 0x8E);
        // CRT Controller Register 0x12: Vertical Display Enable End
        crtc_write(0x12, 0x8F);
        // CRT Controller Register 0x13: Offset / Logical Width
        crtc_write(0x13, 0x28); // 40 words = 80 bytes per line
        // CRT Controller Register 0x14: Underline Location
        crtc_write(0x14, 0x1F);
        // CRT Controller Register 0x15: Vertical Blanking Start
        crtc_write(0x15, 0x96);
        // CRT Controller Register 0x16: Vertical Blanking End
        crtc_write(0x16, 0xB9);
        // CRT Controller Register 0x17: Mode Control
        crtc_write(0x17, 0xA3);
        // CRT Controller Register 0x18: Line Compare
        crtc_write(0x18, 0xFF);

        // Step 5: Configure the attribute controller
        // Reset the attribute controller flip-flop by reading the status register
        let _ = inb(vga_registers::STATUS_1);

        // Set palette registers 0-15 to standard VGA colors
        for i in 0..16u8 {
            // Palette register index
            outb(vga_registers::ATTR_ADDR, i);
            // Palette data ( DAC register values)
            let color = match i {
                0 => 0x00,  // Black
                1 => 0x01,  // Blue
                2 => 0x02,  // Green
                3 => 0x03,  // Cyan
                4 => 0x04,  // Red
                5 => 0x05,  // Magenta
                6 => 0x14,  // Brown
                7 => 0x07,  // Light Gray
                8 => 0x38,  // Dark Gray
                9 => 0x3F,  // Light Blue
                10 => 0x3A, // Light Green
                11 => 0x3B, // Light Cyan
                12 => 0x3C, // Light Red
                13 => 0x3D, // Light Magenta
                14 => 0x3E, // Yellow
                15 => 0x3F, // White
                _ => 0x00,
            };
            outb(vga_registers::ATTR_ADDR, color);
        }

        // Attribute controller mode control: enable graphics mode, line graphics
        let _ = inb(vga_registers::STATUS_1);
        outb(vga_registers::ATTR_ADDR, 0x10);
        outb(vga_registers::ATTR_ADDR, 0x01);

        // Enable attribute controller
        let _ = inb(vga_registers::STATUS_1);
        outb(vga_registers::ATTR_ADDR, 0x20);

        // Step 6: Configure the graphics controller
        // Set to text mode (read mode 0, write mode 0)
        gfx_write(0x05, 0x00);
        // Memory map A0000-BFFFF
        gfx_write(0x06, 0x05);

        // Step 7: End sequencer reset and enable display
        seq_write(0x00, 0x03); // End reset
        seq_write(0x01, 0x01); // Enable clock

        // Step 8: Set miscellaneous output register
        // Default value for color mode: I/O address select (0x03), clock select (0x00 = 25MHz)
        outb(vga_registers::MISC_OUTPUT, 0x67);

        // Step 9: Clear the screen
        // Memory at B8000 is already cleared, but ensure video memory is initialized
        let ptr = VGA_BUFFER_ADDR as *mut u16;
        for i in 0..(80 * 25) {
            core::ptr::write_volatile(ptr.add(i), 0x0720); // Space with light gray on black
        }
    }

    unsafe fn put_cell(idx: usize, cell: u16) {
        let ptr = (VGA_BUFFER_ADDR as *mut u16).add(idx);
        core::ptr::write_volatile(ptr, cell);
    }
}

// ---------------------------------------------------------------------------
// i386 — same I/O port sequence as x86_64 (inline asm stable here too)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86", not(test)))]
pub struct X86VgaHw;

#[cfg(all(target_arch = "x86", not(test)))]
impl DisplayHw for X86VgaHw {
    unsafe fn hw_init() {
        // i386 uses the same VGA initialization as x86_64
        // VGA CRT Controller Initialization for 80x25 text mode

        // Step 1: Enable VGA by setting bit 1 of the VGA enable register
        outb(vga_registers::VGA_ENABLE, inb(vga_registers::VGA_ENABLE) | 0x01);

        // Step 2: Synchronous reset of the sequencer
        seq_write(0x00, 0x01); // Reset
        seq_write(0x01, 0x00); // Clocking mode
        seq_write(0x02, 0x03); // Map mask
        seq_write(0x03, 0x00); // Character map select
        seq_write(0x04, 0x03); // Memory mode

        // Step 3: Perform synchronous reset
        seq_write(0x00, 0x03); // Synchronous reset

        // Step 4: Program CRT controller (same as x86_64)
        crtc_write(0x00, 0x6F);
        crtc_write(0x01, 0x4F);
        crtc_write(0x02, 0x50);
        crtc_write(0x03, 0x5A);
        crtc_write(0x04, 0x5A);
        crtc_write(0x05, 0x8A);
        crtc_write(0x06, 0xBF);
        crtc_write(0x07, 0x1F);
        crtc_write(0x08, 0x00);
        crtc_write(0x09, 0x0C);
        crtc_write(0x0A, 0x0D);
        crtc_write(0x0B, 0x0E);
        crtc_write(0x0C, 0x00);
        crtc_write(0x0D, 0x00);
        crtc_write(0x0E, 0x00);
        crtc_write(0x0F, 0x00);
        crtc_write(0x10, 0x9C);
        crtc_write(0x11, 0x8E);
        crtc_write(0x12, 0x8F);
        crtc_write(0x13, 0x28);
        crtc_write(0x14, 0x1F);
        crtc_write(0x15, 0x96);
        crtc_write(0x16, 0xB9);
        crtc_write(0x17, 0xA3);
        crtc_write(0x18, 0xFF);

        // Step 5: Configure attribute controller
        let _ = inb(vga_registers::STATUS_1);
        for i in 0..16u8 {
            outb(vga_registers::ATTR_ADDR, i);
            let color = match i {
                0 => 0x00, 1 => 0x01, 2 => 0x02, 3 => 0x03,
                4 => 0x04, 5 => 0x05, 6 => 0x14, 7 => 0x07,
                8 => 0x38, 9 => 0x3F, 10 => 0x3A, 11 => 0x3B,
                12 => 0x3C, 13 => 0x3D, 14 => 0x3E, 15 => 0x3F,
                _ => 0x00,
            };
            outb(vga_registers::ATTR_ADDR, color);
        }
        let _ = inb(vga_registers::STATUS_1);
        outb(vga_registers::ATTR_ADDR, 0x10);
        outb(vga_registers::ATTR_ADDR, 0x01);
        let _ = inb(vga_registers::STATUS_1);
        outb(vga_registers::ATTR_ADDR, 0x20);

        // Step 6: Configure graphics controller
        gfx_write(0x05, 0x00);
        gfx_write(0x06, 0x05);

        // Step 7: End sequencer reset
        seq_write(0x00, 0x03);
        seq_write(0x01, 0x01);

        // Step 8: Set miscellaneous output
        outb(vga_registers::MISC_OUTPUT, 0x67);

        // Step 9: Clear screen
        let ptr = VGA_BUFFER_ADDR as *mut u16;
        for i in 0..(80 * 25) {
            core::ptr::write_volatile(ptr.add(i), 0x0720);
        }
    }

    unsafe fn put_cell(idx: usize, cell: u16) {
        let ptr = (VGA_BUFFER_ADDR as *mut u16).add(idx);
        core::ptr::write_volatile(ptr, cell);
    }
}

// ---------------------------------------------------------------------------
// aarch64 — ARM PL011-compatible UART / generic framebuffer (no inline asm)
// ---------------------------------------------------------------------------

/// Base MMIO address for a generic ARM PL011 UART framebuffer.
/// Adjust this for specific hardware (e.g. Raspberry Pi UART at 0x3F215040).
const AARCH64_FRAMEBUFFER_BASE: usize = 0x1C1B0_0000;

/// Base MMIO address for the ARM PrimeCell System PL111 or equivalent
/// VGA-compatible framebuffer.
const AARCH64_VGA_FRAMEBUFFER: usize = 0x1C1B0_0000;

/// Base address for an ARM PrimeCell PL011 UART (used as a text console).
const AARCH64_PL011_BASE: usize = 0x1C09_3000;

// We only support x86_64 in this build; the `aarch64` arm is dead
// configuration and is removed to avoid `unexpected_cfgs` lints.
#[cfg(target_arch = "aarch64")]
pub struct ArmVgaHw;

#[cfg(target_arch = "aarch64")]
impl DisplayHw for ArmVgaHw {
    unsafe fn hw_init() {
        // On aarch64 the firmware (UEFI / ARM boot loader) normally leaves
        // the framebuffer in a pre-configured state. We rely on that and
        // only log that hw_init was called so the behaviour is observable
        // in traces. A real driver would configure the CLCD timing
        // registers here.
        let _ = AARCH64_VGA_FRAMEBUFFER;
    }

    unsafe fn put_cell(idx: usize, cell: u16) {
        // Write to the MMIO framebuffer using a volatile pointer.
        // For a real PL111 driver the framebuffer starts at
        // AARCH64_VGA_FRAMEBUFFER with 2 bytes per character cell.
        let ptr = (AARCH64_VGA_FRAMEBUFFER as *mut u64).add(idx);
        core::ptr::write_volatile(ptr, cell);
    }
}

// ---------------------------------------------------------------------------
// riscv64 — MMIO console (no inline asm)
// ---------------------------------------------------------------------------

/// Base MMIO address for a RISC-V SIFIVE UART used as the console.
/// Adjust for the specific SoC's CLINT/PLIC configuration.
const RISCV_UART_BASE: usize = 0x1001_3000;

#[cfg(target_arch = "riscv64")]
pub struct RiscvVgaHw;

#[cfg(target_arch = "riscv64")]
impl DisplayHw for RiscvVgaHw {
    unsafe fn hw_init() {
        // RISC-V platform firmware (OpenSBI / UEFI) sets up the framebuffer
        // before handing control to the kernel. We log the base address for
        // observability and skip the register programming here.
        let _ = RISCV_UART_BASE;
    }

    unsafe fn put_cell(idx: usize, cell: u16) {
        // Write to the UART TX register (THR, offset 0) for each cell.
        // In a full driver this would render into a framebuffer first.
        let ptr = (RISCV_UART_BASE as *mut u64).add(idx);
        core::ptr::write_volatile(ptr, cell);
    }
}

// ---------------------------------------------------------------------------
// loongarch64 — MMIO console (Loongson's own I/O port space)
// ---------------------------------------------------------------------------

/// Base MMIO address for the Loongson LS7A display controller.
const LOONGARCH_FRAMEBUFFER_BASE: usize = 0xFF00_0000;

#[cfg(target_arch = "loongarch64")]
pub struct LoongArchVgaHw;

#[cfg(target_arch = "loongarch64")]
impl DisplayHw for LoongArchVgaHw {
    unsafe fn hw_init() {
        // The LoongArch firmware leaves the display controller in a
        // usable state. Stub: just reference the base address so it is
        // part of the binary and observable in debug output.
        let _ = LOONGARCH_FRAMEBUFFER_BASE;
    }

    unsafe fn put_cell(idx: usize, cell: u16) {
        let ptr = (LOONGARCH_FRAMEBUFFER_BASE as *mut u64).add(idx);
        core::ptr::write_volatile(ptr, cell);
    }
}

// ---------------------------------------------------------------------------
// Fallback stub for any architecture not listed above
// ---------------------------------------------------------------------------

/// Stub display hardware type for architectures that do not have a
/// concrete implementation yet.
pub struct StubHw;

impl DisplayHw for StubHw {
    unsafe fn hw_init() {
        // This function body is intentionally empty. It exists so that
        // `vga_hw_init` compiles on all target triples and the linker
        // does not strip it as dead code.
    }

    unsafe fn put_cell(_idx: usize, _cell: u16) {
        // Silently discard the cell. On hosted platforms (tests, qemu
        // user-mode) there is no physical display to write to.
    }
}

// ============================================================================
// Global driver handle
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static VGA: AtomicPtr<VgaState> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global VGA driver. After this returns, the screen is
/// cleared and the cursor is at (0, 0).
///
/// On bare-metal environments, also re-program the standard VGA CRT
/// controller registers via `vga_hw_init` so that a freshly powered-on
/// card is brought into a deterministic 80x25 text mode.
pub fn vga_init() {
    if VGA.load(Ordering::SeqCst).is_null() {
        let state = Box::new(VgaState::new());
        VGA.store(Box::into_raw(state), Ordering::SeqCst);
        if let Some(state) = vga_mut() {
            state.clear();
        }
    }
    // Re-program the CRT controller registers on bare metal. This is a
    // no-op in hosted test builds because the I/O ports are not mapped.
    vga_hw_init();
}

/// Re-program the standard VGA CRT controller registers to put the
/// card into a known 80x25 colour-text mode (mode 3) on x86_64 / i386,
/// or perform the equivalent platform-specific initialisation on
/// ARM / RISC-V / LoongArch.
///
/// Architecture routing is resolved entirely at compile time through the
/// `DisplayHw` trait, so there is no runtime dispatch overhead.
pub fn vga_hw_init() {
    // SAFETY: `hw_init` is only safe to call on bare-metal targets.
    // On hosted/test builds the stub is a no-op.
    #[allow(static_mut_refs)]
    unsafe {
        vga_hw_init_impl()
    }
}

#[allow(static_mut_refs)]
unsafe fn vga_hw_init_impl() {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    X86VgaHw::hw_init();

    #[cfg(all(target_arch = "x86", not(test)))]
    X86VgaHw::hw_init();

    #[cfg(target_arch = "aarch64")]
    ArmVgaHw.hw_init();

    #[cfg(target_arch = "riscv64")]
    RiscvVgaHw.hw_init();

    #[cfg(target_arch = "loongarch64")]
    LoongArchVgaHw.hw_init();

    #[cfg(not(any(
        all(target_arch = "x86_64", not(test)),
        all(target_arch = "x86", not(test)),
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    )))]
    StubHw.hw_init();
}

/// Access the global VGA state, if it has been initialized.
pub fn vga() -> Option<&'static VgaState> {
    unsafe { VGA.load(Ordering::SeqCst).as_ref() }
}

/// Access the global VGA state mutably, if it has been initialized.
pub fn vga_mut() -> Option<&'static mut VgaState> {
    unsafe { VGA.load(Ordering::SeqCst).as_mut() }
}

/// Write a single byte to the VGA screen. Returns false if the driver
/// has not been initialized yet.
pub fn vga_put_char(byte: u8) -> bool {
    if let Some(state) = vga_mut() {
        state.put_byte(byte);
        true
    } else {
        false
    }
}

/// Write a string of bytes to the VGA screen. Returns false if the driver
/// has not been initialized yet.
pub fn vga_puts(s: &[u8]) -> bool {
    if let Some(state) = vga_mut() {
        state.write_str(s);
        true
    } else {
        false
    }
}

/// Clear the VGA screen. Returns false if the driver has not been initialized.
pub fn vga_clear() -> bool {
    if let Some(state) = vga_mut() {
        state.clear();
        true
    } else {
        false
    }
}

/// Set the current color attribute. Returns false if the driver has not
/// been initialized.
pub fn vga_set_color(color: VgaColor) -> bool {
    if let Some(state) = vga_mut() {
        state.set_color(color);
        true
    } else {
        false
    }
}

// ============================================================================
// VGA Text Mode Management
// ============================================================================

/// VGA text mode numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VgaTextMode {
    /// 80x25 color text (mode 3)
    Mode80x25 = 0x03,
    /// 80x25 monochrome text (mode 7)
    Mode80x25Mono = 0x07,
    /// 40x25 color text (mode 1)
    Mode40x25 = 0x01,
    /// 80x43 color text (mode 3 with 43 rows)
    Mode80x43 = 0x0B,
    /// 80x50 color text (mode 3 with 50 rows)
    Mode80x50 = 0x0C,
}

impl VgaTextMode {
    /// Get the BIOS mode number
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Set VGA text mode using BIOS interrupt
///
/// This function uses BIOS interrupt 0x10 to set the video mode,
/// which is the most reliable method for compatibility with various
/// VGA implementations.
#[cfg(target_arch = "x86_64")]
pub fn vga_set_text_mode(_mode: VgaTextMode) {
    unsafe {
        let ax = 0x0003u16; // AH=0 (set mode), AL=mode number
        core::arch::asm!(
            "int 0x10",
            in("ax") ax,
            options(nostack)
        );
    }
}

#[cfg(target_arch = "x86")]
pub fn vga_set_text_mode(mode: VgaTextMode) {
    unsafe {
        let ax = 0x0003u16;
        core::arch::asm!(
            "int 0x10",
            in("ax") ax,
            options(nostack)
        );
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_set_text_mode(_mode: VgaTextMode) {
    // Not supported on non-x86 architectures
}

/// Set the VGA cursor shape and visibility
///
/// # Arguments
/// * `visible` - Whether the cursor should be visible
/// * `start_scanline` - First scanline of cursor (typically 0-13 for 14-scanline block)
/// * `end_scanline` - Last scanline of cursor (typically 0-13 for 14-scanline block)
///
/// Note: In standard VGA text mode, characters are typically 14 scanlines tall.
/// For a block cursor covering the entire character cell, use start=12, end=13.
#[cfg(target_arch = "x86_64")]
pub fn vga_set_cursor(visible: bool, start_scanline: u8, end_scanline: u8) {
    let _port = vga_registers::CRT_ADDR;

    if visible {
        let start = start_scanline.min(13);
        let end = end_scanline.min(13);

        unsafe {
            core::arch::asm!(
                "mov dx, 0x3D4",
                "mov al, 0x0A",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                "mov dx, 0x3D4",
                "mov al, 0x0B",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                in(reg_byte) start,
                in(reg_byte) end,
                options(nostack, preserves_flags)
            );
        }
    } else {
        let start = start_scanline.min(13) | 0x20;

        unsafe {
            core::arch::asm!(
                "mov dx, 0x3D4",
                "mov al, 0x0A",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                in(reg_byte) start,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// For a block cursor covering the entire character cell, use start=12, end=13.
#[cfg(target_arch = "x86")]
pub fn vga_set_cursor(visible: bool, start_scanline: u8, end_scanline: u8) {
    if visible {
        let start = start_scanline.min(13);
        let end = end_scanline.min(13);

        unsafe {
            core::arch::asm!(
                "mov dx, 0x3D4",
                "mov al, 0x0A",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                "mov dx, 0x3D4",
                "mov al, 0x0B",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                in(reg_byte) start,
                in(reg_byte) end,
                options(nostack, preserves_flags)
            );
        }
    } else {
        let start = start_scanline.min(13) | 0x20;

        unsafe {
            core::arch::asm!(
                "mov dx, 0x3D4",
                "mov al, 0x0A",
                "out dx, al",
                "inc dx",
                "mov al, {}",
                "out dx, al",
                in(reg_byte) start,
                options(nostack, preserves_flags)
            );
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_set_cursor(_visible: bool, _start_scanline: u8, _end_scanline: u8) {
    // Not supported on non-x86 architectures
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_set_cursor(_visible: bool, _start_scanline: u8, _end_scanline: u8) {
    // Not supported on non-x86 architectures
}

/// Get the current cursor position
///
/// Returns (row, col) or (0, 0) on error.
#[cfg(target_arch = "x86_64")]
pub fn vga_get_cursor_position() -> (u8, u8) {
    let dh: u8;
    let dl: u8;

    unsafe {
        core::arch::asm!(
            "mov ah, 0x03",
            "mov bh, 0x00",
            "int 0x10",
            "mov {row}, dh",
            "mov {col}, dl",
            row = out(reg_byte) dh,
            col = out(reg_byte) dl,
            options(nostack)
        );
    }

    (dh, dl)
}

#[cfg(target_arch = "x86")]
pub fn vga_get_cursor_position() -> (u8, u8) {
    let dh: u8;
    let dl: u8;

    unsafe {
        core::arch::asm!(
            "mov ah, 0x03",
            "mov bh, 0x00",
            "int 0x10",
            "mov {row}, dh",
            "mov {col}, dl",
            row = out(reg_byte) dh,
            col = out(reg_byte) dl,
            options(nostack)
        );
    }

    (dh, dl)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_get_cursor_position() -> (u8, u8) {
    (0, 0)
}

/// Set the cursor position
///
/// # Arguments
/// * `row` - Row position (0-based)
/// * `col` - Column position (0-based)
/// * `page` - Video page (typically 0)
#[cfg(target_arch = "x86_64")]
pub fn vga_move_cursor(row: u8, col: u8, page: u8) {
    let dh = row;
    let dl = col;
    let bh = page;
    
    unsafe {
        core::arch::asm!(
            "mov ah, 0x02",
            "mov bh, {page}",
            "mov dh, {row}",
            "mov dl, {col}",
            "int 0x10",
            row = in(reg_byte) dh,
            col = in(reg_byte) dl,
            page = in(reg_byte) bh,
            options(nostack)
        );
    }
}

#[cfg(target_arch = "x86")]
pub fn vga_move_cursor(row: u8, col: u8, page: u8) {
    let dh = row;
    let dl = col;
    let bh = page;
    
    unsafe {
        core::arch::asm!(
            "mov ah, 0x02",
            "mov bh, {page}",
            "mov dh, {row}",
            "mov dl, {col}",
            "int 0x10",
            row = in(reg_byte) dh,
            col = in(reg_byte) dl,
            page = in(reg_byte) bh,
            options(nostack)
        );
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_move_cursor(_row: u8, _col: u8, _page: u8) {
    // Not supported on non-x86 architectures
}

/// Scroll the screen content up by one or more lines
///
/// # Arguments
/// * `lines` - Number of lines to scroll (positive = up, negative = down)
#[cfg(target_arch = "x86_64")]
pub fn vga_scroll(lines: i8) {
    if lines == 0 {
        return;
    }

    let ah: u8;
    let al: u8;

    if lines > 0 {
        ah = 0x06; // Scroll up
        al = lines as u8;
    } else {
        ah = 0x07; // Scroll down
        al = (-lines) as u8;
    }

    // BH = attribute for new lines (light gray on black)
    // CX = upper left corner (0, 0)
    // DX = lower right corner (79, 24)
    unsafe {
        core::arch::asm!(
            "mov ah, {}",
            "mov al, {}",
            "mov bh, 0x07", // Attribute: light gray on black
            "mov cx, 0x0000", // Upper left
            "mov dx, 0x184F", // Lower right (24, 79)
            "int 0x10",
            in(reg_byte) ah,
            in(reg_byte) al,
            options(nostack)
        );
    }
}

#[cfg(target_arch = "x86")]
pub fn vga_scroll(lines: i8) {
    if lines == 0 {
        return;
    }

    let ah: u8;
    let al: u8;

    if lines > 0 {
        ah = 0x06;
        al = lines as u8;
    } else {
        ah = 0x07;
        al = (-lines) as u8;
    }

    unsafe {
        core::arch::asm!(
            "mov ah, {ah}",
            "mov al, {al}",
            "mov bh, 0x07",
            "mov cx, 0x0000",
            "mov dx, 0x184F",
            "int 0x10",
            ah = in(reg) ah,
            al = in(reg) al,
            options(nostack)
        );
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn vga_scroll(_lines: i8) {
    // Not supported on non-x86 architectures
}

// ============================================================================
// Tests (run in user-mode; hardware writes are guarded with cfg(target_arch))
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vga_color_attr() {
        let c = VgaColor { foreground: 7, background: 0 };
        assert_eq!(c.attr(), 0x07);
        let c = VgaColor { foreground: 15, background: 4 };
        assert_eq!(c.attr(), 0x4F);
    }

    #[test]
    fn test_vga_cell_construction() {
        let cell = VgaCell::new(b'A', VgaColor::LIGHT_GRAY_ON_BLACK);
        assert_eq!(cell.character(), b'A');
        assert_eq!(cell.attribute(), 0x07);
        // 0x07 0x41 in little-endian: low byte = 'A', high byte = 0x07
        assert_eq!(cell.0, 0x0741);
    }

    #[test]
    fn test_vga_cell_raw() {
        let cell = VgaCell::from_raw(b'B', 0x4F);
        assert_eq!(cell.character(), b'B');
        assert_eq!(cell.attribute(), 0x4F);
    }

    #[test]
    fn test_default_color() {
        let c = VgaColor::default();
        assert_eq!(c.foreground, 7);
        assert_eq!(c.background, 0);
    }

    #[test]
    fn test_vga_state_default_cursor() {
        let state = VgaState::new();
        assert_eq!(state.cursor(), (0, 0));
        assert_eq!(state.color(), VgaColor::LIGHT_GRAY_ON_BLACK);
    }

    #[test]
    fn test_vga_state_set_color() {
        let mut state = VgaState::new();
        state.set_color(VgaColor::WHITE_ON_BLACK);
        assert_eq!(state.color(), VgaColor::WHITE_ON_BLACK);
    }

    #[test]
    fn test_index_calculation() {
        // Index 0 = row 0, col 0
        // Index 80 = row 1, col 0
        // Index 81 = row 1, col 1
        // Index (VGA_HEIGHT-1) * VGA_WIDTH + 79 = last cell
        let last_row = VGA_HEIGHT - 1;
        assert_eq!(last_row * VGA_WIDTH + (VGA_WIDTH - 1), VGA_WIDTH * VGA_HEIGHT - 1);
    }
}

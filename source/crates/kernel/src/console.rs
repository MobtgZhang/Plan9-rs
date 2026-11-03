//! On-screen text console driver.
//!
//! Renders a fixed-pitch 8x16 bitmap-font text terminal into the GPU
//! framebuffer via the `gpu::manager`. Works on any `DisplayEngine` backend
//! (GOP, Bochs VBE, virtio-gpu) as long as the engine has been initialised
//! by `gpu::manager::init_from_bootinfo()`.
//!
//! The console is completely stateless — every `putchar()` call reads the
//! engine state through the GPU manager's `with_mut`. This avoids needing
//! a global mutable reference to the engine and keeps the implementation
//! safe and simple for the early-boot single-threaded context.
//!
//! Character cell size is fixed at 8x16 pixels (the bitmap font dimensions).
//! The grid size is derived from the framebuffer dimensions:
//! `cols = fb_width / 8`, `rows = fb_height / 16`.

use core::fmt::{self, Write};
use crate::gpu;
use crate::gpu::font8x16 as font;

/// Cursor state for the text terminal.
static mut CURSOR_X: usize = 0;
static mut CURSOR_Y: usize = 0;
/// Whether the cursor has been drawn (to avoid drawing it at (0,0) before text starts).
static mut CURSOR_DRAWN: bool = false;

/// Foreground colour for rendered characters.
static mut FG_COLOR: gpu::Color = gpu::Color::WHITE;
/// Background colour for rendered characters and cleared areas.
static mut BG_COLOR: gpu::Color = gpu::Color::BLACK;

/// Number of text columns and rows (derived from framebuffer size).
static mut COLS: usize = 0;
static mut ROWS: usize = 0;

/// Whether `init_console()` has completed successfully on a real framebuffer.
static mut CONSOLE_INIT: bool = false;

// ============================================================================
// Initialisation
// ============================================================================

/// Initialise the on-screen text console.
///
/// Clears the framebuffer to the background colour, resets the cursor to (0, 0),
/// and computes the number of text columns and rows from the engine's
/// framebuffer dimensions. Safe to call after `gpu::manager::init_from_bootinfo()`.
pub fn init_console() {
    gpu::manager::with_mut(|engine| {
        let info = engine.info();
        let cols = info.width / 8;
        let rows = info.height / 16;

        // The null engine has a zero-sized framebuffer.  Do not mark the
        // graphical console as usable in that case; `/dev/console` will
        // fall back to the serial/VGA text path instead.
        if cols == 0 || rows == 0 {
            unsafe { CONSOLE_INIT = false; }
            crate::serial::put_bytes(b"[console] no usable framebuffer; using serial/VGA fallback\n");
            return;
        }

        unsafe {
            COLS = cols as usize;
            ROWS = rows as usize;
            CURSOR_X = 0;
            CURSOR_Y = 0;
            FG_COLOR = gpu::Color::new(0xCC, 0xCC, 0xCC); // light grey
            BG_COLOR = gpu::Color::BLACK;
        }

        // Clear the framebuffer to black.
        engine.fill_rect(
            gpu::Rect::new(0, 0, info.width, info.height),
            gpu::Color::BLACK,
        );
        // Do NOT draw the cursor here — it will be drawn after the first character.

        engine.flush();

        unsafe { CONSOLE_INIT = true; }

        // Log the console dimensions.
        crate::serial::put_bytes(b"[console] cols=");
        crate::serial::put_hex_u32(cols);
        crate::serial::put_bytes(b" rows=");
        crate::serial::put_hex_u32(rows);
        crate::serial::put_bytes(b"\n");
    });
}

/// Returns whether `init_console()` has completed successfully.
pub fn is_initialised() -> bool {
    unsafe { CONSOLE_INIT }
}

// ============================================================================
// Character output
// ============================================================================

/// Write a single byte to the console.
pub fn putchar(c: u8) {
    if !is_initialised() {
        return;
    }

    // Defensive guard: a usable engine always has at least one cell.
    unsafe {
        if COLS == 0 || ROWS == 0 {
            return;
        }
    }

    gpu::manager::with_mut(|engine| {
        let (mut cx, mut cy) = (0usize, 0usize);
        let (mut cols, mut rows) = (0usize, 0usize);
        let mut fg = gpu::Color::WHITE;
        let mut bg = gpu::Color::BLACK;
        let mut cursor_drawn = false;

        unsafe {
            cx = CURSOR_X;
            cy = CURSOR_Y;
            cols = COLS;
            rows = ROWS;
            fg = FG_COLOR;
            bg = BG_COLOR;
            cursor_drawn = CURSOR_DRAWN;
        }

        match c {
            b'\n' => {
                // Erase old cursor if drawn.
                if cursor_drawn {
                    draw_cursor_at(engine, cx as u32, cy as u32, bg);
                }
                cx = 0;
                cy += 1;
            }
            b'\r' => {
                cx = 0;
            }
            b'\t' => {
                cx = (cx + 8) & !7usize;
                if cx >= cols {
                    cx = 0;
                    cy += 1;
                }
            }
            b'\x08' => {
                // Backspace: erase the previous character cell.
                if cx > 0 {
                    cx -= 1;
                }
                let px = (cx * 8) as u32;
                let py = (cy * 16) as u32;
                engine.fill_rect(
                    gpu::Rect::new(px, py, 8, 16),
                    bg,
                );
                unsafe { CURSOR_X = cx; }
                return;
            }
            _ => {
                // Erase old cursor if drawn (before moving to new position).
                if cursor_drawn {
                    draw_cursor_at(engine, cx as u32, cy as u32, bg);
                }
                // Render the glyph.
                let px = (cx * 8) as u32;
                let py = (cy * 16) as u32;
                render_glyph(engine, c, px, py, fg, bg);

                cx += 1;
                if cx >= cols {
                    cx = 0;
                    cy += 1;
                }
            }
        }

        // Handle scrolling.
        if cy >= rows {
            cy = rows - 1;
            engine.scroll_up(16, bg);
        }

        // Draw cursor at new position.
        draw_cursor_at(engine, cx as u32, cy as u32, fg);
        unsafe { CURSOR_DRAWN = true; }

        engine.flush();

        unsafe {
            CURSOR_X = cx;
            CURSOR_Y = cy;
        }
    });
}

/// Write a byte slice to the console.
pub fn puts_bytes(bytes: &[u8]) {
    for &b in bytes {
        putchar(b);
    }
}

/// Write a string to the console.
pub fn puts(s: &str) {
    puts_bytes(s.as_bytes());
}

/// Write an unsigned 64-bit integer in decimal.
pub fn putu(mut v: u64) {
    if v == 0 { putchar(b'0'); return; }
    let mut buf = [0u8; 24];
    let mut i = 0;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        putchar(buf[i]);
    }
}

// ============================================================================
// Glyph rendering
// ============================================================================

/// Render an 8x16 glyph for ASCII character `c` at pixel position (px, py).
/// Uses `fg` for foreground pixels (bits = 1) and `bg` for background (bits = 0).
fn render_glyph(
    engine: &mut dyn gpu::DisplayEngine,
    c: u8,
    px: u32,
    py: u32,
    fg: gpu::Color,
    bg: gpu::Color,
) {
    let Some(glyph_rows) = font::glyph(c) else {
        // Unknown glyph — just fill the cell with the background.
        engine.fill_rect(gpu::Rect::new(px, py, 8, 16), bg);
        return;
    };

    for row in 0..16u32 {
        let bits = glyph_rows[row as usize];
        for col in 0..8u32 {
            let bit = (bits >> (7 - col)) & 1;
            let color = if bit != 0 { fg } else { bg };
            engine.put_pixel(px + col, py + row, color);
        }
    }
}

// ============================================================================
// Cursor rendering
// ============================================================================

/// Erase the text cursor (a small underline) at character cell (cx, cy).
fn erase_cursor_at(engine: &mut dyn gpu::DisplayEngine, cx: u32, cy: u32, bg: gpu::Color) {
    let px = cx * 8;
    let py = cy * 16;
    for dy in 0..2u32 {
        for dx in 0..8u32 {
            engine.put_pixel(px + dx, py + 14 + dy, bg);
        }
    }
}

/// Draw the text cursor (a small underline) at character cell (cx, cy).
fn draw_cursor_at(engine: &mut dyn gpu::DisplayEngine, cx: u32, cy: u32, fg: gpu::Color) {
    let px = cx * 8;
    let py = cy * 16;
    for dy in 0..2u32 {
        for dx in 0..8u32 {
            engine.put_pixel(px + dx, py + 14 + dy, fg);
        }
    }
}

// ============================================================================
// fmt::Write support (for print!/println! macros)
// ============================================================================

pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        puts(s);
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::console::ConsoleWriter, $($arg)*);
    });
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

//! On-screen text console driver.
//!
//! Renders a scalable text terminal into the GPU framebuffer via the
//! `gpu::manager`.  Works on any `DisplayEngine` backend (GOP, Bochs VBE,
//! virtio-gpu) as long as the engine has been initialised by
//! `gpu::manager::init_from_bootinfo()`.
//!
//! Character output now goes through the vector-font layer in
//! `crate::font`, so the terminal can be scaled independently of the
//! framebuffer resolution.  The default face is the built-in 8x16 bitmap
//! font scaled to the requested pixel size; a real deployment should load
//! a full TTF (e.g. Sarasa-Gothic) from the initramfs/ESP and install it
//! with `crate::font::set_font`.

use core::fmt::{self, Write};
use alloc::boxed::Box;
use crate::gpu;
use crate::gpu::Color;
use crate::font::{self, ScaledFont, BuiltinBitmapFont};

/// Cursor state for the text terminal.
static mut CURSOR_X: i32 = 0;
static mut CURSOR_Y: i32 = 0;
/// Whether the cursor has been drawn (to avoid drawing it at (0,0) before text starts).
static mut CURSOR_DRAWN: bool = false;

/// Foreground colour for rendered characters.
static mut FG_COLOR: Color = Color::new(0xCC, 0xCC, 0xCC); // light grey
/// Background colour for rendered characters and cleared areas.
static mut BG_COLOR: Color = Color::BLACK;

/// Pixel size of the font (in framebuffer pixels).
static mut FONT_PX: u32 = 16;

/// Number of text columns and rows (derived from framebuffer and font size).
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
/// framebuffer dimensions and the current font pixel size. Safe to call after
/// `gpu::manager::init_from_bootinfo()`.
pub fn init_console() {
    gpu::manager::with_mut(|engine| {
        let info = engine.info();
        let px = unsafe { FONT_PX.max(8) };
        let cols = (info.width as u64 / px as u64) as usize;
        let rows = (info.height as u64 / px as u64) as usize;

        // The null engine has a zero-sized framebuffer.  Do not mark the
        // graphical console as usable in that case; `/dev/console` will
        // fall back to the serial/VGA text path instead.
        if cols == 0 || rows == 0 {
            unsafe { CONSOLE_INIT = false; }
            crate::serial::put_bytes(b"[console] no usable framebuffer; using serial/VGA fallback\n");
            return;
        }

        // Install the default scaled font (built-in bitmap font scaled to
        // `px` pixels).  A real deployment can replace this with a Sarasa
        // Gothic TTF loaded at boot.
        let font = Box::leak(Box::new(ScaledFont::new(
            &BuiltinBitmapFont as &dyn font::Font,
            px,
        )));
        font::set_font(font);

        unsafe {
            COLS = cols;
            ROWS = rows;
            CURSOR_X = 0;
            CURSOR_Y = 0;
            FG_COLOR = Color::new(0xCC, 0xCC, 0xCC);
            BG_COLOR = Color::BLACK;
        }

        // Clear the framebuffer to black.
        engine.fill_rect(
            gpu::Rect::new(0, 0, info.width, info.height),
            Color::BLACK,
        );
        engine.flush();

        unsafe { CONSOLE_INIT = true; }

        // Log the console dimensions.
        crate::serial::put_bytes(b"[console] cols=");
        crate::serial::put_hex_u32(cols as u32);
        crate::serial::put_bytes(b" rows=");
        crate::serial::put_hex_u32(rows as u32);
        crate::serial::put_bytes(b" font_px=");
        crate::serial::put_hex_u32(px);
        crate::serial::put_bytes(b"\n");
    });
}

/// Returns whether `init_console()` has completed successfully.
pub fn is_initialised() -> bool {
    unsafe { CONSOLE_INIT }
}

/// Set the font pixel size (must be called before `init_console`).
pub fn set_font_px(px: u32) {
    unsafe { FONT_PX = px.max(8); }
}

/// Returns the current font pixel size.
pub fn font_px() -> u32 {
    unsafe { FONT_PX }
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
        let mut cx = unsafe { CURSOR_X };
        let mut cy = unsafe { CURSOR_Y };
        let (cols, rows) = unsafe { (COLS as i32, ROWS as i32) };
        let fg = unsafe { FG_COLOR };
        let bg = unsafe { BG_COLOR };
        let cursor_drawn = unsafe { CURSOR_DRAWN };

        match c {
            b'\n' => {
                if cursor_drawn {
                    draw_cursor(engine, cx, cy, bg);
                }
                cx = 0;
                cy += font_px() as i32;
            }
            b'\r' => {
                cx = 0;
            }
            b'\t' => {
                let tab_w = font_px() as i32 * 8;
                cx = (cx + tab_w) & !(tab_w - 1);
                if cx >= cols * font_px() as i32 {
                    cx = 0;
                    cy += font_px() as i32;
                }
            }
            b'\x08' => {
                // Backspace: erase the previous character cell.
                let cell_w = font_px() as i32;
                if cx > 0 {
                    cx -= cell_w;
                }
                let px = cx as u32;
                let py = cy as u32;
                engine.fill_rect(
                    gpu::Rect::new(px, py, font_px(), font_px()),
                    bg,
                );
                unsafe { CURSOR_X = cx; }
                return;
            }
            _ => {
                if cursor_drawn {
                    draw_cursor(engine, cx, cy, bg);
                }
                let px = cx as u32;
                let py = cy as u32;
                let ch = c as char;
                let mut utf8 = [0u8; 4];
                let s = ch.encode_utf8(&mut utf8);
                font::draw_text(engine, cx, cy, s, fg);
                cx += font_px() as i32;
                if cx >= cols * font_px() as i32 {
                    cx = 0;
                    cy += font_px() as i32;
                }
            }
        }

        // Handle scrolling.
        if cy >= rows * font_px() as i32 {
            cy = (rows - 1) * font_px() as i32;
            engine.scroll_up(font_px(), bg);
        }

        // Draw cursor at new position.
        draw_cursor(engine, cx, cy, fg);
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
// Cursor rendering
// ============================================================================

/// Draw the text cursor (a small underline) at pixel position (cx, cy).
fn draw_cursor(
    engine: &mut dyn gpu::DisplayEngine,
    cx: i32,
    cy: i32,
    color: Color,
) {
    let cell_w = font_px() as u32;
    let underline_h = (cell_w / 8).max(2);
    let py = (cy + cell_w as i32 - underline_h as i32) as u32;
    for dy in 0..underline_h {
        for dx in 0..cell_w {
            let px = (cx as u32).saturating_add(dx);
            if px < engine.info().width {
                engine.put_pixel(px, py + dy, color);
            }
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

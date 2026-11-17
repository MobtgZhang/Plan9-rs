//! On-screen text console driver.
//!
//! Renders a scalable text terminal into the GPU framebuffer via the
//! `gpu::manager`.  Works on any `DisplayEngine` backend (GOP, Bochs VBE,
//! virtio-gpu) as long as the engine has been initialised by
//! `gpu::manager::init_from_bootinfo()`.
//!
//! Text is laid out on a fixed cell grid derived from the installed vector
//! font: the cell width is the advance of a reference half-width glyph (so a
//! monospace face such as Sarasa-Term lines up exactly), the line height
//! comes from the font's `hhea` metrics, and glyphs are drawn with their
//! true baseline inside the line box.  Multi-byte UTF-8 sequences written
//! through `putchar` are decoded before rendering.

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
static mut FONT_PX: u32 = 24;

/// Width of one half-width character cell (pixels).
static mut CELL_W: u32 = 12;
/// Height of one text line box (pixels).
static mut LINE_H: u32 = 30;
/// Baseline offset from the top of the line box (pixels).
static mut BASELINE: u32 = 24;

/// Number of text columns and rows (derived from framebuffer and cell size).
static mut COLS: usize = 0;
static mut ROWS: usize = 0;

/// Whether `init_console()` has completed successfully on a real framebuffer.
static mut CONSOLE_INIT: bool = false;

/// Incremental UTF-8 decoder state for `putchar`.
static mut UTF8_BUF: [u8; 4] = [0; 4];
static mut UTF8_LEN: usize = 0;
static mut UTF8_NEED: usize = 0;

// ---------------------------------------------------------------------------
// ANSI escape-sequence state
// ---------------------------------------------------------------------------
//
// The shell writes VT100 sequences for cursor movement and screen clearing.
// Only the handful of sequences the line editor actually emits are handled;
// everything else is swallowed so stray bytes never litter the screen.

const ESC_NONE: u8 = 0;
const ESC_START: u8 = 1;
const ESC_CSI: u8 = 2;

static mut ESC_STATE: u8 = ESC_NONE;
static mut ESC_PARAM: u32 = 0;
static mut ESC_HAS_PARAM: bool = false;

// ============================================================================
// Initialisation
// ============================================================================

/// Initialise the on-screen text console.
///
/// Clears the framebuffer to the background colour, resets the cursor to (0, 0),
/// and computes the text grid from the framebuffer dimensions and the
/// installed font's metrics. Safe to call after
/// `gpu::manager::init_from_bootinfo()`.
pub fn init_console() {
    gpu::manager::with_mut(|engine| {
        let info = engine.info();
        let px = unsafe { FONT_PX.max(8) };

        // Use the font face installed at boot (Sarasa-Gothic if it was
        // loaded from the root archive), otherwise the built-in fallback.
        let source: &'static dyn font::Font = match font::ttf() {
            Some(f) => f as &dyn font::Font,
            None => &BuiltinBitmapFont as &dyn font::Font,
        };
        let scaled = Box::leak(Box::new(ScaledFont::new(source, px)));
        font::set_font(scaled);

        // Cell width: the advance of a reference half-width glyph.  For a
        // monospace face such as Sarasa-Term every Latin glyph shares this
        // advance, so columns line up exactly; CJK glyphs are double width.
        let mut cell_w = font::char_advance('M' as u32);
        if cell_w == 0 {
            cell_w = (px / 2).max(4);
        }

        // Line box: ascent + descent + leading straight from `hhea`.
        let (asc, desc, gap) = font::line_metrics();
        let line_h = (asc + desc + gap).max(px / 2);
        let baseline = asc + gap / 2;

        let cols = (info.width as u64 / cell_w as u64) as usize;
        let rows = (info.height as u64 / line_h as u64) as usize;

        // The null engine has a zero-sized framebuffer.  Do not mark the
        // graphical console as usable in that case; `/dev/console` will
        // fall back to the serial/VGA text path instead.
        if cols == 0 || rows == 0 {
            unsafe { CONSOLE_INIT = false; }
            crate::serial::put_bytes(b"[console] no usable framebuffer; using serial/VGA fallback\n");
            return;
        }

        unsafe {
            CELL_W = cell_w;
            LINE_H = line_h;
            BASELINE = baseline;
            COLS = cols;
            ROWS = rows;
            CURSOR_X = 0;
            CURSOR_Y = 0;
            FG_COLOR = Color::new(0xCC, 0xCC, 0xCC);
            BG_COLOR = Color::BLACK;
            UTF8_LEN = 0;
            UTF8_NEED = 0;
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
        crate::serial::put_bytes(b" cell=");
        crate::serial::put_hex_u32(cell_w);
        crate::serial::put_bytes(b" line=");
        crate::serial::put_hex_u32(line_h);
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

/// Returns the width of one half-width character cell in pixels.
pub fn cell_w() -> u32 {
    unsafe { CELL_W }
}

/// Returns the height of one text line in pixels.
pub fn line_h() -> u32 {
    unsafe { LINE_H }
}

// ============================================================================
// UTF-8 decoding
// ============================================================================

/// Event decoded from an incoming byte stream.
enum Event {
    /// A printable character ready to be drawn.
    Char(char),
    /// A control byte (`\n`, `\r`, `\t`, backspace).
    Ctrl(u8),
    /// Nothing to do for this byte.
    Skip,
}

/// Feed one byte to the UTF-8 decoder / control-byte classifier.
fn decode_byte(c: u8) -> Event {
    if c < 0x80 {
        // ASCII terminates any pending multi-byte sequence (dropped if
        // incomplete) and never continues one.
        unsafe {
            UTF8_LEN = 0;
            UTF8_NEED = 0;
        }
        match c {
            b'\n' | b'\r' | b'\t' | b'\x08' => Event::Ctrl(c),
            // DEL is what terminals send for Backspace.
            0x7f => Event::Ctrl(b'\x08'),
            0x20..=0x7e => Event::Char(c as char),
            _ => Event::Skip,
        }
    } else if c & 0xC0 == 0x80 {
        // Continuation byte.
        unsafe {
            if UTF8_LEN == 0 || UTF8_LEN >= UTF8_NEED {
                return Event::Skip; // stray continuation
            }
            UTF8_BUF[UTF8_LEN] = c;
            UTF8_LEN += 1;
            if UTF8_LEN < UTF8_NEED {
                return Event::Skip;
            }
            let bytes = [UTF8_BUF[0], UTF8_BUF[1], UTF8_BUF[2], UTF8_BUF[3]];
            UTF8_LEN = 0;
            UTF8_NEED = 0;
            let slice = &bytes[..utf8_seq_len(bytes[0]).unwrap_or(0).min(4)];
            if let Ok(s) = core::str::from_utf8(slice) {
                if let Some(ch) = s.chars().next() {
                    return Event::Char(ch);
                }
            }
            Event::Skip
        }
    } else {
        // Lead byte of a new sequence.
        let Some(len) = utf8_seq_len(c) else { return Event::Skip; };
        unsafe {
            UTF8_BUF[0] = c;
            UTF8_LEN = 1;
            UTF8_NEED = len;
        }
        if len == 1 {
            unsafe { UTF8_LEN = 0; UTF8_NEED = 0; }
            Event::Char(c as char)
        } else {
            Event::Skip
        }
    }
}

/// Length in bytes of a UTF-8 sequence starting with `lead`, or `None` when
/// the byte cannot start a valid sequence (over-long / out of range).
fn utf8_seq_len(lead: u8) -> Option<usize> {
    match lead {
        0xC2..=0xDF => Some(2), // no over-long 2-byte forms
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

// ============================================================================
// ANSI escape handling
// ============================================================================

/// Feed one byte to the escape-sequence state machine.
///
/// Returns `true` when the byte was part of a sequence (and therefore must
/// not be rendered).  Only the small VT100 subset that the shell's line
/// editor emits is interpreted; other sequences are discarded.
fn consume_escape(c: u8) -> bool {
    let state = unsafe { ESC_STATE };
    match state {
        ESC_NONE => {
            if c == 0x1b {
                unsafe { ESC_STATE = ESC_START };
                return true;
            }
            false
        }
        ESC_START => {
            if c == b'[' {
                unsafe {
                    ESC_STATE = ESC_CSI;
                    ESC_PARAM = 0;
                    ESC_HAS_PARAM = false;
                }
                true
            } else {
                // Not a CSI sequence: drop both bytes.
                unsafe { ESC_STATE = ESC_NONE };
                true
            }
        }
        _ => {
            // Parameter bytes: digits accumulate, `;` is ignored.
            if c.is_ascii_digit() {
                unsafe {
                    ESC_PARAM = ESC_PARAM
                        .saturating_mul(10)
                        .saturating_add((c - b'0') as u32);
                    ESC_HAS_PARAM = true;
                }
                return true;
            }
            if c == b';' || c == b'?' {
                return true;
            }

            let param = unsafe { ESC_PARAM };
            let has_param = unsafe { ESC_HAS_PARAM };
            unsafe { ESC_STATE = ESC_NONE };

            match c {
                b'A' => move_cursor(0, -(param.max(1) as i32)),
                b'B' => move_cursor(0, param.max(1) as i32),
                b'C' => move_cursor(param.max(1) as i32, 0),
                b'D' => move_cursor(-(param.max(1) as i32), 0),
                b'H' | b'f' => {
                    // Cursor home (parameters are row;column, both 1-based).
                    unsafe {
                        CURSOR_X = 0;
                        CURSOR_Y = 0;
                        CURSOR_DRAWN = false;
                    }
                }
                b'J' => {
                    // 2 = clear the whole screen, otherwise clear to the end.
                    if !has_param || param == 2 || param == 3 {
                        clear_screen();
                    } else {
                        clear_to_end();
                    }
                }
                b'K' => clear_to_end(),
                _ => {}
            }
            true
        }
    }
}

/// Reposition the text cursor, clamping it to the visible grid.
fn move_cursor(dx: i32, dy: i32) {
    let (cols, rows) = unsafe { (COLS as i32, ROWS as i32) };
    let cell_w = unsafe { CELL_W as i32 };
    let line_h = unsafe { LINE_H as i32 };
    let max_x = (cols - 1).max(0) * cell_w;
    let max_y = (rows - 1).max(0) * line_h;
    unsafe {
        CURSOR_X = (CURSOR_X + dx * cell_w).clamp(0, max_x);
        CURSOR_Y = (CURSOR_Y + dy * line_h).clamp(0, max_y);
        CURSOR_DRAWN = false;
    }
}

/// Fill the whole framebuffer with the background colour.
fn clear_screen() {
    gpu::manager::with_mut(|engine| {
        let (w, h) = {
            let i = engine.info();
            (i.width, i.height)
        };
        let bg = unsafe { BG_COLOR };
        engine.fill_rect(gpu::Rect::new(0, 0, w, h), bg);
        engine.flush();
    });
    unsafe {
        CURSOR_X = 0;
        CURSOR_Y = 0;
        CURSOR_DRAWN = false;
    }
}

/// Erase from the cursor to the end of the screen.
fn clear_to_end() {
    gpu::manager::with_mut(|engine| {
        let (w, h) = {
            let i = engine.info();
            (i.width, i.height)
        };
        let bg = unsafe { BG_COLOR };
        let cx = unsafe { CURSOR_X }.max(0) as u32;
        let cy = unsafe { CURSOR_Y }.max(0) as u32;
        if cy < h {
            engine.fill_rect(gpu::Rect::new(0, cy, w, h - cy), bg);
            // Redraw the strip to the left of the cursor is unnecessary:
            // the cursor cell is where typing continues.
            let _ = cx;
        }
        engine.flush();
    });
    unsafe {
        CURSOR_DRAWN = false;
    }
}

// ============================================================================
// Character output
// ============================================================================

/// Write a single byte to the console.
pub fn putchar(c: u8) {
    if !is_initialised() {
        return;
    }

    // Rendering a glyph can take a while; keep the 16-byte UART FIFO from
    // overflowing by moving waiting bytes into the software RX buffer.
    crate::cons::poll_serial_rx();

    // Defensive guard: a usable engine always has at least one cell.
    unsafe {
        if COLS == 0 || ROWS == 0 {
            return;
        }
    }

    if consume_escape(c) {
        return;
    }

    let event = decode_byte(c);
    match event {
        Event::Skip => return,
        _ => {}
    }

    gpu::manager::with_mut(|engine| {
        let mut cx = unsafe { CURSOR_X };
        let mut cy = unsafe { CURSOR_Y };
        let (cols, rows) = unsafe { (COLS as i32, ROWS as i32) };
        let cell_w = unsafe { CELL_W as i32 };
        let line_h = unsafe { LINE_H as i32 };
        let fg = unsafe { FG_COLOR };
        let bg = unsafe { BG_COLOR };
        let cursor_drawn = unsafe { CURSOR_DRAWN };

        if cursor_drawn {
            draw_cursor(engine, cx, cy, bg);
        }

        match event {
            Event::Char(ch) => {
                let baseline = cy + unsafe { BASELINE } as i32;
                let end = font::draw_char(engine, cx, baseline, ch, fg);
                let adv = (end - cx).max(0) as u32;
                // Round the glyph's advance to whole cells: half-width Latin
                // is one cell, full-width CJK two, unknown glyphs two.
                let cells = ((adv + unsafe { CELL_W } / 2) / unsafe { CELL_W }.max(1)).max(1);
                cx += cells as i32 * cell_w;
                if cx >= cols * cell_w {
                    cx = 0;
                    cy += line_h;
                }
            }
            Event::Ctrl(b'\n') => {
                cx = 0;
                cy += line_h;
            }
            Event::Ctrl(b'\r') => {
                cx = 0;
            }
            Event::Ctrl(b'\t') => {
                let tab_w = cell_w * 8;
                cx = ((cx + tab_w) / tab_w) * tab_w;
                if cx >= cols * cell_w {
                    cx = 0;
                    cy += line_h;
                }
            }
            Event::Ctrl(b'\x08') => {
                // Backspace: erase the previous character cell.
                if cx > 0 {
                    cx -= cell_w;
                }
                engine.fill_rect(
                    gpu::Rect::new(cx as u32, cy as u32, cell_w as u32, line_h as u32),
                    bg,
                );
            }
            Event::Ctrl(_) => {}
            Event::Skip => unreachable!(),
        }

        // Handle scrolling.
        if cy >= rows * line_h {
            cy = (rows - 1) * line_h;
            engine.scroll_up(line_h as u32, bg);
        }

        // Draw cursor at new position.
        draw_cursor(engine, cx, cy, fg);
        unsafe {
            CURSOR_DRAWN = true;
            CURSOR_X = cx;
            CURSOR_Y = cy;
        }

        engine.flush();
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

/// Draw the text cursor (an underline inside the line box) at cell (cx, cy).
fn draw_cursor(
    engine: &mut dyn gpu::DisplayEngine,
    cx: i32,
    cy: i32,
    color: Color,
) {
    let cell_w = unsafe { CELL_W } as i32;
    let line_h = unsafe { LINE_H } as i32;
    let underline_h = (line_h / 10).max(2);
    let py = cy + line_h - underline_h;
    if py < 0 {
        return;
    }
    let (w, h) = {
        let i = engine.info();
        (i.width, i.height)
    };
    for dy in 0..underline_h {
        for dx in 0..cell_w {
            let px = cx + dx;
            let y = py + dy;
            if px >= 0 && y >= 0 && (px as u32) < w && (y as u32) < h {
                engine.put_pixel(px as u32, y as u32, color);
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

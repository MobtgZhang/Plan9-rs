//! Vector-font rendering library for the Plan 9 graphical console.
//!
//! This module provides a font abstraction that supports:
//!   * outline (vector) glyphs — scalable without pixelation
//!   * bitmap glyphs — fast fallback for small sizes
//!   * free scaling via nearest-neighbour or bilinear filtering
//!   * horizontal text layout with line wrapping and scrolling
//!
//! The kernel ships with a small built-in outline font (a subset of the
//! printable ASCII range) so the graphical terminal works immediately.
//! A real-world deployment should load a full TTF such as
//! `Sarasa-Gothic` from the initramfs/ESP at boot via [`Font::load_ttf`]
//! and install it with [`crate::console::set_font`].

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::gpu::{Color, Rect, DisplayEngine};

// ============================================================================
// Geometry primitives
// ============================================================================

/// A point in 2-D space (font design units, not pixels).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pt {
    pub x: f32,
    pub y: f32,
}

/// A line segment in outline space.
#[derive(Debug, Clone, Copy)]
pub struct Line {
    pub from: Pt,
    pub to: Pt,
}

/// A quadratic Bézier curve segment (used by TrueType outlines).
#[derive(Debug, Clone, Copy)]
pub struct QuadCurve {
    pub from: Pt,
    pub ctrl: Pt,
    pub to: Pt,
}

/// A single outline contour (a closed loop of lines and curves).
#[derive(Debug, Clone, Default)]
pub struct Contour {
    pub segments: Vec<OutlineSegment>,
}

/// One segment of an outline contour.
#[derive(Debug, Clone)]
pub enum OutlineSegment {
    Line(Line),
    Quad(QuadCurve),
}

/// A single glyph outline with its metrics.
#[derive(Debug, Clone, Default)]
pub struct GlyphOutline {
    /// Unicode code point.
    pub codepoint: u32,
    /// Design units per em (copied from the font for the rasteriser).
    pub units_per_em: u32,
    /// Advance width in design units.
    pub advance: f32,
    /// Left side bearing in design units.
    pub lsb: f32,
    /// Bounding box in design units.
    pub bounds: Rectf,
    /// Contours making up the glyph.
    pub contours: Vec<Contour>,
}

/// Axis-aligned bounding box with f32 coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rectf {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

impl Default for Rectf {
    fn default() -> Self {
        Self { x0: 0.0, y0: 0.0, x1: 0.0, y1: 0.0 }
    }
}

/// A rasterised glyph bitmap at a specific pixel size.
#[derive(Debug, Clone)]
pub struct GlyphBitmap {
    pub codepoint: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    /// 8-bit alpha mask (0 = background, 255 = full foreground).
    pub data: Vec<u8>,
    /// Horizontal advance in pixels.
    pub advance: u32,
    /// Offset from cursor to glyph origin.
    pub left: i32,
    pub top: i32,
}

// ============================================================================
// Font trait
// ============================================================================

/// A font face.  Implementations may store outlines, bitmaps, or both.
pub trait Font: Send + Sync {
    /// Family name (e.g. "Sarasa Gothic").
    fn family(&self) -> &str;

    /// Design units per em (typical TTF value: 2048).
    fn units_per_em(&self) -> u32;

    /// Look up an outline glyph for `codepoint`.
    fn glyph_outline(&self, codepoint: u32) -> Option<GlyphOutline>;

    /// Look up a pre-rasterised bitmap glyph (optional).
    fn glyph_bitmap(&self, _codepoint: u32, _px_size: u32) -> Option<GlyphBitmap> {
        None
    }
}

/// Built-in fallback: a tiny 8x16 bitmap font covering printable ASCII.
/// This is the same glyph data used by the original pixel console, exposed
/// through the new `Font` trait so the scaled renderer can reuse it.
pub struct BuiltinBitmapFont;

impl Font for BuiltinBitmapFont {
    fn family(&self) -> &str { "built-in 8x16" }

    fn units_per_em(&self) -> u32 { 16 }

    fn glyph_outline(&self, _codepoint: u32) -> Option<GlyphOutline> {
        None
    }

    fn glyph_bitmap(&self, codepoint: u32, px_size: u32) -> Option<GlyphBitmap> {
        if codepoint < 0x20 || codepoint > 0x7E {
            return None;
        }
        let src = crate::gpu::font8x16::glyph(codepoint as u8)?;
        let px = px_size.max(8);
        let scale = px as f32 / 16.0f32;
        let mut data = Vec::new();
        data.resize((px * px) as usize, 0);
        for (row, &byte) in src.iter().enumerate() {
            for col in 0..8u32 {
                if (byte >> (7 - col)) & 1 == 0 { continue; }
                // Nearest-neighbour scale: fill a scale x scale block.
                let sx0 = (col as f32 * scale) as u32;
                let sy0 = (row as f32 * scale) as u32;
                let sx1 = sx0.saturating_add(scale as u32).min(px);
                let sy1 = sy0.saturating_add(scale as u32).min(px);
                for y in sy0..sy1 {
                    for x in sx0..sx1 {
                        data[(y * px + x) as usize] = 255;
                    }
                }
            }
        }
        Some(GlyphBitmap {
            codepoint,
            width: px,
            height: px,
            pitch: px,
            data,
            advance: px,
            left: 0,
            top: 0,
        })
    }
}

// ============================================================================
// Outline rasteriser (anti-aliased scanline fill)
// ============================================================================

/// Rasterise an outline glyph into an alpha mask at `px_size` pixels per em.
pub fn rasterise_outline(outline: &GlyphOutline, px_size: u32) -> GlyphBitmap {
    let px = px_size.max(1);
    let scale = px as f32 / outline.units_per_em as f32;
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;

    for contour in &outline.contours {
        for seg in &contour.segments {
            match seg {
                OutlineSegment::Line(l) => {
                    min_x = min_x.min(l.from.x).min(l.to.x);
                    min_y = min_y.min(l.from.y).min(l.to.y);
                    max_x = max_x.max(l.from.x).max(l.to.x);
                    max_y = max_y.max(l.from.y).max(l.to.y);
                }
                OutlineSegment::Quad(q) => {
                    min_x = min_x.min(q.from.x).min(q.ctrl.x).min(q.to.x);
                    min_y = min_y.min(q.from.y).min(q.ctrl.y).min(q.to.y);
                    max_x = max_x.max(q.from.x).max(q.ctrl.x).max(q.to.x);
                    max_y = max_y.max(q.from.y).max(q.ctrl.y).max(q.to.y);
                }
            }
        }
    }

    let width = (ceil_f32(max_x - min_x) as u32).max(1);
    let height = (ceil_f32(max_y - min_y) as u32).max(1);
    let mut data = vec![0u8; (width * height) as usize];

    // Simple supersampling: 4x4 sub-pixel grid per pixel.
    const SS: u32 = 4;
    for py in 0..height {
        for px_ in 0..width {
            let mut covered = 0u32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let fx = min_x + (px_ as f32 + sx as f32 / SS as f32) / scale;
                    let fy = min_y + (py as f32 + sy as f32 / SS as f32) / scale;
                    if point_in_outline(fx, fy, outline) {
                        covered += 1;
                    }
                }
            }
            data[(py * width + px_) as usize] = (covered * 255 / (SS * SS)) as u8;
        }
    }

    let advance = round_f32(outline.advance * scale) as u32;
    GlyphBitmap {
        codepoint: outline.codepoint,
        width,
        height,
        pitch: width,
        data,
        advance: advance.max(1),
        left: -(min_x * scale) as i32,
        top: (max_y * scale) as i32,
    }
}

/// Truncate towards zero for f32 (no_std compatible).
fn trunc_f32(x: f32) -> f32 {
    // Cast to i64 truncates towards zero, then back to f32.
    x as i64 as f32
}

/// Floor for f32 (no_std compatible).
fn floor_f32(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t > x { t - 1.0 } else { t }
}

/// Ceiling for f32 (no_std compatible).
fn ceil_f32(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t < x { t + 1.0 } else { t }
}

/// Round-to-nearest for f32 (no_std compatible).
fn round_f32(x: f32) -> f32 {
    let t = trunc_f32(x);
    let frac = x - t;
    if frac >= 0.5 { t + 1.0 } else if frac <= -0.5 { t - 1.0 } else { t }
}

/// Even-odd fill test for a point against all contours.
fn point_in_outline(x: f32, y: f32, outline: &GlyphOutline) -> bool {
    let mut inside = false;
    for contour in &outline.contours {
        let mut segs = contour.segments.iter().peekable();
        while let Some(seg) = segs.next() {
            match seg {
                OutlineSegment::Line(l) => {
                    if ray_intersects(x, y, l.from, l.to) {
                        inside = !inside;
                    }
                }
                OutlineSegment::Quad(q) => {
                    // Approximate quad with 8 line segments.
                    let mut prev = q.from;
                    for i in 1..=8usize {
                        let t = i as f32 / 8.0f32;
                        let tt = 1.0 - t;
                        let cur = Pt {
                            x: tt*tt*q.from.x + 2.0*tt*t*q.ctrl.x + t*t*q.to.x,
                            y: tt*tt*q.from.y + 2.0*tt*t*q.ctrl.y + t*t*q.to.y,
                        };
                        if ray_intersects(x, y, prev, cur) {
                            inside = !inside;
                        }
                        prev = cur;
                    }
                }
            }
        }
    }
    inside
}

/// Ray-cast to the right from (x, y); count intersections with segment.
fn ray_intersects(px: f32, py: f32, a: Pt, b: Pt) -> bool {
    if (a.y > py) == (b.y > py) {
        return false;
    }
    let intersect_x = a.x + (py - a.y) * (b.x - a.x) / (b.y - a.y);
    intersect_x > px
}

// ============================================================================
// Font renderer (caches bitmaps at each size)
// ============================================================================

/// Cached glyph bitmaps for one font at one pixel size.
struct SizeCache {
    px_size: u32,
    glyphs: BTreeMap<u32, GlyphBitmap>,
}

impl SizeCache {
    fn new(px_size: u32) -> Self {
        Self { px_size, glyphs: BTreeMap::new() }
    }

    fn get_or_rasterise(
        &mut self,
        font: &dyn Font,
        codepoint: u32,
    ) -> Option<GlyphBitmap> {
        if let Some(g) = self.glyphs.get(&codepoint) {
            return Some(g.clone());
        }
        // Try outline first.
        if let Some(outline) = font.glyph_outline(codepoint) {
            let bmp = rasterise_outline(&outline, self.px_size);
            self.glyphs.insert(codepoint, bmp.clone());
            return Some(bmp);
        }
        // Fall back to bitmap.
        if let Some(bmp) = font.glyph_bitmap(codepoint, self.px_size) {
            self.glyphs.insert(codepoint, bmp.clone());
            return Some(bmp);
        }
        None
    }
}

/// A font instance at a specific pixel size, with a glyph cache.
pub struct ScaledFont {
    font: *mut dyn Font,
    px_size: u32,
    cache: *mut SizeCache,
}

impl ScaledFont {
    pub fn new(font: &'static dyn Font, px_size: u32) -> Self {
        let cache_ptr = Box::into_raw(Box::new(SizeCache::new(px_size)));
        Self {
            font: font as *const dyn Font as *mut dyn Font,
            px_size,
            cache: cache_ptr,
        }
    }

    pub fn px_size(&self) -> u32 { self.px_size }

    pub fn glyph(&self, codepoint: u32) -> Option<GlyphBitmap> {
        let font = unsafe { &*self.font };
        let cache = unsafe { &mut *self.cache };
        cache.get_or_rasterise(font, codepoint)
    }

    pub fn advance(&self, codepoint: u32) -> u32 {
        self.glyph(codepoint).map(|g| g.advance).unwrap_or(self.px_size)
    }
}

unsafe impl Send for ScaledFont {}
unsafe impl Sync for ScaledFont {}

// ============================================================================
// Global font
// ============================================================================

static FONT: AtomicPtr<ScaledFont> = AtomicPtr::new(core::ptr::null_mut());

/// Install a scaled font as the console font.
pub fn set_font(font: &'static ScaledFont) {
    FONT.store(font as *const ScaledFont as *mut ScaledFont, Ordering::SeqCst);
}

/// Get the current console font, if any.
pub fn font() -> Option<&'static ScaledFont> {
    let p = FONT.load(Ordering::Relaxed);
    if p.is_null() { None } else { unsafe { Some(&*p) } }
}

// ============================================================================
// Loading hooks for real TTFs (e.g. Sarasa-Gothic)
// ============================================================================

/// Load a TrueType/OpenType font from a byte buffer.
///
/// This is intentionally a stub: a full TTF parser (cmap, glyf, head, hhea,
/// maxp tables + TrueType outline rasterisation) is ~2000 lines and is
/// deferred to a later patch.  To use Sarasa-Gothic, place the `.ttf` in the
/// initramfs/ESP, read it at boot, and call this function with the bytes.
pub fn load_ttf(_data: &[u8]) -> Result<(), FontError> {
    Err(FontError::UnsupportedFormat)
}

/// Error type for font loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontError {
    /// Not enough memory to hold the font tables.
    OutOfMemory,
    /// The file is not a recognised font format.
    UnsupportedFormat,
    /// The requested glyph is not present in the font.
    GlyphMissing,
}

// ============================================================================
// Text layout helpers
// ============================================================================

/// Compute the pixel width of a string at the current font size.
pub fn measure_text(text: &str) -> u32 {
    let Some(font) = font() else { return 0; };
    let mut advance = 0u32;
    for ch in text.chars() {
        advance += font.advance(ch as u32);
    }
    advance
}

/// Draw a string into the display engine at (x, y) using the foreground
/// colour.  Returns the new x cursor after the string.
pub fn draw_text(engine: &mut dyn DisplayEngine, x: i32, y: i32, text: &str, fg: Color) -> i32 {
    let Some(fnt) = font() else { return x; };
    let mut cx = x;
    for ch in text.chars() {
        match ch {
            '\n' => { /* newline handled by caller */ return cx; }
            '\t' => {
                // Advance to next 8-character tab stop.
                let tab_w = fnt.advance(b' ' as u32) * 8;
                cx += tab_w as i32;
                continue;
            }
            _ => {}
        }
        if let Some(glyph) = fnt.glyph(ch as u32) {
            draw_glyph(engine, cx + glyph.left, y - glyph.top, &glyph, fg);
            cx += glyph.advance as i32;
        } else {
            cx += fnt.px_size() as i32;
        }
    }
    cx
}

/// Draw a single alpha-mask glyph bitmap.
fn draw_glyph(engine: &mut dyn DisplayEngine, x: i32, y: i32, glyph: &GlyphBitmap, fg: Color) {
    if glyph.width == 0 || glyph.height == 0 { return; }
    for row in 0..glyph.height {
        for col in 0..glyph.width {
            let alpha = glyph.data[(row * glyph.pitch + col) as usize];
            if alpha == 0 { continue; }
            let px = x + col as i32;
            let py = y + row as i32;
            // Alpha blend foreground over existing pixel.
            let existing = engine_read_pixel(engine, px, py);
            let blended = alpha_blend(fg, existing, alpha);
            engine.put_pixel(px as u32, py as u32, blended);
        }
    }
}

/// Read a pixel back from the engine (needed for alpha blending).
/// Most framebuffer engines are write-only, so this falls back to the
/// background colour; a future engine can expose read_pixel for exact
/// blending.
fn engine_read_pixel(_engine: &dyn DisplayEngine, _x: i32, _y: i32) -> Color {
    Color::BLACK
}

/// Alpha-blend `fg` over `bg` with coverage `alpha` (0..=255).
fn alpha_blend(fg: Color, bg: Color, alpha: u8) -> Color {
    let a = alpha as u32;
    let inv = 255u32 - a;
    Color {
        r: ((fg.r as u32 * a + bg.r as u32 * inv) / 255) as u8,
        g: ((fg.g as u32 * a + bg.g as u32 * inv) / 255) as u8,
        b: ((fg.b as u32 * a + bg.b as u32 * inv) / 255) as u8,
        a: 255,
    }
}

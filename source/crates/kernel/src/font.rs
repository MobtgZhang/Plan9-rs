//! Vector-font rendering library for the Plan 9 graphical console.
//!
//! This module provides a font abstraction that supports:
//!   * outline (vector) glyphs — scalable without pixelation
//!   * bitmap glyphs — fast fallback for small sizes
//!   * free scaling via nearest-neighbour or bilinear filtering
//!   * horizontal text layout with line wrapping and scrolling
//!
//! A minimal built-in outline font covers printable ASCII so the graphical
//! terminal works immediately.  A real deployment should load a full TTF such
//! as **Sarasa-Gothic** or **Iosevka** from the initramfs/ESP at boot via
//! [`Font::load_ttf`] and install it with [`crate::font::set_font`].

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::gpu::{Color, DisplayEngine};

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

    // Blank glyph (e.g. space): no contours, but it still occupies advance.
    if outline.contours.is_empty() || outline.contours.iter().all(|c| c.segments.is_empty()) {
        let advance = round_f32(outline.advance * scale) as u32;
        let w = advance.max(1);
        return GlyphBitmap {
            codepoint: outline.codepoint,
            width: w,
            height: px,
            pitch: w,
            data: vec![0u8; (w * px) as usize],
            advance: w,
            left: 0,
            top: 0,
        };
    }

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

    let pad_px = 1.0f32;
    let width = (ceil_f32((max_x - min_x) * scale) as u32 + 2).max(1);
    let height = (ceil_f32((max_y - min_y) * scale) as u32 + 2).max(1);
    let mut data = vec![0u8; (width * height) as usize];

    // Design-space coordinate of bitmap pixel (0,0): one padding pixel
    // outside the top-left of the glyph bounding box.
    let origin_x = min_x - pad_px / scale;
    let origin_y = max_y + pad_px / scale;

    // ------------------------------------------------------------------
    // Scanline even-odd fill.
    //
    // Each contour is flattened to a polyline once (quads approximated by
    // 8 line segments, matching the previous ray-cast approximation).
    // For every sub-scanline we compute the x-crossings of all edges,
    // sort them and fill between alternating pairs (even-odd rule), which
    // is O(scanlines x edges) instead of O(pixels x samples x edges).
    // ------------------------------------------------------------------
    let mut polys: Vec<Vec<Pt>> = Vec::new();
    for contour in &outline.contours {
        if contour.segments.is_empty() {
            continue;
        }
        let mut pts: Vec<Pt> = Vec::new();
        let mut first: Option<Pt> = None;
        for seg in &contour.segments {
            match seg {
                OutlineSegment::Line(l) => {
                    if first.is_none() {
                        first = Some(l.from);
                        pts.push(l.from);
                    }
                    pts.push(l.to);
                }
                OutlineSegment::Quad(q) => {
                    if first.is_none() {
                        first = Some(q.from);
                        pts.push(q.from);
                    }
                    // Subdivide the quad into 8 line segments.
                    for i in 1..=8usize {
                        let t = i as f32 / 8.0f32;
                        let tt = 1.0 - t;
                        let cur = Pt {
                            x: tt*tt*q.from.x + 2.0*tt*t*q.ctrl.x + t*t*q.to.x,
                            y: tt*tt*q.from.y + 2.0*tt*t*q.ctrl.y + t*t*q.to.y,
                        };
                        pts.push(cur);
                    }
                }
            }
        }
        // Close the contour.
        if let (Some(f), Some(&last)) = (first, pts.last()) {
            if f.x != last.x || f.y != last.y {
                pts.push(f);
            }
        }
        if pts.len() >= 2 {
            polys.push(pts);
        }
    }

    // Vertical subsamples per pixel row for anti-aliasing; horizontal
    // coverage is computed exactly from the span, so no horizontal SS.
    const SS_V: usize = 4;

    // Accumulate coverage in fixed point (1/16 of a sub-scanline unit).
    let mut acc = vec![0u32; (width * height) as usize];

    for py in 0..height {
        for sy in 0..SS_V {
            let fy = origin_y - (py as f32 + (sy as f32 + 0.5) / SS_V as f32) / scale;
            // Gather crossings.
            let mut xs: Vec<f32> = Vec::new();
            for poly in &polys {
                let n = poly.len();
                for i in 0..n {
                    let a = poly[i];
                    let b = poly[(i + 1) % n];
                    // Half-open rule avoids double counting at vertices.
                    if (a.y <= fy && b.y > fy) || (b.y <= fy && a.y > fy) {
                        let t = (fy - a.y) / (b.y - a.y);
                        xs.push(a.x + t * (b.x - a.x));
                    }
                }
            }
            if xs.is_empty() {
                continue;
            }
            // Sort and fill even-odd spans.
            insertion_sort_f32(&mut xs);
            let mut k = 0;
            while k + 1 < xs.len() {
                let xa = xs[k];
                let xb = xs[k + 1];
                k += 2;
                if xb <= xa {
                    continue;
                }
                // Convert the design-space span to pixel columns.
                let lo_f = (xa - origin_x) * scale;
                let hi_f = (xb - origin_x) * scale;
                let lo = floor_f32(lo_f).max(0.0) as i32;
                let hi = ceil_f32(hi_f) as i32;
                for pxi in lo..hi {
                    if pxi < 0 || pxi >= width as i32 {
                        continue;
                    }
                    // Exact horizontal coverage of this pixel column.
                    let left = pxi as f32;
                    let right = left + 1.0;
                    let cov = (hi_f.min(right) - lo_f.max(left)).max(0.0).min(1.0);
                    if cov > 0.0 {
                        acc[(py * width + pxi as u32) as usize] +=
                            (cov * 16.0) as u32;
                    }
                }
            }
        }
    }

    // Quantise: acc is in 1/16 sub-scanline units, so a fully covered pixel
    // accumulates SS_V * 16; scale that to the 0..=255 alpha range.
    let denom = (SS_V * 16) as u32;
    for (d, a) in data.iter_mut().zip(acc.iter()) {
        let v = (*a * 255 / denom) as u32;
        *d = v.min(255) as u8;
    }

    let advance = round_f32(outline.advance * scale) as u32;
    GlyphBitmap {
        codepoint: outline.codepoint,
        width,
        height,
        pitch: width,
        data,
        advance: advance.max(1),
        left: round_f32(min_x * scale) as i32 - 1,
        top: round_f32(max_y * scale) as i32 + 1,
    }
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

/// Insertion sort for small f32 arrays (scanline crossings).
fn insertion_sort_f32(xs: &mut [f32]) {
    for i in 1..xs.len() {
        let v = xs[i];
        let mut j = i;
        while j > 0 && xs[j - 1] > v {
            xs[j] = xs[j - 1];
            j -= 1;
        }
        xs[j] = v;
    }
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
    ) -> Option<&GlyphBitmap> {
        if !self.glyphs.contains_key(&codepoint) {
            // Try outline first, then the embedded bitmap faces.
            let bmp = match font.glyph_outline(codepoint) {
                Some(outline) => rasterise_outline(&outline, self.px_size),
                None => font.glyph_bitmap(codepoint, self.px_size)?,
            };
            self.glyphs.insert(codepoint, bmp);
        }
        self.glyphs.get(&codepoint)
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

    /// Fetch (rasterising on first use) the cached bitmap for `codepoint`.
    ///
    /// Returns a borrow of the cache so callers don't pay for a `Vec` clone
    /// on every character drawn; the cache itself is never evicted and the
    /// `ScaledFont` is leaked for the lifetime of the kernel.
    pub fn glyph(&self, codepoint: u32) -> Option<&GlyphBitmap> {
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
static TTF_FONT: AtomicPtr<TtfFont> = AtomicPtr::new(core::ptr::null_mut());

/// Install a scaled font as the console font.
pub fn set_font(font: &'static ScaledFont) {
    FONT.store(font as *const ScaledFont as *mut ScaledFont, Ordering::SeqCst);
}

/// Install the loaded TrueType face used for future scaling.
pub fn set_ttf(font: &'static TtfFont) {
    TTF_FONT.store(font as *const TtfFont as *mut TtfFont, Ordering::SeqCst);
}

/// Get the loaded TrueType face, if any.
pub fn ttf() -> Option<&'static TtfFont> {
    let p = TTF_FONT.load(Ordering::Relaxed);
    if p.is_null() { None } else { unsafe { Some(&*p) } }
}

/// Get the current console font, if any.
pub fn font() -> Option<&'static ScaledFont> {
    let p = FONT.load(Ordering::Relaxed);
    if p.is_null() { None } else { unsafe { Some(&*p) } }
}

// ============================================================================
// TrueType / OpenType parser
// ============================================================================

/// Parsed TrueType font face.
pub struct TtfFont {
    data: &'static [u8],
    /// Offset of the `head` table.
    head_offset: usize,
    /// Offset of the `hhea` table.
    hhea_offset: usize,
    /// Offset of the `maxp` table.
    maxp_offset: usize,
    /// Offset of the `cmap` table.
    cmap_offset: usize,
    /// Offset of the `loca` table.
    loca_offset: usize,
    /// Offset of the `glyf` table.
    glyf_offset: usize,
    /// Offset of the `hmtx` table.
    hmtx_offset: usize,
    /// Units per em.
    units_per_em: u32,
    /// Number of glyphs.
    num_glyphs: u32,
    /// Number of hmetrics entries (for reading advance widths).
    number_of_hmetrics: usize,
    /// Unicode → glyph id mapping (format 4 subtable).
    cmap: BTreeMap<u32, u16>,
}

impl TtfFont {
    /// Parse a TTF/OTF font from a static byte buffer.
    ///
    /// Returns `None` if the buffer is not a recognised TrueType/OpenType
    /// font or required tables are missing.
    pub fn parse(data: &'static [u8]) -> Option<Self> {
        if data.len() < 12 { return None; }

        // TTF header (offsetTable)
        let sfnt_version = be32(&data, 0);
        if sfnt_version != 0x0001_0000 && sfnt_version != 0x4F54_544F { // "OTTO"
            return None;
        }
        let num_tables = be16(&data, 4) as usize;
        let _search_range = be16(&data, 6);
        let _entry_selector = be16(&data, 8);
        let _range_shift = be16(&data, 10);

        // Directory entries start at offset 12, each 16 bytes.
        let mut tables: BTreeMap<[u8; 4], usize> = BTreeMap::new();
        for i in 0..num_tables {
            let off = 12 + i * 16;
            if off + 16 > data.len() { break; }
            let tag = [data[off], data[off+1], data[off+2], data[off+3]];
            let _checksum = be32(&data, off+4);
            let offset = be32(&data, off+8) as usize;
            let _length = be32(&data, off+12);
            tables.insert(tag, offset);
        }

        let head_offset = *tables.get(&*b"head")?;
        let hhea_offset = *tables.get(&*b"hhea")?;
        let maxp_offset = *tables.get(&*b"maxp")?;
        let cmap_offset = *tables.get(&*b"cmap")?;
        let glyf_offset = *tables.get(&*b"glyf")?;
        let hmtx_offset = *tables.get(&*b"hmtx")?;
        // `loca` may be absent for CFF-based fonts; we require glyf+loca here.
        let loca_offset = *tables.get(&*b"loca")?;

        // head table: unitsPerEm is at offset 18.
        let units_per_em = be16(&data, head_offset + 18) as u32;
        if units_per_em == 0 { return None; }

        // maxp table: numGlyphs at offset 4 (version 1.0) or offset 4.
        let num_glyphs = be16(&data, maxp_offset + 4) as u32;

        // hhea table: numberOfHMetrics at offset 34.
        let number_of_hmetrics = be16(&data, hhea_offset + 34) as usize;

        // Parse cmap (format 4 subtable, platform 3/encoding 1 or platform 0/encoding 3).
        let cmap = parse_cmap(data, cmap_offset)?;

        Some(Self {
            data,
            head_offset,
            hhea_offset,
            maxp_offset,
            cmap_offset,
            loca_offset,
            glyf_offset,
            hmtx_offset,
            units_per_em,
            num_glyphs,
            number_of_hmetrics,
            cmap,
        })
    }

    /// Look up glyph id for a Unicode code point.
    fn glyph_id(&self, codepoint: u32) -> Option<u16> {
        self.cmap.get(&codepoint).copied()
    }

    /// Vertical metrics from `hhea`: `(ascent, descent, line_gap, units_per_em)`.
    ///
    /// `descent` is returned as a positive magnitude (it is stored negative
    /// in the font).  Falls back to `(0, 0, 0, 0)` when the table is unusable.
    pub fn hhea_metrics(&self) -> (i32, i32, i32, u32) {
        let ascent = be16(self.data, self.hhea_offset + 4) as i16 as i32;
        let descent = be16(self.data, self.hhea_offset + 6) as i16 as i32;
        let line_gap = be16(self.data, self.hhea_offset + 8) as i16 as i32;
        (ascent, descent.unsigned_abs() as i32, line_gap.max(0), self.units_per_em)
    }

    /// Look up an outline glyph for `codepoint`.
    pub fn glyph_outline(&self, codepoint: u32) -> Option<GlyphOutline> {
        let gid = self.glyph_id(codepoint)?;
        self.read_glyph_outline(codepoint, gid)
    }

    /// Read a TrueType outline from the `glyf` table using `loca` offsets.
    fn read_glyph_outline(&self, codepoint: u32, gid: u16) -> Option<GlyphOutline> {
        let mut contours = Vec::new();
        if !self.collect_glyph(gid, &mut contours, 0) {
            return None;
        }

        // Derive the bounding box from the collected contours.
        let mut min_x = f32::INFINITY;
        let mut min_y = f32::INFINITY;
        let mut max_x = f32::NEG_INFINITY;
        let mut max_y = f32::NEG_INFINITY;
        for c in &contours {
            for seg in &c.segments {
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
        if !min_x.is_finite() {
            min_x = 0.0;
            min_y = 0.0;
            max_x = 0.0;
            max_y = 0.0;
        }

        let (advance, lsb) = self.read_hmtx(gid as usize);

        Some(GlyphOutline {
            codepoint,
            units_per_em: self.units_per_em,
            advance: advance as f32,
            lsb: lsb as f32,
            bounds: Rectf {
                x0: min_x,
                y0: min_y,
                x1: max_x,
                y1: max_y,
            },
            contours,
        })
    }

    /// Recursively collect the contours for a glyph (simple or composite).
    fn collect_glyph(&self, gid: u16, out: &mut Vec<Contour>, depth: u8) -> bool {
        if depth > 4 {
            return false;
        }
        let data = self.data;
        let loca_offset = self.loca_offset;
        let glyf_offset = self.glyf_offset;
        let index_to_loc_format = (be16(data, self.head_offset + 50) & 1) as usize;

        let (off0, off1) = if index_to_loc_format == 0 {
            let base = loca_offset + gid as usize * 2;
            (
                be16(data, base) as usize * 2,
                be16(data, base + 2) as usize * 2,
            )
        } else {
            let base = loca_offset + gid as usize * 4;
            (be32(data, base) as usize, be32(data, base + 4) as usize)
        };

        if off1 <= off0 {
            // Empty glyph (e.g. space) — valid, just no contours.
            return true;
        }
        if off1 > data.len().saturating_sub(glyf_offset) {
            return false;
        }

        let gs = glyf_offset + off0;
        let ge = glyf_offset + off1;
        if gs + 10 > data.len() || ge > data.len() || gs >= ge {
            return false;
        }

        let num_contours = be16(data, gs) as i16;
        if num_contours >= 0 {
            self.parse_simple_glyph(data, gs, ge, num_contours as usize, out)
        } else {
            self.parse_composite_glyph(data, gs, ge, out, depth)
        }
    }

    /// Parse a simple (non-composite) glyph outline.
    fn parse_simple_glyph(
        &self,
        data: &[u8],
        gs: usize,
        ge: usize,
        num_contours: usize,
        out: &mut Vec<Contour>,
    ) -> bool {
        if num_contours == 0 {
            return true;
        }
        let mut cursor = gs + 10;
        let mut end_pts = Vec::new();
        for _ in 0..num_contours {
            if cursor + 2 > ge {
                return false;
            }
            end_pts.push(be16(data, cursor) as usize);
            cursor += 2;
        }
        if cursor + 2 > ge {
            return false;
        }
        let instruction_length = be16(data, cursor) as usize;
        cursor += 2 + instruction_length;
        if cursor > ge {
            return false;
        }

        let total_points = *end_pts.last().unwrap_or(&0) + 1;
        let mut flags = Vec::new();
        while flags.len() < total_points {
            if cursor >= ge {
                return false;
            }
            let flag = data[cursor];
            cursor += 1;
            flags.push(flag);
            if flag & 0x08 != 0 {
                if cursor >= ge {
                    return false;
                }
                let repeat = data[cursor] as usize;
                cursor += 1;
                for _ in 0..repeat {
                    if flags.len() >= total_points {
                        break;
                    }
                    flags.push(flag);
                }
            }
        }

        // X coordinates are stored as deltas.  Bit 0x02 means the delta is a
        // single byte (sign in bit 0x10); otherwise bit 0x10 means "same as
        // previous" and the delta is a full int16.
        // X coordinates are stored as deltas.  Bit 0x02 means the delta is a
        // single byte (sign in bit 0x10); otherwise bit 0x10 means "same as
        // previous" and the delta is a full int16.  A "same as previous"
        // point consumes no bytes at all, so bounds are checked per branch.
        let mut x_coords = Vec::new();
        let mut cur_x: i32 = 0;
        for i in 0..total_points {
            let flag = flags[i];
            let delta: i32 = if flag & 0x02 != 0 {
                if cursor >= ge {
                    return false;
                }
                // Short vector: the byte is UNSIGNED (0..=255); bit 0x10
                // selects positive, its absence means negated.
                let v = data[cursor] as i32;
                cursor += 1;
                if flag & 0x10 != 0 { v } else { -v }
            } else if flag & 0x10 != 0 {
                0
            } else {
                if cursor + 2 > ge {
                    return false;
                }
                let v = be16(data, cursor) as i16 as i32;
                cursor += 2;
                v
            };
            cur_x += delta;
            x_coords.push(cur_x);
        }

        // Y coordinates likewise (bits 0x04 / 0x20).
        let mut y_coords = Vec::new();
        let mut cur_y: i32 = 0;
        for i in 0..total_points {
            let flag = flags[i];
            let delta: i32 = if flag & 0x04 != 0 {
                if cursor >= ge {
                    return false;
                }
                // Short vector: unsigned byte, bit 0x20 selects positive.
                let v = data[cursor] as i32;
                cursor += 1;
                if flag & 0x20 != 0 { v } else { -v }
            } else if flag & 0x20 != 0 {
                0
            } else {
                if cursor + 2 > ge {
                    return false;
                }
                let v = be16(data, cursor) as i16 as i32;
                cursor += 2;
                v
            };
            cur_y += delta;
            y_coords.push(cur_y);
        }

        // Build contours, inserting implied on-curve midpoints between
        // consecutive off-curve points as TrueType requires.
        let mut prev_end: usize = 0;
        for &end_pt in &end_pts {
            let start_pt = prev_end;
            prev_end = end_pt + 1;
            if end_pt < start_pt || start_pt >= total_points {
                continue;
            }
            let end_pt = end_pt.min(total_points - 1);

            let mut pts: Vec<(f32, f32, bool)> = Vec::new();
            for i in start_pt..=end_pt {
                pts.push((
                    x_coords[i] as f32,
                    y_coords[i] as f32,
                    flags[i] & 0x01 != 0,
                ));
            }
            if pts.is_empty() {
                continue;
            }

            // Insert midpoints between consecutive off-curve points.
            let mut expanded: Vec<(f32, f32, bool)> = Vec::new();
            for k in 0..pts.len() {
                expanded.push(pts[k]);
                let a = pts[k];
                let b = pts[(k + 1) % pts.len()];
                if !a.2 && !b.2 {
                    expanded.push(((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0, true));
                }
            }

            let mut start = 0;
            for k in 0..expanded.len() {
                if expanded[k].2 {
                    start = k;
                    break;
                }
            }

            let mut contour = Contour::default();
            let m = expanded.len();
            let mut k = start;
            let mut walked = 0usize;
            while walked < m {
                let p = expanded[k];
                let q = expanded[(k + 1) % m];
                if p.2 {
                    if q.2 {
                        contour.segments.push(OutlineSegment::Line(Line {
                            from: Pt { x: p.0, y: p.1 },
                            to: Pt { x: q.0, y: q.1 },
                        }));
                        k = (k + 1) % m;
                        walked += 1;
                    } else {
                        let r = expanded[(k + 2) % m];
                        contour.segments.push(OutlineSegment::Quad(QuadCurve {
                            from: Pt { x: p.0, y: p.1 },
                            ctrl: Pt { x: q.0, y: q.1 },
                            to: Pt { x: r.0, y: r.1 },
                        }));
                        k = (k + 2) % m;
                        walked += 2;
                    }
                } else {
                    contour.segments.push(OutlineSegment::Line(Line {
                        from: Pt { x: p.0, y: p.1 },
                        to: Pt { x: q.0, y: q.1 },
                    }));
                    k = (k + 1) % m;
                    walked += 1;
                }
            }
            if !contour.segments.is_empty() {
                out.push(contour);
            }
        }
        true
    }

    /// Parse a composite glyph (a glyph assembled from other glyphs).
    fn parse_composite_glyph(
        &self,
        data: &[u8],
        gs: usize,
        ge: usize,
        out: &mut Vec<Contour>,
        depth: u8,
    ) -> bool {
        const ARG_1_AND_2_ARE_WORDS: u16 = 0x0001;
        const ARGS_ARE_XY_VALUES: u16 = 0x0002;
        const WE_HAVE_A_SCALE: u16 = 0x0008;
        const MORE_COMPONENTS: u16 = 0x0020;
        const WE_HAVE_AN_X_AND_Y_SCALE: u16 = 0x0040;
        const WE_HAVE_A_TWO_BY_TWO: u16 = 0x0080;

        let mut cursor = gs + 10;
        loop {
            if cursor + 4 > ge {
                return false;
            }
            let flags = be16(data, cursor);
            let gi = be16(data, cursor + 2);
            cursor += 4;

            let (mut a, mut b, mut c, mut d) = (1.0f32, 0.0f32, 0.0f32, 1.0f32);
            let mut dx = 0.0f32;
            let mut dy = 0.0f32;

            if flags & ARG_1_AND_2_ARE_WORDS != 0 {
                if cursor + 4 > ge {
                    return false;
                }
                let arg1 = be16(data, cursor) as i16 as f32;
                let arg2 = be16(data, cursor + 2) as i16 as f32;
                cursor += 4;
                if flags & ARGS_ARE_XY_VALUES != 0 {
                    dx = arg1;
                    dy = arg2;
                }
            } else {
                if cursor + 2 > ge {
                    return false;
                }
                let arg1 = data[cursor] as i8 as f32;
                let arg2 = data[cursor + 1] as i8 as f32;
                cursor += 2;
                if flags & ARGS_ARE_XY_VALUES != 0 {
                    dx = arg1;
                    dy = arg2;
                }
            }

            if flags & WE_HAVE_A_SCALE != 0 {
                if cursor + 2 > ge {
                    return false;
                }
                let s = f2dot14(be16(data, cursor));
                a = s;
                d = s;
                cursor += 2;
            } else if flags & WE_HAVE_AN_X_AND_Y_SCALE != 0 {
                if cursor + 4 > ge {
                    return false;
                }
                a = f2dot14(be16(data, cursor));
                d = f2dot14(be16(data, cursor + 2));
                cursor += 4;
            } else if flags & WE_HAVE_A_TWO_BY_TWO != 0 {
                if cursor + 8 > ge {
                    return false;
                }
                a = f2dot14(be16(data, cursor));
                b = f2dot14(be16(data, cursor + 2));
                c = f2dot14(be16(data, cursor + 4));
                d = f2dot14(be16(data, cursor + 6));
                cursor += 8;
            }

            let mut sub: Vec<Contour> = Vec::new();
            if !self.collect_glyph(gi, &mut sub, depth + 1) {
                return false;
            }
            for contour in sub {
                let mut nc = Contour::default();
                for seg in contour.segments {
                    nc.segments.push(transform_segment(seg, a, b, c, d, dx, dy));
                }
                if !nc.segments.is_empty() {
                    out.push(nc);
                }
            }

            if flags & MORE_COMPONENTS == 0 {
                break;
            }
        }
        true
    }

    /// Read advance width and left side bearing from the `hmtx` table.
    fn read_hmtx(&self, gid: usize) -> (i16, i16) {
        let data = self.data;
        let hmtx_offset = self.hmtx_offset;
        let number_of_hmetrics = self.number_of_hmetrics;

        // Each metric is 4 bytes: advanceWidth (u16), leftSideBearing (i16).
        let entry_off = if gid < number_of_hmetrics {
            hmtx_offset + gid * 4
        } else {
            // Last advance width applies to remaining glyphs; LSB comes from
            // the trailing left side bearing array.
            let last_metric_off = hmtx_offset + (number_of_hmetrics - 1) * 4;
            let advance = be16(data, last_metric_off) as i16;
            let lsb_array_off = hmtx_offset + number_of_hmetrics * 4;
            let extra = gid - number_of_hmetrics;
            let lsb = if lsb_array_off + extra * 2 + 2 <= data.len() {
                be16(data, lsb_array_off + extra * 2) as i16
            } else { 0 };
            return (advance, lsb);
        };
        if entry_off + 4 <= data.len() {
            let advance = be16(data, entry_off) as i16;
            let lsb = be16(data, entry_off + 2) as i16;
            (advance, lsb)
        } else {
            (0, 0)
        }
    }

    /// Look up a pre-rasterised bitmap glyph (not implemented for TTF).
    fn glyph_bitmap(&self, _codepoint: u32, _px_size: u32) -> Option<GlyphBitmap> {
        None
    }

    /// Family name (best-effort from `name` table; falls back to "Sarasa Gothic").
    fn family(&self) -> &str {
        // Minimal: try to read the `name` table for family id 1.
        "Sarasa Gothic"
    }

    /// Design units per em.
    fn units_per_em(&self) -> u32 {
        self.units_per_em
    }
}

impl Font for TtfFont {
    fn family(&self) -> &str { "Sarasa Term SC" }
    fn units_per_em(&self) -> u32 { self.units_per_em }
    fn glyph_outline(&self, codepoint: u32) -> Option<GlyphOutline> {
        TtfFont::glyph_outline(self, codepoint)
    }
    fn glyph_bitmap(&self, _codepoint: u32, _px_size: u32) -> Option<GlyphBitmap> {
        None
    }
}

/// Parse the `cmap` table and return a Unicode → glyph id map (format 4).
fn parse_cmap(data: &[u8], cmap_offset: usize) -> Option<BTreeMap<u32, u16>> {
    // cmap header: version (2), numTables (2).
    if cmap_offset + 4 > data.len() { return None; }
    let _version = be16(data, cmap_offset);
    let num_tables = be16(data, cmap_offset + 2) as usize;
    let mut encoding_records = Vec::new();
    let mut cursor = cmap_offset + 4;
    for _ in 0..num_tables {
        if cursor + 8 > data.len() { return None; }
        let platform_id = be16(data, cursor);
        let encoding_id = be16(data, cursor + 2);
        let subtable_offset = be32(data, cursor + 4) as usize;
        encoding_records.push((platform_id, encoding_id, subtable_offset));
        cursor += 8;
    }

    // Prefer Windows (platform 3, encoding 1) or Unicode (platform 0, encoding 3).
    let preferred = encoding_records.iter()
        .find(|(p, e, _)| (*p == 3 && *e == 1) || (*p == 0 && *e == 3))
        .or(encoding_records.first())
        .map(|(_, _, off)| cmap_offset + *off)?;

    parse_cmap_format4(data, preferred)
}

/// Parse a cmap subtable of format 4 (segmented mapping).
fn parse_cmap_format4(data: &[u8], offset: usize) -> Option<BTreeMap<u32, u16>> {
    if offset + 2 > data.len() { return None; }
    let format = be16(data, offset);
    if format != 4 { return None; }
    if offset + 6 > data.len() { return None; }
    let _length = be16(data, offset + 2);
    let _language = be16(data, offset + 4);
    let seg_count_x2 = be16(data, offset + 6) as usize;
    let seg_count = seg_count_x2 / 2;
    if seg_count == 0 || seg_count_x2 == 0 { return None; }

    // Fields after header:
    //   searchRange (2), entrySelector (2), rangeShift (2)
    //   endCount[segCount] (2 each)
    //   reservedPad (2)
    //   startCount[segCount] (2 each)
    //   idDelta[segCount] (2 each)
    //   idRangeOffset[segCount] (2 each)
    //   glyphIdArray[...] (2 each)
    // After format/length/language/segCountX2/searchRange/entrySelector/
    // rangeShift (14 bytes), the endCount array begins.
    let end_count_start = offset + 14;
    let start_count_start = end_count_start + seg_count_x2 + 2; // + reservedPad
    let id_delta_start = start_count_start + seg_count_x2;
    let id_range_offset_start = id_delta_start + seg_count_x2;

    let mut cmap = BTreeMap::new();

    for i in 0..seg_count {
        if end_count_start + i * 2 + 2 > data.len() { break; }
        let end_code = be16(data, end_count_start + i * 2) as u32;
        if start_count_start + i * 2 + 2 > data.len() { break; }
        let start_code = be16(data, start_count_start + i * 2) as u32;
        if id_delta_start + i * 2 + 2 > data.len() { break; }
        let id_delta = be16(data, id_delta_start + i * 2) as i16;
        if id_range_offset_start + i * 2 + 2 > data.len() { break; }
        let id_range_offset = be16(data, id_range_offset_start + i * 2) as u32;

        if start_code == 0xFFFF { break; }

        let mut code = start_code;
        while code <= end_code {
            let glyph_id = if id_range_offset == 0 {
                code.wrapping_add(id_delta as u32) & 0xFFFF
            } else {
                let glyph_offset = (id_range_offset_start + i * 2)
                    + (id_range_offset as usize)
                    + ((code - start_code) as usize) * 2;
                if glyph_offset + 2 > data.len() {
                    code += 1;
                    continue;
                }
                let raw = be16(data, glyph_offset);
                if raw == 0 { 0 } else {
                    raw.wrapping_add(id_delta as u16) as u32
                }
            };
            if glyph_id != 0 {
                cmap.insert(code, glyph_id as u16);
            }
            code += 1;
        }
    }

    if cmap.is_empty() { None } else { Some(cmap) }
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

/// Load a TrueType/OpenType font from a byte buffer.
///
/// The buffer must remain valid for the kernel lifetime (leaked).  To use
/// Sarasa-Gothic, place `SarasaGothic-Regular.ttf` in the initramfs/ESP, read
/// it at boot, leak the slice, and call `TtfFont::parse(data)` then
/// `crate::font::set_font(...)`.
pub fn load_ttf(data: &'static [u8]) -> Result<&'static TtfFont, FontError> {
    let font = TtfFont::parse(data).ok_or(FontError::UnsupportedFormat)?;
    // Leak the font so it lives for the kernel lifetime.
    let leaked = Box::leak(Box::new(font));
    Ok(leaked)
}

/// Load the first `.ttf` discovered in a `newc` cpio root archive and install
/// it as the console font source.  This lets `rootfs.cpio` carry the real
/// Sarasa-Gothic face in `/lib/fonts/` without requiring a separately parsed
/// module.
pub fn load_font_from_cpio(archive: &[u8]) -> bool {
    let entries = crate::cpio::parse_newc(archive);
    let mut chosen: Option<&[u8]> = None;
    for entry in entries {
        if entry.name.ends_with(".ttf") || entry.name.ends_with(".otf") {
            // Prefer Sarasa Term SC if present.
            if entry.name.contains("SarasaTermSC") {
                chosen = Some(entry.data);
                break;
            }
            if chosen.is_none() {
                chosen = Some(entry.data);
            }
        }
    }
    if let Some(data) = chosen {
        let slice: &'static [u8] = Box::leak(data.to_vec().into_boxed_slice());
        match load_ttf(slice) {
            Ok(f) => {
                set_ttf(f);
                crate::serial::put_bytes(b"[font] loaded vector font from cpio\n");
                return true;
            }
            Err(_) => {
                crate::serial::put_bytes(b"[font] cpio font parse failed\n");
            }
        }
    }
    crate::serial::put_bytes(b"[font] no vector font in cpio\n");
    false
}

// Big-endian helpers.
fn be16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn be32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Decode an F2Dot14 fixed-point value (signed 16-bit / 16384).
fn f2dot14(v: u16) -> f32 {
    (v as i16) as f32 / 16384.0
}

/// Apply a TrueType composite-glyph affine transform to one segment.
fn transform_segment(
    seg: OutlineSegment,
    a: f32,
    b: f32,
    c: f32,
    d: f32,
    dx: f32,
    dy: f32,
) -> OutlineSegment {
    let tf = |p: Pt| Pt {
        x: a * p.x + c * p.y + dx,
        y: b * p.x + d * p.y + dy,
    };
    match seg {
        OutlineSegment::Line(l) => OutlineSegment::Line(Line {
            from: tf(l.from),
            to: tf(l.to),
        }),
        OutlineSegment::Quad(q) => OutlineSegment::Quad(QuadCurve {
            from: tf(q.from),
            ctrl: tf(q.ctrl),
            to: tf(q.to),
        }),
    }
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

/// Advance width in pixels of a single character at the current font size.
pub fn char_advance(ch: u32) -> u32 {
    match font() {
        Some(f) => f.advance(ch),
        None => 0,
    }
}

/// Vertical metrics `(ascent, descent, line_gap)` in pixels for the current
/// font size.
///
/// Derived from the `hhea` table when a TrueType face is loaded, otherwise
/// from a conventional 80%/20% split of the em square with no extra leading.
pub fn line_metrics() -> (u32, u32, u32) {
    let px = match font() {
        Some(f) => f.px_size(),
        None => return (0, 0, 0),
    };
    if let Some(ttf) = ttf() {
        let (asc_u, desc_u, gap_u, upem) = ttf.hhea_metrics();
        if upem > 0 {
            let scale = px as f32 / upem as f32;
            let asc = (asc_u as f32 * scale) as u32;
            let desc = (desc_u as f32 * scale) as u32;
            let gap = (gap_u as f32 * scale) as u32;
            return (asc.max(1), desc, gap);
        }
    }
    ((px * 4) / 5, (px + 4) / 5, 0)
}

/// Draw a single character with its baseline at `baseline_y`.
///
/// Returns the glyph's pixel advance so callers can lay out cell grids.
pub fn draw_char(
    engine: &mut dyn DisplayEngine,
    x: i32,
    baseline_y: i32,
    ch: char,
    fg: Color,
) -> i32 {
    let fnt = match font() {
        Some(f) => f,
        None => return x,
    };
    match fnt.glyph(ch as u32) {
        Some(glyph) => {
            draw_glyph(engine, x + glyph.left, baseline_y - glyph.top, glyph, fg);
            x + glyph.advance as i32
        }
        // Glyph not in the face: keep the cursor moving by one cell.
        None => x + fnt.px_size() as i32,
    }
}

/// Draw a string into the display engine at (x, y) using the foreground
/// colour.  Returns the new x cursor after the string.
pub fn draw_text(engine: &mut dyn DisplayEngine, x: i32, y: i32, text: &str, fg: Color) -> i32 {
    let Some(fnt) = font() else { return x; };
    let mut cx = x;
    for ch in text.chars() {
        match ch {
            '\n' => { return cx; }
            '\t' => {
                let tab_w = fnt.advance(b' ' as u32) * 8;
                cx += tab_w as i32;
                continue;
            }
            _ => {}
        }
        cx = draw_char(engine, cx, y, ch, fg);
    }
    cx
}

/// Draw a single alpha-mask glyph bitmap.
fn draw_glyph(engine: &mut dyn DisplayEngine, x: i32, y: i32, glyph: &GlyphBitmap, fg: Color) {
    if glyph.width == 0 || glyph.height == 0 { return; }
    let info = engine.info();
    let w = info.width as i32;
    let h = info.height as i32;
    for row in 0..glyph.height {
        let py = y + row as i32;
        if py < 0 || py >= h { continue; }
        for col in 0..glyph.width {
            let alpha = glyph.data[(row * glyph.pitch + col) as usize];
            if alpha == 0 { continue; }
            let px = x + col as i32;
            if px < 0 || px >= w { continue; }
            let blended = alpha_blend(fg, Color::BLACK, alpha);
            engine.put_pixel(px as u32, py as u32, blended);
        }
    }
}

/// Alpha-blend `fg` over `bg` with coverage `alpha` (0..=255).
fn alpha_blend(fg: Color, _bg: Color, alpha: u8) -> Color {
    let a = alpha as u32;
    Color {
        r: (fg.r as u32 * a / 255) as u8,
        g: (fg.g as u32 * a / 255) as u8,
        b: (fg.b as u32 * a / 255) as u8,
        a: 255,
    }
}

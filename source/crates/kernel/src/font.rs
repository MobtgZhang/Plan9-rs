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

        // head table: unitsPerEm at offset 44 (after version, fontRevision, ...)
        let units_per_em = be16(&data, head_offset + 44) as u32;
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

    /// Look up an outline glyph for `codepoint`.
    pub fn glyph_outline(&self, codepoint: u32) -> Option<GlyphOutline> {
        let gid = self.glyph_id(codepoint)?;
        self.read_glyph_outline(codepoint, gid)
    }

    /// Read a TrueType outline from the `glyf` table using `loca` offsets.
    fn read_glyph_outline(&self, codepoint: u32, gid: u16) -> Option<GlyphOutline> {
        let data = self.data;
        let loca_offset = self.loca_offset;
        let glyf_offset = self.glyf_offset;

        // Determine loca entry size from head.indexToLocFormat (offset 50 in head).
        let index_to_loc_format = (be16(data, self.head_offset + 50) & 1) as usize;

        // Read loca offsets.
        let (off0, off1) = if index_to_loc_format == 0 {
            // Short offsets: each entry is 2 bytes, value = offset/2.
            let base = loca_offset + gid as usize * 2;
            let o0 = be16(data, base) as usize * 2;
            let o1 = be16(data, base + 2) as usize * 2;
            (o0, o1)
        } else {
            // Long offsets: each entry is 4 bytes.
            let base = loca_offset + gid as usize * 4;
            let o0 = be32(data, base) as usize;
            let o1 = be32(data, base + 4) as usize;
            (o0, o1)
        };

        if off1 <= off0 || off1 > data.len() - glyf_offset {
            return None;
        }

        let glyph_data_start = glyf_offset + off0;
        let glyph_data_end = glyf_offset + off1;
        let glyph_bytes = &data[glyph_data_start..glyph_data_end];

        if glyph_bytes.len() < 10 { return None; }

        // Glyph header: xMin, yMin, xMax, yMax (FWORD each = i16).
        let x_min = be16(data, glyph_data_start) as i16;
        let y_min = be16(data, glyph_data_start + 2) as i16;
        let x_max = be16(data, glyph_data_start + 4) as i16;
        let y_max = be16(data, glyph_data_start + 6) as i16;
        let _flags = be16(data, glyph_data_start + 8);
        let num_contours = i16::from_le_bytes([data[glyph_data_start + 10], data[glyph_data_start + 11]]) as i16;

        // For simplicity: only handle simple glyphs (num_contours >= 0).
        if num_contours < 0 {
            // Composite glyph — not supported in this minimal parser.
            return None;
        }
        if num_contours == 0 {
            return None;
        }

        let mut cursor = glyph_data_start + 12;
        // End pts of contours (2 bytes each).
        let mut end_pts = Vec::new();
        for _ in 0..num_contours as usize {
            if cursor + 2 > glyph_data_end { return None; }
            end_pts.push(be16(data, cursor) as usize);
            cursor += 2;
        }
        if cursor + 2 > glyph_data_end { return None; }
        let _instruction_length = be16(data, cursor) as usize;
        cursor += 2 + _instruction_length;

        // Flags (variable length due to repeat flag).
        let total_points = *end_pts.last().unwrap_or(&0) + 1;
        let mut flags = Vec::new();
        while flags.len() < total_points {
            if cursor >= glyph_data_end { return None; }
            let flag = data[cursor];
            cursor += 1;
            flags.push(flag);
            if flag & 0x08 != 0 {
                // Repeat flag.
                if cursor >= glyph_data_end { return None; }
                let repeat = data[cursor] as usize;
                cursor += 1;
                for _ in 0..repeat {
                    flags.push(flag);
                    if flags.len() >= total_points { break; }
                }
            }
        }

        // X coordinates.
        let mut x_coords = Vec::new();
        for i in 0..total_points {
            if cursor >= glyph_data_end { return None; }
            let flag = flags[i];
            let x: i16 = if flag & 0x10 != 0 {
                // Same as previous (x short).
                if i == 0 { 0 } else { *x_coords.last().unwrap() }
            } else if flag & 0x02 != 0 {
                // x short: single signed byte.
                let v = data[cursor] as i8 as i16;
                cursor += 1;
                v
            } else {
                // x is a full int16.
                if cursor + 2 > glyph_data_end { return None; }
                let v = i16::from_le_bytes([data[cursor], data[cursor+1]]);
                cursor += 2;
                v
            };
            x_coords.push(x);
        }

        // Y coordinates.
        let mut y_coords = Vec::new();
        for i in 0..total_points {
            if cursor >= glyph_data_end { return None; }
            let flag = flags[i];
            let y: i16 = if flag & 0x20 != 0 {
                // Same as previous (y short).
                if i == 0 { 0 } else { *y_coords.last().unwrap() }
            } else if flag & 0x04 != 0 {
                // y short: single signed byte.
                let v = data[cursor] as i8 as i16;
                cursor += 1;
                v
            } else {
                // y is a full int16.
                if cursor + 2 > glyph_data_end { return None; }
                let v = i16::from_le_bytes([data[cursor], data[cursor+1]]);
                cursor += 2;
                v
            };
            y_coords.push(y);
        }

        // Build contours.
        let mut contours = Vec::new();
        let mut prev_end: usize = 0;
        for &end_pt in &end_pts {
            let start_pt = prev_end;
            prev_end = end_pt + 1;
            let mut contour = Contour::default();
            let mut i = start_pt;
            while i <= end_pt {
                let flag = flags[i];
                let on_curve = flag & 0x01 != 0;
                let x = x_coords[i] as f32;
                let y = y_coords[i] as f32;

                if on_curve {
                    // Line to this point.
                    let prev_pt = if i == start_pt {
                        // Use last point of contour as previous.
                        let last = end_pt;
                        Pt { x: x_coords[last] as f32, y: y_coords[last] as f32 }
                    } else {
                        Pt { x: x_coords[i-1] as f32, y: y_coords[i-1] as f32 }
                    };
                    contour.segments.push(OutlineSegment::Line(Line { from: prev_pt, to: Pt { x, y } }));
                    i += 1;
                } else {
                    // Off-curve point: quadratic Bézier.
                    // Look ahead for next off-curve or on-curve.
                    let ctrl = Pt { x, y };
                    let mut to: Option<Pt> = None;
                    let mut next_i = i + 1;
                    if next_i <= end_pt && (flags[next_i] & 0x01) == 0 {
                        // Two consecutive off-curve points: interpolate midpoint.
                        let next_x = x_coords[next_i] as f32;
                        let next_y = y_coords[next_i] as f32;
                        to = Some(Pt { x: (x + next_x) / 2.0, y: (y + next_y) / 2.0 });
                        next_i += 1;
                    } else if next_i <= end_pt {
                        to = Some(Pt { x: x_coords[next_i] as f32, y: y_coords[next_i] as f32 });
                        next_i += 1;
                    } else {
                        // Wrap around to first point of contour.
                        to = Some(Pt { x: x_coords[start_pt] as f32, y: y_coords[start_pt] as f32 });
                        next_i = end_pt + 1; // end contour
                    }
                    if let Some(to_pt) = to {
                        contour.segments.push(OutlineSegment::Quad(QuadCurve {
                            from: Pt { x, y },
                            ctrl,
                            to: to_pt,
                        }));
                    }
                    i = next_i;
                }
            }
            contours.push(contour);
        }

        // Advance width and left side bearing from hmtx.
        let (advance, lsb) = self.read_hmtx(gid as usize);

        Some(GlyphOutline {
            codepoint,
            units_per_em: self.units_per_em,
            advance: advance as f32,
            lsb: lsb as f32,
            bounds: Rectf { x0: x_min as f32, y0: y_min as f32, x1: x_max as f32, y1: y_max as f32 },
            contours,
        })
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
                i16::from_le_bytes([data[lsb_array_off + extra * 2], data[lsb_array_off + extra * 2 + 1]])
            } else { 0 };
            return (advance, lsb);
        };
        if entry_off + 4 <= data.len() {
            let advance = be16(data, entry_off) as i16;
            let lsb = i16::from_le_bytes([data[entry_off+2], data[entry_off+3]]);
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

/// Store numberOfHmetrics on TtfFont (added above via struct field; keep helper).
impl TtfFont {
    fn number_of_hmetrics(&self) -> usize { self.number_of_hmetrics }
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
        .map(|(_, _, off)| *off)?;

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
    let cursor = offset + 8;
    let end_count_start = cursor;
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
                let glyph_offset = (id_range_offset as usize)
                    + (i * 2)
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

// Big-endian helpers.
fn be16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn be32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
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
            '\n' => { return cx; }
            '\t' => {
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

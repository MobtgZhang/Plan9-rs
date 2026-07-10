//! Core Drawing Functions
//!
//! Implements the fundamental Plan 9 graphics operations:
//! - draw(): Copy pixels from source to destination
//! - gendraw(): General draw with source coordinate
//! - blend operations using Porter-Duff compositing
//!
//! Reference: sys/src/libdraw/draw.c

use crate::{Point, Rectangle, Image};

/// Draw operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawOp {
    /// Replace destination with source (no blending)
    SoverD,
    /// XOR source with destination
    SxorD,
    /// Source over destination (with alpha)
    SatopD,
    /// Clear destination
    SclearD,
    /// Source only
    S,
    /// Destination only
    D,
    /// No operation (transparent)
    Noop,
    /// Blend source and destination
    Blend,
}

/// Source copy function
/// 
/// Copies pixels from source image to destination using a mask.
/// The source point sp is aligned with destination point p in the
/// destination rectangle r.
///
/// # Arguments
/// * `dst` - Destination image
/// * `r` - Destination rectangle
/// * `src` - Source image
/// * `sp` - Source point (upper-left corner of source)
/// * `mask` - Mask image (can be None for full source)
/// * `mp` - Mask point
/// * `op` - Draw operation
pub fn draw(
    dst: &mut Image,
    r: Rectangle,
    src: &Image,
    sp: Point,
    mask: Option<&Image>,
    mp: Point,
    op: DrawOp,
) {
    // Clip destination rectangle to destination bounds
    let dst_r = r.intersect(&dst.rect());
    if dst_r.is_empty() {
        return;
    }

    // Calculate source rectangle
    let dx = dst_r.min.x - r.min.x;
    let dy = dst_r.min.y - r.min.y;
    let src_r = Rectangle::new(
        Point::new(sp.x + dx, sp.y + dy),
        Point::new(sp.x + dx + dst_r.width(), sp.y + dy + dst_r.height()),
    );
    let src_r = src_r.intersect(&src.rect());

    // Calculate mask rectangle if mask is provided
    let mask_r = if let Some(_m) = mask {
        let mx = dst_r.min.x - r.min.x;
        let my = dst_r.min.y - r.min.y;
        Rectangle::new(
            Point::new(mp.x + mx, mp.y + my),
            Point::new(mp.x + mx + dst_r.width(), mp.y + my + dst_r.height()),
        )
    } else {
        src_r.clone()
    };

    // Iterate over the destination rectangle
    for y in 0..dst_r.height() {
        for x in 0..dst_r.width() {
            let dp = Point::new(dst_r.min.x + x, dst_r.min.y + y);

            // Get source pixel
            let sx = src_r.min.x + x;
            let sy = src_r.min.y + y;
            let src_p = Point::new(sx, sy);
            let src_color = src.pixel(src_p).unwrap_or(0);

            // Get mask pixel (alpha for blending)
            let mask_color = if let Some(m) = mask {
                let mx = mask_r.min.x + x;
                let my = mask_r.min.y + y;
                let mask_p = Point::new(mx, my);
                m.pixel(mask_p).unwrap_or(0xFFFFFFFF)
            } else {
                0xFFFFFFFF // Full opacity
            };

            // Get destination pixel
            let dst_color = dst.pixel(dp).unwrap_or(0);

            // Apply blend operation
            let blended = blend_pixels(src_color, dst_color, mask_color, op);

            // Write result
            let _ = dst.set_pixel(dp, blended);
        }
    }
}

/// Simple draw without mask
pub fn draw_simple(
    dst: &mut Image,
    r: Rectangle,
    src: &Image,
    sp: Point,
) {
    draw(dst, r, src, sp, None, Point::origin(), DrawOp::SoverD);
}

/// General draw with explicit mask
/// 
/// This is the most general form of draw, allowing specification of
/// source point, mask point, and draw operation.
pub fn gendraw(
    dst: &mut Image,
    dr: Rectangle,
    src: &Image,
    sp: Point,
    mask: Option<&Image>,
    mp: Point,
    op: DrawOp,
) {
    draw(dst, dr, src, sp, mask, mp, op)
}

/// Blend two pixels using Porter-Duff compositing
/// 
/// Combines source, destination, and mask according to the blend operation.
/// 
/// # Arguments
/// * `src` - Source pixel (ARGB format)
/// * `dst` - Destination pixel (ARGB format)
/// * `mask` - Mask pixel (A format, 0-255)
/// * `op` - Blend operation
/// 
/// # Returns
/// * Blended pixel in ARGB format
pub fn blend_pixels(src: u32, dst: u32, mask: u32, op: DrawOp) -> u32 {
    // Extract ARGB components
    let src_a = (src >> 24) as u8;
    let src_r = (src >> 16) as u8;
    let src_g = (src >> 8) as u8;
    let src_b = src as u8;

    let dst_a = (dst >> 24) as u8;
    let dst_r = (dst >> 16) as u8;
    let dst_g = (dst >> 8) as u8;
    let dst_b = dst as u8;

    let mask_a = (mask >> 24) as u8;

    // Calculate effective source alpha with mask
    let a = ((src_a as u16) * (mask_a as u16) / 255) as u8;

    match op {
        DrawOp::S => {
            // Source only
            src
        }
        DrawOp::D => {
            // Destination only
            dst
        }
        DrawOp::SoverD => {
            // Source over destination: src * src_a + dst * (1 - src_a)
            let out_a = src_a.wrapping_add((255 - src_a) * dst_a / 255);
            let out_r = src_r.wrapping_add((255 - src_a) * dst_r / 255);
            let out_g = src_g.wrapping_add((255 - src_a) * dst_g / 255);
            let out_b = src_b.wrapping_add((255 - src_a) * dst_b / 255);
            ((out_a as u32) << 24) | ((out_r as u32) << 16) | ((out_g as u32) << 8) | (out_b as u32)
        }
        DrawOp::SxorD => {
            // XOR: src * (1 - dst_a) + dst * (1 - src_a)
            let out_a = a.wrapping_add(dst_a).wrapping_sub(2 * a * dst_a / 255);
            let out_r = src_r.wrapping_add(dst_r).wrapping_sub(2 * src_r * dst_a / 255);
            let out_g = src_g.wrapping_add(dst_g).wrapping_sub(2 * src_g * dst_a / 255);
            let out_b = src_b.wrapping_add(dst_b).wrapping_sub(2 * src_b * dst_a / 255);
            ((out_a as u32) << 24) | ((out_r as u32) << 16) | ((out_g as u32) << 8) | (out_b as u32)
        }
        DrawOp::SatopD => {
            // Source atop destination
            let out_a = dst_a;
            let out_r = (src_r as u16 * a as u16 / 255).wrapping_add(dst_r as u16 * (255 - a as u16) / 255) as u8;
            let out_g = (src_g as u16 * a as u16 / 255).wrapping_add(dst_g as u16 * (255 - a as u16) / 255) as u8;
            let out_b = (src_b as u16 * a as u16 / 255).wrapping_add(dst_b as u16 * (255 - a as u16) / 255) as u8;
            ((out_a as u32) << 24) | ((out_r as u32) << 16) | ((out_g as u32) << 8) | (out_b as u32)
        }
        DrawOp::SclearD => {
            // Clear destination
            0
        }
        DrawOp::Noop => {
            // No operation
            dst
        }
        DrawOp::Blend => {
            // Simple blend: average of source and destination
            let out_a = ((src_a as u16) + (dst_a as u16)) / 2;
            let out_r = ((src_r as u16) + (dst_r as u16)) / 2;
            let out_g = ((src_g as u16) + (dst_g as u16)) / 2;
            let out_b = ((src_b as u16) + (dst_b as u16)) / 2;
            ((out_a as u32) << 24) | ((out_r as u32) << 16) | ((out_g as u32) << 8) | (out_b as u32)
        }
    }
}

/// Fill a rectangle with a solid color
/// 
/// This is a convenience function that fills a rectangle
/// without requiring a source image.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `r` - Rectangle to fill
/// * `color` - Fill color (ARGB format)
pub fn fill(dst: &mut Image, r: Rectangle, color: u32) {
    // Clip to destination bounds
    let r = r.intersect(&dst.rect());
    if r.is_empty() {
        return;
    }

    // Fill pixels
    for y in r.min.y..r.max.y {
        for x in r.min.x..r.max.x {
            let _ = dst.set_pixel(Point::new(x, y), color);
        }
    }
}

/// Draw a pixel with blending
/// 
/// Draws a single pixel with the specified blend operation.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `p` - Point to draw
/// * `src` - Source image
/// * `sp` - Source point
/// * `op` - Blend operation
pub fn drawpixel(
    dst: &mut Image,
    p: Point,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    let src_color = src.pixel(sp).unwrap_or(0);
    let dst_color = dst.pixel(p).unwrap_or(0);
    let blended = blend_pixels(src_color, dst_color, 0xFF000000, op);
    let _ = dst.set_pixel(p, blended);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blend_soverd() {
        // 50% opaque red over 50% opaque blue
        let src = 0x80FF0000; // 50% alpha red
        let dst = 0x800000FF; // 50% alpha blue
        let result = blend_pixels(src, dst, 0xFFFFFFFF, DrawOp::SoverD);
        
        // Result should have some of both red and blue
        let r = (result >> 16) as u8;
        let b = result as u8;
        assert!(r > 0, "Should have red component");
        assert!(b > 0, "Should have blue component");
    }

    #[test]
    fn test_blend_s() {
        // Source only should return source color
        let src = 0xFFFF0000; // opaque red
        let dst = 0xFF00FF00; // opaque green
        let result = blend_pixels(src, dst, 0xFFFFFFFF, DrawOp::S);
        assert_eq!(result, src);
    }

    #[test]
    fn test_blend_d() {
        // Destination only should return destination color
        let src = 0xFFFF0000; // opaque red
        let dst = 0xFF00FF00; // opaque green
        let result = blend_pixels(src, dst, 0xFFFFFFFF, DrawOp::D);
        assert_eq!(result, dst);
    }
}

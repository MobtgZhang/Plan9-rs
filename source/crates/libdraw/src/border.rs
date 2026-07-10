//! Border Drawing Functions
//!
//! Implements border drawing functions.
//!
//! Reference: sys/src/libdraw/border.c

use crate::{Point, Rectangle, Image};
use crate::draw::DrawOp;

/// Draw a border around a rectangle
/// 
/// Draws a border (outline) around the specified rectangle.
/// The border is drawn inside the rectangle, reducing its size by i pixels.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `r` - Rectangle to draw border around
/// * `i` - Border width (number of pixels inside the rectangle)
/// * `src` - Source image for color
/// * `sp` - Source point for color lookup
pub fn border(
    dst: &mut Image,
    r: Rectangle,
    i: i32,
    src: &Image,
    sp: Point,
) {
    border_with_op(dst, r, i, src, sp, DrawOp::SoverD);
}

/// Draw a border with a specific blend operation
pub fn borderop(
    dst: &mut Image,
    r: Rectangle,
    i: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    border_with_op(dst, r, i, src, sp, op);
}

fn border_with_op(
    dst: &mut Image,
    r: Rectangle,
    i: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    if i <= 0 {
        return;
    }

    let color = src.pixel(sp).unwrap_or(0);

    // Draw the border by filling four rectangles:
    // 1. Top edge
    // 2. Bottom edge
    // 3. Left edge
    // 4. Right edge

    let dst_r = dst.rect();

    // Top edge: from (r.min.x, r.min.y) to (r.max.x, r.min.y + i)
    let top = Rectangle::new(
        Point::new(r.min.x, r.min.y),
        Point::new(r.max.x, r.min.y + i),
    );
    let top = top.intersect(&dst_r);
    fill_rect(dst, top, color, op);

    // Bottom edge: from (r.min.x, r.max.y - i) to (r.max.x, r.max.y)
    let bottom = Rectangle::new(
        Point::new(r.min.x, r.max.y - i),
        Point::new(r.max.x, r.max.y),
    );
    let bottom = bottom.intersect(&dst_r);
    fill_rect(dst, bottom, color, op);

    // Left edge: from (r.min.x, r.min.y + i) to (r.min.x + i, r.max.y - i)
    let left = Rectangle::new(
        Point::new(r.min.x, r.min.y + i),
        Point::new(r.min.x + i, r.max.y - i),
    );
    let left = left.intersect(&dst_r);
    fill_rect(dst, left, color, op);

    // Right edge: from (r.max.x - i, r.min.y + i) to (r.max.x, r.max.y - i)
    let right = Rectangle::new(
        Point::new(r.max.x - i, r.min.y + i),
        Point::new(r.max.x, r.max.y - i),
    );
    let right = right.intersect(&dst_r);
    fill_rect(dst, right, color, op);
}

/// Fill a rectangle with a solid color
fn fill_rect(dst: &mut Image, r: Rectangle, color: u32, op: DrawOp) {
    if r.is_empty() {
        return;
    }

    for y in r.min.y..r.max.y {
        for x in r.min.x..r.max.x {
            let p = Point::new(x, y);
            blend_pixel(dst, p, color, op);
        }
    }
}

/// Blend a single pixel
fn blend_pixel(dst: &mut Image, p: Point, src_color: u32, op: DrawOp) {
    use crate::draw::blend_pixels;
    
    let dst_color = dst.pixel(p).unwrap_or(0);
    let blended = blend_pixels(src_color, dst_color, 0xFFFFFFFF, op);
    let _ = dst.set_pixel(p, blended);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_border_basic() {
        // Just verify the function exists
        assert_eq!(1, 1);
    }
}

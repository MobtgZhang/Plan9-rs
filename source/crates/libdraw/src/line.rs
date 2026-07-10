//! Line Drawing Functions
//!
//! Implements Bresenham's line drawing algorithm and related functions.
//!
//! Reference: sys/src/libdraw/line.c

use crate::{Point, Image};
use crate::draw::DrawOp;

/// Line end style
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Square end (default)
    Square,
    /// Round end
    Round,
    /// Butt end (no cap)
    Butt,
    /// Arrow end
    Arrow,
}

/// Draw a line between two points
/// 
/// Uses Bresenham's algorithm for efficient line drawing.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `p1` - Starting point
/// * `p2` - Ending point
/// * `end0` - Style of starting end
/// * `end1` - Style of ending end
/// * `width` - Line width in pixels
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
pub fn line(
    dst: &mut Image,
    p1: Point,
    p2: Point,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
) {
    let op = DrawOp::SoverD;
    line_with_op(dst, p1, p2, end0, end1, width, src, sp, op);
}

/// Draw a line with a specific blend operation
pub fn lineop(
    dst: &mut Image,
    p1: Point,
    p2: Point,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    line_with_op(dst, p1, p2, end0, end1, width, src, sp, op);
}

/// Internal line drawing implementation
fn line_with_op(
    dst: &mut Image,
    p1: Point,
    p2: Point,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    let dx = (p2.x - p1.x).abs();
    let dy = (p2.y - p1.y).abs();
    let sx = if p1.x < p2.x { 1 } else { -1 };
    let sy = if p1.y < p2.y { 1 } else { -1 };
    let mut err = if dx > dy { dx } else { -dy } / 2;
    let mut err2: i32;

    let mut x = p1.x;
    let mut y = p1.y;

    // Calculate texture/color offset
    let color = src.pixel(sp).unwrap_or(0);

    loop {
        // Draw pixel at (x, y)
        draw_line_pixel(dst, x, y, width, color, op);

        if x == p2.x && y == p2.y {
            break;
        }

        err2 = err;
        if err2 > -dx {
            err -= dy;
            x += sx;
        }
        if err2 < dy {
            err += dx;
            y += sy;
        }
    }

    // Draw end caps
    draw_end(dst, p1, end0, width, src, sp, op);
    draw_end(dst, p2, end1, width, src, sp, op);
}

/// Draw a single pixel with width
fn draw_line_pixel(dst: &mut Image, x: i32, y: i32, width: i32, color: u32, op: DrawOp) {
    if width <= 1 {
        // Single pixel
        let p = Point::new(x, y);
        if dst.rect().contains(p) {
            blend_pixel(dst, p, color, op);
        }
    } else {
        // Draw a small filled circle for width > 1
        let radius = width / 2;
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= radius * radius {
                    let p = Point::new(x + dx, y + dy);
                    if dst.rect().contains(p) {
                        blend_pixel(dst, p, color, op);
                    }
                }
            }
        }
    }
}

/// Draw end cap
fn draw_end(
    dst: &mut Image,
    p: Point,
    end: End,
    width: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    let color = src.pixel(sp).unwrap_or(0);

    match end {
        End::Square => {
            // Draw a square at the end point
            let half = width / 2;
            for dy in -half..=half {
                for dx in -half..=half {
                    let pt = Point::new(p.x + dx, p.y + dy);
                    if dst.rect().contains(pt) {
                        blend_pixel(dst, pt, color, op);
                    }
                }
            }
        }
        End::Round => {
            // Draw a filled circle at the end point
            let radius = width / 2;
            for dy in -radius..=radius {
                for dx in -radius..=radius {
                    if dx * dx + dy * dy <= radius * radius {
                        let pt = Point::new(p.x + dx, p.y + dy);
                        if dst.rect().contains(pt) {
                            blend_pixel(dst, pt, color, op);
                        }
                    }
                }
            }
        }
        End::Butt => {
            // No cap needed - line ends exactly at point
        }
        End::Arrow => {
            // Draw arrow head at the end
            draw_arrow_head(dst, p, width, color, op);
        }
    }
}

/// Draw an arrow head at the end of a line
fn draw_arrow_head(dst: &mut Image, p: Point, size: i32, color: u32, op: DrawOp) {
    let half = size / 2 + 1;
    // Draw a simple triangle pointing at the end
    for dy in 0..=half {
        for dx in -dy..=dy {
            let pt = Point::new(p.x + dx, p.y + dy);
            if dst.rect().contains(pt) {
                blend_pixel(dst, pt, color, op);
            }
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

/// Polyline - draw connected line segments
/// 
/// Draws a series of connected line segments from an array of points.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `pt` - Array of points
/// * `n` - Number of points
/// * `end0` - Style of starting end
/// * `end1` - Style of ending end
/// * `width` - Line width in pixels
/// * `src` - Source image for color
/// * `sp` - Source point
pub fn polyline(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
) {
    if n < 2 {
        return;
    }

    // Draw line segments
    for i in 0..n - 1 {
        let p1 = pt[i];
        let p2 = pt[i + 1];
        
        // Only draw end cap on first and last segments
        let e0 = if i == 0 { end0 } else { End::Butt };
        let e1 = if i == n - 2 { end1 } else { End::Butt };
        
        line(dst, p1, p2, e0, e1, width, src, sp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_styles() {
        // Just verify the enum variants exist
        assert_eq!(End::Square, End::Square);
        assert_eq!(End::Round, End::Round);
        assert_eq!(End::Butt, End::Butt);
        assert_eq!(End::Arrow, End::Arrow);
    }
}

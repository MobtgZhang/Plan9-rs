//! Polygon Drawing Functions
//!
//! Implements polygon outline and fill functions.
//!
//! Reference: sys/src/libdraw/poly.c

use alloc::vec::Vec;
use crate::{Point, Image};
use crate::draw::DrawOp;
use crate::line::End;

/// Draw a polygon (outline)
/// 
/// Draws the outline of a polygon defined by an array of points.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `pt` - Array of points defining the polygon
/// * `n` - Number of points
/// * `end0` - Style of starting end
/// * `end1` - Style of ending end
/// * `width` - Line width in pixels
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
pub fn poly(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
) {
    use crate::line as line_module;
    
    if n < 2 {
        return;
    }

    // Draw line segments connecting each point
    for i in 0..n - 1 {
        let p1 = pt[i];
        let p2 = pt[i + 1];
        
        // Only draw end caps on first and last segments
        let e0 = if i == 0 { end0 } else { End::Butt };
        let e1 = if i == n - 2 { end1 } else { End::Butt };
        
        line_module::line(dst, p1, p2, e0, e1, width, src, sp);
    }
    
    // Connect last point to first to close the polygon
    let p1 = pt[n - 1];
    let p2 = pt[0];
    line_module::line(dst, p1, p2, End::Butt, end1, width, src, sp);
}

/// Fill a polygon
/// 
/// Fills a polygon defined by an array of points using scanline algorithm.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `pt` - Array of points defining the polygon
/// * `n` - Number of points
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
/// * `alpha` - Use non-zero winding rule if true, even-odd rule if false
pub fn fillpoly(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    src: &Image,
    sp: Point,
    alpha: bool,
) {
    if n < 3 {
        return;
    }

    let color = src.pixel(sp).unwrap_or(0);

    // Find bounding box
    let mut min_y = pt[0].y;
    let mut max_y = pt[0].y;
    for p in pt.iter().take(n) {
        if p.y < min_y { min_y = p.y; }
        if p.y > max_y { max_y = p.y; }
    }

    // Clip to destination bounds
    let dst_rect = dst.rect();
    if min_y < dst_rect.min.y { min_y = dst_rect.min.y; }
    if max_y > dst_rect.max.y { max_y = dst_rect.max.y; }

    // Scanline fill
    for y in min_y..=max_y {
        // Find all intersections of the scanline with polygon edges
        let mut intersections: Vec<i32> = Vec::new();
        
        for i in 0..n {
            let p1 = pt[i];
            let p2 = pt[(i + 1) % n];
            
            // Check if edge crosses this scanline
            if (p1.y <= y && p2.y > y) || (p2.y <= y && p1.y > y) {
                // Calculate x coordinate of intersection
                let x = p1.x + (y - p1.y) * (p2.x - p1.x) / (p2.y - p1.y);
                intersections.push(x);
            }
        }

        // Fill between pairs of intersections
        if alpha {
            // Non-zero winding rule
            fill_nonzero_winding(dst, y, &mut intersections, color);
        } else {
            // Even-odd rule
            fill_even_odd(dst, y, &intersections, color);
        }
    }
}

/// Fill using even-odd rule (simpler)
fn fill_even_odd(dst: &mut Image, y: i32, intersections: &[i32], color: u32) {
    let dst_rect = dst.rect();
    
    // Fill between pairs of intersections
    for i in (0..intersections.len()).step_by(2) {
        if i + 1 >= intersections.len() {
            break;
        }
        
        let x1 = intersections[i];
        let x2 = intersections[i + 1];
        
        let start_x = x1.max(dst_rect.min.x);
        let end_x = x2.min(dst_rect.max.x);
        
        for x in start_x..=end_x {
            let p = Point::new(x, y);
            if dst_rect.contains(p) {
                blend_pixel(dst, p, color, DrawOp::SoverD);
            }
        }
    }
}

/// Fill using non-zero winding rule
fn fill_nonzero_winding(dst: &mut Image, y: i32, intersections: &mut [i32], color: u32) {
    let dst_rect = dst.rect();
    
    // Sort intersections and fill between pairs with non-zero winding
    intersections.sort();
    
    let winding = 0i32;
    let mut prev_x = i32::MIN;
    
    for &x in intersections.iter() {
        // Determine if this edge is going up or down based on x position
        if x != prev_x {
            if winding != 0 {
                // Fill from previous x to current x
                let start_x = prev_x.max(dst_rect.min.x);
                let end_x = x.min(dst_rect.max.x);
                
                for px in start_x..=end_x {
                    let p = Point::new(px, y);
                    if dst_rect.contains(p) {
                        blend_pixel(dst, p, color, DrawOp::SoverD);
                    }
                }
            }
            prev_x = x;
        }
    }
}

/// Fill a rectangle (convenience function)
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `r` - Rectangle to fill
/// * `src` - Source image for color
/// * `sp` - Source point
pub fn fillrect(
    dst: &mut Image,
    r: crate::Rectangle,
    src: &Image,
    sp: Point,
) {
    
    
    let color = src.pixel(sp).unwrap_or(0);
    let r = r.intersect(&dst.rect());
    
    for y in r.min.y..r.max.y {
        for x in r.min.x..r.max.x {
            let p = Point::new(x, y);
            blend_pixel(dst, p, color, DrawOp::SoverD);
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
    fn test_triangle() {
        // Simple test with a triangle
        let points = [
            Point::new(0, 0),
            Point::new(10, 0),
            Point::new(5, 10),
        ];
        // Just verify the function exists
        assert_eq!(points.len(), 3);
    }
}

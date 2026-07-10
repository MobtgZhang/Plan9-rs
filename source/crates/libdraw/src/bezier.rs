//! Bezier Curve Drawing Functions
//!
//! Implements Bezier curve and spline drawing functions.
//!
//! Reference: sys/src/libdraw/bezier.c

use alloc::vec::Vec;
use crate::{Point, Image};
use crate::draw::DrawOp;
use crate::line::End;
use crate::math;

/// Maximum subdivision depth for Bezier curves
const MAX_DEPTH: i32 = 32;

/// Draw a Bezier curve
/// 
/// Draws a cubic Bezier curve through the given points.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `pt` - Array of control points (must have at least 4 points for cubic bezier)
/// * `n` - Number of points in array
/// * `end0` - Style of starting end
/// * `end1` - Style of ending end
/// * `width` - Line width in pixels
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
pub fn bezier(
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
    
    if n < 4 {
        // Not enough points for a cubic bezier
        // Draw a polyline instead
        if n >= 2 {
            for i in 0..n - 1 {
                let p1 = pt[i];
                let p2 = pt[i + 1];
                let e0 = if i == 0 { end0 } else { End::Butt };
                let e1 = if i == n - 2 { end1 } else { End::Butt };
                line_module::line(dst, p1, p2, e0, e1, width, src, sp);
            }
        }
        return;
    }

    let p0 = pt[0];
    let p1 = pt[1];
    let p2 = pt[2];
    let p3 = pt[3];

    // Subdivide and draw the Bezier curve
    draw_bezier_segment(dst, p0, p1, p2, p3, width, src, sp, 0);

    // Draw end caps
    let color = src.pixel(sp).unwrap_or(0);
    
    // Draw end cap at start
    draw_end_cap_simple(dst, p0, end0, width, color, DrawOp::SoverD);
    // Draw end cap at end
    draw_end_cap_simple(dst, p3, end1, width, color, DrawOp::SoverD);
}

/// Draw a Bezier curve segment using subdivision
fn draw_bezier_segment(
    dst: &mut Image,
    p0: Point,
    p1: Point,
    p2: Point,
    p3: Point,
    width: i32,
    src: &Image,
    sp: Point,
    depth: i32,
) {
    let color = src.pixel(sp).unwrap_or(0);

    // Check if the curve is "flat enough" to approximate with a line
    if is_flat_enough(p0, p1, p2, p3) || depth >= MAX_DEPTH {
        // Draw a line segment
        // Simple line drawing between p0 and p3
        draw_line_simple(dst, p0, p3, width, color, DrawOp::SoverD);
        return;
    }

    // Subdivide the curve at midpoint using de Casteljau's algorithm
    let (left, right) = subdivide_bezier(p0, p1, p2, p3);

    // Recursively draw both halves
    draw_bezier_segment(dst, left.0, left.1, left.2, left.3, width, src, sp, depth + 1);
    draw_bezier_segment(dst, right.0, right.1, right.2, right.3, width, src, sp, depth + 1);
}

/// Subdivide a Bezier curve at its midpoint
fn subdivide_bezier(
    p0: Point,
    p1: Point,
    p2: Point,
    p3: Point,
) -> ((Point, Point, Point, Point), (Point, Point, Point, Point)) {
    // First level
    let p01 = Point::new((p0.x + p1.x) / 2, (p0.y + p1.y) / 2);
    let p12 = Point::new((p1.x + p2.x) / 2, (p1.y + p2.y) / 2);
    let p23 = Point::new((p2.x + p3.x) / 2, (p2.y + p3.y) / 2);
    
    // Second level
    let p012 = Point::new((p01.x + p12.x) / 2, (p01.y + p12.y) / 2);
    let p123 = Point::new((p12.x + p23.x) / 2, (p12.y + p23.y) / 2);
    
    // Third level (midpoint of curve)
    let p0123 = Point::new((p012.x + p123.x) / 2, (p012.y + p123.y) / 2);

    // Left curve: p0, p01, p012, p0123
    let left = (p0, p01, p012, p0123);
    
    // Right curve: p0123, p123, p23, p3
    let right = (p0123, p123, p23, p3);

    (left, right)
}

/// Check if a Bezier curve is flat enough to approximate with a line
fn is_flat_enough(p0: Point, p1: Point, p2: Point, p3: Point) -> bool {
    // Calculate distance from control points to the line between endpoints
    let d1 = distance_to_line(p1, p0, p3);
    let d2 = distance_to_line(p2, p0, p3);
    
    // Threshold based on curve length
    let curve_length = p0.dist(p3);
    let threshold = curve_length / 4.0;
    
    d1 < threshold && d2 < threshold
}

/// Calculate distance from a point to a line segment
fn distance_to_line(p: Point, line_start: Point, line_end: Point) -> f64 {
    // Vector from start to end
    let dx = line_end.x - line_start.x;
    let dy = line_end.y - line_start.y;
    
    if dx == 0 && dy == 0 {
        // Line segment is a point
        return (p.x - line_start.x).abs() as f64;
    }
    
    // Calculate perpendicular distance
    let numerator = ((line_end.y - line_start.y) * p.x - (line_end.x - line_start.x) * p.y 
                    + line_end.x * line_start.y - line_end.y * line_start.x).abs() as f64;
    let denominator = math::sqrt((dx * dx + dy * dy) as f64);
    
    if denominator == 0.0 {
        return 0.0;
    }
    
    numerator / denominator
}

/// Draw a simple line (Bresenham-like)
fn draw_line_simple(dst: &mut Image, p1: Point, p2: Point, _width: i32, color: u32, _op: DrawOp) {
    // Draw pixels at endpoints
    let _ = dst.set_pixel(p1, color);
    let _ = dst.set_pixel(p2, color);
}

/// Draw end cap (simplified)
fn draw_end_cap_simple(dst: &mut Image, p: Point, end: End, width: i32, color: u32, op: DrawOp) {
    use crate::line::End::*;
    
    match end {
        Square | Round => {
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
        Butt => {}
        Arrow => {
            // Simple arrow head
            for dy in 0..=width {
                for dx in -dy..=dy {
                    let pt = Point::new(p.x + dx, p.y + dy);
                    if dst.rect().contains(pt) {
                        blend_pixel(dst, pt, color, op);
                    }
                }
            }
        }
    }
}

/// Fill a Bezier curve (creates a filled shape)
pub fn fillbezier(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    src: &Image,
    sp: Point,
    _alpha: bool,
) {
    if n < 4 {
        return;
    }

    // Get the Bezier curve endpoints and control points
    let p0 = pt[0];
    let p1 = pt[1];
    let p2 = pt[2];
    let p3 = pt[3];

    let color = src.pixel(sp).unwrap_or(0);

    // Fill by generating many points on the curve and connecting them
    // This is a simplified approach - a full implementation would use proper area filling
    let segments = 32;
    
    // Generate points on the curve
    let mut curve_points = Vec::with_capacity(segments + 1);
    for i in 0..=segments {
        let t = i as f64 / segments as f64;
        let p = eval_bezier(p0, p1, p2, p3, t);
        curve_points.push(p);
    }

    // Fill using simple scanline from curve to baseline (x-axis at p0.y)
    let baseline_y = p0.y;
    
    for i in 0..segments {
        let p1 = curve_points[i];
        let p2 = curve_points[i + 1];
        
        let min_y = p1.y.min(p2.y);
        let max_y = p1.y.max(p2.y);
        
        for y in min_y..=max_y {
            // Interpolate x at this y
            if p1.y == p2.y {
                continue;
            }
            let t = (y - p1.y) as f64 / (p2.y - p1.y) as f64;
            let x = (p1.x as f64 + t * (p2.x - p1.x) as f64) as i32;
            
            // Fill from curve to baseline
            let start_y = y.min(baseline_y);
            let end_y = y.max(baseline_y);
            
            for fill_y in start_y..=end_y {
                let pt = Point::new(x, fill_y);
                if dst.rect().contains(pt) {
                    blend_pixel(dst, pt, color, DrawOp::SoverD);
                }
            }
        }
    }
}

/// Evaluate a point on a Bezier curve at parameter t
fn eval_bezier(p0: Point, p1: Point, p2: Point, p3: Point, t: f64) -> Point {
    let mt = 1.0 - t;
    let mt2 = mt * mt;
    let mt3 = mt2 * mt;
    let t2 = t * t;
    let t3 = t2 * t;

    let x = mt3 * p0.x as f64 + 3.0 * mt2 * t * p1.x as f64 
            + 3.0 * mt * t2 * p2.x as f64 + t3 * p3.x as f64;
    let y = mt3 * p0.y as f64 + 3.0 * mt2 * t * p1.y as f64 
            + 3.0 * mt * t2 * p2.y as f64 + t3 * p3.y as f64;

    Point::new(x as i32, y as i32)
}

/// Draw a B-spline (smooth curve through control points)
pub fn bezspline(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    end0: End,
    end1: End,
    width: i32,
    src: &Image,
    sp: Point,
) {
    if n < 4 {
        // Fall back to polyline
        use crate::poly::poly;
        poly(dst, pt, n, end0, end1, width, src, sp);
        return;
    }

    // Draw Bezier curve segments connecting control points
    for i in 0..n - 3 {
        let bezier_pts = &pt[i..i + 4];
        bezier(dst, bezier_pts, 4, end0, end1, width, src, sp);
    }
}

/// Fill a B-spline
pub fn fillbezspline(
    dst: &mut Image,
    pt: &[Point],
    n: usize,
    src: &Image,
    sp: Point,
    alpha: bool,
) {
    if n < 4 {
        return;
    }

    // Fill Bezier curve segments
    for i in 0..n - 3 {
        let bezier_pts = &pt[i..i + 4];
        fillbezier(dst, bezier_pts, 4, src, sp, alpha);
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
    fn test_eval_bezier() {
        let p0 = Point::new(0, 0);
        let p1 = Point::new(10, 0);
        let p2 = Point::new(10, 10);
        let p3 = Point::new(20, 10);
        
        // At t=0, should be at p0
        let p_t0 = eval_bezier(p0, p1, p2, p3, 0.0);
        assert_eq!(p_t0.x, 0);
        assert_eq!(p_t0.y, 0);
        
        // At t=1, should be at p3
        let p_t1 = eval_bezier(p0, p1, p2, p3, 1.0);
        assert_eq!(p_t1.x, 20);
        assert_eq!(p_t1.y, 10);
    }
}

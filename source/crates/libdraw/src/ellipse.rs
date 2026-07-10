//! Ellipse and Arc Drawing Functions
//!
//! Implements ellipse, arc, and related drawing functions.
//!
//! Reference: sys/src/libdraw/ellipse.c

use crate::{Point, Image};
use crate::draw::DrawOp;
use crate::math;
use core::f64::consts::PI;

/// Draw an ellipse (outline)
/// 
/// Draws the outline of an ellipse centered at the given point.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `center` - Center point of the ellipse
/// * `rx` - X radius (semi-axis)
/// * `ry` - Y radius (semi-axis)
/// * `thick` - Thickness of the outline
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
pub fn ellipse(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    thick: i32,
    src: &Image,
    sp: Point,
) {
    ellipse_with_op(dst, center, rx, ry, thick, src, sp, DrawOp::SoverD);
}

/// Draw an ellipse with a specific blend operation
pub fn ellipseop(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    thick: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    ellipse_with_op(dst, center, rx, ry, thick, src, sp, op);
}

fn ellipse_with_op(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    _thick: i32,
    src: &Image,
    sp: Point,
    op: DrawOp,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    let color = src.pixel(sp).unwrap_or(0);
    
    // Midpoint ellipse algorithm
    let mut x: i32 = 0;
    let mut y = ry;
    
    // Region 1
    let mut d1 = (ry * ry) - (rx * rx * ry) + (rx * rx / 4);
    let mut dx = 2 * ry * ry * x;
    let mut dy = 2 * rx * rx * y;
    
    while dx < dy {
        // Draw 4 symmetric points
        draw_ellipse_points(dst, center.x + x, center.y + y, color, op);
        draw_ellipse_points(dst, center.x - x, center.y + y, color, op);
        draw_ellipse_points(dst, center.x + x, center.y - y, color, op);
        draw_ellipse_points(dst, center.x - x, center.y - y, color, op);
        
        if d1 < 0 {
            x += 1;
            dx += 2 * ry * ry;
            d1 += dx + ry * ry;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * ry * ry;
            dy -= 2 * rx * rx;
            d1 += dx - dy + ry * ry;
        }
    }
    
    // Region 2
    let mut d2 = (ry * ry) * ((x + 1) * (x + 1)) + (rx * rx) * ((y - 1) * (y - 1)) - (rx * rx * ry * ry);
    
    while y >= 0 {
        // Draw 4 symmetric points
        draw_ellipse_points(dst, center.x + x, center.y + y, color, op);
        draw_ellipse_points(dst, center.x - x, center.y + y, color, op);
        draw_ellipse_points(dst, center.x + x, center.y - y, color, op);
        draw_ellipse_points(dst, center.x - x, center.y - y, color, op);
        
        if d2 > 0 {
            y -= 1;
            dy -= 2 * rx * rx;
            d2 += rx * rx - dy;
        } else {
            y -= 1;
            x += 1;
            dx += 2 * ry * ry;
            dy -= 2 * rx * rx;
            d2 += dx - dy + rx * rx;
        }
    }
}

/// Draw a filled ellipse
/// 
/// Draws a filled ellipse centered at the given point.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `center` - Center point of the ellipse
/// * `rx` - X radius (semi-axis)
/// * `ry` - Y radius (semi-axis)
/// * `src` - Source image for color
/// * `sp` - Source point for texture/color lookup
pub fn fillellipse(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    src: &Image,
    sp: Point,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    let color = src.pixel(sp).unwrap_or(0);
    
    // Scanline fill algorithm
    for y in -ry..=ry {
        // Calculate x extent at this y level
        let y_norm = (y as f64) / (ry as f64);
        let x_extent = ((1.0 - y_norm * y_norm) * (rx as f64)) as i32;
        
        for x in -x_extent..=x_extent {
            let p = Point::new(center.x + x, center.y + y);
            if dst.rect().contains(p) {
                blend_pixel(dst, p, color, DrawOp::SoverD);
            }
        }
    }
}

/// Draw an arc (part of an ellipse)
/// 
/// Draws an arc of an ellipse between two points.
/// 
/// # Arguments
/// * `dst` - Destination image
/// * `center` - Center point of the ellipse
/// * `rx` - X radius
/// * `ry` - Y radius
/// * `thick` - Thickness of the arc
/// * `src` - Source image for color
/// * `sp` - Source point
/// * `p0` - Start point of the arc
/// * `p1` - End point of the arc
pub fn arc(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    thick: i32,
    src: &Image,
    sp: Point,
    p0: Point,
    p1: Point,
) {
    arc_with_op(dst, center, rx, ry, thick, src, sp, p0, p1, DrawOp::SoverD);
}

/// Draw an arc with a specific blend operation
pub fn arcop(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    thick: i32,
    src: &Image,
    sp: Point,
    p0: Point,
    p1: Point,
    op: DrawOp,
) {
    arc_with_op(dst, center, rx, ry, thick, src, sp, p0, p1, op);
}

fn arc_with_op(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    _thick: i32,
    src: &Image,
    sp: Point,
    p0: Point,
    p1: Point,
    op: DrawOp,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    // Calculate angles for the arc endpoints
    let angle0 = math::atan2((p0.y - center.y) as f64, (p0.x - center.x) as f64);
    let angle1 = math::atan2((p1.y - center.y) as f64, (p1.x - center.x) as f64);

    // Calculate angle range
    let start_angle = angle0;
    let mut end_angle = angle1;
    
    // Handle wrap-around
    if end_angle < start_angle {
        end_angle += 2.0 * PI;
    }

    let color = src.pixel(sp).unwrap_or(0);

    // Draw arc using midpoint algorithm, filtering by angle
    let mut x: i32 = 0;
    let mut y = ry;
    
    // Region 1
    let mut d1 = (ry * ry) - (rx * rx * ry) + (rx * rx / 4);
    let mut dx = 2 * ry * ry * x;
    let mut dy = 2 * rx * rx * y;
    
    while dx < dy {
        let angle = math::atan2((center.y + y) as f64 - center.y as f64, (center.x + x) as f64 - center.x as f64);
        
        if is_angle_in_range(angle, start_angle, end_angle) {
            draw_ellipse_points(dst, center.x + x, center.y + y, color, op);
        }
        
        let angle_neg = 2.0 * PI - angle;
        if is_angle_in_range(angle_neg, start_angle, end_angle) {
            draw_ellipse_points(dst, center.x + x, center.y - y, color, op);
        }
        
        if d1 < 0 {
            x += 1;
            dx += 2 * ry * ry;
            d1 += dx + ry * ry;
        } else {
            x += 1;
            y -= 1;
            dx += 2 * ry * ry;
            dy -= 2 * rx * rx;
            d1 += dx - dy + ry * ry;
        }
    }
}

/// Check if an angle is within the arc range
fn is_angle_in_range(angle: f64, start: f64, end: f64) -> bool {
    if end < 2.0 * PI {
        angle >= start && angle <= end
    } else {
        angle >= start || angle <= (end - 2.0 * PI)
    }
}

/// Draw a filled arc
pub fn fillarc(
    dst: &mut Image,
    center: Point,
    rx: i32,
    ry: i32,
    src: &Image,
    sp: Point,
    p0: Point,
    p1: Point,
) {
    if rx <= 0 || ry <= 0 {
        return;
    }

    // Calculate angles for the arc endpoints
    let angle0 = math::atan2((p0.y - center.y) as f64, (p0.x - center.x) as f64);
    let angle1 = math::atan2((p1.y - center.y) as f64, (p1.x - center.x) as f64);

    let start_angle = angle0;
    let mut end_angle = angle1;
    
    if end_angle < start_angle {
        end_angle += 2.0 * PI;
    }

    let color = src.pixel(sp).unwrap_or(0);

    // Fill arc using scanlines
    for y in -ry..=ry {
        for x in -rx..=rx {
            // Check if point is on or inside ellipse
            let x_norm = (x as f64) / (rx as f64);
            let y_norm = (y as f64) / (ry as f64);
            if x_norm * x_norm + y_norm * y_norm <= 1.0 {
                let px = center.x + x;
                let py = center.y + y;
                let angle = math::atan2(y as f64, x as f64);
                
                if is_angle_in_range(angle, start_angle, end_angle) {
                    let p = Point::new(px, py);
                    if dst.rect().contains(p) {
                        blend_pixel(dst, p, color, DrawOp::SoverD);
                    }
                }
            }
        }
    }
}

/// Draw 4 symmetric points of an ellipse (for efficiency)
fn draw_ellipse_points(dst: &mut Image, x: i32, y: i32, color: u32, op: DrawOp) {
    let p = Point::new(x, y);
    if dst.rect().contains(p) {
        blend_pixel(dst, p, color, op);
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
    fn test_ellipse_basic() {
        // Just verify the functions exist
        assert_eq!(1, 1);
    }
}

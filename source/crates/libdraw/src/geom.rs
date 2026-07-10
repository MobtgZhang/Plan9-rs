//! Geometry Types
//!
//! Basic geometric types for the Plan 9 graphics library.

use crate::math;

/// Point in 2D space
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Point {
    /// X coordinate
    pub x: i32,
    /// Y coordinate
    pub y: i32,
}

impl Point {
    /// Create a new point
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }

    /// Create origin point (0, 0)
    pub fn origin() -> Self {
        Self { x: 0, y: 0 }
    }

    /// Add two points
    pub fn add(self, other: Point) -> Point {
        Point::new(self.x + other.x, self.y + other.y)
    }

    /// Subtract two points
    pub fn sub(self, other: Point) -> Point {
        Point::new(self.x - other.x, self.y - other.y)
    }

    /// Multiply point by scalar
    pub fn mul(self, scalar: i32) -> Point {
        Point::new(self.x * scalar, self.y * scalar)
    }

    /// Divide point by scalar
    pub fn div(self, scalar: i32) -> Point {
        Point::new(self.x / scalar, self.y / scalar)
    }

    /// Calculate distance to another point
    pub fn dist(self, other: Point) -> f64 {
        let dx = (self.x - other.x) as f64;
        let dy = (self.y - other.y) as f64;
        math::sqrt(dx * dx + dy * dy)
    }

    /// Calculate squared distance to another point
    pub fn dist2(self, other: Point) -> i64 {
        let dx = (self.x - other.x) as i64;
        let dy = (self.y - other.y) as i64;
        dx * dx + dy * dy
    }

    /// Check if point is in rectangle
    pub fn in_rect(self, r: Rectangle) -> bool {
        r.contains(self)
    }
}

impl core::ops::Add<Point> for Point {
    type Output = Point;
    fn add(self, other: Point) -> Point {
        self.add(other)
    }
}

impl core::ops::Sub<Point> for Point {
    type Output = Point;
    fn sub(self, other: Point) -> Point {
        self.sub(other)
    }
}

impl core::ops::Mul<i32> for Point {
    type Output = Point;
    fn mul(self, scalar: i32) -> Point {
        self.mul(scalar)
    }
}

impl core::ops::Div<i32> for Point {
    type Output = Point;
    fn div(self, scalar: i32) -> Point {
        self.div(scalar)
    }
}

/// Size in 2D space
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Size {
    /// Width
    pub width: i32,
    /// Height
    pub height: i32,
}

impl Size {
    /// Create a new size
    pub fn new(width: i32, height: i32) -> Self {
        Self { width, height }
    }

    /// Create zero size
    pub fn zero() -> Self {
        Self { width: 0, height: 0 }
    }

    /// Check if size is zero
    pub fn is_zero(&self) -> bool {
        self.width == 0 && self.height == 0
    }

    /// Calculate area
    pub fn area(&self) -> i64 {
        (self.width as i64) * (self.height as i64)
    }
}

/// Rectangle defined by two corners
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rectangle {
    /// Minimum corner (inclusive)
    pub min: Point,
    /// Maximum corner (exclusive)
    pub max: Point,
}

impl Rectangle {
    /// Create a new rectangle from two corners
    pub fn new(min: Point, max: Point) -> Self {
        Self { min, max }
    }

    /// Create rectangle from origin and size
    pub fn from_size(origin: Point, size: Size) -> Self {
        Self {
            min: origin,
            max: Point::new(origin.x + size.width, origin.y + size.height),
        }
    }

    /// Create zero rectangle
    pub fn zero() -> Self {
        Self {
            min: Point::origin(),
            max: Point::origin(),
        }
    }

    /// Check if rectangle is empty
    pub fn is_empty(&self) -> bool {
        self.min.x >= self.max.x || self.min.y >= self.max.y
    }

    /// Get width
    pub fn width(&self) -> i32 {
        self.max.x - self.min.x
    }

    /// Get height
    pub fn height(&self) -> i32 {
        self.max.y - self.min.y
    }

    /// Get size
    pub fn size(&self) -> Size {
        Size::new(self.width(), self.height())
    }

    /// Check if point is inside rectangle
    pub fn contains(&self, p: Point) -> bool {
        p.x >= self.min.x && p.x < self.max.x && p.y >= self.min.y && p.y < self.max.y
    }

    /// Check if rectangle intersects another
    pub fn intersects(&self, other: &Rectangle) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && self.min.x < other.max.x
            && self.max.x > other.min.x
            && self.min.y < other.max.y
            && self.max.y > other.min.y
    }

    /// Get intersection of two rectangles
    pub fn intersect(&self, other: &Rectangle) -> Rectangle {
        if !self.intersects(other) {
            return Rectangle::zero();
        }

        Rectangle::new(
            Point::new(
                self.min.x.max(other.min.x),
                self.min.y.max(other.min.y),
            ),
            Point::new(
                self.max.x.min(other.max.x),
                self.max.y.min(other.max.y),
            ),
        )
    }

    /// Get union of two rectangles
    pub fn union(&self, other: &Rectangle) -> Rectangle {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }

        Rectangle::new(
            Point::new(
                self.min.x.min(other.min.x),
                self.min.y.min(other.min.y),
            ),
            Point::new(
                self.max.x.max(other.max.x),
                self.max.y.max(other.max.y),
            ),
        )
    }

    /// Add inset to rectangle (reduce size)
    pub fn inset(&self, n: i32) -> Rectangle {
        Rectangle::new(
            Point::new(self.min.x + n, self.min.y + n),
            Point::new(self.max.x - n, self.max.y - n),
        )
    }

    /// Add outset to rectangle (expand size)
    pub fn outset(&self, n: i32) -> Rectangle {
        self.inset(-n)
    }

    /// Translate rectangle by offset
    pub fn translate(&self, p: Point) -> Rectangle {
        Rectangle::new(self.min + p, self.max + p)
    }

    /// Get center point
    pub fn center(&self) -> Point {
        Point::new((self.min.x + self.max.x) / 2, (self.min.y + self.max.y) / 2)
    }

    /// Get minimum dimension (smaller of width and height)
    pub fn min_dim(&self) -> i32 {
        self.width().min(self.height())
    }

    /// Get maximum dimension (larger of width and height)
    pub fn max_dim(&self) -> i32 {
        self.width().max(self.height())
    }

    /// Add point to max corner
    pub fn addpt(&self, p: Point) -> Rectangle {
        Rectangle::new(self.min, self.max + p)
    }

    /// Subtract point from max corner
    pub fn subpt(&self, p: Point) -> Rectangle {
        Rectangle::new(self.min - p, self.max - p)
    }
}

/// 2D Transformation matrix (3x3 for affine transformations)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Matrix {
    /// Matrix elements [a, b, c, d, tx, ty]
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
    pub tx: f64,
    pub ty: f64,
}

impl Matrix {
    /// Create identity matrix
    pub fn identity() -> Self {
        Self {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            tx: 0.0,
            ty: 0.0,
        }
    }

    /// Create translation matrix
    pub fn translate(x: f64, y: f64) -> Self {
        Self {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            tx: x,
            ty: y,
        }
    }

    /// Create scale matrix
    pub fn scale(x: f64, y: f64) -> Self {
        Self {
            a: x,
            b: 0.0,
            c: 0.0,
            d: y,
            tx: 0.0,
            ty: 0.0,
        }
    }

    /// Create rotation matrix (angle in radians)
    pub fn rotate(angle: f64) -> Self {
        let cos_val = math::cos(angle);
        let sin_val = math::sin(angle);
        Self {
            a: cos_val,
            b: sin_val,
            c: -sin_val,
            d: cos_val,
            tx: 0.0,
            ty: 0.0,
        }
    }

    /// Multiply two matrices
    pub fn mul(self, other: Matrix) -> Matrix {
        Matrix {
            a: self.a * other.a + self.c * other.b,
            b: self.b * other.a + self.d * other.b,
            c: self.a * other.c + self.c * other.d,
            d: self.b * other.c + self.d * other.d,
            tx: self.a * other.tx + self.c * other.ty + self.tx,
            ty: self.b * other.tx + self.d * other.ty + self.ty,
        }
    }

    /// Transform a point
    pub fn transform(&self, p: Point) -> Point {
        Point::new(
            (self.a * (p.x as f64) + self.c * (p.y as f64) + self.tx) as i32,
            (self.b * (p.x as f64) + self.d * (p.y as f64) + self.ty) as i32,
        )
    }

    /// Transform a rectangle (returns bounding box)
    pub fn transform_rect(&self, r: Rectangle) -> Rectangle {
        let p1 = self.transform(r.min);
        let p2 = self.transform(Point::new(r.max.x, r.min.y));
        let p3 = self.transform(r.max);
        let p4 = self.transform(Point::new(r.min.x, r.max.y));

        Rectangle::new(
            Point::new(p1.x.min(p2.x).min(p3.x).min(p4.x), p1.y.min(p2.y).min(p3.y).min(p4.y)),
            Point::new(p1.x.max(p2.x).max(p3.x).max(p4.x), p1.y.max(p2.y).max(p3.y).max(p4.y)),
        )
    }
}

//! Types Module
//!
//! Common types used throughout Rio.

/// Point structure
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
    
    pub fn add(&self, other: &Point) -> Self {
        Self::new(self.x + other.x, self.y + other.y)
    }
    
    pub fn sub(&self, other: &Point) -> Self {
        Self::new(self.x - other.x, self.y - other.y)
    }
}

/// Rectangle structure
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect {
    pub min: Point,
    pub max: Point,
}

impl Rect {
    pub fn new(min: Point, max: Point) -> Self {
        Self { min, max }
    }
    
    pub fn from_coords(x0: i32, y0: i32, x1: i32, y1: i32) -> Self {
        Self {
            min: Point::new(x0, y0),
            max: Point::new(x1, y1),
        }
    }
    
    pub fn width(&self) -> i32 {
        self.max.x - self.min.x
    }
    
    pub fn height(&self) -> i32 {
        self.max.y - self.min.y
    }
    
    pub fn is_empty(&self) -> bool {
        self.min.x >= self.max.x || self.min.y >= self.max.y
    }
    
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.min.x && point.x < self.max.x &&
        point.y >= self.min.y && point.y < self.max.y
    }
    
    pub fn intersects(&self, other: &Rect) -> bool {
        self.min.x < other.max.x && self.max.x > other.min.x &&
        self.min.y < other.max.y && self.max.y > other.min.y
    }
    
    pub fn intersection(&self, other: &Rect) -> Option<Rect> {
        let min = Point::new(
            self.min.x.max(other.min.x),
            self.min.y.max(other.min.y),
        );
        let max = Point::new(
            self.max.x.min(other.max.x),
            self.max.y.min(other.max.y),
        );
        
        let rect = Rect::new(min, max);
        if rect.is_empty() {
            None
        } else {
            Some(rect)
        }
    }
    
    pub fn union(&self, other: &Rect) -> Rect {
        Rect::new(
            Point::new(self.min.x.min(other.min.x), self.min.y.min(other.min.y)),
            Point::new(self.max.x.max(other.max.x), self.max.y.max(other.max.y)),
        )
    }
    
    pub fn inset(&self, amount: i32) -> Rect {
        Rect::new(
            Point::new(self.min.x + amount, self.min.y + amount),
            Point::new(self.max.x - amount, self.max.y - amount),
        )
    }
    
    pub fn addpt(&self, pt: Point) -> Rect {
        Rect::new(
            Point::new(self.min.x + pt.x, self.min.y + pt.y),
            Point::new(self.max.x + pt.x, self.max.y + pt.y),
        )
    }
}

/// Color representation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
    
    pub fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }
    
    pub fn from_u32(c: u32) -> Self {
        Self {
            r: ((c >> 16) & 0xFF) as u8,
            g: ((c >> 8) & 0xFF) as u8,
            b: (c & 0xFF) as u8,
            a: ((c >> 24) & 0xFF) as u8,
        }
    }
    
    pub fn to_u32(&self) -> u32 {
        ((self.a as u32) << 24) |
        ((self.r as u32) << 16) |
        ((self.g as u32) << 8) |
        (self.b as u32)
    }
    
    // Predefined colors
    pub fn black() -> Self { Self::new(0, 0, 0) }
    pub fn white() -> Self { Self::new(255, 255, 255) }
    pub fn red() -> Self { Self::new(255, 0, 0) }
    pub fn green() -> Self { Self::new(0, 255, 0) }
    pub fn blue() -> Self { Self::new(0, 0, 255) }
    pub fn yellow() -> Self { Self::new(255, 255, 0) }
    pub fn cyan() -> Self { Self::new(0, 255, 255) }
    pub fn magenta() -> Self { Self::new(255, 0, 255) }
    pub fn gray() -> Self { Self::new(128, 128, 128) }
    pub fn light_gray() -> Self { Self::new(192, 192, 192) }
    pub fn dark_gray() -> Self { Self::new(64, 64, 64) }
    
    pub fn invert(&self) -> Self {
        Self::new(255 - self.r, 255 - self.g, 255 - self.b)
    }
}

/// Title bar height
pub const TITLE_HEIGHT: i32 = 20;

/// Border width
pub const BORDER_WIDTH: i32 = 2;

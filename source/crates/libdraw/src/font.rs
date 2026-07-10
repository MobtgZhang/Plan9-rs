//! Font Operations

use alloc::string::{String, ToString};

/// Font representation
pub struct Font {
    /// Font name
    name: String,
    /// Font height
    height: i32,
    /// Font ascent
    ascent: i32,
}

impl Font {
    /// Create a new font
    pub fn new(name: &str, height: i32, ascent: i32) -> Self {
        Self {
            name: name.to_string(),
            height,
            ascent,
        }
    }

    /// Get font name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get font height
    pub fn height(&self) -> i32 {
        self.height
    }

    /// Get font ascent
    pub fn ascent(&self) -> i32 {
        self.ascent
    }

    /// Get font metrics
    pub fn metrics(&self) -> FontMetrics {
        FontMetrics {
            name: self.name.clone(),
            height: self.height,
            ascent: self.ascent,
            descent: self.height - self.ascent,
            width_of_space: 8, // Default width for space character
        }
    }
}

/// Font metrics
#[derive(Debug, Clone)]
pub struct FontMetrics {
    /// Font name
    pub name: String,
    /// Height of font
    pub height: i32,
    /// Ascent above baseline
    pub ascent: i32,
    /// Descent below baseline
    pub descent: i32,
    /// Width of space character
    pub width_of_space: i32,
}

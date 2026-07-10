//! Window Module
//!
//! Implements the Window structure for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/wind.c`

use super::types::{Point, Rect, Color, TITLE_HEIGHT, BORDER_WIDTH};
use std::vec::Vec;

/// Window ID
pub type WindowId = u64;

/// Window state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    Normal,
    Active,
    Hidden,
    Iconic,
    Deleted,
}

/// Border position for resizing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Border {
    None,
    Left,
    Right,
    Top,
    Bottom,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
    Interior,
}

/// Window structure
pub struct Window {
    /// Unique window ID
    pub id: WindowId,
    /// Window state
    pub state: WindowState,
    /// Window rectangle (including border)
    pub rect: Rect,
    /// Inner rectangle (client area)
    pub client: Rect,
    /// Border width
    pub border: i32,
    /// Title text
    pub title: alloc::string::String,
    /// Image/frame data
    pub image: Option<Vec<u8>>,
    /// Background color
    pub background: Color,
    /// Current process
    pub pid: Option<u64>,
    /// Previous rectangle (for undo)
    pub prev_rect: Option<Rect>,
    /// Whether window is focused
    pub focused: bool,
    /// Last mouse position
    last_mouse: Point,
    /// Last mouse button state
    last_buttons: i32,
}

impl Window {
    /// Create a new window
    pub fn new(id: WindowId, rect: Rect) -> Self {
        let border = BORDER_WIDTH;
        
        Self {
            id,
            state: WindowState::Normal,
            rect,
            client: Rect {
                min: Point {
                    x: rect.min.x + border,
                    y: rect.min.y + border + TITLE_HEIGHT,
                },
                max: Point {
                    x: rect.max.x - border,
                    y: rect.max.y - border,
                },
            },
            border,
            title: alloc::string::String::from(""),
            image: None,
            background: Color::default(),
            pid: None,
            prev_rect: None,
            focused: false,
            last_mouse: Point { x: 0, y: 0 },
            last_buttons: 0,
        }
    }

    /// Create with title
    pub fn with_title(id: WindowId, rect: Rect, title: &str) -> Self {
        let mut w = Self::new(id, rect);
        w.title = alloc::string::String::from(title);
        w
    }

    /// Set title
    pub fn set_title(&mut self, title: &str) {
        self.title = alloc::string::String::from(title);
    }

    /// Get title
    pub fn get_title(&self) -> &str {
        &self.title
    }

    /// Resize window
    pub fn resize(&mut self, rect: Rect) {
        self.prev_rect = Some(self.rect);
        self.rect = rect;
        self.update_client();
    }

    /// Move window
    pub fn move_to(&mut self, point: Point) {
        self.prev_rect = Some(self.rect);
        let width = self.rect.width();
        let height = self.rect.height();
        
        self.rect = Rect {
            min: point,
            max: Point {
                x: point.x + width,
                y: point.y + height,
            },
        };
        self.update_client();
    }

    /// Update client rectangle
    fn update_client(&mut self) {
        self.client = Rect {
            min: Point {
                x: self.rect.min.x + self.border,
                y: self.rect.min.y + self.border + TITLE_HEIGHT,
            },
            max: Point {
                x: self.rect.max.x - self.border,
                y: self.rect.max.y - self.border,
            },
        };
    }

    /// Get border at position
    pub fn border_at(&self, point: Point) -> Border {
        if !self.rect.contains(point) {
            return Border::None;
        }
        
        let r = self.rect;
        let b = self.border;
        
        // Title bar
        if point.y >= r.min.y && point.y < r.min.y + TITLE_HEIGHT {
            return Border::Interior;
        }
        
        // Left border
        if point.x >= r.min.x && point.x < r.min.x + b {
            if point.y >= r.min.y + TITLE_HEIGHT && point.y < r.max.y - b {
                return Border::Left;
            }
        }
        
        // Right border
        if point.x >= r.max.x - b && point.x < r.max.x {
            if point.y >= r.min.y + TITLE_HEIGHT && point.y < r.max.y - b {
                return Border::Right;
            }
        }
        
        // Top border
        if point.y >= r.min.y + TITLE_HEIGHT && point.y < r.min.y + TITLE_HEIGHT + b {
            if point.x >= r.min.x + b && point.x < r.max.x - b {
                return Border::Top;
            }
        }
        
        // Bottom border
        if point.y >= r.max.y - b && point.y < r.max.y {
            if point.x >= r.min.x + b && point.x < r.max.x - b {
                return Border::Bottom;
            }
        }
        
        // Corners
        if point.x < r.min.x + b && point.y < r.min.y + TITLE_HEIGHT + b {
            return Border::TopLeft;
        }
        if point.x >= r.max.x - b && point.y < r.min.y + TITLE_HEIGHT + b {
            return Border::TopRight;
        }
        if point.x < r.min.x + b && point.y >= r.max.y - b {
            return Border::BottomLeft;
        }
        if point.x >= r.max.x - b && point.y >= r.max.y - b {
            return Border::BottomRight;
        }
        
        Border::Interior
    }

    /// Check if point is in title bar
    pub fn in_title(&self, point: Point) -> bool {
        let r = self.rect;
        point.x >= r.min.x && point.x < r.max.x &&
        point.y >= r.min.y && point.y < r.min.y + TITLE_HEIGHT
    }

    /// Check if point is in client area
    pub fn in_client(&self, point: Point) -> bool {
        self.client.contains(point)
    }

    /// Focus window
    pub fn focus(&mut self) {
        self.focused = true;
    }

    /// Unfocus window
    pub fn unfocus(&mut self) {
        self.focused = false;
    }

    /// Hide window
    pub fn hide(&mut self) {
        self.state = WindowState::Hidden;
    }

    /// Unhide window
    pub fn show(&mut self) {
        self.state = WindowState::Normal;
    }

    /// Delete window
    pub fn delete(&mut self) {
        self.state = WindowState::Deleted;
    }

    /// Start resize operation
    pub fn start_resize(&mut self, border: Border) {
        // Would initiate resize operation
        let _ = border;
    }

    /// Start move operation
    pub fn start_move(&mut self) {
        // Would initiate move operation
    }

    /// Get minimum size
    pub fn min_size() -> (i32, i32) {
        (50, 50)
    }

    /// Snap to grid
    pub fn snap(&mut self, grid: i32) {
        let dx = self.rect.min.x % grid;
        let dy = self.rect.min.y % grid;
        
        if dx != 0 || dy != 0 {
            self.prev_rect = Some(self.rect);
            self.rect.min.x -= dx;
            self.rect.min.y -= dy;
            self.rect.max.x -= dx;
            self.rect.max.y -= dy;
            self.update_client();
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::new(0, Rect::default())
    }
}

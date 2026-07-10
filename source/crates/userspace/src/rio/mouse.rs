//! Mouse Module
//!
//! Implements mouse event handling for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/wind.c`

use super::types::Point;

/// Mouse button
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

impl MouseButton {
    pub fn from_buttons(buttons: i32) -> Option<Self> {
        match buttons {
            1 => Some(Self::Left),
            2 => Some(Self::Middle),
            4 => Some(Self::Right),
            _ => None,
        }
    }
}

/// Mouse event kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEventKind {
    Move,
    Down,
    Up,
    DoubleClick,
}

/// Mouse event
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    pub kind: MouseEventKind,
    pub x: i32,
    pub y: i32,
    pub buttons: i32,
    pub timestamp: u64,
    pub modifiers: MouseModifiers,
}

impl MouseEvent {
    /// Create a new mouse event
    pub fn new(kind: MouseEventKind, x: i32, y: i32, buttons: i32) -> Self {
        Self {
            kind,
            x,
            y,
            buttons,
            timestamp: 0,
            modifiers: MouseModifiers::default(),
        }
    }

    /// Get position as Point
    pub fn position(&self) -> Point {
        Point::new(self.x, self.y)
    }

    /// Check if left button is pressed
    pub fn left_pressed(&self) -> bool {
        self.buttons & 1 != 0
    }

    /// Check if middle button is pressed
    pub fn middle_pressed(&self) -> bool {
        self.buttons & 2 != 0
    }

    /// Check if right button is pressed
    pub fn right_pressed(&self) -> bool {
        self.buttons & 4 != 0
    }

    /// Get button that triggered this event
    pub fn button(&self) -> Option<MouseButton> {
        MouseButton::from_buttons(self.buttons)
    }
}

/// Mouse modifiers
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
}

impl MouseModifiers {
    pub fn new(shift: bool, ctrl: bool, alt: bool) -> Self {
        Self {
            shift,
            ctrl,
            alt,
            meta: false,
        }
    }
}

/// Mouse state
pub struct MouseState {
    /// Current position
    position: Point,
    /// Current button state
    buttons: i32,
    /// Last click position
    last_click: Point,
    /// Last click time
    last_click_time: u64,
    /// Click count (for double-click detection)
    click_count: u32,
}

impl MouseState {
    /// Create new mouse state
    pub fn new() -> Self {
        Self {
            position: Point::new(0, 0),
            buttons: 0,
            last_click: Point::new(0, 0),
            last_click_time: 0,
            click_count: 0,
        }
    }

    /// Update position
    pub fn update_position(&mut self, x: i32, y: i32) {
        self.position = Point::new(x, y);
    }

    /// Update buttons
    pub fn update_buttons(&mut self, buttons: i32, timestamp: u64) -> MouseEventKind {
        let changed = self.buttons ^ buttons;
        self.buttons = buttons;
        
        // Determine event type
        if changed == 0 {
            MouseEventKind::Move
        } else if buttons & changed != 0 {
            // Button pressed
            if self.is_double_click(timestamp) {
                MouseEventKind::DoubleClick
            } else {
                MouseEventKind::Down
            }
        } else {
            MouseEventKind::Up
        }
    }

    /// Check for double click
    fn is_double_click(&mut self, timestamp: u64) -> bool {
        const DOUBLE_CLICK_TIME: u64 = 300; // milliseconds
        const DOUBLE_CLICK_DIST: i32 = 5;
        
        let dx = self.position.x - self.last_click.x;
        let dy = self.position.y - self.last_click.y;
        let dist_sq = dx * dx + dy * dy;
        
        if timestamp - self.last_click_time < DOUBLE_CLICK_TIME && dist_sq < DOUBLE_CLICK_DIST * DOUBLE_CLICK_DIST {
            self.click_count += 1;
            self.last_click_time = 0; // Reset to prevent triple-click detection
            true
        } else {
            self.click_count = 1;
            self.last_click = self.position;
            self.last_click_time = timestamp;
            false
        }
    }

    /// Get position
    pub fn position(&self) -> Point {
        self.position
    }

    /// Get buttons
    pub fn buttons(&self) -> i32 {
        self.buttons
    }

    /// Get click count
    pub fn click_count(&self) -> u32 {
        self.click_count
    }

    /// Reset click count
    pub fn reset_click_count(&mut self) {
        self.click_count = 0;
    }
}

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}

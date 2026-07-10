//! Event Handling
//!
//! Mouse and keyboard event handling for Plan 9 graphics.

use super::{Point, Rectangle, DrawError};
use alloc::format;
use alloc::string::{String, ToString};

/// Mouse button state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// No button pressed
    None,
    /// Left button
    Left,
    /// Middle button
    Middle,
    /// Right button
    Right,
}

/// Mouse state
#[derive(Debug, Clone, Copy)]
pub struct Mouse {
    /// Mouse position
    pub point: Point,
    /// Button state
    pub buttons: MouseButton,
    /// Modifiers (shift, ctrl, alt, etc.)
    pub modifiers: u32,
    /// Timestamp in milliseconds
    pub timestamp: u64,
}

impl Default for Mouse {
    fn default() -> Self {
        Self {
            point: Point::origin(),
            buttons: MouseButton::None,
            modifiers: 0,
            timestamp: 0,
        }
    }
}

/// Key modifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifiers {
    /// Shift key
    pub shift: bool,
    /// Control key
    pub ctrl: bool,
    /// Alt/Option key
    pub alt: bool,
    /// Meta/Command key
    pub meta: bool,
}

impl Default for Modifiers {
    fn default() -> Self {
        Self {
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
        }
    }
}

impl Modifiers {
    /// Convert to raw bitmask
    pub fn to_bits(&self) -> u32 {
        (self.shift as u32) | 
        ((self.ctrl as u32) << 1) | 
        ((self.alt as u32) << 2) | 
        ((self.meta as u32) << 3)
    }
    
    /// Create from raw bitmask
    pub fn from_bits(bits: u32) -> Self {
        Self {
            shift: (bits & 1) != 0,
            ctrl: (bits & 2) != 0,
            alt: (bits & 4) != 0,
            meta: (bits & 8) != 0,
        }
    }
}

/// Keyboard event
#[derive(Debug, Clone)]
pub struct KeyEvent {
    /// Key code (Plan 9 key codes)
    pub key: u32,
    /// Unicode character (if applicable)
    pub rune: char,
    /// Modifiers at time of event
    pub modifiers: Modifiers,
    /// Timestamp in milliseconds
    pub timestamp: u64,
}

/// Resize event
#[derive(Debug, Clone, Copy)]
pub struct ResizeEvent {
    /// Screen/image that was resized
    pub screen_id: i32,
    /// New rectangle
    pub rect: Rectangle,
}

/// Event types
#[derive(Debug, Clone)]
pub enum DrawEvent {
    /// Mouse event
    Mouse(Mouse),
    /// Keyboard event
    Key(KeyEvent),
    /// Resize event
    Resize(ResizeEvent),
    /// No event (polling)
    None,
}

/// Mouse constants
pub const MOUSE_L: MouseButton = MouseButton::Left;
pub const MOUSE_M: MouseButton = MouseButton::Middle;
pub const MOUSE_R: MouseButton = MouseButton::Right;

/// Modifier constants
pub const MOD_SHIFT: u32 = 1;
pub const MOD_CTRL: u32 = 2;
pub const MOD_ALT: u32 = 4;
pub const MOD_META: u32 = 8;

/// Get mouse state from display
///
/// In a real implementation, this would read from the mouse device.
/// Returns the current mouse position and button state.
pub fn getmouse(_d: &mut super::Display) -> Result<Mouse, DrawError> {
    // In a real implementation, this would read from /dev/mouse
    // For now, return default mouse state
    Ok(Mouse::default())
}

/// Get keyboard and mouse state
///
/// Fills the buffer with encoded keyboard/mouse state.
/// Returns the number of bytes written.
pub fn kbdmouse(_d: &mut super::Display, _buf: &mut [u8]) -> Result<usize, DrawError> {
    // In a real implementation, this would read combined state
    // Format: mouse(3bytes) + modifiers(1byte) + keycount(2bytes) + runes(n*2bytes)
    Err(DrawError::DeviceError)
}

/// Read event from event file descriptor
///
/// Waits for and returns the next event.
pub fn readevent(_efd: i32) -> Result<DrawEvent, DrawError> {
    // In a real implementation, this would read from an event pipe
    Err(DrawError::DeviceError)
}

/// Read mouse event
pub fn readmouse(_efd: i32) -> Result<Mouse, DrawError> {
    // In a real implementation, this would read mouse events
    Err(DrawError::DeviceError)
}

/// Read keyboard event
pub fn readkey(_efd: i32) -> Result<KeyEvent, DrawError> {
    // In a real implementation, this would read key events
    Err(DrawError::DeviceError)
}

/// Convert Plan 9 key code to string
pub fn keyname(key: u32) -> String {
    match key {
        0xF001 => "shift".to_string(),
        0xF002 => "ctrl".to_string(),
        0xF003 => "alt".to_string(),
        0xF004 => "meta".to_string(),
        0xF100 => "up".to_string(),
        0xF101 => "down".to_string(),
        0xF102 => "left".to_string(),
        0xF103 => "right".to_string(),
        0xF104 => "home".to_string(),
        0xF105 => "end".to_string(),
        0xF106 => "pgup".to_string(),
        0xF107 => "pgdown".to_string(),
        0xF108 => "ins".to_string(),
        0xF109 => "del".to_string(),
        0xF10A => "F1".to_string(),
        0xF11B => "F12".to_string(),
        _ => format!("key{:04x}", key),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mouse_default() {
        let m = Mouse::default();
        assert_eq!(m.point, Point::origin());
        assert_eq!(m.buttons, MouseButton::None);
    }

    #[test]
    fn test_modifiers_roundtrip() {
        let m = Modifiers {
            shift: true,
            ctrl: false,
            alt: true,
            meta: false,
        };
        let bits = m.to_bits();
        let m2 = Modifiers::from_bits(bits);
        assert_eq!(m.shift, m2.shift);
        assert_eq!(m.ctrl, m2.ctrl);
        assert_eq!(m.alt, m2.alt);
        assert_eq!(m.meta, m2.meta);
    }

    #[test]
    fn test_keyname() {
        assert_eq!(keyname(0xF001), "shift");
        assert_eq!(keyname(0xF100), "up");
    }
}

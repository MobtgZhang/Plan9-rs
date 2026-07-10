//! Rio Window Manager
//!
//! Rio is the window manager for Plan 9, providing a simple tiling
//! window system with mouse-based manipulation.
//!
//! ## Architecture
//!
//! - `Window`: A managed window with a border and title bar
//! - `Screen`: A container for windows
//! - `Mouse`: Mouse event handling
//! - `Keyboard`: Keyboard event handling
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/`

pub mod window;
pub mod screen;
pub mod mouse;
pub mod keyboard;
pub mod wctl;
pub mod fsys;

pub use window::Window;
pub use screen::Screen;
pub use mouse::{MouseState, MouseButton, MouseEvent};
pub use keyboard::{KeyboardState, KeyboardEvent};
pub use wctl::WindowControl;
pub use fsys::RioFsys;

/// Default Rio settings
pub const DEFAULT_FONT: &str = "/lib/font/bit/lucm/unicode.9.font";
pub const DEFAULT_TABSTOP: usize = 4;
pub const BORDER_WIDTH: i32 = 2;
pub const TITLE_HEIGHT: i32 = 20;

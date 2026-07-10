//! Display Operations

use super::{DrawError, Point};
use alloc::string::{String, ToString};

/// Display connection
pub struct Display {
    /// Display address
    address: String,
}

impl Display {
    /// Open a display
    pub fn open(address: Option<&str>) -> Result<Self, DrawError> {
        Ok(Self {
            address: address.unwrap_or("/dev/screen").to_string(),
        })
    }

    /// Get address
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Display operation trait
pub trait DisplayOps {
    /// Flush changes to screen
    fn flush(&mut self);
    
    /// Get mouse position
    fn mouse_position(&self) -> Point;
    
    /// Get window size
    fn window_size(&self) -> (i32, i32);
}

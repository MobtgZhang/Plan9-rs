//! Screen Operations

use super::{Image, Rectangle, DrawError};

/// Screen represents the display screen
pub struct Screen {
    /// Screen image
    image: Image,
    /// Is this the visible screen?
    visible: bool,
}

impl Screen {
    /// Create a new screen
    pub fn new(image: Image, visible: bool) -> Self {
        Self { image, visible }
    }

    /// Get screen image
    pub fn image(&self) -> &Image {
        &self.image
    }

    /// Get screen rectangle
    pub fn rect(&self) -> Rectangle {
        self.image.rect()
    }

    /// Check if this is the visible screen
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

/// Screen operation trait
pub trait ScreenOps {
    /// Get the primary screen
    fn get_screen() -> Result<Screen, DrawError>;
    
    /// Flush changes to display
    fn flush(&mut self);
}

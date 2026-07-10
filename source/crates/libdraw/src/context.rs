//! Graphics Context

use alloc::boxed::Box;

/// Graphics context for drawing operations
pub struct Context {
    /// Source image
    pub source: Option<Box<dyn super::image::ImageOps>>,
    /// Mask image
    pub mask: Option<Box<dyn super::image::ImageOps>>,
    /// Destination
    pub dst: Option<Box<dyn super::image::ImageOps>>,
    /// Operation
    pub op: BlendOp,
}

/// Blend operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendOp {
    /// Source over (default)
    Over,
    /// Source copy
    Copy,
    /// Source in destination
    In,
    /// Source out of destination
    Out,
    /// Source atop destination
    Atop,
    /// XOR
    Xor,
}

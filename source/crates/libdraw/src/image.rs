//! Image Operations
//!
//! Pixel buffer and image manipulation operations.

use super::{Point, Rectangle, Size, PixelFormat, ChannelDesc, DrawError};
use alloc::vec;
use alloc::vec::Vec;

/// Image represents a pixel buffer
pub struct Image {
    /// Pixel data
    pub(crate) data: Vec<u8>,
    /// Image rectangle
    pub r: Rectangle,
    /// Pixel format
    pub format: PixelFormat,
    /// Channel descriptor
    pub(crate) ch: ChannelDesc,
    /// Stride (bytes per row)
    pub(crate) stride: i32,
}

impl Image {
    /// Create a new image with given size and format
    pub fn new(size: Size, format: PixelFormat) -> Result<Self, DrawError> {
        let ch = match format {
            PixelFormat::GREY8 => ChannelDesc::grey8(),
            PixelFormat::RGB24 => ChannelDesc::rgb24(),
            PixelFormat::RGBA32 => ChannelDesc::rgba32(),
            _ => return Err(DrawError::InvalidFormat),
        };

        let bpp = (ch.bpp as i32 + 7) / 8;
        let stride = (size.width * bpp + 3) & !3; // Word-aligned
        let data_len = (stride * size.height) as usize;

        Ok(Self {
            data: vec![0u8; data_len],
            r: Rectangle::from_size(Point::origin(), size),
            format,
            ch,
            stride,
        })
    }

    /// Get image rectangle
    pub fn rect(&self) -> Rectangle {
        self.r
    }
    
    /// Set image rectangle
    pub fn set_rect(&mut self, r: Rectangle) {
        self.r = r;
    }

    /// Get image size
    pub fn size(&self) -> Size {
        self.r.size()
    }

    /// Get pixel format
    pub fn format(&self) -> PixelFormat {
        self.format
    }

    /// Get channel descriptor
    pub fn channels(&self) -> ChannelDesc {
        self.ch
    }

    /// Get pixel at point
    pub fn pixel(&self, p: Point) -> Option<u32> {
        if !self.r.contains(p) {
            return None;
        }

        let bpp = (self.ch.bpp as i32 + 7) / 8;
        let offset = ((p.y - self.r.min.y) * self.stride + (p.x - self.r.min.x) * bpp) as usize;
        
        if self.ch.bpp == 32 {
            Some(u32::from_le_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]))
        } else if self.ch.bpp == 24 {
            Some(u32::from_le_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                0,
            ]))
        } else {
            None
        }
    }

    /// Set pixel at point
    pub fn set_pixel(&mut self, p: Point, color: u32) -> Result<(), DrawError> {
        if !self.r.contains(p) {
            return Err(DrawError::InvalidPoint);
        }

        let bpp = (self.ch.bpp as i32 + 7) / 8;
        let offset = ((p.y - self.r.min.y) * self.stride + (p.x - self.r.min.x) * bpp) as usize;
        
        let bytes = self.ch.bpp as usize / 8;
        for i in 0..bytes {
            self.data[offset + i] = (color >> (i * 8)) as u8;
        }

        Ok(())
    }
}

/// Image operation trait
pub trait ImageOps {
    /// Draw a filled rectangle
    fn fill(&mut self, r: Rectangle, color: u32);

    /// Copy from another image
    fn copy_from(&mut self, src: &Image, src_r: Rectangle, dst: Point);

    /// Clear the image
    fn clear(&mut self, color: u32);
}

impl ImageOps for Image {
    fn fill(&mut self, r: Rectangle, color: u32) {
        let r = r.intersect(&self.r);
        if r.is_empty() {
            return;
        }

        for y in r.min.y..r.max.y {
            for x in r.min.x..r.max.x {
                let _ = self.set_pixel(Point::new(x, y), color);
            }
        }
    }

    fn copy_from(&mut self, src: &Image, src_r: Rectangle, dst: Point) {
        let src_r = src_r.intersect(&src.r);
        if src_r.is_empty() {
            return;
        }

        let dst_r = Rectangle::new(dst, Point::new(dst.x + src_r.width(), dst.y + src_r.height()));
        let dst_r = dst_r.intersect(&self.r);

        for y in 0..dst_r.height() {
            for x in 0..dst_r.width() {
                let src_p = Point::new(src_r.min.x + x, src_r.min.y + y);
                let dst_p = Point::new(dst_r.min.x + x, dst_r.min.y + y);
                
                if let Some(color) = src.pixel(src_p) {
                    let _ = self.set_pixel(dst_p, color);
                }
            }
        }
    }

    fn clear(&mut self, color: u32) {
        self.fill(self.r, color);
    }
}

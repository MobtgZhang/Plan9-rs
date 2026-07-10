//! Image I/O Operations
//!
//! File-based image reading and writing, following Plan 9's libdraw conventions.
//! 
//! Plan 9 Image Format:
//! - Channel description line (e.g., "r8g8b8a8\n")
//! - Width and height (two decimal integers)
//! - Optional: "compressed\n" for LZ77 compression
//! - Pixel data

use super::{Image, Rectangle, Size, DrawError};
use alloc::string::{String, ToString};
use alloc::format;
use alloc::vec::Vec;

/// Maximum supported image dimensions
const MAX_DIMENSION: i32 = 4096;

/// Read an image from a file descriptor
///
/// The format follows Plan 9 conventions:
/// - Channel description: "r8g8b8a8\n" or similar
/// - Width and height: two decimal integers
/// - Optional "compressed\n" line
/// - Pixel data
pub fn readimage(_fd: i32) -> Result<Image, DrawError> {
    // In a real implementation, this would read from the file descriptor
    // For now, we provide the structure and return an error
    Err(DrawError::DeviceError)
}

/// Read an image from raw bytes
///
/// Parses Plan 9 image format from a byte slice.
pub fn readimage_from_bytes(data: &[u8]) -> Result<Image, DrawError> {
    let mut offset = 0;
    
    // Skip leading whitespace
    while offset < data.len() && data[offset] == b'\n' {
        offset += 1;
    }
    
    if offset >= data.len() {
        return Err(DrawError::InvalidFormat);
    }
    
    // Read channel description
    let channel_end = data[offset..].iter().position(|&b| b == b'\n').unwrap_or(data.len() - offset);
    let channel_desc = core::str::from_utf8(&data[offset..offset + channel_end])
        .map_err(|_| DrawError::InvalidFormat)?;
    offset += channel_end + 1;
    
    // Skip "compressed\n" if present
    if data.len() > offset && &data[offset..offset.min(data.len())] == b"compressed\n" {
        offset += 10;
    }
    
    // Read width and height
    let dims_end = data[offset..].iter().position(|&b| b == b'\n').unwrap_or(data.len() - offset);
    let dims_str = core::str::from_utf8(&data[offset..offset + dims_end])
        .map_err(|_| DrawError::InvalidFormat)?;
    
    let parts: Vec<&str> = dims_str.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(DrawError::InvalidFormat);
    }
    
    let width: i32 = parts[0].parse().map_err(|_| DrawError::InvalidFormat)?;
    let height: i32 = parts[1].parse().map_err(|_| DrawError::InvalidFormat)?;
    offset += dims_end + 1;
    
    // Validate dimensions
    if width <= 0 || height <= 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(DrawError::InvalidFormat);
    }
    
    // Parse channel format
    let format = parse_channel_format(channel_desc)?;
    
    // Create image
    let mut image = Image::new(Size::new(width, height), format)?;
    
    // Read pixel data
    let expected_size = image.stride() as usize * height as usize;
    if offset + expected_size > data.len() {
        return Err(DrawError::InvalidFormat);
    }
    
    image.load_data(&data[offset..offset + expected_size])?;
    
    Ok(image)
}

/// Write an image to a file descriptor
///
/// The format follows Plan 9 conventions with optional LZ77 compression.
pub fn writeimage(_fd: i32, _im: &Image, _compress: bool) -> Result<(), DrawError> {
    // In a real implementation, this would write to the file descriptor
    // For now, return DeviceError
    Err(DrawError::DeviceError)
}

/// Write an image to bytes
///
/// Produces Plan 9 image format bytes.
pub fn writeimage_to_bytes(im: &Image, compress: bool) -> Result<alloc::vec::Vec<u8>, DrawError> {
    let mut result = alloc::vec::Vec::new();
    
    // Write channel description
    let channel_str = format_channel_format(im);
    result.extend_from_slice(channel_str.as_bytes());
    result.push(b'\n');
    
    // Write compressed indicator if needed
    if compress {
        result.extend_from_slice(b"compressed\n");
    }
    
    // Write dimensions
    let size = im.size();
    result.extend_from_slice(format!("{} {}\n", size.width, size.height).as_bytes());
    
    // Write pixel data
    result.extend_from_slice(im.data());
    
    Ok(result)
}

/// Load pixel data into an existing image from a byte slice
///
/// This copies pixel data into the image's internal buffer.
/// Only the portion within the rectangle is loaded.
pub fn loadimage(im: &mut Image, r: Rectangle, data: &[u8]) -> Result<usize, DrawError> {
    // Clip rectangle to image bounds
    let r = r.intersect(&im.rect());
    if r.is_empty() {
        return Ok(0);
    }
    
    let stride = im.stride() as usize;
    let bpp = im.bytes_per_pixel() as usize;
    
    // Calculate required data size
    let width = r.width() as usize;
    let height = r.height() as usize;
    let required = width * bpp * height;
    
    if data.len() < required {
        return Err(DrawError::InvalidFormat);
    }
    
    // Copy data row by row
    let mut src_offset = 0;
    for y in 0..height {
        let dst_row = (r.min.y + y as i32 - im.rect().min.y) as usize;
        let dst_col = (r.min.x - im.rect().min.x) as usize;
        
        for x in 0..width {
            let src_idx = src_offset + x * bpp;
            let dst_idx = dst_row * stride + (dst_col + x) * bpp;
            
            for b in 0..bpp {
                im.data_mut()[dst_idx + b] = data[src_idx + b];
            }
        }
        src_offset += width * bpp;
    }
    
    Ok(required)
}

/// Unload pixel data from an image to a byte vector
///
/// Extracts pixel data from the specified rectangle.
pub fn unloadimage(im: &Image, r: Rectangle, data: &mut [u8]) -> Result<usize, DrawError> {
    // Clip rectangle to image bounds
    let r = r.intersect(&im.rect());
    if r.is_empty() {
        return Ok(0);
    }
    
    let stride = im.stride() as usize;
    let bpp = im.bytes_per_pixel() as usize;
    
    // Calculate required data size
    let width = r.width() as usize;
    let height = r.height() as usize;
    let required = width * bpp * height;
    
    if data.len() < required {
        return Err(DrawError::InvalidFormat);
    }
    
    // Copy data row by row
    let mut dst_offset = 0;
    for y in 0..height {
        let src_row = (r.min.y + y as i32 - im.rect().min.y) as usize;
        let src_col = (r.min.x - im.rect().min.x) as usize;
        
        for x in 0..width {
            let src_idx = src_row * stride + (src_col + x) * bpp;
            let dst_idx = dst_offset + x * bpp;
            
            for b in 0..bpp {
                data[dst_idx + b] = im.data()[src_idx + b];
            }
        }
        dst_offset += width * bpp;
    }
    
    Ok(required)
}

/// Parse channel format string
fn parse_channel_format(s: &str) -> Result<super::PixelFormat, DrawError> {
    match s.trim() {
        "r8g8b8a8" | "RGBA32" | "xrgb" | "rgba" => Ok(super::PixelFormat::RGBA32),
        "r8g8b8" | "RGB24" | "rgb24" | "b8r8g8" => Ok(super::PixelFormat::RGB24),
        "r5g6b5" | "RGB16" | "rgb16" => Ok(super::PixelFormat::RGB16),
        "k8" | "GREY8" | "grey8" => Ok(super::PixelFormat::GREY8),
        "m8" | "GREY1" | "grey1" => Ok(super::PixelFormat::GREY1),
        _ => Err(DrawError::InvalidFormat),
    }
}

/// Format channel description string
fn format_channel_format(im: &Image) -> String {
    let ch = im.channels();
    match im.format() {
        super::PixelFormat::RGBA32 => "r8g8b8a8".to_string(),
        super::PixelFormat::RGB24 => "r8g8b8".to_string(),
        super::PixelFormat::RGB16 => "r5g6b5".to_string(),
        super::PixelFormat::GREY8 => "k8".to_string(),
        super::PixelFormat::GREY1 => "m8".to_string(),
        _ => format!("r{}g{}b{}a{}", ch.red.1, ch.green.1, ch.blue.1, ch.alpha.1),
    }
}

/// Extension trait for Image to access internal data
pub trait ImageData {
    /// Get raw pixel data
    fn data(&self) -> &[u8];
    
    /// Get mutable raw pixel data
    fn data_mut(&mut self) -> &mut Vec<u8>;
    
    /// Get stride (bytes per row)
    fn stride(&self) -> i32;
    
    /// Get bytes per pixel
    fn bytes_per_pixel(&self) -> i32;
    
    /// Load data from byte slice
    fn load_data(&mut self, data: &[u8]) -> Result<(), DrawError>;
}

impl ImageData for Image {
    fn data(&self) -> &[u8] {
        &self.data
    }
    
    fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
    
    fn stride(&self) -> i32 {
        self.stride
    }
    
    fn bytes_per_pixel(&self) -> i32 {
        (self.ch.bpp as i32 + 7) / 8
    }
    
    fn load_data(&mut self, data: &[u8]) -> Result<(), DrawError> {
        if data.len() < self.data.len() {
            return Err(DrawError::InvalidFormat);
        }
        self.data.copy_from_slice(data);
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Point, PixelFormat};
    use alloc::vec;

    #[test]
    fn test_read_write_roundtrip() {
        // Create a simple RGBA32 image
        let mut im = Image::new(Size::new(4, 4), PixelFormat::RGBA32).unwrap();
        
        // Fill with test pattern
        for y in 0..4i32 {
            for x in 0..4i32 {
                let color = ((x as u32) << 24) | ((y as u32) << 16) | (0xFFu32 << 8) | 0xFF;
                im.set_pixel(Point::new(x, y), color).unwrap();
            }
        }
        
        // Write to bytes
        let bytes = writeimage_to_bytes(&im, false).unwrap();
        
        // Read back
        let im2 = readimage_from_bytes(&bytes).unwrap();
        
        // Verify
        assert_eq!(im.size(), im2.size());
        assert_eq!(im.format(), im2.format());
        
        // Verify some pixels
        assert_eq!(im.pixel(Point::new(0, 0)), im2.pixel(Point::new(0, 0)));
        assert_eq!(im.pixel(Point::new(3, 3)), im2.pixel(Point::new(3, 3)));
    }
    
    #[test]
    fn test_parse_channel_format() {
        assert_eq!(parse_channel_format("r8g8b8a8").unwrap(), PixelFormat::RGBA32);
        assert_eq!(parse_channel_format("r8g8b8").unwrap(), PixelFormat::RGB24);
        assert_eq!(parse_channel_format("k8").unwrap(), PixelFormat::GREY8);
    }
    
    #[test]
    fn test_load_unload() {
        let mut im = Image::new(Size::new(4, 4), PixelFormat::RGBA32).unwrap();
        
        // Create test data
        let test_data: vec::Vec<u8> = (0..64).map(|i| i as u8).collect();
        
        // Load into sub-rectangle
        let r = Rectangle::new(Point::new(1, 1), Point::new(3, 3));
        let loaded = loadimage(&mut im, r, &test_data).unwrap();
        assert_eq!(loaded, 16 * 4); // 4x4 * 4 bytes per pixel
        
        // Unload back
        let mut output = vec![0u8; 64];
        let unloaded = unloadimage(&im, r, &mut output).unwrap();
        assert_eq!(unloaded, 16 * 4);
    }
}

//! Block device abstraction for read-only filesystem parsers.
//!
//! The kernel adapts an SD unit to this trait so EXT/NTFS/XFS parsers can
//! read arbitrary byte ranges without knowing about AHCI or DMA.

use alloc::vec;
use alloc::vec::Vec;
use super::common::error::Error;

pub type Result<T> = core::result::Result<T, Error>;

/// Read-only byte source for a filesystem image.
pub trait FsBlockReader: Send + Sync {
    /// Read up to `buf.len()` bytes starting at `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Total byte capacity of the image.
    fn total_bytes(&self) -> u64;

    /// Sector size reported by the underlying device.
    fn sector_size(&self) -> usize;
}

/// Read exactly `buf.len()` bytes, returning Eio when the image ends.
pub fn read_exact(source: &dyn FsBlockReader, offset: u64, buf: &mut [u8]) -> Result<()> {
    let n = source.read_at(offset, buf)?;
    if n != buf.len() {
        return Err(Error::Eio);
    }
    Ok(())
}

/// Read a block of `size` bytes from the image.
pub fn read_block(source: &dyn FsBlockReader, offset: u64, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    read_exact(source, offset, &mut buf)?;
    Ok(buf)
}

// Little-endian helpers used by the on-disk parsers.
pub fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn le64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ])
}

pub fn be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn be64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ])
}

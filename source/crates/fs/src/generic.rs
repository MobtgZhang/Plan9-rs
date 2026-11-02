//! Generic read-only filesystem interface shared by EXT/NTFS/XFS/FAT.
//!
//! The kernel's `#f` device only needs a small set of operations: resolve a
//! name in a directory, list that directory, inspect a node, and read file
//! bytes.  Filesystem-specific parsers implement this trait directly.

use alloc::vec::Vec;
use super::common::error::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct FsNode {
    /// Filesystem-specific node identifier (inode number, MFT record, etc.)
    pub id: u64,
    /// Name in the parent directory, when known.
    pub name: Vec<u8>,
    /// Size in bytes.
    pub size: u64,
    /// Mode bits as stored on disk (permissions plus file-type bits).
    pub mode: u32,
    /// True when this node is a directory.
    pub is_dir: bool,
}

pub trait Filesystem: Send + Sync {
    fn root_id(&self) -> u64;
    fn node_info(&self, id: u64) -> Result<FsNode>;
    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64>;
    fn list_dir(&self, dir: u64) -> Result<Vec<FsNode>>;
    fn read_file(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// Plan 9-style mode: permissions plus `0o40000` for directories.
pub fn plan9_mode(node: &FsNode) -> u32 {
    let perms = node.mode & 0o777;
    if node.is_dir {
        perms | 0o40000
    } else {
        perms
    }
}

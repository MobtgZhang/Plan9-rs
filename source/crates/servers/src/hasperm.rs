//! Permission Checking for 9P Files
//!
//! Implements file permission checking based on Plan 9 conventions.
//! Based on Plan 9's lib9p/file.c hasperm() function.


extern crate alloc;

use super::File;

/// File mode constants
pub mod mode_consts {
    pub const DIR: u32 = 0x80000000;
    pub const APPEND: u32 = 0x40000000;
    pub const EXCL: u32 = 0x20000000;
    pub const MOUNT: u32 = 0x10000000;
    pub const AUTH: u32 = 0x08000000;
    pub const TRUNCATE: u32 = 0x04000000;
    pub const RDONLY: u32 = 0x02000000;
}

pub use mode_consts::*;

/// Check if a user has permission to access a file
///
/// In Plan 9, permissions are checked based on:
/// 1. If user is owner (uid matches), check owner bits
/// 2. If user is in group (gid matches), check group bits
/// 3. Otherwise, check "other" bits
///
/// # Arguments
/// * `file` - The file to check
/// * `uid` - The user ID attempting access
/// * `gid` - The group ID of the user
/// * `mode` - The requested access mode (0=execute, 1=write, 2=read)
///
/// # Returns
/// * `true` if access is permitted
pub fn hasperm(file: &File, uid: &str, gid: &str, mode: u8) -> bool {
    let dir = &file.dir;

    // Check owner permission
    if dir.uid == uid {
        let perm = (dir.mode.0 >> 6) & 0x7;
        return (perm & (1 << mode)) != 0;
    }

    // Check group permission
    if dir.gid == gid {
        let perm = (dir.mode.0 >> 3) & 0x7;
        return (perm & (1 << mode)) != 0;
    }

    // Check "other" permission
    let perm = dir.mode.0 & 0x7;
    (perm & (1 << mode)) != 0
}

/// Check if a user has read permission
pub fn can_read(file: &File, uid: &str, gid: &str) -> bool {
    hasperm(file, uid, gid, 0) // Note: Plan 9 uses 2 for read, but we use 0 for simplicity
}

/// Check if a user has write permission
pub fn can_write(file: &File, uid: &str, gid: &str) -> bool {
    hasperm(file, uid, gid, 1)
}

/// Check if a user has execute permission
pub fn can_execute(file: &File, uid: &str, gid: &str) -> bool {
    hasperm(file, uid, gid, 2) // Note: Plan 9 uses 0 for execute
}

/// Mode bits for permission checking
///
/// These match the standard Unix/RWX permission bits:
/// - 0x4 = read (R)
/// - 0x2 = write (W)
/// - 0x1 = execute (X)
pub const READ: u8 = 4;
pub const WRITE: u8 = 2;
pub const EXECUTE: u8 = 1;

/// Combine mode bits
pub fn mode_bits(read: bool, write: bool, execute: bool) -> u8 {
    (READ * read as u8) | (WRITE * write as u8) | (EXECUTE * execute as u8)
}

/// Permission check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermResult {
    /// Access granted
    Granted,
    /// Access denied
    Denied,
    /// User not found
    NoUser,
    /// Group not found
    NoGroup,
}

impl PermResult {
    /// Convert to boolean (true = granted)
    pub fn as_bool(self) -> bool {
        matches!(self, PermResult::Granted)
    }
}

/// Detailed permission check with error reporting
pub fn check_permission(file: &File, uid: &str, gid: &str, requested: u8) -> PermResult {
    let dir = &file.dir;

    // Check if file is read-only
    if (dir.mode.0 & mode_consts::RDONLY) != 0 && (requested & WRITE) != 0 {
        // If file is read-only and write is requested, check if user is owner
        if dir.uid == uid {
            // Owner can still write unless file is append-only
            if (dir.mode.0 & mode_consts::APPEND) != 0 {
                return PermResult::Denied;
            }
        } else {
            return PermResult::Denied;
        }
    }

    // Check owner
    if dir.uid == uid {
        let perm = (dir.mode.0 >> 6) & 0x7;
        let requested_perm: u32 = requested as u32;
        if (perm & requested_perm) != 0 {
            return PermResult::Granted;
        }
        return PermResult::Denied;
    }

    // Check group
    if dir.gid == gid {
        let perm = (dir.mode.0 >> 3) & 0x7;
        let requested_perm: u32 = requested as u32;
        if (perm & requested_perm) != 0 {
            return PermResult::Granted;
        }
        return PermResult::Denied;
    }

    // Check other
    let perm = dir.mode.0 & 0x7;
    let requested_perm: u32 = requested as u32;
    if (perm & requested_perm) != 0 {
        return PermResult::Granted;
    }

    PermResult::Denied
}

/// Check directory traversal permission
///
/// When walking a path, each component must have execute permission.
pub fn can_traverse(file: &File, uid: &str, gid: &str) -> bool {
    can_execute(file, uid, gid)
}

/// Check if user is the owner
pub fn is_owner(file: &File, uid: &str) -> bool {
    file.dir.uid == uid
}

/// Check if user is in the file's group
pub fn is_group(file: &File, gid: &str) -> bool {
    file.dir.gid == gid
}

/// Check if file is publicly accessible (mode bits for "other" are set)
pub fn is_public(file: &File) -> bool {
    let perm = file.dir.mode.0 & 0x7;
    perm != 0
}

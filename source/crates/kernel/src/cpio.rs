//! Minimal `newc` cpio archive parser.
//!
//! The Plan 9 root image is packed as a `newc` cpio archive and loaded by
//! GRUB as a Multiboot2 module.  Each entry is:
//!
//!   070701 <inode> <mode> <uid> <gid> <nlink> <mtime>
//!         <filesize> <devmajor> <devminor> <rdevmajor> <rdevminor>
//!         <namesize> <check>
//!   <name> NUL, padded to 4 bytes, <data>, padded to 4 bytes.
//!
//! The parser returns raw entries; `rootfs::RootFsDev::import_cpio` turns
//! them into a RAM file system.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct CpioEntry<'a> {
    pub name: String,
    /// Payload borrowed straight from the archive mapping — no per-entry
    /// heap copy (the rootfs archive is multi-megabyte).
    pub data: &'a [u8],
    pub mode: u32,
    pub is_dir: bool,
}

fn read_hex(data: &[u8], start: usize, len: usize) -> Option<u32> {
    let mut value = 0u32;
    for i in 0..len {
        let b = *data.get(start + i)?;
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        value = value * 16 + digit as u32;
    }
    Some(value)
}

pub fn parse_newc(archive: &[u8]) -> Vec<CpioEntry<'_>> {
    let mut entries = Vec::new();
    let mut off = 0usize;

    while off + 110 <= archive.len() {
        if &archive[off..off + 6] != b"070701" && &archive[off..off + 6] != b"070702" {
            break;
        }

        let fields = [
            (off + 6, 8),   // inode
            (off + 14, 8),  // mode
            (off + 22, 8),  // uid
            (off + 30, 8),  // gid
            (off + 38, 8),  // nlink
            (off + 46, 8),  // mtime
            (off + 54, 8),  // filesize
            (off + 62, 8),  // devmajor
            (off + 70, 8),  // devminor
            (off + 78, 8),  // rdevmajor
            (off + 86, 8),  // rdevminor
            (off + 94, 8),  // namesize
            (off + 102, 8), // check
        ];

        let mut nums = [0u32; 13];
        for (i, (start, len)) in fields.iter().enumerate() {
            match read_hex(archive, *start, *len) {
                Some(v) => nums[i] = v,
                None => return entries,
            }
        }

        let mode = nums[1];
        let filesize = nums[6] as usize;
        let namesize = nums[11] as usize;
        let name_start = off + 110;
        let name_end = name_start + namesize;
        if name_end > archive.len() {
            break;
        }
        let name_bytes = &archive[name_start..name_end];
        let name = String::from_utf8_lossy(name_bytes);
        let name = name.trim_end_matches('\0').to_string();

        // Header + name is padded to a 4-byte boundary.
        let mut data_start = name_end;
        while (data_start - off) % 4 != 0 {
            data_start += 1;
        }
        let data_end = data_start + filesize;
        if data_end > archive.len() {
            break;
        }

        let mut data = &archive[data_start..data_end];

        // Directory entries have no data; their mode carries S_IFDIR (0o40000).
        let is_dir = (mode & 0o170000) == 0o40000;
        if is_dir {
            data = &[];
        }

        let is_trailer = name == "TRAILER!!!";
        entries.push(CpioEntry {
            name,
            data,
            mode: mode & 0o7777,
            is_dir,
        });

        if is_trailer {
            break;
        }

        // Advance past data padding.
        let mut next = data_end;
        while (next - off) % 4 != 0 {
            next += 1;
        }
        off = next;
    }

    entries
}

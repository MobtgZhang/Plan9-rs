//! File System Crate
//!
//! Provides VFS abstraction, FAT, RAM file system, and procfs implementations.

#![no_std]

extern crate alloc;

extern crate plan9_common;

// Create a re-export alias so submodules can use `crate::common`
use plan9_common as common;

pub mod vfs;
pub mod fat;
pub mod ramfs;
pub mod procfs;

pub use vfs::{Vfs, Channel, MountPoint, Inode, FileType, DirEntry, Result};
pub use vfs::{FileOperations, DirectoryOperations, VfsOperations};
pub use vfs::path;
pub use fat::{FatFileSystem, FatBootSector, FatDirEntry, FatType, FatDevice, FatFile};
pub use ramfs::{RamFileSystem, RamfsEntry, RamfsNode, RamfsFile, RamfsDir};
pub use procfs::{
    Proc, ProcThread, ProcFd, ProcInfo, ProcState, ProcQid, ProcCtl,
    proc_create, proc_get, proc_alloc_pid, proc_kill, proc_note,
    proc_readmem, proc_writemem, proc_qid, proc_parse_qid,
};

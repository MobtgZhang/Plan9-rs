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
pub mod mntfs;
pub mod venti;
pub mod nfs;
pub mod webfs;
pub mod devfs;

pub use vfs::{Vfs, Channel, MountPoint, Inode, FileType, DirEntry, Result};
pub use vfs::{FileOperations, DirectoryOperations, VfsOperations};
pub use vfs::path;
pub use fat::{FatFileSystem, FatBootSector, FatDirEntry, FatType, FatDevice, FatFile};
pub use ramfs::{RamFileSystem, RamfsEntry, RamfsNode, RamfsFile, RamfsDir};
pub use mntfs::{MountEntry, MountFlags, MountTable, bind_mount, umount, lookup_mount};
pub use procfs::{
    Proc, ProcThread, ProcFd, ProcInfo, ProcState, ProcQid, ProcCtl,
    proc_create, proc_get, proc_alloc_pid, proc_kill, proc_note,
    proc_readmem, proc_writemem, proc_qid, proc_parse_qid,
};

// Re-export Venti types
pub use venti::{
    Score, VentiScore, VentiConn, VentiError, VentiResult, VentiState,
    block_type, VENTI_PORT, MAX_VENTI_PACKET, SCORE_SIZE,
    read_score, read_score_typed, write_score, write_score_typed,
    ping, sync, score_data, parse_score, score_to_hex, is_zero_score,
};

// Re-export NFS types
pub use nfs::{
    NFS_VERSION3, NFS_PORT, MOUNT_PORT,
    rpc_program, rpc_version, rpc_msgtype, rpc_auth,
    nfs3_proc, mount3_proc,
    NfsFileType, NfsHandle, NfsTime, NfsFattr, NfsEntry,
    NfsReadResult, NfsWriteResult, WriteCommitment, NfsLookupResult, NfsStat,
    RpcCred, RpcVerf, RpcHeader,
    NfsClient, MountClient, NfsFile,
    NfsFsStat, NfsFsInfo, NfsCommitResult,
};

// Re-export WebFS types
pub use webfs::{
    UrlScheme, Url, HttpMethod, HttpStatus, HttpHeader, HttpResponse,
    FtpTransferMode, FtpFileType, FtpReply,
    WebFsError, WebFsResult, WebFsFile, Client,
    HTTP_PORT, HTTPS_PORT, FTP_PORT, MAX_URL_LENGTH, MAX_REDIRECTS, DEFAULT_TIMEOUT,
};

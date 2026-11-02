//! Read-only FAT32 image adapter exposing the generic `Filesystem` API.
//!
//! Reuses the FAT boot-sector and cluster-chain implementation in `fat.rs`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::common::error::Error;
use super::common::sync::Mutex;
use super::fat::{FatBootSector, FatDevice, FatFileSystem, FatType};
use super::generic::{FsNode, Filesystem, Result};

pub struct FatImage {
    fs: FatFileSystem,
    root_cluster: u32,
    cache: Mutex<BTreeMap<u64, FsNode>>,
}

impl FatImage {
    pub fn new(device: Box<dyn FatDevice>) -> Result<Self> {
        let mut boot_bytes = vec![0u8; 512];
        device.read_sector(0, &mut boot_bytes)?;
        let boot = FatBootSector::from_bytes(&boot_bytes)?;
        if boot.is_valid() != true {
            return Err(Error::Einval);
        }

        let root_cluster = boot.root_cluster;
        let mut fs = FatFileSystem::new(boot);
        fs.set_device(device);

        let cache = Mutex::new(BTreeMap::new());
        cache.lock().insert(
            root_cluster as u64,
            FsNode {
                id: root_cluster as u64,
                name: Vec::new(),
                size: 0,
                mode: 0o755,
                is_dir: true,
            },
        );

        Ok(Self { fs, root_cluster, cache })
    }

    fn sfn_to_name(entry: &super::fat::FatDirEntry) -> Vec<u8> {
        // FAT 8.3 names store 8 characters in bytes 0..7 and 3 extension
        // characters in bytes 8..10.  Use the FAT helper so the first
        // extension character is not dropped and directories do not get a
        // trailing dot.
        entry.name_str().as_bytes().to_vec()
    }

    fn populate(&self, dir: u64) -> Result<Vec<FsNode>> {
        let entries = self.fs.read_directory_lfn(dir as u32)?;
        let mut out = Vec::new();
        let mut cache = self.cache.lock();

        for (entry, lfn) in entries {
            if entry.is_free() || entry.is_long_filename() || entry.is_volume_label() {
                continue;
            }
            let name = match lfn {
                Some(s) => s.as_bytes().to_vec(),
                None => Self::sfn_to_name(&entry),
            };
            if name.is_empty() || name == b"." || name == b".." {
                continue;
            }

            let id = entry.first_cluster() as u64;
            let is_dir = entry.is_directory();
            let info = FsNode {
                id,
                name: name.clone(),
                size: if is_dir { 0 } else { entry.file_size as u64 },
                mode: if is_dir { 0o755 } else { 0o666 },
                is_dir,
            };
            cache.insert(id, info.clone());
            out.push(info);
        }
        Ok(out)
    }
}

impl Filesystem for FatImage {
    fn root_id(&self) -> u64 {
        self.root_cluster as u64
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        if let Some(n) = self.cache.lock().get(&id) {
            return Ok(n.clone());
        }
        // Unknown nodes are treated as ordinary files; the caller will
        // normally have discovered them through `lookup` or `list_dir`.
        Ok(FsNode {
            id,
            name: Vec::new(),
            size: 0,
            mode: 0o666,
            is_dir: false,
        })
    }

    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64> {
        // FAT names are case-insensitive; the on-disk 8.3 name is uppercase.
        for e in self.populate(dir)? {
            if e.name.eq_ignore_ascii_case(name) {
                return Ok(e.id);
            }
        }
        Err(Error::Enoent)
    }

    fn list_dir(&self, dir: u64) -> Result<Vec<FsNode>> {
        self.populate(dir)
    }

    fn read_file(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let info = self.node_info(id)?;
        if info.is_dir {
            return Err(Error::Eisdir);
        }
        if offset >= info.size {
            return Ok(0);
        }
        // The FAT cluster chain has no byte length; the directory entry size
        // is authoritative, so never return bytes past the file end.
        let want = core::cmp::min(buf.len() as u64, info.size - offset);
        self.fs.read_file(id as u32, offset as usize, &mut buf[..want as usize])
    }
}

// The FAT type is intentionally limited to FAT32 in this adapter; the
// lower-level `FatFileSystem` still supports FAT12/16 cluster chains.
impl FatImage {
    pub fn fat_type(&self) -> FatType {
        self.fs.fat_type()
    }
}

pub type FatImageArc = Arc<FatImage>;

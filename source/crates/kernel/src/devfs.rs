//! `#f` filesystem device.
//!
//! `#f/sdN` attaches a read-only filesystem image stored on SD unit N.
//! EXT2/3/4, NTFS, FAT32, and XFS are detected from the image header.
//!
//! Qid paths encode the SD unit in the upper 16 bits and the
//! filesystem node id in the lower 48 bits, so `Chan::clone` keeps the
//! node identity without relying on `aux`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::dev::{Chan, Dev, DirEntry, Error as DevError, devtype, qidtype, Qid};
use crate::plan9_common::sync::Mutex;
use plan9_fs::{
    be32, le16, read_exact, FatDevice, FatImage, FsBlockReader, Filesystem,
    ExtFilesystem, NtfsFilesystem, XfsFilesystem, plan9_mode,
};

const FS_TOP: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const UNIT_SHIFT: u64 = 48;
const NODE_MASK: u64 = (1u64 << UNIT_SHIFT) - 1;

fn encode(unit: usize, node: u64) -> u64 {
    ((unit as u64) << UNIT_SHIFT) | (node & NODE_MASK)
}

fn decode(path: u64) -> (usize, u64) {
    ((path >> UNIT_SHIFT) as usize, path & NODE_MASK)
}

/// Adapter from a kernel SD unit to the filesystem crate's byte reader.
struct SdBlock {
    unit: usize,
}

impl SdBlock {
    fn sd(&self) -> Option<&crate::devsd::SdUnit> {
        crate::devsd::SdDev::get_global().get_unit(self.unit)
    }

    fn block_size(&self) -> usize {
        self.sd().map(|u| u.block_size).unwrap_or(512)
    }
}

impl FsBlockReader for SdBlock {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, plan9_common::error::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let unit = match self.sd() {
            Some(u) => u,
            None => return Err(plan9_common::error::Error::Eio),
        };
        let bs = unit.block_size as u64;
        let start_lba = offset / bs;
        let within = offset % bs;
        let sectors = ((within + buf.len() as u64 + bs - 1) / bs) as usize;
        let mut tmp = vec![0u8; sectors * bs as usize];
        match unit.read(start_lba, &mut tmp) {
            Ok(_) => {}
            Err(_) => return Err(plan9_common::error::Error::Eio),
        }
        let start = within as usize;
        let n = core::cmp::min(buf.len(), tmp.len() - start);
        buf[..n].copy_from_slice(&tmp[start..start + n]);
        Ok(n)
    }

    fn total_bytes(&self) -> u64 {
        self.sd().map(|u| u.sectors * self.block_size() as u64).unwrap_or(0)
    }

    fn sector_size(&self) -> usize {
        self.block_size()
    }
}

impl FatDevice for SdBlock {
    fn read_sector(&self, sector: u32, buf: &mut [u8]) -> Result<(), plan9_common::error::Error> {
        let unit = match self.sd() {
            Some(u) => u,
            None => return Err(plan9_common::error::Error::Eio),
        };
        if buf.len() % unit.block_size != 0 {
            return Err(plan9_common::error::Error::Einval);
        }
        match unit.read(sector as u64, buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(plan9_common::error::Error::Eio),
        }
    }

    fn write_sector(&self, _sector: u32, _buf: &[u8]) -> Result<(), plan9_common::error::Error> {
        Err(plan9_common::error::Error::Eperm)
    }

    fn sector_size(&self) -> usize {
        self.block_size()
    }

    fn total_sectors(&self) -> u64 {
        self.sd().map(|u| u.sectors).unwrap_or(0)
    }
}

pub struct FsDev {
    units: Mutex<Vec<Option<Arc<dyn Filesystem>>>>,
    names: Mutex<BTreeMap<u64, Vec<u8>>>,
}

impl FsDev {
    pub fn new() -> Self {
        Self {
            units: Mutex::new(Vec::new()),
            names: Mutex::new(BTreeMap::new()),
        }
    }

    fn parse_sd_spec(spec: &str) -> Option<usize> {
        let s = spec.trim().trim_start_matches('/');
        let digits = if s.starts_with("sd") { &s[2..] } else { s };
        if digits.is_empty() {
            return None;
        }
        digits.parse::<usize>().ok().filter(|n| *n < 8)
    }

    fn detect(unit: usize) -> Result<Arc<dyn Filesystem>, plan9_common::error::Error> {
        crate::serial::put_bytes(b"[fs] detect sd");
        crate::serial::put_bytes(unit.to_string().as_bytes());
        crate::serial::put_bytes(b"\n");
        let sd = crate::devsd::SdDev::get_global();
        let u = sd.get_unit(unit).ok_or(plan9_common::error::Error::Enoent)?;
        if !u.online.load(core::sync::atomic::Ordering::SeqCst) {
            crate::serial::put_bytes(b"[fs] unit offline\n");
            return Err(plan9_common::error::Error::Eio);
        }
        crate::serial::put_bytes(b"[fs] unit online sectors=");
        crate::serial::put_bytes(u.sectors.to_string().as_bytes());
        crate::serial::put_bytes(b"\n");

        let block = SdBlock { unit };
        let mut boot = vec![0u8; 512];
        if read_exact(&block, 0, &mut boot).is_err() {
            crate::serial::put_bytes(b"[fs] boot read failed\n");
            return Err(plan9_common::error::Error::Eio);
        }
        crate::serial::put_bytes(b"[fs] boot bytes=");
        crate::serial::put_bytes(boot[0].to_string().as_bytes());
        crate::serial::put_bytes(b"\n");

        if &boot[3..7] == b"NTFS" {
            let source: Arc<dyn FsBlockReader> = Arc::new(SdBlock { unit });
            let fs = NtfsFilesystem::new(source)?;
            return Ok(Arc::new(fs));
        }
        if be32(&boot, 0) == 0x5846_5342 {
            let source: Arc<dyn FsBlockReader> = Arc::new(SdBlock { unit });
            let fs = XfsFilesystem::new(source)?;
            return Ok(Arc::new(fs));
        }
        if boot[510] == 0x55 && boot[511] == 0xAA {
            let device: Box<dyn FatDevice> = Box::new(SdBlock { unit });
            let fs = FatImage::new(device)?;
            return Ok(Arc::new(fs));
        }

        // EXT superblock lives at byte 1024.
        let mut sb = vec![0u8; 1024];
        if read_exact(&block, 1024, &mut sb).is_err() {
            crate::serial::put_bytes(b"[fs] superblock read failed\n");
            return Err(plan9_common::error::Error::Eio);
        }
        crate::serial::put_bytes(b"[fs] sb magic=");
        crate::serial::put_bytes(le16(&sb, 56).to_string().as_bytes());
        crate::serial::put_bytes(b"\n");
        if le16(&sb, 56) == 0xEF53 {
            let source: Arc<dyn FsBlockReader> = Arc::new(SdBlock { unit });
            let fs = ExtFilesystem::new(source)?;
            crate::serial::put_bytes(b"[fs] ext mounted\n");
            return Ok(Arc::new(fs));
        }

        crate::serial::put_bytes(b"[fs] unknown image\n");
        Err(plan9_common::error::Error::Einval)
    }

    fn get_or_create(&self, unit: usize) -> Result<Arc<dyn Filesystem>, plan9_common::error::Error> {
        {
            let units = self.units.lock();
            if let Some(u) = units.get(unit) {
                if let Some(fs) = u {
                    return Ok(fs.clone());
                }
            }
        }
        let fs = Self::detect(unit)?;
        let mut units = self.units.lock();
        while units.len() <= unit {
            units.push(None);
        }
        if units[unit].is_none() {
            units[unit] = Some(fs.clone());
        }
        Ok(fs)
    }

    fn root_qid(&self, unit: usize, fs: &Arc<dyn Filesystem>) -> Qid {
        Qid::new(encode(unit, fs.root_id()), 0, qidtype::DIR)
    }

    fn node_of(&self, ch: &Chan) -> Result<(usize, u64, Arc<dyn Filesystem>), DevError> {
        let (unit, node) = decode(ch.qid.path);
        let fs = self.get_or_create(unit).map_err(|_| DevError::Enoent)?;
        Ok((unit, node, fs))
    }
}

impl Dev for FsDev {
    fn attach(&mut self, spec: Option<&str>) -> Result<Chan, DevError> {
        if spec.is_none() || spec.unwrap_or("").is_empty() {
            return Ok(Chan::new(
                devtype::FS,
                Qid::new(FS_TOP, 0, qidtype::DIR),
                0,
            ));
        }
        let unit = Self::parse_sd_spec(spec.unwrap_or("")).ok_or(DevError::Enoent)?;
        let fs = self.get_or_create(unit).map_err(|_| DevError::Eio)?;
        let qid = self.root_qid(unit, &fs);
        self.names.lock().insert(qid.path, b"fs".to_vec());
        Ok(Chan::new(devtype::FS, qid, 0))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        if ch.qid.path == FS_TOP {
            if name == ".." || name == "." {
                return Ok(Some(ch.qid));
            }
            let unit = Self::parse_sd_spec(name).ok_or(DevError::Enoent)?;
            let fs = self.get_or_create(unit).map_err(|_| DevError::Enoent)?;
            ch.qid = self.root_qid(unit, &fs);
            return Ok(Some(ch.qid));
        }

        let (unit, node, fs) = self.node_of(ch)?;

        if name == ".." {
            let root = fs.root_id();
            if node == root {
                ch.qid = Qid::new(FS_TOP, 0, qidtype::DIR);
            } else {
                ch.qid = self.root_qid(unit, &fs);
            }
            return Ok(Some(ch.qid));
        }
        if name == "." {
            return Ok(Some(ch.qid));
        }

        let id = fs.lookup(node, name.as_bytes()).map_err(|_| DevError::Enoent)?;
        let info = fs.node_info(id).map_err(|_| DevError::Eio)?;
        let path = encode(unit, id);
        ch.qid = Qid::new(
            path,
            0,
            if info.is_dir { qidtype::DIR } else { qidtype::FILE },
        );
        self.names.lock().insert(path, name.as_bytes().to_vec());
        Ok(Some(ch.qid))
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        ch.mode = mode;
        Ok(())
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        if ch.qid.path == FS_TOP {
            let sd = crate::devsd::SdDev::get_global();
            let mut text = String::new();
            for unit in 0..8 {
                if let Some(u) = sd.get_unit(unit) {
                    if u.online.load(core::sync::atomic::Ordering::SeqCst) {
                        text.push_str("sd");
                        text.push_str(&unit.to_string());
                        text.push('\n');
                    }
                }
            }
            let start = offset as usize;
            if start >= text.len() {
                return Ok(0);
            }
            let bytes = text.as_bytes();
            let end = core::cmp::min(start + buf.len(), bytes.len());
            let n = end - start;
            buf[..n].copy_from_slice(&bytes[start..end]);
            return Ok(n);
        }

        let (_, node, fs) = self.node_of(ch)?;
        let info = fs.node_info(node).map_err(|_| DevError::Eio)?;
        if info.is_dir {
            let entries = fs.list_dir(node).map_err(|_| DevError::Eio)?;
            let mut names: Vec<String> = entries
                .iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect();
            names.sort();
            let mut text = String::new();
            for n in names {
                text.push_str(&n);
                text.push('\n');
            }
            let start = offset as usize;
            if start >= text.len() {
                return Ok(0);
            }
            let bytes = text.as_bytes();
            let end = core::cmp::min(start + buf.len(), bytes.len());
            let n = end - start;
            buf[..n].copy_from_slice(&bytes[start..end]);
            return Ok(n);
        }

        fs.read_file(node, offset, buf).map_err(|_| DevError::Eio)
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        if ch.qid.path == FS_TOP {
            return Ok(DirEntry {
                dev: devtype::FS,
                qid: ch.qid,
                mode: 0o555 | 0o40000,
                atime: 0,
                mtime: 0,
                length: 0,
                name: b"fs".to_vec(),
                uid: 0,
                gid: 0,
});
        }
        let (_, node, fs) = self.node_of(ch)?;
        let info = fs.node_info(node).map_err(|_| DevError::Eio)?;
        let name = self
            .names
            .lock()
            .get(&ch.qid.path)
            .cloned()
            .unwrap_or_default();
        Ok(DirEntry {
            dev: devtype::FS,
            qid: ch.qid,
            mode: plan9_mode(&info),
            atime: 0,
            mtime: 0,
            length: info.size,
            name,
                uid: 0,
                gid: 0,
})
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn write(&mut self, _ch: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        'f'
    }

    fn name(&self) -> &'static str {
        "fs"
    }
}

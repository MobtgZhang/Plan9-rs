//! EXT2/EXT3/EXT4 read-only parser.
//!
//! Supports the ext4 extent tree used by modern images and the classic
//! direct/indirect block layout used by ext2/ext3.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::block::{le16, le32, read_block, read_exact, FsBlockReader};
use super::generic::{FsNode, Filesystem, Result};
use super::common::error::Error;

const EXT_MAGIC: u16 = 0xEF53;
const EXTENT_MAGIC: u16 = 0xF30A;

pub struct ExtFilesystem {
    source: Arc<dyn FsBlockReader>,
    block_size: u64,
    inode_size: u64,
    inodes_per_group: u64,
    group_desc_size: u64,
    gdt_block: u64,
    first_data_block: u64,
    inodes_count: u64,
}

impl ExtFilesystem {
    pub fn new(source: Arc<dyn FsBlockReader>) -> Result<Self> {
        let mut sb = [0u8; 1024];
        read_exact(source.as_ref(), 1024, &mut sb)?;

        if le16(&sb, 56) != EXT_MAGIC {
            return Err(Error::Einval);
        }

        let log_block = le32(&sb, 24);
        let block_size = 1024u64 << log_block;
        let first_data_block = le32(&sb, 20) as u64;
        let inodes_per_group = le32(&sb, 40) as u64;
        let inode_size = le16(&sb, 88) as u64;
        let inode_size = if inode_size == 0 { 128 } else { inode_size };
        let group_desc_size = if sb.len() >= 256 {
            le16(&sb, 254) as u64
        } else {
            0
        };
        let group_desc_size = if group_desc_size == 0 { 32 } else { group_desc_size };
        let inodes_count = le32(&sb, 0) as u64;

        if inodes_per_group == 0 || inode_size == 0 {
            return Err(Error::Einval);
        }

        Ok(Self {
            source,
            block_size,
            inode_size,
            inodes_per_group,
            group_desc_size,
            gdt_block: first_data_block + 1,
            first_data_block,
            inodes_count,
        })
    }

    fn read_inode(&self, id: u64) -> Result<Vec<u8>> {
        if id == 0 || id > self.inodes_count {
            return Err(Error::Enoent);
        }
        let group = (id - 1) / self.inodes_per_group;
        let index = (id - 1) % self.inodes_per_group;

        let desc_off = self.gdt_block * self.block_size + group * self.group_desc_size;
        let mut desc = vec![0u8; self.group_desc_size as usize];
        read_exact(self.source.as_ref(), desc_off, &mut desc)?;

        // ext4 group descriptor: block_bitmap, inode_bitmap, inode_table.
        let inode_table = le32(&desc, 8) as u64;
        let inode_off = inode_table * self.block_size + index * self.inode_size;
        let mut inode = vec![0u8; self.inode_size as usize];
        read_exact(self.source.as_ref(), inode_off, &mut inode)?;
        Ok(inode)
    }

    fn is_dir_mode(mode: u16) -> bool {
        (mode & 0xF000) == 0x4000
    }

    fn inode_info(&self, inode: &[u8], id: u64, name: &[u8]) -> FsNode {
        let mode = le16(inode, 0) as u32;
        let size_lo = le32(inode, 4) as u64;
        let size_hi = if inode.len() >= 112 {
            le32(inode, 108) as u64
        } else {
            0
        };
        FsNode {
            id,
            name: name.to_vec(),
            size: size_lo | (size_hi << 32),
            mode,
            is_dir: Self::is_dir_mode(mode as u16),
        }
    }

    fn extents(&self, inode: &[u8]) -> Option<Vec<(u64, u64, u64)>> {
        let i_block = &inode[40..100];
        if i_block.len() < 60 {
            return None;
        }
        if le16(i_block, 0) != EXTENT_MAGIC {
            return None;
        }
        let mut runs = Vec::new();
        if self.collect_extent_node(i_block, 0, &mut runs).is_err() {
            return None;
        }
        Some(runs)
    }

    fn collect_extent_node(
        &self,
        data: &[u8],
        base_off: usize,
        runs: &mut Vec<(u64, u64, u64)>,
    ) -> Result<()> {
        if data.len() < base_off + 12 {
            return Err(Error::Eio);
        }
        let entries = le16(data, base_off + 2);
        let depth = le16(data, base_off + 6);
        let entry_base = base_off + 12;

        for i in 0..entries as usize {
            let off = entry_base + i * 12;
            if off + 12 > data.len() {
                return Err(Error::Eio);
            }
            let logical = le32(data, off) as u64;
            let len = le16(data, off + 4) as u64;
            let start_hi = le16(data, off + 6) as u64;
            let start_lo = le32(data, off + 8) as u64;
            let physical = (start_hi << 32) | start_lo;
            if len == 0 {
                continue;
            }
            if depth == 0 {
                runs.push((logical, physical, len));
            } else {
                let child = read_block(self.source.as_ref(), physical * self.block_size, self.block_size as usize)?;
                self.collect_extent_node(&child, 0, runs)?;
            }
        }
        Ok(())
    }

    fn direct_pointer(&self, inode: &[u8], logical_block: u64) -> Option<u64> {
        let i_block = &inode[40..100];
        if i_block.len() < 60 {
            return None;
        }
        let ptr = |idx: usize| le32(i_block, idx * 4) as u64;
        let n = self.block_size / 4;

        if logical_block < 12 {
            let p = ptr(logical_block as usize);
            return if p == 0 { None } else { Some(p) };
        }

        let mut idx = logical_block - 12;
        if idx < n {
            let single = ptr(12);
            if single == 0 { return None; }
            let block = read_block(self.source.as_ref(), single * self.block_size, self.block_size as usize).ok()?;
            let p = le32(&block, idx as usize * 4) as u64;
            return if p == 0 { None } else { Some(p) };
        }

        idx -= n;
        if idx < n * n {
            let double = ptr(13);
            if double == 0 { return None; }
            let first = read_block(self.source.as_ref(), double * self.block_size, self.block_size as usize).ok()?;
            let a = (idx / n) as usize;
            let b = (idx % n) as usize;
            let second = le32(&first, a * 4) as u64;
            if second == 0 { return None; }
            let block = read_block(self.source.as_ref(), second * self.block_size, self.block_size as usize).ok()?;
            let p = le32(&block, b * 4) as u64;
            return if p == 0 { None } else { Some(p) };
        }

        idx -= n * n;
        if idx < n * n * n {
            let triple = ptr(14);
            if triple == 0 { return None; }
            let first = read_block(self.source.as_ref(), triple * self.block_size, self.block_size as usize).ok()?;
            let a = (idx / (n * n)) as usize;
            let b = ((idx / n) % n) as usize;
            let c = (idx % n) as usize;
            let second = le32(&first, a * 4) as u64;
            if second == 0 { return None; }
            let mid = read_block(self.source.as_ref(), second * self.block_size, self.block_size as usize).ok()?;
            let third = le32(&mid, b * 4) as u64;
            if third == 0 { return None; }
            let block = read_block(self.source.as_ref(), third * self.block_size, self.block_size as usize).ok()?;
            let p = le32(&block, c * 4) as u64;
            return if p == 0 { None } else { Some(p) };
        }

        None
    }

    fn logical_block_physical(&self, inode: &[u8], logical_block: u64) -> Option<u64> {
        if let Some(runs) = self.extents(inode) {
            for (start, physical, len) in runs {
                if logical_block >= start && logical_block < start + len {
                    return Some(physical + (logical_block - start));
                }
            }
            None
        } else {
            self.direct_pointer(inode, logical_block)
        }
    }

    fn read_logical_block(&self, inode: &[u8], logical_block: u64) -> Result<Vec<u8>> {
        let phys = self.logical_block_physical(inode, logical_block).ok_or(Error::Eio)?;
        read_block(self.source.as_ref(), phys * self.block_size, self.block_size as usize)
    }

    fn list_dir_entries(&self, id: u64) -> Result<Vec<FsNode>> {
        let inode = self.read_inode(id)?;
        let info = self.inode_info(&inode, id, b"");
        if !info.is_dir {
            return Err(Error::Enotdir);
        }
        let blocks = (info.size + self.block_size - 1) / self.block_size;
        let mut out = Vec::new();

        for b in 0..blocks {
            let block = self.read_logical_block(&inode, b)?;
            let mut pos = 0usize;
            while pos + 8 <= block.len() {
                let ino = le32(&block, pos) as u64;
                let rec_len = le16(&block, pos + 4) as usize;
                if rec_len < 8 || pos + rec_len > block.len() {
                    break;
                }
                if ino != 0 {
                    let name_len = block[pos + 6] as usize;
                    if name_len > 0 && pos + 8 + name_len <= block.len() {
                        let name = &block[pos + 8..pos + 8 + name_len];
                        let child = self.read_inode(ino)?;
                        let child_info = self.inode_info(&child, ino, name);
                        out.push(child_info);
                    }
                }
                pos += rec_len;
            }
        }
        Ok(out)
    }
}

impl Filesystem for ExtFilesystem {
    fn root_id(&self) -> u64 {
        2
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        let inode = self.read_inode(id)?;
        Ok(self.inode_info(&inode, id, b""))
    }

    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64> {
        let entries = self.list_dir_entries(dir)?;
        for e in entries {
            if e.name == name {
                return Ok(e.id);
            }
        }
        Err(Error::Enoent)
    }

    fn list_dir(&self, dir: u64) -> Result<Vec<FsNode>> {
        self.list_dir_entries(dir)
    }

    fn read_file(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(id)?;
        let info = self.inode_info(&inode, id, b"");
        if info.is_dir {
            return Err(Error::Eisdir);
        }
        if offset >= info.size {
            return Ok(0);
        }
        let want = core::cmp::min(buf.len() as u64, info.size - offset);
        let mut done = 0usize;
        while (done as u64) < want {
            let pos = offset + done as u64;
            let logical_block = pos / self.block_size;
            let within = pos % self.block_size;
            let block = self.read_logical_block(&inode, logical_block)?;
            let n = core::cmp::min((want - done as u64) as usize, block.len() - within as usize);
            buf[done..done + n].copy_from_slice(&block[within as usize..within as usize + n]);
            done += n;
        }
        Ok(done)
    }
}

/// Keep a helper used by callers that want the ext4 block size reported.
impl ExtFilesystem {
    pub fn block_size(&self) -> u64 {
        self.block_size
    }
}

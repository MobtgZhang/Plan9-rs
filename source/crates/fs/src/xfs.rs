//! XFS read-only parser.
//!
//! Handles v5 inode layout (512-byte inodes), short-form directories, and
//! data-fork extent records. Directory formats other than short-form are not
//! implemented.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::block::{be16, be32, be64, read_block, read_exact, FsBlockReader};
use super::generic::{FsNode, Filesystem, Result};
use super::common::error::Error;

const XFS_MAGIC: u32 = 0x5846_5342;
const XFS_INODE_MAGIC: u16 = 0x494E;

pub struct XfsFilesystem {
    source: Arc<dyn FsBlockReader>,
    block_size: u64,
    rootino: u64,
    agblocks: u64,
    agblklog: u32,
    inopblog: u32,
    inode_size: u64,
    has_ftype: bool,
}

impl XfsFilesystem {
    pub fn new(source: Arc<dyn FsBlockReader>) -> Result<Self> {
        let mut sb = [0u8; 512];
        read_exact(source.as_ref(), 0, &mut sb)?;
        if be32(&sb, 0) != XFS_MAGIC {
            return Err(Error::Einval);
        }

        let block_size = be32(&sb, 4) as u64;
        let rootino = be64(&sb, 56);
        let agblocks = be32(&sb, 84) as u64;
        let inode_size = be16(&sb, 104) as u64;
        let inopblog = sb[123] as u32;
        let agblklog = sb[124] as u32;
        let features_incompat = be32(&sb, 216);

        if block_size == 0 || agblocks == 0 || inode_size == 0 || agblklog == 0 {
            return Err(Error::Einval);
        }

        Ok(Self {
            source,
            block_size,
            rootino,
            agblocks,
            agblklog,
            inopblog,
            inode_size,
            has_ftype: (features_incompat & 0x1) != 0,
        })
    }

    fn inode_offset(&self, id: u64) -> u64 {
        let agno = id >> self.agblklog;
        let mask = (1u64 << self.agblklog) - 1;
        let agbno = (id >> self.inopblog) & mask;
        let slot = id & ((1u64 << self.inopblog) - 1);
        agno * self.agblocks * self.block_size + agbno * self.block_size + slot * self.inode_size
    }

    fn read_inode(&self, id: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.inode_size as usize];
        read_exact(self.source.as_ref(), self.inode_offset(id), &mut buf)?;
        if be16(&buf, 0) != XFS_INODE_MAGIC {
            return Err(Error::Enoent);
        }
        Ok(buf)
    }

    fn nextents(&self, inode: &[u8]) -> u64 {
        let flags2 = be64(inode, 120);
        if (flags2 & 0x10) != 0 {
            be64(inode, 24)
        } else {
            be32(inode, 76) as u64
        }
    }

    fn extents(&self, inode: &[u8]) -> Vec<(u64, u64, u64)> {
        let count = self.nextents(inode);
        let mut out = Vec::new();
        for i in 0..count as usize {
            let off = 176 + i * 16;
            if off + 16 > inode.len() {
                break;
            }
            let l0 = be64(inode, off);
            let l1 = be64(inode, off + 8);
            let startoff = l0 >> 9;
            let startblock = ((l0 & 0x1FF) << 43) | (l1 >> 21);
            let blockcount = l1 & 0x001F_FFFF;
            out.push((startoff, startblock, blockcount));
        }
        out
    }

    fn dir_entries(&self, inode: &[u8]) -> Result<Vec<(u64, Vec<u8>, bool)>> {
        let mode = be16(inode, 2) as u32;
        if (mode & 0xF000) != 0x4000 {
            return Err(Error::Enotdir);
        }
        let format = inode[5];
        if format != 1 {
            return Err(Error::Enotdir);
        }

        let data = &inode[176..];
        if data.len() < 6 {
            return Err(Error::Eio);
        }
        let count = data[0] as usize;
        let i8count = data[1] != 0;
        let mut pos = 6usize;
        let mut out = Vec::new();

        for _ in 0..count {
            if pos >= data.len() {
                break;
            }
            let namelen = data[pos] as usize;
            pos += 1;
            if pos + 2 + namelen > data.len() {
                break;
            }
            pos += 2; // offset
            let name = data[pos..pos + namelen].to_vec();
            pos += namelen;
            if self.has_ftype {
                if pos >= data.len() {
                    break;
                }
                pos += 1;
            }
            let ino = if i8count {
                if pos + 8 > data.len() {
                    break;
                }
                let v = be64(data, pos);
                pos += 8;
                v
            } else {
                if pos + 4 > data.len() {
                    break;
                }
                let v = be32(data, pos) as u64;
                pos += 4;
                v
            };
            out.push((ino, name, false));
        }
        Ok(out)
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        let inode = self.read_inode(id)?;
        let mode = be16(&inode, 2) as u32;
        let is_dir = (mode & 0xF000) == 0x4000;
        let size = be64(&inode, 56);
        Ok(FsNode {
            id,
            name: Vec::new(),
            size,
            mode,
            is_dir,
        })
    }

    fn read_logical_block(&self, inode: &[u8], logical: u64) -> Result<Vec<u8>> {
        for (startoff, startblock, count) in self.extents(inode) {
            if logical >= startoff && logical < startoff + count {
                let phys = startblock + (logical - startoff);
                return read_block(self.source.as_ref(), phys * self.block_size, self.block_size as usize);
            }
        }
        Err(Error::Eio)
    }
}

impl Filesystem for XfsFilesystem {
    fn root_id(&self) -> u64 {
        self.rootino
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        XfsFilesystem::node_info(self, id)
    }

    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64> {
        let inode = self.read_inode(dir)?;
        let entries = self.dir_entries(&inode)?;
        for (id, n, _) in entries {
            if n == name {
                return Ok(id);
            }
        }
        Err(Error::Enoent)
    }

    fn list_dir(&self, dir: u64) -> Result<Vec<FsNode>> {
        let inode = self.read_inode(dir)?;
        let entries = self.dir_entries(&inode)?;
        let mut out = Vec::new();
        for (id, name, _) in entries {
            let info = self.node_info(id)?;
            out.push(FsNode { name, ..info });
        }
        Ok(out)
    }

    fn read_file(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(id)?;
        let info = XfsFilesystem::node_info(self, id)?;
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
            let logical = pos / self.block_size;
            let within = pos % self.block_size;
            let block = self.read_logical_block(&inode, logical)?;
            let n = core::cmp::min((want - done as u64) as usize, block.len() - within as usize);
            buf[done..done + n].copy_from_slice(&block[within as usize..within as usize + n]);
            done += n;
        }
        Ok(done)
    }
}

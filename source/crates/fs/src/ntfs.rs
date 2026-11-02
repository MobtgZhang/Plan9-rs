//! NTFS read-only parser.
//!
//! This implementation reads the MFT stream from the boot-sector `$MFT`
//! location, parses resident and non-resident attributes, and reconstructs
//! directory entries from `$FILE_NAME` attributes. It is sufficient for the
//! test image and for small NTFS volumes; it does not implement the index
//! B-tree or journaling.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::block::{le16, le32, le64, read_exact, FsBlockReader};
use super::generic::{FsNode, Filesystem, Result};
use super::common::error::Error;

const ATTR_END: u32 = 0xFFFF_FFFF;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;

struct Run {
    vcn: u64,
    lcn: i64,
    length: u64,
}

struct Attr {
    typ: u32,
    non_resident: bool,
    data_size: u64,
    data_start: usize,
    mapping_start: usize,
    mapping_end: usize,
    name_len: u8,
}

pub struct NtfsFilesystem {
    source: Arc<dyn FsBlockReader>,
    cluster_size: u64,
    record_size: u64,
    mft_runs: Vec<Run>,
    mft_size: u64,
}

impl NtfsFilesystem {
    pub fn new(source: Arc<dyn FsBlockReader>) -> Result<Self> {
        let mut boot = [0u8; 512];
        read_exact(source.as_ref(), 0, &mut boot)?;
        if &boot[3..7] != b"NTFS" {
            return Err(Error::Einval);
        }

        let bytes_per_sector = le16(&boot, 11) as u64;
        let sectors_per_cluster = boot[13] as u64;
        let cluster_size = bytes_per_sector * sectors_per_cluster;
        if cluster_size == 0 {
            return Err(Error::Einval);
        }

        let mft_lcn = le64(&boot, 48);
        let record_byte = boot[64] as i8;
        let record_size = if record_byte >= 0 {
            (1u64 << record_byte as u8) * cluster_size
        } else {
            1u64 << ((-record_byte) as u8)
        };
        if record_size == 0 {
            return Err(Error::Einval);
        }

        let mft_offset = mft_lcn * cluster_size;
        let mut rec0 = vec![0u8; record_size as usize];
        read_exact(source.as_ref(), mft_offset, &mut rec0)?;
        let attrs = parse_attrs(&rec0)?;

        let mut mft_runs = Vec::new();
        let mut mft_size = 0u64;
        for a in attrs {
            if a.typ == ATTR_DATA && a.name_len == 0 && a.non_resident {
                mft_runs = decode_runlist(&rec0[a.mapping_start..a.mapping_end])?;
                mft_size = a.data_size;
                break;
            }
        }
        if mft_runs.is_empty() {
            return Err(Error::Eio);
        }

        Ok(Self {
            source,
            cluster_size,
            record_size,
            mft_runs,
            mft_size,
        })
    }

    fn record_count(&self) -> u64 {
        self.mft_size / self.record_size
    }

    fn read_mft_record(&self, record: u64) -> Result<Vec<u8>> {
        let offset = record * self.record_size;
        let mut buf = vec![0u8; self.record_size as usize];
        self.read_stream(&self.mft_runs, offset, &mut buf)?;
        Ok(buf)
    }

    fn read_stream(&self, runs: &[Run], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut done = 0usize;
        let want = buf.len() as u64;
        while (done as u64) < want {
            let pos = offset + done as u64;
            let cluster = pos / self.cluster_size;
            let within = (pos % self.cluster_size) as usize;
            let run = runs.iter().find(|r| cluster >= r.vcn && cluster < r.vcn + r.length);
            let r = match run {
                Some(r) => r,
                None => return Err(Error::Eio),
            };
            if r.lcn < 0 {
                let n = core::cmp::min((want - done as u64) as usize, self.cluster_size as usize - within);
                buf[done..done + n].fill(0);
                done += n;
                continue;
            }
            // The runlist's `vcn` is the stream-relative cluster index, and
            // `lcn` is the physical cluster of that run's first cluster.
            // Add the offset within the run, not just the byte offset inside
            // the first physical cluster.
            let phys = (r.lcn + (cluster as i64 - r.vcn as i64)) as u64 * self.cluster_size
                + within as u64;
            let n = core::cmp::min(
                (want - done as u64) as usize,
                self.cluster_size as usize - within,
            );
            let mut tmp = vec![0u8; n];
            read_exact(self.source.as_ref(), phys, &mut tmp)?;
            buf[done..done + n].copy_from_slice(&tmp);
            done += n;
        }
        Ok(done)
    }

    fn name_of(&self, rec: &[u8], a: &Attr) -> Vec<u8> {
        // FILE_NAME data layout:
        //   parent (8), times (32), allocated (8), data size (8),
        //   attributes (4), reparse (4), name_len (1), namespace (1),
        //   UTF-16LE name.
        let data = a.data_start;
        if data + 66 > rec.len() {
            return Vec::new();
        }
        let name_len = rec[data + 64] as usize;
        let mut out = Vec::new();
        for i in 0..name_len {
            let off = data + 66 + i * 2;
            if off + 2 > rec.len() {
                break;
            }
            let cu = u16::from_le_bytes([rec[off], rec[off + 1]]);
            if cu < 0x80 {
                out.push(cu as u8);
            } else {
                // Approximate non-ASCII code units as their low byte.
                out.push((cu & 0xFF) as u8);
            }
        }
        out
    }

    fn parent_of(&self, rec: &[u8], a: &Attr) -> u64 {
        let data = a.data_start;
        if data + 8 > rec.len() {
            return 0;
        }
        le64(rec, data) & 0x0000_FFFF_FFFF_FFFF
    }

    fn file_size(&self, rec: &[u8], attrs: &[Attr], id: u64) -> u64 {
        let mut best = 0u64;
        for a in attrs {
            if a.typ == ATTR_DATA && a.name_len == 0 {
                best = a.data_size;
            }
        }
        let _ = id;
        best
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        let rec = self.read_mft_record(id)?;
        if rec.len() < 4 || &rec[0..4] != b"FILE" {
            return Err(Error::Enoent);
        }
        let attrs = parse_attrs(&rec)?;
        let flags = le16(&rec, 22);
        let is_dir = (flags & 0x2) != 0;
        let size = if is_dir { 0 } else { self.file_size(&rec, &attrs, id) };
        Ok(FsNode {
            id,
            name: Vec::new(),
            size,
            mode: if is_dir { 0o755 } else { 0o666 },
            is_dir,
        })
    }

    fn list_names(&self, dir: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut out = Vec::new();
        let count = self.record_count();
        for r in 0..count {
            let rec = self.read_mft_record(r)?;
            if rec.len() < 4 || &rec[0..4] != b"FILE" {
                continue;
            }
            let attrs = parse_attrs(&rec).unwrap_or_default();
            for a in attrs {
                if a.typ == ATTR_FILE_NAME && a.data_start + 66 <= rec.len() {
                    if self.parent_of(&rec, &a) == dir {
                        let name = self.name_of(&rec, &a);
                        if name == b"." || name == b".." || name.is_empty() {
                            continue;
                        }
                        out.push((r, name));
                    }
                }
            }
        }
        Ok(out)
    }
}

impl Filesystem for NtfsFilesystem {
    fn root_id(&self) -> u64 {
        5
    }

    fn node_info(&self, id: u64) -> Result<FsNode> {
        NtfsFilesystem::node_info(self, id)
    }

    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64> {
        for (id, n) in self.list_names(dir)? {
            if n == name {
                return Ok(id);
            }
        }
        Err(Error::Enoent)
    }

    fn list_dir(&self, dir: u64) -> Result<Vec<FsNode>> {
        let mut out = Vec::new();
        for (id, name) in self.list_names(dir)? {
            let info = self.node_info(id)?;
            out.push(FsNode { name, ..info });
        }
        Ok(out)
    }

    fn read_file(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let rec = self.read_mft_record(id)?;
        let attrs = parse_attrs(&rec)?;
        let flags = le16(&rec, 22);
        if (flags & 0x2) != 0 {
            return Err(Error::Eisdir);
        }
        let data = attrs.iter().find(|a| a.typ == ATTR_DATA && a.name_len == 0);
        let a = match data {
            Some(a) => a,
            None => return Ok(0),
        };
        if a.non_resident {
            let runs = decode_runlist(&rec[a.mapping_start..a.mapping_end])?;
            let size = a.data_size;
            if offset >= size {
                return Ok(0);
            }
            let want = core::cmp::min(buf.len() as u64, size - offset);
            self.read_stream(&runs, offset, &mut buf[..want as usize])?;
            return Ok(want as usize);
        } else {
            let start = a.data_start;
            let size = a.data_size as usize;
            if offset >= size as u64 {
                return Ok(0);
            }
            let begin = offset as usize;
            let end = core::cmp::min(begin + buf.len(), size);
            let n = end - begin;
            buf[..n].copy_from_slice(&rec[start + begin..start + begin + n]);
            return Ok(n);
        }
    }
}

fn parse_attrs(rec: &[u8]) -> Result<Vec<Attr>> {
    if rec.len() < 24 {
        return Err(Error::Eio);
    }
    let attr_off = le16(rec, 20) as usize;
    let mut p = attr_off;
    let mut out = Vec::new();
    while p + 8 <= rec.len() {
        let typ = le32(rec, p);
        if typ == ATTR_END {
            break;
        }
        let length = le32(rec, p + 4) as usize;
        if length == 0 || p + length > rec.len() {
            break;
        }
        let non_resident = rec[p + 8] != 0;
        let name_len = rec[p + 9];
        let mut attr = Attr {
            typ,
            non_resident,
            data_size: 0,
            data_start: 0,
            mapping_start: 0,
            mapping_end: 0,
            name_len,
        };
        if non_resident {
            let mapping_off = le16(rec, p + 32) as usize;
            attr.data_size = le64(rec, p + 48);
            attr.mapping_start = p + mapping_off;
            attr.mapping_end = core::cmp::min(rec.len(), p + length);
        } else {
            attr.data_size = le32(rec, p + 16) as u64;
            attr.data_start = p + 24;
        }
        out.push(attr);
        p += length;
    }
    Ok(out)
}

fn read_var_le(bytes: &[u8], start: usize, n: usize) -> u64 {
    let mut value = 0u64;
    for i in 0..n {
        value |= (bytes[start + i] as u64) << (8 * i);
    }
    value
}

fn read_signed_le(bytes: &[u8], start: usize, n: usize) -> i64 {
    if n == 0 {
        return 0;
    }
    let mut value = 0i64;
    for i in 0..n {
        value |= (bytes[start + i] as i64) << (8 * i);
    }
    if bytes[start + n - 1] & 0x80 != 0 {
        value -= 1i64 << (8 * n);
    }
    value
}

fn decode_runlist(bytes: &[u8]) -> Result<Vec<Run>> {
    let mut pos = 0usize;
    let mut vcn = 0u64;
    let mut lcn = 0i64;
    let mut runs = Vec::new();
    while pos < bytes.len() {
        let head = bytes[pos];
        if head == 0 {
            break;
        }
        let len_bytes = (head & 0x0F) as usize;
        let lcn_bytes = (head >> 4) as usize;
        pos += 1;
        if pos + len_bytes + lcn_bytes > bytes.len() {
            return Err(Error::Eio);
        }
        let length = read_var_le(bytes, pos, len_bytes);
        pos += len_bytes;
        let delta = read_signed_le(bytes, pos, lcn_bytes);
        pos += lcn_bytes;
        if length == 0 {
            break;
        }
        if lcn_bytes == 0 {
            lcn = -1;
        } else {
            if lcn < 0 {
                lcn = 0;
            }
            lcn += delta;
        }
        runs.push(Run { vcn, lcn, length });
        vcn += length;
    }
    Ok(runs)
}

use alloc::{collections::BTreeSet, string::String, vec, vec::Vec};
use plan9_common::sync::Spinlock;

use crate::dev::{self, Error};
use crate::devsd::{SdDev, SdUnit, SD_MAX_UNITS};
use crate::rootfs::{AclEntry, RamNode, RootFsDev};

const BLOCK: usize = 4096;
const DISK_MAGIC: &[u8; 8] = b"P9ROOT1\0";
const SLOT_MAGIC: &[u8; 8] = b"P9SLOT1\0";
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_NODES: u64 = 16_384;
const HASH_SEED: u64 = 0xcbf29ce484222325;

pub(crate) const MACHINE: u16 = if cfg!(target_arch = "x86_64") { 62 }
    else if cfg!(target_arch = "aarch64") { 183 }
    else if cfg!(target_arch = "riscv64") { 243 }
    else { 258 };

type Result<T> = core::result::Result<T, Error>;

struct Header {
    slot: u64,
    generation: u64,
    length: u64,
    hash: u64,
}

struct RootDisk {
    unit: usize,
    current: Option<Header>,
}

static ROOT: Spinlock<Option<RootDisk>> = Spinlock::new(None);

struct Disk<'a> {
    unit: &'a SdUnit,
    sectors_per_block: u64,
    blocks_per_slot: u64,
}

impl<'a> Disk<'a> {
    fn new(unit: &'a SdUnit) -> Option<Self> {
        if !unit.supports_checkpoint() || unit.block_size == 0 || BLOCK % unit.block_size != 0 {
            return None;
        }
        let sectors_per_block = (BLOCK / unit.block_size) as u64;
        let blocks_per_slot = (unit.sectors / sectors_per_block).saturating_sub(1) / 2;
        (blocks_per_slot >= 2).then_some(Self { unit, sectors_per_block, blocks_per_slot })
    }

    fn read(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let count = self.unit.read(block * self.sectors_per_block, buffer)?;
        (count == BLOCK).then_some(()).ok_or(Error::Eio)
    }

    fn write(&self, block: u64, buffer: &[u8]) -> Result<()> {
        let count = self.unit.write(block * self.sectors_per_block, buffer)?;
        (count == BLOCK).then_some(()).ok_or(Error::Eio)
    }

    fn slot_start(&self, slot: u64) -> u64 {
        1 + slot * self.blocks_per_slot
    }

    fn limit(&self) -> u64 {
        (self.blocks_per_slot - 1).saturating_mul(BLOCK as u64).min(MAX_BYTES)
    }

    fn header(&self, slot: u64, buffer: &mut [u8]) -> Result<Option<Header>> {
        self.read(self.slot_start(slot), buffer)?;
        if buffer.get(..8) != Some(SLOT_MAGIC) || buffer[8..10] != MACHINE.to_le_bytes() {
            return Ok(None);
        }
        let generation = word(&buffer[16..24]);
        let length = word(&buffer[24..32]);
        let hash = word(&buffer[32..40]);
        let header_hash = word(&buffer[40..48]);
        if generation == 0 || !(8..=self.limit()).contains(&length)
            || hash_bytes(HASH_SEED, &buffer[..40]) != header_hash
        {
            return Ok(None);
        }
        Ok(Some(Header { slot, generation, length, hash }))
    }
}

struct Stream<'a> {
    disk: Disk<'a>,
    first: u64,
    buffer: Vec<u8>,
    offset: u64,
    limit: u64,
    hash: u64,
}

impl Stream<'_> {
    fn read(&mut self, mut output: &mut [u8]) -> Result<()> {
        if output.len() as u64 > self.limit - self.offset {
            return Err(Error::Einval);
        }
        while !output.is_empty() {
            let start = self.offset as usize % BLOCK;
            if start == 0 {
                self.disk.read(self.first + self.offset / BLOCK as u64, &mut self.buffer)?;
            }
            let count = output.len().min(BLOCK - start);
            let bytes = &self.buffer[start..start + count];
            output[..count].copy_from_slice(bytes);
            output = &mut output[count..];
            self.hash = hash_bytes(self.hash, bytes);
            self.offset += count as u64;
        }
        Ok(())
    }

    fn write(&mut self, mut input: &[u8]) -> Result<()> {
        if input.len() as u64 > self.limit - self.offset {
            return Err(Error::Enospace);
        }
        while !input.is_empty() {
            let start = self.offset as usize % BLOCK;
            let count = input.len().min(BLOCK - start);
            let bytes = &input[..count];
            self.buffer[start..start + count].copy_from_slice(bytes);
            self.hash = hash_bytes(self.hash, bytes);
            if start + count == BLOCK {
                self.disk.write(self.first + self.offset / BLOCK as u64, &self.buffer)?;
            }
            self.offset += count as u64;
            input = &input[count..];
        }
        Ok(())
    }

    fn get_word(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        self.read(&mut bytes)?;
        Ok(word(&bytes))
    }

    fn put_word(&mut self, value: u64) -> Result<()> {
        self.write(&value.to_le_bytes())
    }

    fn get_bytes(&mut self, len: u64) -> Result<Vec<u8>> {
        if len > self.limit - self.offset {
            return Err(Error::Einval);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(len as usize).map_err(|_| Error::Enomem)?;
        out.resize(len as usize, 0);
        self.read(&mut out)?;
        Ok(out)
    }

    fn finish(mut self, slot: u64, generation: u64) -> Result<Header> {
        let remainder = self.offset as usize % BLOCK;
        if remainder != 0 {
            self.buffer[remainder..].fill(0);
            self.disk.write(self.first + self.offset / BLOCK as u64, &self.buffer)?;
        }
        self.disk.unit.flush()?;
        self.buffer.fill(0);
        self.buffer[..8].copy_from_slice(SLOT_MAGIC);
        self.buffer[8..10].copy_from_slice(&MACHINE.to_le_bytes());
        self.buffer[16..24].copy_from_slice(&generation.to_le_bytes());
        self.buffer[24..32].copy_from_slice(&self.offset.to_le_bytes());
        self.buffer[32..40].copy_from_slice(&self.hash.to_le_bytes());
        let header_hash = hash_bytes(HASH_SEED, &self.buffer[..40]);
        self.buffer[40..48].copy_from_slice(&header_hash.to_le_bytes());
        self.disk.write(self.disk.slot_start(slot), &self.buffer)?;
        self.disk.unit.flush()?;
        Ok(Header { slot, generation, length: self.offset, hash: self.hash })
    }
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    hash
}

fn encode(stream: &mut Stream<'_>, nodes: &[RamNode]) -> Result<()> {
    if nodes.len() as u64 > MAX_NODES {
        return Err(Error::Enospace);
    }
    stream.put_word(nodes.len() as u64)?;
    for node in nodes {
        for value in [node.id, node.parent.unwrap_or(u64::MAX), u64::from(node.is_dir),
                      node.perm.into(), node.uid.into(), node.gid.into(), node.atime.into(), node.mtime.into(),
                      node.name.len() as u64, node.acl.len() as u64, node.data.len() as u64] {
            stream.put_word(value)?;
        }
        stream.write(node.name.as_bytes())?;
        for entry in &node.acl {
            stream.put_word(entry.uid.into())?;
            stream.put_word(entry.bits.into())?;
        }
        stream.write(&node.data)?;
    }
    Ok(())
}

fn decode(stream: &mut Stream<'_>) -> Result<Vec<RamNode>> {
    let count = stream.get_word()?;
    if !(1..=MAX_NODES).contains(&count) || count > (stream.limit - 8) / 88 {
        return Err(Error::Einval);
    }
    let mut nodes = Vec::<RamNode>::new();
    nodes.try_reserve_exact(count as usize).map_err(|_| Error::Enomem)?;
    for index in 0..count {
        let id = stream.get_word()?;
        let parent = match stream.get_word()? {
            u64::MAX => None,
            value => Some(value),
        };
        let is_dir = match stream.get_word()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Einval),
        };
        let perm = stream.get_word()? as u32;
        let uid = stream.get_word()? as u32;
        let gid = stream.get_word()? as u32;
        let atime = stream.get_word()? as u32;
        let mtime = stream.get_word()? as u32;
        let name_size = stream.get_word()?;
        let acl_count = stream.get_word()?;
        let size = stream.get_word()?;
        if id >= u64::MAX - 1 || !(1..=4096).contains(&name_size) || acl_count > (stream.limit - stream.offset) / 16
            || (is_dir && size != 0) || (index != 0 && (id == 0 || parent.is_none()))
        {
            return Err(Error::Einval);
        }
        let name = String::from_utf8(stream.get_bytes(name_size)?).map_err(|_| Error::Einval)?;
        if index == 0 {
            if id != 0 || parent.is_some() || !is_dir || name != "/" {
                return Err(Error::Einval);
            }
        } else if name.contains(['/', '\0']) || name == "." || name == ".." {
            return Err(Error::Einval);
        }
        let mut acl = Vec::new();
        acl.try_reserve_exact(acl_count as usize).map_err(|_| Error::Enomem)?;
        for _ in 0..acl_count {
            let entry_uid = stream.get_word()? as u32;
            let bits = stream.get_word()? as u32;
            acl.push(AclEntry { uid: entry_uid, bits });
        }
        let data = stream.get_bytes(size)?;
        nodes.push(RamNode { id, name, parent, is_dir, perm, uid, gid, atime, mtime, acl, data });
    }
    let mut ids = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for node in &nodes {
        if !ids.insert(node.id) || node.parent.is_some_and(|parent| !directories.contains(&parent))
            || !paths.insert((node.parent, node.name.as_str()))
        {
            return Err(Error::Einval);
        }
        if node.is_dir {
            directories.insert(node.id);
        }
    }
    Ok(nodes)
}

pub(crate) fn recover(root: &RootFsDev) -> bool {
    let mut buffer = vec![0; BLOCK];
    for unit in (0..SD_MAX_UNITS).filter_map(|index| SdDev::get_global().get_unit(index)) {
        let Some(disk) = Disk::new(unit) else { continue };
        if disk.read(0, &mut buffer).is_err() || buffer.get(..8) != Some(DISK_MAGIC) {
            continue;
        }
        let mut headers = [disk.header(0, &mut buffer), disk.header(1, &mut buffer)];
        if headers.iter().any(|header| header.is_err()) {
            crate::serial::put_bytes(b"[rootdisk] checkpoint header read failed\n");
        }
        headers.sort_unstable_by_key(|header| {
            core::cmp::Reverse(header.as_ref().ok().and_then(Option::as_ref).map(|value| value.generation))
        });
        let mut restored = None;
        for header in headers.into_iter().filter_map(|header| header.ok().flatten()) {
            let mut stream = Stream { first: disk.slot_start(header.slot) + 1, disk: Disk::new(unit).unwrap(),
                offset: 0, limit: header.length, hash: HASH_SEED, buffer };
            if let Ok(nodes) = decode(&mut stream) {
                if stream.offset == header.length && stream.hash == header.hash {
                    let next = nodes.iter().map(|node| node.id).max().unwrap_or(0) + 1;
                    *root.next_id.lock() = next;
                    *root.nodes.lock() = nodes;
                    restored = Some(header);
                    break;
                }
            }
            buffer = stream.buffer;
        }
        let recovered = restored.is_some();
        *ROOT.lock() = Some(RootDisk { unit: unit.unit, current: restored });
        crate::serial::put_bytes(if recovered { b"[rootdisk] recovered checkpoint\n" } else { b"[rootdisk] using boot archive\n" });
        return recovered;
    }
    false
}

pub(crate) fn sync(unit: &SdUnit) -> Result<()> {
    let mut state = ROOT.lock();
    let root_disk = state.as_mut().filter(|disk| disk.unit == unit.unit).ok_or(Error::Enotsup)?;
    let disk = Disk::new(unit).ok_or(Error::Eio)?;
    let mut buffer = vec![0; BLOCK];
    disk.read(0, &mut buffer)?;
    if buffer.get(..8) != Some(DISK_MAGIC) {
        return Err(Error::Eio);
    }
    let (slot, generation) = match &root_disk.current {
        Some(header) => (1 - header.slot, header.generation.checked_add(1).ok_or(Error::Enospace)?),
        None => (0, 1),
    };
    let root = dev::devs().find_by_char('/').and_then(|index| dev::devs().get(index))
        .and_then(|device| device.as_any().downcast_ref::<RootFsDev>()).ok_or(Error::Enoent)?;
    let mut stream = Stream { first: disk.slot_start(slot) + 1, limit: disk.limit(), disk, buffer,
        offset: 0, hash: HASH_SEED };
    encode(&mut stream, &root.nodes.lock())?;
    root_disk.current = Some(stream.finish(slot, generation)?);
    Ok(())
}

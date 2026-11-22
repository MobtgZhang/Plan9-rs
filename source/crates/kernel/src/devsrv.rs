use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::dev::{self, Chan, Dev, DirEntry, Error, Qid, qidtype};
use crate::plan9_common::sync::Spinlock;

static SERVICES: Spinlock<Vec<Service>> = Spinlock::new(Vec::new());
static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

struct Service {
    path: u64,
    name: Vec<u8>,
    owner: u32,
    group: u32,
    perm: u32,
    channel: Option<Box<dyn crate::proc::Chan>>,
}

pub struct SrvDev;

impl SrvDev {
    pub fn new() -> Self {
        Self
    }
}

pub(crate) fn is_service(chan: &Chan) -> bool {
    chan.qid.path != 0 && dev::devs().find_by_char('s') == Some(chan.dev)
}

pub(crate) fn directory_records(device: usize) -> Result<Vec<u8>, Error> {
    let services = SERVICES.lock();
    let mut records = Vec::new();
    for service in services.iter() {
        records.extend(crate::devmnt::encode_stat(&service.stat(device), 's')?);
    }
    Ok(records)
}

impl Service {
    fn stat(&self, device: usize) -> DirEntry {
        DirEntry { dev: device, qid: Qid::new(self.path, 0, 0), mode: self.perm, atime: 0, mtime: 0,
            length: 0, name: self.name.clone(), uid: self.owner, gid: self.group }
    }
}

pub(crate) fn service_id(path: &[u8]) -> Result<Option<usize>, crate::vfs::VfsError> {
    let chan = crate::vfs::namec(path, crate::vfs::NamecMode::Walk, 0, 0)?;
    open_service(&chan, 0).map_err(crate::vfs::VfsError::from_dev_error)
        .map(|file| file.open_id())
}

pub(crate) fn open_service(chan: &Chan, mode: u8) -> Result<Box<dyn crate::proc::Chan>, Error> {
    if mode & !3 != 0 {
        return Err(Error::Eperm);
    }
    let caller = crate::proc::curproc().ok_or(Error::Eperm)?;
    let (published, required) = {
        let services = SERVICES.lock();
        let service = services.iter().find(|entry| entry.path == chan.qid.path)
            .ok_or(Error::Enoent)?;
        let access = match mode {
            0 => 4,
            1 => 2,
            2 => 6,
            _ => return Err(Error::Eperm),
        };
        let shift = if caller.uid == service.owner { 6 }
            else if caller.gid == service.group || caller.groups.contains(&service.group) { 3 }
            else { 0 };
        if caller.uid != 0 && (service.perm >> shift) & access != access {
            return Err(Error::Eperm);
        }
        (service.channel.as_ref().ok_or(Error::Enoent)?.dup(), mode)
    };
    let actual = published.access_mode();
    if actual != 2 && actual != required {
        return Err(Error::Eperm);
    }
    Ok(published)
}

impl Dev for SrvDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(dev::devtype::SRV, Qid::new(0, 0, qidtype::DIR), 0))
    }

    fn walk(&mut self, chan: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        if name == ".." {
            chan.qid = Qid::new(0, 0, qidtype::DIR);
        } else if name != "." {
            if chan.qid.path != 0 {
                return Err(Error::Enotdir);
            }
            let services = SERVICES.lock();
            let service = services.iter().find(|entry| entry.name == name.as_bytes())
                .ok_or(Error::Enoent)?;
            chan.qid = Qid::new(service.path, 0, 0);
        }
        Ok(Some(chan.qid))
    }

    fn open(&mut self, chan: &mut Chan, mode: u8) -> Result<(), Error> {
        if chan.qid.path != 0 {
            return Err(Error::Eexists);
        }
        if mode != 0 {
            return Err(Error::Eisdir);
        }
        Ok(())
    }

    fn create(&mut self, chan: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), Error> {
        if chan.qid.path != 0 || mode & 3 != 1 || perm & 0x8000_0000 != 0 || name.is_empty() {
            return Err(Error::Eperm);
        }
        let caller = crate::proc::curproc().ok_or(Error::Eperm)?;
        let mut services = SERVICES.lock();
        if services.iter().any(|entry| entry.name == name.as_bytes()) {
            return Err(Error::Eexists);
        }
        let path = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        services.push(Service {
            path, name: name.as_bytes().to_vec(), owner: caller.uid, group: caller.gid,
            perm: perm & 0o777, channel: None,
        });
        chan.qid = Qid::new(path, 0, 0);
        chan.mode = mode;
        chan.flag |= dev::CREATED_OPEN;
        Ok(())
    }

    fn close(&mut self, chan: &mut Chan) {
        if chan.mode & 0x40 != 0 {
            let removed = {
                let mut services = SERVICES.lock();
                services.iter().position(|entry| entry.path == chan.qid.path && entry.name != b"boot")
                    .map(|index| services.remove(index))
            };
            drop(removed);
        }
    }

    fn read(&mut self, chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if chan.qid.path != 0 {
            return Err(Error::Eperm);
        }
        let mut listing = Vec::new();
        for entry in SERVICES.lock().iter() {
            listing.extend_from_slice(&entry.name);
            listing.push(b'\n');
        }
        Ok(dev::read_bytes(&listing, buf, offset))
    }

    fn write(&mut self, chan: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, Error> {
        if chan.flag & dev::CREATED_OPEN == 0 || offset != 0 || buf.len() >= 32 {
            return Err(Error::Eperm);
        }
        let fd = core::str::from_utf8(buf).map_err(|_| Error::Einval)?.trim()
            .parse::<i32>().map_err(|_| Error::Einval)?;
        let file = crate::vfs::fd_channel(fd).ok_or(Error::Ebadfd)?;
        if file.dev() == chan.dev {
            return Err(Error::Eperm);
        }
        if let Some(raw) = file.dev_chan() {
            if raw.mode & 0x60 != 0 || raw.qid.type_ & 8 != 0 {
                return Err(Error::Eperm);
            }
        }
        let mut services = SERVICES.lock();
        let service = services.iter_mut().find(|entry| entry.path == chan.qid.path)
            .ok_or(Error::Enoent)?;
        if service.channel.is_some() {
            return Err(Error::Eexists);
        }
        service.channel = Some(file);
        Ok(buf.len())
    }

    fn stat(&mut self, chan: &mut Chan) -> Result<DirEntry, Error> {
        let services = SERVICES.lock();
        if chan.qid.path == 0 {
            Ok(DirEntry { dev: chan.dev, qid: chan.qid, mode: 0x8000_0000 | 0o777, atime: 0, mtime: 0,
                length: 0, name: b"srv".to_vec(), uid: 0, gid: 0 })
        } else {
            let entry = services.iter().find(|entry| entry.path == chan.qid.path)
                .ok_or(Error::Enoent)?;
            Ok(entry.stat(chan.dev))
        }
    }

    fn wstat(&mut self, chan: &mut Chan, entry: &DirEntry) -> Result<(), Error> {
        let caller = crate::proc::curproc().ok_or(Error::Eperm)?;
        let mut services = SERVICES.lock();
        let index = services.iter().position(|service| service.path == chan.qid.path)
            .ok_or(Error::Enoent)?;
        let service = &services[index];
        if caller.uid != 0 && caller.uid != service.owner {
            return Err(Error::Eperm);
        }
        if entry.name.is_empty() || entry.name == b"." || entry.name == b".."
            || entry.name.contains(&b'/') || entry.name.contains(&0)
        {
            return Err(Error::Einval);
        }
        if entry.name != service.name {
            if service.name == b"boot" {
                return Err(Error::Eperm);
            }
            if services.iter().any(|other| other.name == entry.name) {
                return Err(Error::Eexists);
            }
        }
        let service = &mut services[index];
        service.name.clone_from(&entry.name);
        service.owner = entry.uid;
        service.group = entry.gid;
        service.perm = entry.mode & 0o777;
        Ok(())
    }

    fn remove(&mut self, chan: &mut Chan) -> Result<(), Error> {
        let caller = crate::proc::curproc().ok_or(Error::Eperm)?;
        let removed = {
            let mut services = SERVICES.lock();
            let index = services.iter().position(|entry| entry.path == chan.qid.path)
                .ok_or(Error::Enoent)?;
            let entry = &services[index];
            if entry.name == b"boot" || caller.uid != 0 && caller.uid != entry.owner
                && (entry.owner == 0 || entry.perm & 7 != 7)
            {
                return Err(Error::Eperm);
            }
            services.remove(index)
        };
        drop(removed);
        Ok(())
    }

    fn dev_char(&self) -> char { 's' }
    fn name(&self) -> &'static str { "srv" }
}

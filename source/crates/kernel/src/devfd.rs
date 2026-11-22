use alloc::{boxed::Box, string::ToString, vec::Vec};

use crate::dev::{self, Chan, Dev, DirEntry, Error, Qid, qidtype};

pub struct FdDev;

pub(crate) fn is_descriptor(chan: &Chan) -> bool {
    chan.qid.path != 0 && dev::devs().find_by_char('d') == Some(chan.dev)
}

pub(crate) fn reopen(chan: &Chan, mode: u32) -> Result<Box<dyn crate::proc::Chan>, Error> {
    let file = crate::vfs::fd_channel((chan.qid.path - 1) as i32).ok_or(Error::Ebadfd)?;
    if mode > 2 || (file.access_mode() != 2 && file.access_mode() as u32 != mode) {
        return Err(Error::Eperm);
    }
    Ok(file.dup())
}

impl Dev for FdDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(dev::devtype::FD, Qid::new(0, 0, qidtype::DIR), 0))
    }

    fn walk(&mut self, chan: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        match name {
            "." => {},
            ".." => chan.qid = Qid::new(0, 0, qidtype::DIR),
            name if chan.qid.path == 0 => {
                let fd = name.parse::<i32>().map_err(|_| Error::Enoent)?;
                if crate::vfs::fd_channel(fd).is_none() {
                    return Err(Error::Enoent);
                }
                chan.qid = Qid::new(fd as u64 + 1, 0, 0);
            }
            _ => return Err(Error::Enotdir),
        }
        Ok(Some(chan.qid))
    }

    fn open(&mut self, chan: &mut Chan, mode: u8) -> Result<(), Error> {
        if chan.qid.path != 0 || mode != 0 {
            return Err(Error::Eperm);
        }
        Ok(())
    }

    fn read(&mut self, chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if chan.qid.path != 0 {
            return Err(Error::Eperm);
        }
        let mut entries = Vec::new();
        for fd in 0..crate::proc::NFD as i32 {
            if crate::vfs::fd_channel(fd).is_some() {
                entries.extend_from_slice(fd.to_string().as_bytes());
                entries.push(b'\n');
            }
        }
        Ok(dev::read_bytes(&entries, buf, offset))
    }

    fn stat(&mut self, chan: &mut Chan) -> Result<DirEntry, Error> {
        let caller = crate::proc::curproc().ok_or(Error::Eperm)?;
        let (name, mode) = if chan.qid.path == 0 {
            (b"fd".to_vec(), 0x8000_0000 | 0o500)
        } else {
            let fd = (chan.qid.path - 1) as i32;
            let file = crate::vfs::fd_channel(fd).ok_or(Error::Enoent)?;
            let mode = match file.access_mode() {
                0 => 0o400,
                1 => 0o200,
                _ => 0o600,
            };
            (fd.to_string().into_bytes(), mode)
        };
        Ok(DirEntry { dev: chan.dev, qid: chan.qid, mode, atime: 0, mtime: 0,
            length: 0, name, uid: caller.uid, gid: caller.gid })
    }

    fn dev_char(&self) -> char { 'd' }
    fn name(&self) -> &'static str { "fd" }
}

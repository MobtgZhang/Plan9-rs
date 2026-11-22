use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use crate::dev::{devtype, qidtype, read_bytes, Chan, Dev, DirEntry, Error, Qid};
use crate::plan9_common::sync::Mutex;

const MAX_VARIABLES: usize = 256;
const MAX_VALUE: usize = 4096;
const DMDIR: u32 = 0x8000_0000;

#[derive(Clone, Debug)]
struct Variable {
    id: u64,
    value: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct Variables {
    next_id: u64,
    entries: BTreeMap<String, Variable>,
}

#[derive(Debug)]
pub(crate) struct EnvGroup(Mutex<Variables>);

impl Default for EnvGroup {
    fn default() -> Self {
        Self(Mutex::new(Variables::default()))
    }
}

impl EnvGroup {
    pub(crate) fn copy(group: &Self) -> Self {
        Self(Mutex::new(group.0.lock().clone()))
    }

    pub(crate) fn set_boot_value(&self, name: &str, value: &[u8]) {
        let mut vars = self.0.lock();
        vars.next_id += 1;
        let id = vars.next_id;
        vars.entries.insert(String::from(name), Variable { id, value: value.to_vec() });
    }
}

pub(crate) const CPU_TYPE: &[u8] = if cfg!(target_arch = "x86_64") {
    b"amd64"
} else if cfg!(target_arch = "aarch64") {
    b"arm64"
} else if cfg!(target_arch = "riscv64") {
    b"riscv64"
} else {
    b"loongarch64"
};

pub(crate) struct EnvDev {
    config: Arc<EnvGroup>,
}

impl EnvDev {
    pub(crate) fn new() -> Self {
        let config = Arc::new(EnvGroup::default());
        config.set_boot_value("cputype", CPU_TYPE);
        Self { config }
    }

    fn group(channel: &Chan) -> Result<Arc<EnvGroup>, Error> {
        if let Some(group) = &channel.aux {
            return group.clone().downcast().map_err(|_| Error::Einval);
        }
        crate::proc::curproc()
            .and_then(|proc| proc.egrp.as_deref())
            .map(|group| group.values.clone())
            .ok_or(Error::Eperm)
    }

    fn check_write(channel: &Chan) -> Result<(), Error> {
        if channel.aux.is_some() && crate::proc::curproc().is_some_and(|proc| proc.uid != 0) {
            return Err(Error::Eperm);
        }
        Ok(())
    }

    fn variable_mut(vars: &mut Variables, id: u64) -> Result<&mut Variable, Error> {
        vars.entries.values_mut().find(|var| var.id == id).ok_or(Error::Enoent)
    }
}

impl Dev for EnvDev {
    fn attach(&mut self, spec: Option<&str>) -> Result<Chan, Error> {
        let mut channel = Chan::new(devtype::ENV, Qid::new(0, 0, qidtype::DIR), 0);
        match spec {
            None | Some("") => {}
            Some("c") => channel.aux = Some(self.config.clone()),
            _ => return Err(Error::Einval),
        }
        Ok(channel)
    }

    fn walk(&mut self, channel: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        if matches!(name, "." | "..") {
            return Ok(Some(channel.qid));
        }
        if channel.qid.path != 0 {
            return Err(Error::Enoent);
        }
        let group = Self::group(channel)?;
        let vars = group.0.lock();
        let var = vars.entries.get(name).ok_or(Error::Enoent)?;
        channel.qid = Qid::new(var.id, 0, qidtype::FILE);
        Ok(Some(channel.qid))
    }

    fn open(&mut self, channel: &mut Chan, mode: u8) -> Result<(), Error> {
        if channel.qid.path == 0 {
            if mode & 3 != 0 || mode & 0x10 != 0 {
                return Err(Error::Eperm);
            }
            return Ok(());
        }
        if mode & 3 != 0 || mode & 0x10 != 0 {
            Self::check_write(channel)?;
        }
        let group = Self::group(channel)?;
        let mut vars = group.0.lock();
        let var = Self::variable_mut(&mut vars, channel.qid.path)?;
        if mode & 0x10 != 0 {
            var.value.clear();
        }
        channel.mode = mode;
        Ok(())
    }

    fn create(&mut self, channel: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), Error> {
        Self::check_write(channel)?;
        if channel.qid.path != 0 || perm & DMDIR != 0 || name.is_empty()
            || name.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'/'))
        {
            return Err(Error::Einval);
        }
        let group = Self::group(channel)?;
        let mut vars = group.0.lock();
        if vars.entries.contains_key(name) {
            return Err(Error::Eexists);
        }
        if vars.entries.len() >= MAX_VARIABLES {
            return Err(Error::Enomem);
        }
        vars.next_id += 1;
        let id = vars.next_id;
        vars.entries.insert(String::from(name), Variable { id, value: Vec::new() });
        channel.qid = Qid::new(id, 0, qidtype::FILE);
        channel.mode = mode;
        Ok(())
    }

    fn read(&mut self, channel: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if channel.mode & 3 == 1 {
            return Err(Error::Eperm);
        }
        let group = Self::group(channel)?;
        let vars = group.0.lock();
        if channel.qid.path == 0 {
            let mut names = String::new();
            for name in vars.entries.keys() {
                names.push_str(name);
                names.push('\n');
            }
            return Ok(read_bytes(names.as_bytes(), buf, offset));
        }
        let var = vars.entries.values().find(|var| var.id == channel.qid.path).ok_or(Error::Enoent)?;
        Ok(read_bytes(&var.value, buf, offset))
    }

    fn write(&mut self, channel: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, Error> {
        Self::check_write(channel)?;
        if !matches!(channel.mode & 3, 1 | 2) || channel.qid.path == 0 {
            return Err(Error::Eperm);
        }
        let start = usize::try_from(offset).map_err(|_| Error::Einval)?;
        let end = start.checked_add(buf.len()).filter(|end| *end <= MAX_VALUE).ok_or(Error::Einval)?;
        let group = Self::group(channel)?;
        let mut vars = group.0.lock();
        let var = Self::variable_mut(&mut vars, channel.qid.path)?;
        if !buf.is_empty() {
            if end > var.value.len() {
                var.value.resize(end, 0);
            }
            var.value[start..end].copy_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn truncate(&mut self, channel: &mut Chan) -> Result<(), Error> {
        Self::check_write(channel)?;
        let group = Self::group(channel)?;
        Self::variable_mut(&mut group.0.lock(), channel.qid.path)?.value.clear();
        Ok(())
    }

    fn remove(&mut self, channel: &mut Chan) -> Result<(), Error> {
        Self::check_write(channel)?;
        if channel.qid.path == 0 {
            return Err(Error::Eperm);
        }
        let group = Self::group(channel)?;
        let mut vars = group.0.lock();
        let name = vars.entries.iter().find(|(_, var)| var.id == channel.qid.path)
            .map(|(name, _)| name.clone()).ok_or(Error::Enoent)?;
        vars.entries.remove(&name);
        Ok(())
    }

    fn stat(&mut self, channel: &mut Chan) -> Result<DirEntry, Error> {
        let (name, length, mode) = if channel.qid.path == 0 {
            (b"env".to_vec(), 0, DMDIR | 0o775)
        } else {
            let group = Self::group(channel)?;
            let vars = group.0.lock();
            let (name, var) = vars.entries.iter().find(|(_, var)| var.id == channel.qid.path)
                .ok_or(Error::Enoent)?;
            (name.as_bytes().to_vec(), var.value.len() as u64, 0o666)
        };
        Ok(DirEntry {
            dev: channel.dev, qid: channel.qid, mode, atime: 0, mtime: 0,
            length, name, uid: 0, gid: 0,
        })
    }

    fn dev_char(&self) -> char {
        'e'
    }

    fn name(&self) -> &'static str {
        "env"
    }
}

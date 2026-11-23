//! Virtual File System
//!
//! Plan 9 style VFS layer that connects file systems and devices to the
//! system-call interface.  Provides `namec()` for path-to-channel
//! conversion, a mount table for bind/union mounts, and channel
//! reference management.
//!
//! The device table is owned by `crate::dev`; this module only borrows
//! devices through the small helpers exported there.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::chan::Qid;
use crate::dev::{self, Chan, DirEntry, Error as DevError, devs_mut};
use crate::plan9_common::sync::{Mutex, Spinlock};
use crate::proc::Chan as _;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum mount points
pub const NMOUNT: usize = 32;

/// Maximum path components
pub const MAX_PATH_COMPONENTS: usize = 64;

/// Maximum file name length
pub const MAX_FILE_NAME: usize = 256;

/// Root device character
pub const ROOTDEV: char = '/';

const OCEXEC: u32 = 0x20;
const OEXCL: u32 = 0x1000;
const OTRUNC: u32 = 0x10;

/// Mount flags (Plan 9 semantics)
pub const MBEFORE: u32 = 0x01;
pub const MAFTER: u32 = 0x02;
pub const MCREATE: u32 = 0x04;
pub const MCACHE: u32 = 0x08;
pub const MREPL: u32 = 0x10;
pub const MBIND: u32 = 0x20;
pub const MUNION: u32 = 0x40;

#[derive(Clone, Debug)]
pub(crate) struct MountEntry {
    root: Chan,
    create: bool,
}

pub(crate) type NamespaceMounts = alloc::collections::BTreeMap<Vec<u8>, Vec<MountEntry>>;

// ============================================================================
// Path helpers
// ============================================================================

/// Parse a path into components.
pub fn parse_path(path: &[u8]) -> Vec<&[u8]> {
    let mut components = Vec::new();
    let mut i = 0;

    while i < path.len() && path[i] == b'/' {
        i += 1;
    }

    while i < path.len() {
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        if i > start {
            components.push(&path[start..i]);
        }
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
    }

    components
}

/// Last component of a path.
pub fn file_name(path: &[u8]) -> Option<&[u8]> {
    parse_path(path).last().copied()
}

/// Parent directory of a path.
pub fn parent_path(path: &[u8]) -> Option<Vec<u8>> {
    let components = parse_path(path);
    if components.len() <= 1 {
        return Some(b"/".to_vec());
    }

    let mut result = Vec::new();
    for comp in components.iter().take(components.len() - 1) {
        result.push(b'/');
        result.extend_from_slice(comp);
    }
    Some(result)
}

fn parse_path_start(path: &[u8]) -> (PathStart, Option<&[u8]>) {
    if path.is_empty() {
        return (PathStart::Current, None);
    }
    if path[0] == b'/' {
        return (PathStart::Root, Some(&path[1..]));
    }
    if path[0] == b'#' && path.len() > 1 {
        let dev_char = path[1] as char;
        let rest = if path.len() > 2 { &path[2..] } else { &[] };
        return (PathStart::Special(dev_char), Some(rest));
    }
    (PathStart::Current, Some(path))
}

// ============================================================================
// Namec modes
// ============================================================================

/// Name to channel mode
#[derive(Debug, Clone, Copy)]
pub enum NamecMode {
    /// Open existing file
    Open(u32),
    /// Create new file
    Create(u32, u32),
    /// Walk path only
    Walk,
    /// Bind mount
    Bind(u32),
    /// Unmount
    Unmount,
    /// Remove file or directory
    Remove,
}

/// Path starting point
#[derive(Debug)]
enum PathStart {
    Root,
    Special(char),
    Current,
}

// ============================================================================
// Mount table
// ============================================================================

#[derive(Debug)]
pub struct MountPoint {
    /// Source (device or server)
    pub source: Vec<u8>,
    /// Mount point path
    pub path: Vec<u8>,
    /// File system type
    pub fs_type: Vec<u8>,
    /// Mount flags
    pub flags: u32,
    /// Root channel for this mount
    pub root: Option<Chan>,
    /// Next mount index in the static table
    pub next: Option<usize>,
}

impl MountPoint {
    pub fn new(source: &[u8], path: &[u8], fs_type: &[u8]) -> Self {
        Self {
            source: source.to_vec(),
            path: path.to_vec(),
            fs_type: fs_type.to_vec(),
            flags: 0,
            root: None,
            next: None,
        }
    }
}

pub struct MountTable {
    entries: [Option<MountPoint>; NMOUNT],
    count: usize,
}

impl MountTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; NMOUNT],
            count: 0,
        }
    }

    pub fn add(&mut self, mp: MountPoint) -> Option<usize> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(mp);
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    pub fn remove(&mut self, path: &[u8]) -> Option<MountPoint> {
        for slot in &mut self.entries {
            if let Some(mp) = slot {
                if mp.path == path {
                    self.count -= 1;
                    return slot.take();
                }
            }
        }
        None
    }

    /// Longest-prefix match; `find(b"")` returns the root mount.
    pub fn find(&self, path: &[u8]) -> Option<&MountPoint> {
        let mut best: Option<&MountPoint> = None;
        let mut best_len = 0usize;

        for slot in &self.entries {
            if let Some(mp) = slot {
                let mp_path = if mp.path.first() == Some(&b'/') {
                    &mp.path[1..]
                } else {
                    &mp.path[..]
                };
                let check = if path.first() == Some(&b'/') {
                    &path[1..]
                } else {
                    path
                };
                if check.starts_with(mp_path) && mp_path.len() > best_len {
                    best = Some(mp);
                    best_len = mp_path.len();
                }
            }
        }
        best
    }

    /// Exact mount-point match.  A mount point consumes exactly the
    /// component named by its path; paths *below* it must continue walking
    /// inside the mounted filesystem instead of being redirected again.
    pub fn find_exact(&self, path: &[u8]) -> Option<&MountPoint> {
        let check = if path.first() == Some(&b'/') {
            &path[1..]
        } else {
            path
        };
        let check = check.strip_suffix(b"/").unwrap_or(check);

        for slot in &self.entries {
            if let Some(mp) = slot {
                let mp_path = if mp.path.first() == Some(&b'/') {
                    &mp.path[1..]
                } else {
                    &mp.path[..]
                };
                let mp_path = mp_path.strip_suffix(b"/").unwrap_or(mp_path);
                if check == mp_path {
                    return Some(mp);
                }
            }
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = &MountPoint> {
        self.entries.iter().flatten()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut MountPoint> {
        self.entries.iter_mut().flatten()
    }
}

// ============================================================================
// Global VFS state
// ============================================================================

static MOUNTS: Mutex<MountTable> = Mutex::new(MountTable::new());
static ROOT_CHAN: Spinlock<Option<Chan>> = Spinlock::new(None);
static NEXT_QID: AtomicU64 = AtomicU64::new(0x1000);

/// Allocate a monotonically increasing Qid path for anonymous channels.
fn fresh_qid_path() -> u64 {
    NEXT_QID.fetch_add(1, Ordering::Relaxed)
}

// ============================================================================
// VFS errors
// ============================================================================

#[derive(Debug)]
pub enum VfsError {
    Ok,
    Enoent,
    Eperm,
    Enomem,
    Ebadfd,
    Eio,
    Eintr,
    Einval,
    Eisdir,
    Enotdir,
    Eexists,
    Enametoolong,
    Enotsup,
    Unknown,
}

impl VfsError {
    pub fn to_isize(&self) -> isize {
        match self {
            VfsError::Ok => 0,
            VfsError::Enoent => -12,
            VfsError::Eperm => -6,
            VfsError::Enomem => -2,
            VfsError::Ebadfd => -4,
            VfsError::Eio => -3,
            VfsError::Eintr => crate::syscall::Error::Eintr.to_isize(),
            VfsError::Einval => -10,
            VfsError::Eisdir => -9,
            VfsError::Enotdir => -8,
            VfsError::Eexists => -7,
            VfsError::Enametoolong => -11,
            VfsError::Enotsup => -13,
            VfsError::Unknown => -1,
        }
    }

    pub fn from_dev_error(err: DevError) -> Self {
        match err {
            DevError::Ok => VfsError::Ok,
            DevError::Enoent => VfsError::Enoent,
            DevError::Eperm => VfsError::Eperm,
            DevError::Enomem => VfsError::Enomem,
            DevError::Ebadfd => VfsError::Ebadfd,
            DevError::Eio => VfsError::Eio,
            DevError::Eintr => VfsError::Eintr,
            DevError::Einval => VfsError::Einval,
            DevError::Enotdir => VfsError::Enotdir,
            DevError::Eisdir => VfsError::Eisdir,
            DevError::Eexists => VfsError::Eexists,
            DevError::Enospace => VfsError::Enomem,
            DevError::Enotsup => VfsError::Enotsup,
            _ => VfsError::Unknown,
        }
    }
}

// ============================================================================
// Device helpers
// ============================================================================

/// Attach the device at `index` and produce a channel.
fn attach_device(index: usize, spec: Option<&str>, mode: u8) -> Result<Chan, VfsError> {
    match devs_mut().get_mut(index) {
        Some(dev) => dev.attach(spec).map_err(VfsError::from_dev_error),
        None => Err(VfsError::Enoent),
    }
    .map(|mut c| {
        // Device implementations use their Plan 9 device type in Chan::new,
        // but Chan.dev is a table index used by dev_read/dev_write/etc.
        // Always bind the channel to the actual registered slot.
        c.dev = index;
        c.mode = mode;
        c
    })
}

/// Find the root device index.
fn root_device_index() -> Option<usize> {
    dev::devs().find_by_char(ROOTDEV)
}

/// Current working directory, taken from the process namespace.
///
/// The authoritative working directory is `Proc.dot`, which CHDIR
/// maintains (and which fork inherits).  The namespace `dot` on the
/// process group is kept in sync as a fallback for code paths that only
/// populate the namespace.  Without bridging the two representations,
/// relative paths in `namec` kept resolving against the root — the
/// classic "ls always lists /" bug.
fn proc_namespace_dot() -> Option<Chan> {
    let proc = crate::proc::curproc()?;
    if let Some(dot) = proc.dot.as_ref() {
        if let Some(c) = dot.dev_chan() {
            return Some(c);
        }
    }
    let pgrp = proc.pgrp.as_ref()?;
    let ns = pgrp.namespace()?;
    ns.dot.as_ref().map(|c| c.dup())
}

// ============================================================================
// namec()
// ============================================================================

pub fn namec(
    path: &[u8],
    amode: NamecMode,
    _omode: u32,
    _perm: u32,
) -> Result<Chan, VfsError> {
    let mut lookup = PathLookup::new(path)?;
    lookup.for_create = matches!(amode, NamecMode::Create(..));
    let mut chan = lookup.progress(false, false)?.ok_or(VfsError::Eio)?;
    match amode {
        NamecMode::Create(mode, perm) => {
            if let Some(name) = lookup.missing_name {
                create_on(&mut chan, &name, mode, perm)?;
            } else if mode & OEXCL != 0 {
                return Err(VfsError::Eexists);
            }
        }
        NamecMode::Remove => remove_on(&mut chan)?,
        _ => {}
    }
    Ok(chan)
}

fn create_on(chan: &mut Chan, name: &[u8], mode: u32, perm: u32) -> Result<(), VfsError> {
    let path = chan.namespace_path.take();
    let name = core::str::from_utf8(name).map_err(|_| VfsError::Einval)?;
    chan.create(name, mode as u8, perm)?;
    chan.namespace_path = path;
    Ok(())
}

fn remove_on(chan: &mut Chan) -> Result<(), VfsError> {
    let device = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    device.remove(chan).map_err(VfsError::from_dev_error)
}

fn append_component(path: &mut Vec<u8>, component: &[u8]) {
    if path.as_slice() != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(component);
}

fn path_start(path: &[u8]) -> Result<(Chan, Option<Vec<u8>>, Option<&[u8]>), VfsError> {
    if path.is_empty() {
        return Err(VfsError::Einval);
    }
    if path.len() > MAX_FILE_NAME * MAX_PATH_COMPONENTS {
        return Err(VfsError::Enametoolong);
    }

    let (start, mut rest) = parse_path_start(path);

    let (chan, current_path) = match start {
        PathStart::Root => {
            (namespace_root()?, Some(b"/".to_vec()))
        }

        PathStart::Special(c) => {
            let idx = dev::devs().find_by_char(c).ok_or(VfsError::Enoent)?;
            let suffix = rest.unwrap_or_default();
            let end = suffix.iter().position(|byte| *byte == b'/').unwrap_or(suffix.len());
            let spec = core::str::from_utf8(&suffix[..end]).map_err(|_| VfsError::Einval)?;
            rest = suffix.get(end + 1..);
            (attach_device(idx, (!spec.is_empty()).then_some(spec), 0)?, None)
        }

        PathStart::Current => {
            if let Some(dot) = proc_namespace_dot() {
                let path = dot.namespace_path.clone();
                (dot, path)
            } else {
                (namespace_root()?, Some(b"/".to_vec()))
            }
        }
    };

    Ok((chan, current_path, rest))
}

pub(crate) struct PathLookup {
    components: VecDeque<Vec<u8>>,
    path: Option<Vec<u8>>,
    current: Option<Chan>,
    component: Option<(Vec<u8>, alloc::vec::IntoIter<Chan>)>,
    pending: Option<(Chan, crate::devmnt::PendingWalk)>,
    for_create: bool,
    create_parent: Option<Chan>,
    missing_name: Option<Vec<u8>>,
}

impl PathLookup {
    pub(crate) fn new(path: &[u8]) -> Result<Self, VfsError> {
        let (current, path, rest) = path_start(path)?;
        let components = rest.map(parse_path).unwrap_or_default().into_iter().map(<[u8]>::to_vec).collect();
        Ok(Self { components, path, current: Some(current), component: None, pending: None,
            for_create: false, create_parent: None, missing_name: None })
    }

    pub(crate) fn progress(&mut self, asynchronous: bool, interrupted: bool) -> Result<Option<Chan>, VfsError> {
        loop {
            if let Some((name, candidates)) = &mut self.component {
                let name = core::str::from_utf8(name).map_err(|_| VfsError::Einval)?;
                if let Some((candidate, walk)) = &mut self.pending {
                    match walk.progress(candidate, Some(name), interrupted).map_err(VfsError::from_dev_error) {
                        Ok(false) => return Ok(None),
                        Ok(true) => {
                            self.current = self.pending.take().map(|(chan, _)| chan);
                            self.component = None;
                        }
                        Err(VfsError::Enoent) => self.pending = None,
                        Err(error) => return Err(error),
                    }
                    continue;
                }
                let Some(mut candidate) = candidates.next() else {
                    if !self.for_create || !self.components.is_empty() || name == ".." {
                        return Err(VfsError::Enoent);
                    }
                    let mut parent = self.create_parent.take().ok_or(VfsError::Eperm)?;
                    parent.namespace_path = self.path.take();
                    self.missing_name = Some(name.as_bytes().to_vec());
                    return Ok(Some(parent));
                };
                if let Some(walk) = asynchronous.then(|| crate::devmnt::PendingWalk::new(&candidate)).flatten() {
                    self.pending = Some((candidate, walk));
                    continue;
                }
                match candidate.walk_to(name) {
                    Ok(Some(_)) => {
                        self.current = Some(candidate);
                        self.component = None;
                    }
                    Ok(None) | Err(VfsError::Enoent) => {}
                    Err(error) => return Err(error),
                }
                continue;
            }

            let mut current = self.current.take().ok_or(VfsError::Eio)?;
            let Some(component) = self.components.pop_front() else {
                current.namespace_path = self.path.take();
                return Ok(Some(current));
            };
            if component == b"." {
                self.current = Some(current);
                continue;
            }
            if current.qid.type_ & dev::qidtype::DIR == 0 {
                return Err(VfsError::Enoent);
            }
            if let Some(path) = self.path.as_ref().filter(|_| component == b"..") {
                let parent = parent_path(path).unwrap_or_else(|| b"/".to_vec());
                for part in parse_path(&parent).into_iter().rev() {
                    self.components.push_front(part.to_vec());
                }
                self.path = Some(b"/".to_vec());
                self.current = Some(namespace_root()?);
                continue;
            }
            let mounts = self.path.as_deref().and_then(namespace_mounts);
            if let Some(path) = &mut self.path {
                append_component(path, &component);
                if let Some(root) = find_mount(path) {
                    self.current = Some(root);
                    continue;
                }
            }
            let can_create = self.for_create && self.components.is_empty();
            let candidates = match mounts {
                Some(entries) => {
                    if can_create {
                        self.create_parent = entries.iter().find(|entry| entry.create).map(|entry| entry.root.dup());
                    }
                    entries.into_iter().map(|entry| entry.root).collect()
                }
                None => {
                    if can_create {
                        self.create_parent = Some(current.dup());
                    }
                    vec![current]
                }
            };
            self.component = Some((component, candidates.into_iter()));
        }
    }
}

fn namespace_root() -> Result<Chan, VfsError> {
    if let Some(root) = find_mount(b"/").or_else(|| get_root_chan()) {
        return Ok(root);
    }
    attach_device(root_device_index().ok_or(VfsError::Enoent)?, None, 0)
}

pub fn mount_children(path: &[u8]) -> Vec<String> {
    MOUNTS.lock().iter().filter_map(|mount| {
        let suffix = mount.path.strip_prefix(path)?;
        let name = if path == b"/" { suffix } else { suffix.strip_prefix(b"/")? };
        if mount.root.is_none() || name.is_empty() || name.contains(&b'/') {
            return None;
        }
        core::str::from_utf8(name).ok().map(String::from)
    }).collect()
}

// ============================================================================
// Channel helpers
// ============================================================================

impl Chan {
    /// Duplicate a reference to the same channel.
    pub fn dup(&self) -> Self {
        self.incref();
        Self {
            dev: self.dev,
            qid: self.qid,
            mode: self.mode,
            flag: self.flag,
            offset: self.offset,
            namespace_path: self.namespace_path.clone(),
            aux: self.aux.clone(),
            refcount: Mutex::new(self.refcount()),
        }
    }

    pub fn parent(&mut self) -> Result<Chan, VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        if dev.walk(self, "..").is_err() {
            return Err(VfsError::Enoent);
        }
        Ok(self.dup())
    }

    pub fn walk_to(&mut self, name: &str) -> Result<Option<Qid>, VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        dev.walk(self, name).map_err(VfsError::from_dev_error)
    }

    pub fn open(&mut self, mode: u8) -> Result<(), VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        dev.open(self, mode).map_err(VfsError::from_dev_error)
    }

    pub fn create(&mut self, name: &str, mode: u8, perm: u32) -> Result<(), VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        dev.create(self, name, mode, perm).map_err(VfsError::from_dev_error)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        let result = dev.read(self, buf, self.offset).map_err(VfsError::from_dev_error)?;
        self.offset += result as u64;
        Ok(result)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        let result = dev.write(self, buf, self.offset).map_err(VfsError::from_dev_error)?;
        self.offset += result as u64;
        Ok(result)
    }

    pub fn seek(&mut self, offset: u64, whence: u8) -> Result<u64, VfsError> {
        match whence {
            0 => self.offset = offset,
            1 => self.offset = self.offset.saturating_add(offset),
            2 => {
                // Seek to end-of-file: ask the device for the file length.
                let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
                let len = dev
                    .stat(self)
                    .map(|d| d.length)
                    .map_err(|_| VfsError::Eio)?;
                self.offset = len;
            }
            _ => return Err(VfsError::Einval),
        }
        Ok(self.offset)
    }

    pub fn stat(&mut self) -> Result<DirEntry, VfsError> {
        let dev = devs_mut().get_mut(self.dev).ok_or(VfsError::Enoent)?;
        dev.stat(self).map_err(VfsError::from_dev_error)
    }
}

// ============================================================================
// Public operations
// ============================================================================

pub fn open(path: &[u8], mode: u32) -> Result<Chan, VfsError> {
    let mut chan = namec(path, NamecMode::Open(mode), 0, 0)?;
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.open(&mut chan, mode as u8)
        .map_err(VfsError::from_dev_error)?;
    Ok(chan)
}

/// Adapter that exposes a kernel `dev::Chan` through the `proc::Chan` trait.
pub struct DevChanAdapter {
    chan: Chan,
    directory_records: Option<alloc::sync::Arc<[u8]>>,
}

impl DevChanAdapter {
    pub fn new(chan: Chan) -> Self {
        Self { chan, directory_records: None }
    }

    pub(crate) fn pending_names(&self, address: u64, size: usize) -> Option<crate::devmnt::PendingIo> {
        crate::devmnt::PendingIo::list(&self.chan, address, size)
    }

    fn read_channel(&mut self, buf: &mut [u8], interruptible: bool) -> crate::proc::Result<usize> {
        let device = devs_mut().get_mut(self.chan.dev).ok_or(crate::proc::Error::Eio)?;
        let offset = self.chan.offset;
        let result = if interruptible {
            device.read_interruptible(&mut self.chan, buf, offset)
        } else {
            device.read(&mut self.chan, buf, offset)
        };
        let count = result.map_err(|error| match error {
            DevError::Eintr => crate::proc::Error::Eintr,
            _ => crate::proc::Error::Eio,
        })?;
        self.chan.offset += count as u64;
        Ok(count)
    }

    fn read_names(&mut self, buf: &mut [u8]) -> crate::proc::Result<usize> {
        let offset = self.chan.offset;
        let count = crate::devmnt::read_names(&mut self.chan, buf, offset).map_err(|error| match error {
            DevError::Eintr => crate::proc::Error::Eintr,
            _ => crate::proc::Error::Eio,
        })?;
        self.chan.offset += count as u64;
        Ok(count)
    }

    fn read_directory(&mut self, output: &mut [u8], interruptible: bool) -> crate::proc::Result<usize> {
        use crate::proc::Error;

        if dev::devs().find_by_char('M') == Some(self.chan.dev) {
            return self.read_channel(output, interruptible);
        }
        if output.is_empty() {
            return Ok(0);
        }
        if self.directory_records.is_none() {
            let records = if dev::devs().find_by_char('s') == Some(self.chan.dev) {
                crate::devsrv::directory_records(self.chan.dev).map_err(|_| Error::Eio)?
            } else {
                local_directory_records(&self.chan)?
            };
            self.directory_records = Some(records.into());
        }
        let offset = usize::try_from(self.chan.offset).map_err(|_| Error::Einval)?;
        let records = self.directory_records.as_deref().unwrap().get(offset..).ok_or(Error::Einval)?;
        let mut count = 0;
        while count < records.len() {
            let size = u16::from_le_bytes([records[count], records[count + 1]]) as usize + 2;
            if size > output.len() - count {
                if count == 0 {
                    return Err(Error::Einval);
                }
                break;
            }
            count += size;
        }
        output[..count].copy_from_slice(&records[..count]);
        self.chan.offset += count as u64;
        Ok(count)
    }
}

fn local_directory_records(chan: &Chan) -> crate::proc::Result<Vec<u8>> {
    use crate::proc::Error;

    let mut directory = chan.dup();
    let mut names = Vec::new();
    let mut buffer = [0; 512];
    loop {
        let count = dev::dev_read(&mut directory, &mut buffer, names.len() as u64).map_err(|_| Error::Eio)?;
        if count == 0 {
            break;
        }
        names.extend_from_slice(&buffer[..count]);
    }
    let mut records = Vec::new();
    for name in names.split(|byte| *byte == b'\n').filter(|name| !name.is_empty()) {
        let name = core::str::from_utf8(name).map_err(|_| Error::Eio)?;
        let path = chan.namespace_path.as_ref().map(|parent| {
            let mut path = parent.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(name.as_bytes());
            path
        });
        let mut child = match path.as_deref().and_then(find_mount) {
            Some(mounted) => mounted,
            None => {
                let mut child = chan.dup();
                match child.walk_to(name) {
                    Ok(Some(_)) => child,
                    Ok(None) | Err(VfsError::Enoent) => continue,
                    Err(_) => return Err(Error::Eio),
                }
            }
        };
        child.namespace_path = path;
        records.extend(crate::devmnt::stat_record(&mut child, true).map_err(|_| Error::Eio)?);
    }
    Ok(records)
}

impl crate::proc::Chan for DevChanAdapter {
    fn access_mode(&self) -> u8 {
        self.chan.mode & 3
    }

    fn dev_chan(&self) -> Option<Chan> {
        Some(self.chan.clone())
    }

    fn io_device_chan(&self) -> Option<Chan> {
        self.dev_chan()
    }

    fn read(&mut self, buf: &mut [u8]) -> crate::proc::Result<usize> {
        if self.chan.qid.type_ & dev::qidtype::DIR != 0 {
            self.read_directory(buf, false)
        } else {
            self.read_channel(buf, false)
        }
    }

    fn read_interruptible(&mut self, buf: &mut [u8]) -> crate::proc::Result<usize> {
        if self.chan.qid.type_ & dev::qidtype::DIR != 0 {
            self.read_directory(buf, true)
        } else {
            self.read_channel(buf, true)
        }
    }

    fn write(&mut self, buf: &[u8]) -> crate::proc::Result<usize> {
        let dev = match devs_mut().get_mut(self.chan.dev) {
            Some(d) => d,
            None => return Err(crate::proc::Error::Eio),
        };
        let offset = self.chan.offset;
        let n = match dev.write(&mut self.chan, buf, offset) {
            Ok(n) => n,
            Err(DevError::Eintr) => return Err(crate::proc::Error::Eintr),
            Err(_) => return Err(crate::proc::Error::Eio),
        };
        self.chan.offset += n as u64;
        Ok(n)
    }

    fn close(&mut self) {
        if let Some(dev) = devs_mut().get_mut(self.chan.dev) {
            dev.close(&mut self.chan);
        }
    }

    fn pending_close(&mut self) -> Option<crate::devmnt::PendingClose> {
        crate::devmnt::PendingClose::start(&mut self.chan)
    }

    fn dev(&self) -> usize {
        self.chan.dev
    }

    fn offset(&self) -> u64 {
        self.chan.offset
    }

    fn set_offset(&mut self, offset: u64) {
        self.chan.offset = offset;
        if offset == 0 {
            self.directory_records = None;
        }
    }

    fn seek(&mut self, offset: i64, whence: u8) -> crate::proc::Result<i64> {
        if crate::procfs::is_memory_channel(&self.chan) {
            let position = match whence {
                0 => Some(offset as u64),
                1 => self.chan.offset.checked_add_signed(offset),
                _ => None,
            }.ok_or(crate::proc::Error::Einval)?;
            self.chan.offset = position;
            return Ok(position as i64);
        }
        if self.chan.qid.type_ & dev::qidtype::DIR != 0 && (whence != 0 || offset != 0) {
            return Err(crate::proc::Error::Einval);
        }
        let base = match whence {
            0 => 0,
            1 => self.chan.offset,
            2 => self.stat()?.length,
            _ => return Err(crate::proc::Error::Einval),
        };
        let position = base.checked_add_signed(offset).and_then(|value| i64::try_from(value).ok())
            .ok_or(crate::proc::Error::Einval)?;
        self.set_offset(position as u64);
        Ok(position)
    }

    fn dup(&self) -> alloc::boxed::Box<dyn crate::proc::Chan> {
        alloc::boxed::Box::new(Self { chan: self.chan.dup(), directory_records: self.directory_records.clone() })
    }

    fn stat(&mut self) -> crate::proc::Result<crate::dev::DirEntry> {
        let dev = match devs_mut().get_mut(self.chan.dev) {
            Some(d) => d,
            None => return Err(crate::proc::Error::Eio),
        };
        match dev.stat(&mut self.chan) {
            Ok(s) => Ok(s),
            Err(_) => Err(crate::proc::Error::Eio),
        }
    }
}

fn fgrp() -> Option<&'static mut crate::proc::Fgrp> {
    crate::proc::curproc_mut()
        .and_then(|p| p.fgrp.as_mut())
        .map(|b| b.as_mut())
}

pub(crate) fn alloc_fd(chan: Chan) -> Result<i32, VfsError> {
    alloc_device_channel(chan, false)
}

fn alloc_device_channel(chan: Chan, close_on_exec: bool) -> Result<i32, VfsError> {
    alloc_device_channel_in(fgrp().ok_or(VfsError::Eperm)?, chan, close_on_exec)
}

pub(crate) fn alloc_device_channel_in(group: &crate::proc::Fgrp, chan: Chan, close_on_exec: bool) -> Result<i32, VfsError> {
    alloc_channel_in(group, alloc::boxed::Box::new(DevChanAdapter::new(chan)), close_on_exec)
}

pub(crate) fn fd_channel(fd: i32) -> Option<alloc::boxed::Box<dyn crate::proc::Chan>> {
    if fd < 0 {
        return None;
    }
    fgrp().and_then(|f| f.get_channel(fd))
}

pub(crate) enum PathOperation {
    Open(u32),
    Create { mode: u32, perm: u32 },
    Remove,
    Stat { address: u64, size: usize },
    Wstat(Vec<u8>),
    List { address: u64, size: usize },
    Chdir(Vec<u8>),
    Bind { target: Vec<u8>, flags: u32 },
    Unmount(Option<Vec<u8>>),
}

pub(crate) struct PendingPath {
    operation: PathOperation,
    lookup: Option<PathLookup>,
    resolved: Option<Chan>,
    mutation: Option<crate::devmnt::PendingOpen>,
    opening: Option<DirectoryOpens>,
    metadata: Option<crate::devmnt::PendingIo>,
    listing: Option<ListNames>,
}

impl PendingPath {
    pub(crate) fn new(path: &[u8], operation: PathOperation) -> Result<Self, VfsError> {
        let mut lookup = PathLookup::new(path)?;
        lookup.for_create = matches!(operation, PathOperation::Create { .. });
        Ok(Self { operation, lookup: Some(lookup), resolved: None, mutation: None,
            opening: None, metadata: None, listing: None })
    }

    pub(crate) fn progress(&mut self, proc: &mut crate::proc::Proc) -> crate::syscall::Result<Option<usize>> {
        use crate::syscall::{self, Error};

        while let Some(lookup) = &mut self.lookup {
            let Some(mut chan) = lookup.progress(true, proc.has_pending_signals())? else { return Ok(None) };
            let missing_name = lookup.missing_name.take();
            self.lookup = None;
            match &self.operation {
                PathOperation::Create { mode, perm } => {
                    use crate::devmnt::{FidOperation, PendingOpen};

                    let clean_mode = *mode & !(OCEXEC | OEXCL);
                    let close_on_exec = mode & OCEXEC != 0;
                    let directory = perm & 0x8000_0000 != 0;
                    let operation = if let Some(name) = &missing_name {
                        FidOperation::Create { mode: clean_mode as u8, perm: *perm, name: name.clone() }
                    } else {
                        if mode & OEXCL != 0 {
                            return Err(VfsError::Eexists.into());
                        }
                        let remote_mode = if directory { clean_mode } else { clean_mode | OTRUNC };
                        FidOperation::Open(remote_mode as u8)
                    };
                    match PendingOpen::start_operation(chan, operation) {
                        Ok(pending) => self.mutation = Some(pending),
                        Err(mut local) => {
                            if let Some(name) = &missing_name {
                                create_on(&mut local, name, clean_mode, *perm)?;
                            }
                            return finish_local_create(local, clean_mode, directory, close_on_exec)
                                .map(|fd| Some(fd as usize)).map_err(Into::into);
                        }
                    }
                }
                PathOperation::Remove => {
                    match crate::devmnt::PendingOpen::start_operation(chan, crate::devmnt::FidOperation::Remove) {
                        Ok(pending) => self.mutation = Some(pending),
                        Err(mut local) => {
                            remove_on(&mut local)?;
                            let _ = dev::dev_close(&mut local);
                            return Ok(Some(0));
                        }
                    }
                }
                PathOperation::Chdir(path) => {
                    syscall::change_directory(proc, chan, path)?;
                    return Ok(Some(0));
                }
                PathOperation::Bind { target, flags } => {
                    if let Some(source) = self.resolved.take() {
                        bind(source, chan, *flags).map_err(|_| Error::Eio)?;
                        return Ok(Some(0));
                    }
                    self.resolved = Some(chan);
                    self.lookup = Some(PathLookup::new(target)?);
                }
                PathOperation::Unmount(source) => {
                    if let Some(source) = source {
                        if let Some(target) = self.resolved.take() {
                            let transport = if crate::devsrv::is_service(&chan) {
                                crate::devsrv::open_service(&chan, 0)?.open_id()
                            } else {
                                None
                            };
                            unmount_namespace(target, Some((chan, transport)))?;
                            return Ok(Some(0));
                        }
                        self.resolved = Some(chan);
                        self.lookup = Some(PathLookup::new(source)?);
                    } else {
                        unmount_namespace(chan, None)?;
                        return Ok(Some(0));
                    }
                }
                PathOperation::Open(mode) => {
                    let clean_mode = mode & !OCEXEC;
                    let close_on_exec = mode & OCEXEC != 0;
                    if let Some(fd) = open_special(&chan, clean_mode, close_on_exec)? {
                        return Ok(Some(fd as usize));
                    }
                    self.opening = Some(DirectoryOpens::new(chan, clean_mode as u8, clean_mode == 0));
                }
                PathOperation::List { .. } => {
                    if chan.qid.type_ & dev::qidtype::DIR == 0 {
                        return Err(Error::Enotdir);
                    }
                    self.opening = Some(DirectoryOpens::new(chan, 0, true));
                }
                PathOperation::Stat { address, size } => {
                    self.metadata = crate::devmnt::PendingIo::stat(&chan, *address, *size, true);
                    if self.metadata.is_none() {
                        let result = crate::devmnt::stat_record(&mut chan, true);
                        let _ = dev::dev_close(&mut chan);
                        return syscall::copy_stat_to_proc(proc, *address, *size, &result?).map(Some);
                    }
                }
                PathOperation::Wstat(stat) => {
                    self.metadata = crate::devmnt::PendingIo::wstat(&chan, stat)?;
                    if self.metadata.is_none() {
                        crate::devmnt::wstat(&mut chan, stat)?;
                        return Ok(Some(stat.len()));
                    }
                }
            }
        }
        if let Some(mutation) = &mut self.mutation {
            let Some(chan) = mutation.open_channel(proc.has_pending_signals())? else { return Ok(None) };
            return match self.operation {
                PathOperation::Create { mode, .. } => {
                    let group = proc.fgrp.as_deref().ok_or(Error::Eperm)?;
                    Ok(Some(alloc_device_channel_in(group, chan, mode & OCEXEC != 0)? as usize))
                }
                PathOperation::Remove => Ok(Some(0)),
                _ => Err(Error::Eio),
            };
        }
        if let Some(metadata) = &mut self.metadata {
            return metadata.poll(proc).transpose();
        }
        if let Some(opening) = &mut self.opening {
            let Some(mut opened) = opening.progress(proc.has_pending_signals())? else { return Ok(None) };
            let union = opening.union;
            self.opening = None;
            if let PathOperation::Open(mode) = self.operation {
                let channel: alloc::boxed::Box<dyn crate::proc::Chan> = if union {
                    alloc::boxed::Box::new(UnionDirectory::new(opened))
                } else {
                    alloc::boxed::Box::new(opened.pop().ok_or(Error::Eio)?)
                };
                let group = proc.fgrp.as_deref().ok_or(Error::Eperm)?;
                return Ok(Some(alloc_channel_in(group, channel, mode & OCEXEC != 0)? as usize));
            }
            self.listing = Some(ListNames { directories: opened.into_iter(), pending: None, copied: 0 });
        }
        if let (Some(listing), PathOperation::List { address, size }) = (&mut self.listing, &self.operation) {
            return listing.progress(proc, *address, *size);
        }
        Err(Error::Eio)
    }
}

fn open_special(chan: &Chan, mode: u32, close_on_exec: bool) -> Result<Option<i32>, VfsError> {
    if let Some(image) = crate::procfs::open_exec_image(chan, mode) {
        return alloc_device_channel(image.map_err(VfsError::from_dev_error)?, close_on_exec).map(Some);
    }
    if crate::devfd::is_descriptor(chan) {
        return alloc_channel(crate::devfd::reopen(chan, mode).map_err(VfsError::from_dev_error)?, close_on_exec)
            .map(Some);
    }
    if crate::devsrv::is_service(chan) {
        let published = crate::devsrv::open_service(chan, mode as u8)
            .map_err(VfsError::from_dev_error)?;
        return alloc_channel(published, close_on_exec).map(Some);
    }
    Ok(None)
}

struct DirectoryOpens {
    channels: alloc::vec::IntoIter<Chan>,
    opened: Vec<DevChanAdapter>,
    active: Option<crate::devmnt::PendingOpen>,
    mode: u8,
    union: bool,
}

impl DirectoryOpens {
    fn new(chan: Chan, mode: u8, expand_union: bool) -> Self {
        let entries = if expand_union && chan.qid.type_ & dev::qidtype::DIR != 0 {
            chan.namespace_path.as_deref().and_then(namespace_mounts).filter(|entries| entries.len() > 1)
        } else {
            None
        };
        let union = entries.is_some();
        let channels = entries.map_or_else(|| vec![chan], |entries| entries.into_iter().map(|entry| entry.root).collect());
        Self { channels: channels.into_iter(), opened: Vec::new(), active: None, mode, union }
    }

    fn progress(&mut self, interrupted: bool) -> Result<Option<Vec<DevChanAdapter>>, VfsError> {
        loop {
            let result = if let Some(active) = &mut self.active {
                let result = active.open_channel(interrupted).map_err(VfsError::from_dev_error);
                if matches!(result, Ok(None)) {
                    return Ok(None);
                }
                self.active = None;
                result
            } else if let Some(chan) = self.channels.next() {
                match crate::devmnt::PendingOpen::start(chan, self.mode) {
                    Ok(pending) => {
                        self.active = Some(pending);
                        continue;
                    }
                    Err(mut chan) => chan.open(self.mode).map(|()| Some(chan)),
                }
            } else if self.opened.is_empty() {
                return Err(VfsError::Eperm);
            } else {
                return Ok(Some(core::mem::take(&mut self.opened)));
            };
            match result {
                Ok(Some(chan)) => self.opened.push(DevChanAdapter::new(chan)),
                Err(error) if matches!(error, VfsError::Eintr) || !self.union => return Err(error),
                _ => {}
            }
        }
    }
}

impl Drop for DirectoryOpens {
    fn drop(&mut self) {
        for opened in &mut self.opened {
            crate::proc::Chan::close(opened);
        }
    }
}

struct ListNames {
    directories: alloc::vec::IntoIter<DevChanAdapter>,
    pending: Option<crate::devmnt::PendingIo>,
    copied: usize,
}

impl ListNames {
    fn progress(&mut self, proc: &mut crate::proc::Proc, address: u64, size: usize) -> crate::syscall::Result<Option<usize>> {
        while self.copied < size {
            if let Some(pending) = &mut self.pending {
                let Some(count) = pending.poll(proc).transpose()? else { return Ok(None) };
                self.pending = None;
                self.copied += count;
            } else if let Some(mut directory) = self.directories.next() {
                let remaining = size - self.copied;
                let destination = address + self.copied as u64;
                self.pending = directory.pending_names(destination, remaining);
                if self.pending.is_none() {
                    let mut output = Vec::new();
                    output.try_reserve_exact(remaining).map_err(|_| VfsError::Enomem)?;
                    output.resize(remaining, 0);
                    let result = directory.read_names(&mut output);
                    crate::proc::Chan::close(&mut directory);
                    let count = result?;
                    crate::syscall::put_user_bytes(proc, destination, &output[..count])?;
                    self.copied += count;
                }
            } else {
                break;
            }
        }
        Ok(Some(self.copied))
    }
}

impl Drop for ListNames {
    fn drop(&mut self) {
        for mut directory in self.directories.by_ref() {
            crate::proc::Chan::close(&mut directory);
        }
    }
}

fn alloc_channel(chan: alloc::boxed::Box<dyn crate::proc::Chan>, close_on_exec: bool) -> Result<i32, VfsError> {
    alloc_channel_in(fgrp().ok_or(VfsError::Eperm)?, chan, close_on_exec)
}

fn alloc_channel_in(group: &crate::proc::Fgrp, chan: alloc::boxed::Box<dyn crate::proc::Chan>, close_on_exec: bool) -> Result<i32, VfsError> {
    let fd = group.alloc_fd_with_exec_mode(chan, close_on_exec);
    if fd < 0 { Err(VfsError::Enomem) } else { Ok(fd) }
}

struct UnionCursor {
    directories: Vec<DevChanAdapter>,
    index: usize,
    offset: u64,
    busy: bool,
}

impl Drop for UnionCursor {
    fn drop(&mut self) {
        for directory in &mut self.directories {
            directory.close();
        }
    }
}

#[doc(hidden)]
pub struct PendingUnionRead {
    cursor: Arc<Spinlock<UnionCursor>>,
    address: u64,
    size: usize,
    claimed: bool,
    active: Option<crate::devmnt::PendingData>,
}

impl PendingUnionRead {
    pub(crate) fn progress(&mut self, proc: &crate::proc::Proc) -> crate::syscall::Result<Option<usize>> {
        use crate::syscall::{self, Error};

        if !self.claimed {
            if proc.has_pending_signals() {
                return Err(Error::Eintr);
            }
            let mut cursor = self.cursor.lock();
            if cursor.busy {
                return Ok(None);
            }
            cursor.busy = true;
            self.claimed = true;
        }
        loop {
            if let Some(active) = &mut self.active {
                let Some(count) = active.poll(proc).transpose()? else { return Ok(None) };
                self.active = None;
                let mut cursor = self.cursor.lock();
                if count != 0 {
                    let index = cursor.index;
                    cursor.directories[index].chan.offset += count as u64;
                    cursor.offset += count as u64;
                    return Ok(Some(count));
                }
                cursor.index += 1;
                continue;
            }
            if proc.has_pending_signals() {
                return Err(Error::Eintr);
            }
            let mut cursor = self.cursor.lock();
            let index = cursor.index;
            let Some(directory) = cursor.directories.get_mut(index) else { return Ok(Some(0)) };
            if let Ok(pending) = crate::devmnt::PendingData::start(directory.dup(), self.address, self.size, false) {
                self.active = Some(pending);
                continue;
            }
            let mut output = vec![0; self.size.min(u16::MAX as usize + 2)];
            let count = directory.read_directory(&mut output, true)?;
            if count != 0 {
                cursor.offset += count as u64;
                syscall::put_user_bytes(proc, self.address, &output[..count])?;
                return Ok(Some(count));
            }
            cursor.index += 1;
        }
    }
}

impl Drop for PendingUnionRead {
    fn drop(&mut self) {
        drop(self.active.take());
        if self.claimed {
            self.cursor.lock().busy = false;
        }
    }
}

struct UnionDirectory(Arc<Spinlock<UnionCursor>>);

impl UnionDirectory {
    fn new(directories: Vec<DevChanAdapter>) -> Self {
        Self(Arc::new(Spinlock::new(UnionCursor { directories, index: 0, offset: 0, busy: false })))
    }
}

impl crate::proc::Chan for UnionDirectory {
    fn pending_union_read(&self, address: u64, size: usize) -> Option<PendingUnionRead> {
        Some(PendingUnionRead { cursor: self.0.clone(), address, size, claimed: false, active: None })
    }

    fn read(&mut self, output: &mut [u8]) -> crate::proc::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut cursor = self.0.lock();
        if cursor.busy {
            return Err(crate::proc::Error::Eagain);
        }
        loop {
            let index = cursor.index;
            let Some(directory) = cursor.directories.get_mut(index) else { return Ok(0) };
            let count = directory.read_directory(output, true)?;
            if count > 0 {
                cursor.offset += count as u64;
                return Ok(count);
            }
            cursor.index += 1;
        }
    }

    fn write(&mut self, _input: &[u8]) -> crate::proc::Result<usize> {
        Err(crate::proc::Error::Eperm)
    }

    fn close(&mut self) {}

    fn dev(&self) -> usize { self.0.lock().directories[0].dev() }
    fn stat(&mut self) -> crate::proc::Result<DirEntry> { self.0.lock().directories[0].stat() }
    fn dev_chan(&self) -> Option<Chan> { self.0.lock().directories[0].dev_chan() }
    fn access_mode(&self) -> u8 { 0 }
    fn offset(&self) -> u64 { self.0.lock().offset }

    fn set_offset(&mut self, offset: u64) {
        let _ = self.seek(offset as i64, 0);
    }

    fn seek(&mut self, offset: i64, whence: u8) -> crate::proc::Result<i64> {
        if whence == 0 && offset == 0 {
            let mut cursor = self.0.lock();
            if cursor.busy {
                return Err(crate::proc::Error::Eagain);
            }
            cursor.offset = 0;
            cursor.index = 0;
            for directory in &mut cursor.directories {
                directory.set_offset(0);
            }
            Ok(0)
        } else {
            Err(crate::proc::Error::Einval)
        }
    }

    fn dup(&self) -> alloc::boxed::Box<dyn crate::proc::Chan> {
        alloc::boxed::Box::new(Self(self.0.clone()))
    }
}

fn finish_local_create(mut chan: Chan, mode: u32, directory: bool, close_on_exec: bool) -> Result<i32, VfsError> {
    if !directory && crate::devfd::is_descriptor(&chan) {
        return alloc_channel(crate::devfd::reopen(&chan, mode).map_err(VfsError::from_dev_error)?, close_on_exec);
    }
    if chan.flag & dev::CREATED_OPEN != 0 {
        return alloc_device_channel(chan, close_on_exec);
    }
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.open(&mut chan, mode as u8)
        .map_err(VfsError::from_dev_error)?;
    // Plan 9 `create` truncates an existing *file*.  Opening an existing
    // file goes through the walk path, so the truncation has to happen
    // here rather than in the device's create hook.  Directories are
    // never truncated — a DMDIR create would otherwise fail here after
    // the directory had already been created.
    if !directory {
        crate::dev::dev_truncate(&mut chan).map_err(VfsError::from_dev_error)?;
    }
    alloc_device_channel(chan, close_on_exec)
}

pub fn sys_read(fd: i32, buf: &mut [u8]) -> Result<usize, VfsError> {
    let mut chan = fd_channel(fd).ok_or(VfsError::Ebadfd)?;
    chan.read(buf).map_err(|_| VfsError::Eio)
}

pub fn sys_write(fd: i32, buf: &[u8]) -> Result<usize, VfsError> {
    let mut chan = fd_channel(fd).ok_or(VfsError::Ebadfd)?;
    chan.write(buf).map_err(|_| VfsError::Eio)
}

pub fn sys_close(fd: i32) -> Result<(), VfsError> {
    let f = fgrp().ok_or(VfsError::Eperm)?;
    if f.close_fd(fd).is_none() {
        return Err(VfsError::Ebadfd);
    }
    Ok(())
}

pub fn sys_flock(_fd: i32, _operation: i32) -> Result<(), VfsError> {
    // Advisory locks are not implemented in the prototype.
    Err(VfsError::Enotsup)
}

pub fn symlink(_target: &[u8], _link: &[u8]) -> Result<(), VfsError> {
    Err(VfsError::Enotsup)
}

pub fn readlink(_path: &[u8], _buf: &mut [u8]) -> Result<usize, VfsError> {
    Err(VfsError::Enotsup)
}

// ============================================================================
// Mount operations
// ============================================================================

pub fn init_vfs() {
    // Mount table starts empty; the root channel is installed during boot.
}

pub fn get_root_chan() -> Option<Chan> {
    ROOT_CHAN.lock().as_ref().map(|c| c.dup())
}

pub fn set_root_chan(chan: Chan) {
    *ROOT_CHAN.lock() = Some(chan);
}

pub fn mount(
    source: Option<&[u8]>,
    target: &[u8],
    fs_type: &[u8],
    flags: u32,
) -> Result<(), VfsError> {
    let src = source.unwrap_or(b"/");

    // A source such as `#p` names the device by the character after `#`.
    // A plain source such as `/` names the root device directly.
    let (dev_char, spec) = if src.len() >= 2 && src[0] == b'#' {
        (src[1] as char, core::str::from_utf8(&src[2..]).unwrap_or(""))
    } else {
        (src.first().copied().unwrap_or(b'#') as char,
         core::str::from_utf8(&src[1..]).unwrap_or(""))
    };

    let idx = dev::devs().find_by_char(dev_char).ok_or(VfsError::Enoent)?;
    let root = attach_device(idx, Some(spec), 0)?;

    let mut mp = MountPoint::new(src, target, fs_type);
    mp.flags = flags;
    mp.root = Some(root);

    let mut mounts = MOUNTS.lock();
    if mounts.add(mp).is_none() {
        return Err(VfsError::Enomem);
    }
    Ok(())
}

pub fn unmount(target: &[u8]) -> Result<(), VfsError> {
    let mut mounts = MOUNTS.lock();
    if mounts.remove(target).is_none() {
        return Err(VfsError::Enoent);
    }
    Ok(())
}

pub fn find_mount(path: &[u8]) -> Option<Chan> {
    if let Some(root) = namespace().and_then(|ns| {
        ns.mounts.lock().get(path)?.first().map(|entry| entry.root.dup())
    }) {
        return Some(root);
    }
    let mounts = MOUNTS.lock();
    mounts.find_exact(path).and_then(|mp| mp.root.as_ref().map(|c| c.dup()))
}

fn namespace() -> Option<&'static crate::proc::Namespace> {
    crate::proc::curproc()?.pgrp.as_ref()?.namespace()
}

fn namespace_mounts(path: &[u8]) -> Option<Vec<MountEntry>> {
    namespace()?.mounts.lock().get(path).cloned()
}

pub(crate) fn replace_mount(source: Chan, target: Chan, flags: u32) -> Result<(), VfsError> {
    let order = flags & (MBEFORE | MAFTER);
    if flags & !(MREPL | MCACHE | MCREATE | MBEFORE | MAFTER) != 0
        || order == (MBEFORE | MAFTER) || (order != 0 && flags & MREPL != 0)
    {
        return Err(VfsError::Einval);
    }
    if (source.qid.type_ ^ target.qid.type_) & dev::qidtype::DIR != 0 {
        return Err(VfsError::Einval);
    }
    if order != 0 && target.qid.type_ & dev::qidtype::DIR == 0 {
        return Err(VfsError::Enotdir);
    }
    let path = target.namespace_path.clone().ok_or(VfsError::Einval)?;
    let entries = vec![MountEntry { root: source, create: order == 0 || flags & MCREATE != 0 }];
    let ns = namespace().ok_or(VfsError::Eperm)?;
    if order == 0 {
        let previous = ns.mounts.lock().insert(path, entries);
        drop(previous);
    } else {
        let mut mounts = ns.mounts.lock();
        let union = mounts.entry(path).or_insert_with(|| vec![MountEntry { root: target, create: false }]);
        if order == MBEFORE {
            union.splice(..0, entries);
        } else {
            union.extend(entries);
        }
    }
    Ok(())
}

fn unmount_namespace(target: Chan, candidate: Option<(Chan, Option<usize>)>) -> Result<(), VfsError> {
    let path = target.namespace_path.ok_or(VfsError::Einval)?;
    let removed = {
        let mut mounts = namespace().ok_or(VfsError::Eperm)?.mounts.lock();
        let mounted = mounts.get_mut(&path).ok_or(VfsError::Enoent)?;
        if let Some((source, transport)) = candidate.as_ref() {
            let index = mounted.iter().position(|entry| {
                let root = &entry.root;
                if let Some(transport) = transport {
                    crate::devmnt::transport_id(root) == Some(*transport)
                } else {
                    source.dev == root.dev && source.qid.path == root.qid.path
                        && crate::devmnt::transport_id(source) == crate::devmnt::transport_id(root)
                }
            }).ok_or(VfsError::Enoent)?;
            let removed = mounted.remove(index);
            if mounted.is_empty() {
                mounts.remove(&path);
            }
            Some(vec![removed])
        } else {
            mounts.remove(&path)
        }
    };
    drop(removed);
    Ok(())
}

pub fn walk_chan(chan: &mut Chan, name: &str) -> Result<Option<Qid>, VfsError> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.walk(chan, name).map_err(VfsError::from_dev_error)
}

pub fn create_chan(chan: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), VfsError> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.create(chan, name, mode, perm).map_err(VfsError::from_dev_error)
}

pub fn open_chan(chan: &mut Chan, mode: u8) -> Result<(), VfsError> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.open(chan, mode).map_err(VfsError::from_dev_error)
}

pub fn read_chan(chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, VfsError> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.read(chan, buf, offset).map_err(VfsError::from_dev_error)
}

pub fn write_chan(chan: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, VfsError> {
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.write(chan, buf, offset).map_err(VfsError::from_dev_error)
}

pub fn bind(source: Chan, target: Chan, flags: u32) -> Result<(), VfsError> {
    replace_mount(source, target, flags)
}

// ============================================================================
// VFS trait
// ============================================================================

/// File-system operations trait, implemented by concrete file systems.
pub trait Vfs: Send + Sync {
    fn init(&mut self) {}
    fn root(&mut self) -> Result<Chan, VfsError>;
    fn sync(&mut self) {}
}

// ============================================================================
// Mount-table syscall helpers
// ============================================================================

pub mod mount_table {
    use super::*;

    pub fn add(source: Chan, path: String, flags: u32) -> Result<(), VfsError> {
        let mut mp = MountPoint::new(path.as_bytes(), path.as_bytes(), b"bind");
        mp.flags = flags;
        mp.root = Some(source);

        let mut mounts = MOUNTS.lock();
        if mounts.add(mp).is_none() {
            return Err(VfsError::Enomem);
        }
        Ok(())
    }

    pub fn remove(path: &str) -> Result<(), VfsError> {
        let mut mounts = MOUNTS.lock();
        if mounts.remove(path.as_bytes()).is_none() {
            return Err(VfsError::Enoent);
        }
        Ok(())
    }
}

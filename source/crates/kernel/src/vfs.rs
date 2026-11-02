//! Virtual File System
//!
//! Plan 9 style VFS layer that connects file systems and devices to the
//! system-call interface.  Provides `namec()` for path-to-channel
//! conversion, a mount table for bind/union mounts, and channel
//! reference management.
//!
//! The device table is owned by `crate::dev`; this module only borrows
//! devices through the small helpers exported there.

use alloc::string::String;
use alloc::vec::Vec;

use crate::chan::Qid;
use crate::dev::{self, Chan, DirEntry, Error as DevError, devs_mut, devtype, qidtype};
use crate::plan9_common::sync::{Mutex, Spinlock};
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum mount points
pub const NMOUNT: usize = 16;

/// Maximum path components
pub const MAX_PATH_COMPONENTS: usize = 64;

/// Maximum file name length
pub const MAX_FILE_NAME: usize = 256;

/// Root device character
pub const ROOTDEV: char = '/';

/// Mount flags (Plan 9 semantics)
pub const MBEFORE: u32 = 0x01;
pub const MAFTER: u32 = 0x02;
pub const MCREATE: u32 = 0x04;
pub const MCACHE: u32 = 0x08;
pub const MREPL: u32 = 0x10;
pub const MBIND: u32 = 0x20;
pub const MUNION: u32 = 0x40;

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
    Parent,
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
        for (i, slot) in self.entries.iter_mut().enumerate() {
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
fn proc_namespace_dot() -> Option<Chan> {
    let proc = crate::proc::curproc()?;
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
    perm: u32,
) -> Result<Chan, VfsError> {
    if path.is_empty() {
        return Err(VfsError::Einval);
    }
    if path.len() > MAX_FILE_NAME * MAX_PATH_COMPONENTS {
        return Err(VfsError::Enametoolong);
    }

    let (start, rest) = parse_path_start(path);

    let mut chan = match start {
        PathStart::Root => {
            // Root mount if one exists; otherwise the root device.
            let mut mounts = MOUNTS.lock();
            if let Some(mp) = mounts.find_exact(b"") {
                if let Some(root) = mp.root.as_ref() {
                    return walk_from_root(root, rest, amode, perm);
                }
            }
            drop(mounts);

            if let Some(root) = ROOT_CHAN.lock().as_ref() {
                return walk_from_root(root, rest, amode, perm);
            }

            let idx = root_device_index().ok_or(VfsError::Enoent)?;
            attach_device(idx, None, 0)?
        }

        PathStart::Special(c) => {
            let idx = dev::devs().find_by_char(c).ok_or(VfsError::Enoent)?;
            let spec = rest.and_then(|r| core::str::from_utf8(r).ok());
            attach_device(idx, spec, 0)?
        }

        PathStart::Current => {
            if let Some(dot) = proc_namespace_dot() {
                dot
            } else if let Some(root) = ROOT_CHAN.lock().as_ref() {
                root.dup()
            } else {
                let idx = root_device_index().ok_or(VfsError::Enoent)?;
                attach_device(idx, None, 0)?
            }
        }

        PathStart::Parent => {
            let dot = proc_namespace_dot().ok_or(VfsError::Eperm)?;
            let mut parent = dot.dup();
            let dev = devs_mut().get_mut(parent.dev).ok_or(VfsError::Enoent)?;
            if dev.walk(&mut parent, "..").is_err() {
                return Err(VfsError::Enoent);
            }
            parent
        }
    };

    // Walk the remaining components.
    let mut current_path: Vec<u8> = Vec::new();
    let components = rest.map(parse_path).unwrap_or_default();

    for comp in components {
        if comp.is_empty() || comp == b"." {
            continue;
        }

        if comp == b".." {
            if let Some(dev) = devs_mut().get_mut(chan.dev) {
                if dev.walk(&mut chan, "..").is_err() {
                    return Err(VfsError::Enoent);
                }
            } else {
                return Err(VfsError::Enoent);
            }
            current_path = parent_path(&current_path).unwrap_or_else(|| b"/".to_vec());
            continue;
        }

        current_path.push(b'/');
        current_path.extend_from_slice(comp);

        // Mount table redirect: if this path is a mount point, switch to the
        // mounted device's root.  The component that names the mount point is
        // consumed by the mount itself, so we do not walk it again inside the
        // mounted device.
        {
            let mounts = MOUNTS.lock();
            if let Some(mp) = mounts.find_exact(&current_path) {
                if let Some(root) = mp.root.as_ref() {
                    chan = root.dup();
                    continue;
                }
            }
        }

        let name = core::str::from_utf8(comp).map_err(|_| VfsError::Einval)?;
        let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;

        match dev.walk(&mut chan, name) {
            Ok(Some(_qid)) => {}
            Ok(None) => {
                if let NamecMode::Create(mode, create_perm) = amode {
                    dev.create(&mut chan, name, mode as u8, create_perm)
                        .map_err(VfsError::from_dev_error)?;
                } else {
                    return Err(VfsError::Enoent);
                }
            }
            Err(e) => return Err(VfsError::from_dev_error(e)),
        }
    }

    if let NamecMode::Remove = amode {
        if let Some(dev) = devs_mut().get_mut(chan.dev) {
            dev.remove(&mut chan).map_err(VfsError::from_dev_error)?;
        } else {
            return Err(VfsError::Enoent);
        }
    }

    Ok(chan)
}

fn walk_from_root(
    root: &Chan,
    rest: Option<&[u8]>,
    amode: NamecMode,
    perm: u32,
) -> Result<Chan, VfsError> {
    let mut chan = root.dup();
    let components = rest.map(parse_path).unwrap_or_default();
    let mut current_path: Vec<u8> = Vec::new();

    for comp in components {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." {
            if let Some(dev) = devs_mut().get_mut(chan.dev) {
                if dev.walk(&mut chan, "..").is_err() {
                    return Err(VfsError::Enoent);
                }
            } else {
                return Err(VfsError::Enoent);
            }
            current_path = parent_path(&current_path).unwrap_or_else(|| b"/".to_vec());
            continue;
        }

        current_path.push(b'/');
        current_path.extend_from_slice(comp);

        // A mount point consumes this component and switches to the mounted
        // device root; do not walk the same name inside that device.
        {
            let mounts = MOUNTS.lock();
            if let Some(mp) = mounts.find_exact(&current_path) {
                if let Some(root) = mp.root.as_ref() {
                    chan = root.dup();
                    continue;
                }
            }
        }

        let name = core::str::from_utf8(comp).map_err(|_| VfsError::Einval)?;
        let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
        match dev.walk(&mut chan, name) {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let NamecMode::Create(mode, create_perm) = amode {
                    dev.create(&mut chan, name, mode as u8, create_perm)
                        .map_err(VfsError::from_dev_error)?;
                } else {
                    return Err(VfsError::Enoent);
                }
            }
            Err(e) => return Err(VfsError::from_dev_error(e)),
        }
    }

    // The mount point itself should return the mounted device's root.
    if let Some(mp) = MOUNTS.lock().find_exact(&current_path) {
        if let Some(root) = mp.root.as_ref() {
            chan = root.dup();
        }
    }

    Ok(chan)
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
            // `aux` is device-private and not generally cloneable.
            aux: None,
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
            2 => self.offset = offset, // no file length available -> treat as end
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
}

impl DevChanAdapter {
    pub fn new(chan: Chan) -> Self {
        Self { chan }
    }
}

impl crate::proc::Chan for DevChanAdapter {
    fn read(&mut self, buf: &mut [u8]) -> crate::proc::Result<usize> {
        let dev = match devs_mut().get_mut(self.chan.dev) {
            Some(d) => d,
            None => return Err(crate::proc::Error::Eio),
        };
        let offset = self.chan.offset;
        let n = match dev.read(&mut self.chan, buf, offset) {
            Ok(n) => n,
            Err(_) => return Err(crate::proc::Error::Eio),
        };
        self.chan.offset += n as u64;
        Ok(n)
    }

    fn write(&mut self, buf: &[u8]) -> crate::proc::Result<usize> {
        let dev = match devs_mut().get_mut(self.chan.dev) {
            Some(d) => d,
            None => return Err(crate::proc::Error::Eio),
        };
        let offset = self.chan.offset;
        let n = match dev.write(&mut self.chan, buf, offset) {
            Ok(n) => n,
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

    fn dev(&self) -> usize {
        self.chan.dev
    }

    fn offset(&self) -> u64 {
        self.chan.offset
    }

    fn set_offset(&mut self, offset: u64) {
        self.chan.offset = offset;
    }

    fn dup(&self) -> alloc::boxed::Box<dyn crate::proc::Chan> {
        alloc::boxed::Box::new(DevChanAdapter::new(self.chan.dup()))
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

fn alloc_fd(chan: Chan) -> Result<i32, VfsError> {
    let f = fgrp().ok_or(VfsError::Eperm)?;
    let fd = f.alloc_fd(alloc::boxed::Box::new(DevChanAdapter::new(chan)));
    if fd < 0 {
        return Err(VfsError::Enomem);
    }
    Ok(fd)
}

fn fd_channel(fd: i32) -> Option<&'static mut alloc::boxed::Box<dyn crate::proc::Chan>> {
    if fd < 0 {
        return None;
    }
    fgrp().and_then(|f| f.get_channel(fd))
}

pub fn sys_open(path: &[u8], mode: u32) -> Result<i32, VfsError> {
    let chan = open(path, mode)?;
    alloc_fd(chan)
}

pub fn sys_create(path: &[u8], mode: u32, perm: u32) -> Result<i32, VfsError> {
    let mut chan = namec(path, NamecMode::Create(mode, perm), mode, perm)?;
    let dev = devs_mut().get_mut(chan.dev).ok_or(VfsError::Enoent)?;
    dev.open(&mut chan, mode as u8)
        .map_err(VfsError::from_dev_error)?;
    alloc_fd(chan)
}

pub fn sys_read(fd: i32, buf: &mut [u8]) -> Result<usize, VfsError> {
    let chan = fd_channel(fd).ok_or(VfsError::Ebadfd)?;
    chan.read(buf).map_err(|_| VfsError::Eio)
}

pub fn sys_write(fd: i32, buf: &[u8]) -> Result<usize, VfsError> {
    let chan = fd_channel(fd).ok_or(VfsError::Ebadfd)?;
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
    let mounts = MOUNTS.lock();
    mounts.find_exact(path).and_then(|mp| mp.root.as_ref().map(|c| c.dup()))
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

pub fn bind(source: Chan, target: Chan, _flags: u32) -> Result<(), VfsError> {
    let _ = source;
    let _ = target;
    Ok(())
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

//! In-memory root filesystem.
//!
//! Plan 9 boots from a root file server.  In this Rust prototype the root
//! is a RAM file system (`ramfs`) that is populated from a `cpio` archive
//! loaded by GRUB as a Multiboot2 module.  The device exposes the Plan 9
//! naming conventions (`/bin`, `/dev`, `/rc/bin`, `/usr`, ...), and can be
//! mounted as the root channel by `vfs::set_root_chan()`.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dev::{Chan, Dev, DirEntry, Error as DevError, devtype, qidtype};
use crate::plan9_common::sync::{Mutex, Spinlock};

/// One access-control entry attached to a file.
///
/// Plan 9 models ACLs as extra `DMACL` directory entries; this prototype
/// stores the same information inline: an explicit user id plus the
/// read/write/execute bits granted to it, which are OR-ed with the
/// traditional owner/group/other bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclEntry {
    /// User id the entry applies to.
    pub uid: u32,
    /// Granted permission bits (0o7).
    pub bits: u32,
}

/// One node in the RAM root tree.
#[derive(Clone, Debug)]
pub struct RamNode {
    /// Qid path (unique within the device).
    pub id: u64,
    /// File name (not the full path).
    pub name: String,
    /// Parent node id.
    pub parent: Option<u64>,
    /// Directory flag.
    pub is_dir: bool,
    /// Permission bits (Plan 9 style).
    pub perm: u32,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    pub atime: u32,
    pub mtime: u32,
    /// Explicit per-user access-control entries.
    pub acl: Vec<AclEntry>,
    /// File contents.
    pub data: Vec<u8>,
}

/// What a caller wants to do with a file, expressed as Plan 9 permission
/// bits (4 = read, 2 = write, 1 = execute/search).
pub mod want {
    /// Read a file or list a directory.
    pub const READ: u32 = 4;
    /// Write a file or create/remove entries in a directory.
    pub const WRITE: u32 = 2;
    /// Execute a file or search a directory while walking.
    pub const EXEC: u32 = 1;
}

/// Credentials of the caller, captured once per operation.
#[derive(Clone, Debug)]
struct Caller {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl Caller {
    fn current() -> Self {
        match crate::proc::curproc() {
            Some(p) => Self {
                uid: p.uid,
                gid: p.gid,
                groups: p.groups.clone(),
            },
            // Kernel-context callers (boot, mount) act as the host owner.
            None => Self { uid: 0, gid: 0, groups: Vec::new() },
        }
    }

    fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.iter().any(|g| *g == gid)
    }
}

/// Plan 9-style permission check.
///
/// The owner bits apply to the file owner, the group bits to the owner's
/// primary or supplementary groups, and the remaining bits to everyone
/// else.  Explicit ACL entries are consulted as well and can only widen
/// access.  uid 0 (the host owner) is never denied.
fn permitted(node: &RamNode, who: &Caller, bits: u32) -> bool {
    if who.uid == 0 {
        return true;
    }
    let perm = node.perm & 0o777;
    let mut granted = if node.uid == who.uid {
        (perm >> 6) & 0o7
    } else if who.in_group(node.gid) {
        (perm >> 3) & 0o7
    } else {
        perm & 0o7
    };
    for entry in &node.acl {
        if entry.uid == who.uid {
            granted |= entry.bits & 0o7;
        }
    }
    granted & bits == bits
}

pub struct RootFsDev {
    nodes: Spinlock<Vec<RamNode>>,
    next_id: Mutex<u64>,
}

impl RootFsDev {
    pub fn new() -> Self {
        let mut nodes = Vec::new();
        // Node 0 is `/`.
        nodes.push(RamNode {
            id: 0,
            name: "/".to_string(),
            parent: None,
            is_dir: true,
            perm: 0o755 | 0o40000,
            uid: 0,
            gid: 0,
            atime: 0,
            mtime: 0,
            acl: Vec::new(),
            data: Vec::new(),
        });

        let dev = Self {
            nodes: Spinlock::new(nodes),
            next_id: Mutex::new(1),
        };

        // Standard Plan 9 root directories.
        for path in [
            "bin", "boot", "cfg", "dev", "etc", "proc", "tmp", "usr", "home",
            "adm", "env", "fd", "mnt", "n", "net", "rc", "srv",
            "lib", "lib/modules", "usr/glenda", "usr/root",
        ] {
            dev.mkdir_path(path);
        }
        dev.mkdir_path("rc/bin");
        // Everyone can write to the temporary directory (Plan 9 sets the
        // same permissions on /tmp: sticky is not modelled).
        for path in ["tmp"] {
            if let Some(id) = dev.lookup_path(path) {
                let mut nodes = dev.nodes.lock();
                if let Some(n) = nodes.iter_mut().find(|n| n.id == id) {
                    n.perm = 0o777 | 0o40000;
                }
            }
        }
        dev
    }

    fn new_id(&self) -> u64 {
        let mut next = self.next_id.lock();
        let id = *next;
        *next += 1;
        id
    }

    /// Resolve an absolute or slash-separated path to a node id.
    pub fn lookup_path(&self, path: &str) -> Option<u64> {
        let mut parent = 0u64;
        for comp in path.split('/').filter(|s| !s.is_empty() && *s != ".") {
            if comp == ".." {
                parent = self.node(parent)?.parent.unwrap_or(0);
                continue;
            }
            parent = self.find_child(parent, comp)?.id;
        }
        Some(parent)
    }

    fn find_child(&self, parent: u64, name: &str) -> Option<RamNode> {
        let nodes = self.nodes.lock();
        nodes.iter()
            .find(|n| n.parent == Some(parent) && n.name == name)
            .cloned()
    }

    fn node(&self, id: u64) -> Option<RamNode> {
        let nodes = self.nodes.lock();
        nodes.iter().find(|n| n.id == id).cloned()
    }

    fn insert(&self, parent: u64, name: &str, is_dir: bool, perm: u32, data: Vec<u8>) -> u64 {
        let id = self.new_id();
        let owner = Caller::current();
        let mut nodes = self.nodes.lock();
        nodes.push(RamNode {
            id,
            name: name.to_string(),
            parent: Some(parent),
            is_dir,
            perm,
            uid: owner.uid,
            gid: owner.gid,
            atime: 0,
            mtime: 0,
            acl: Vec::new(),
            data,
        });
        id
    }

    /// Create every directory component of `path`.
    pub fn mkdir_path(&self, path: &str) -> u64 {
        self.mkdir_path_mode(path, 0o755)
    }

    /// `mkdir_path` with an explicit permission word for the final and any
    /// newly created intermediate directories.
    pub fn mkdir_path_mode(&self, path: &str, bits: u32) -> u64 {
        let bits = if bits & 0o777 == 0 { 0o755 } else { bits & 0o777 };
        let mut parent = 0u64;
        for comp in path.split('/').filter(|s| !s.is_empty()) {
            if let Some(node) = self.find_child(parent, comp) {
                if !node.is_dir {
                    // Replace a file with a directory.
                    let mut nodes = self.nodes.lock();
                    if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                        n.is_dir = true;
                        n.data.clear();
                        n.perm = bits | 0o40000;
                    }
                }
                parent = node.id;
            } else {
                parent = self.insert(parent, comp, true, bits | 0o40000, Vec::new());
            }
        }
        parent
    }

    /// Add a file at an absolute path, creating its parent directories.
    ///
    /// `perm` is the permission word from the archive (mode bits only are
    /// used); pass 0 to get the default 0o755.
    pub fn add_file(&self, path: &str, data: Vec<u8>) -> u64 {
        self.add_file_mode(path, data, 0o755)
    }

    /// `add_file` with an explicit permission word.
    pub fn add_file_mode(&self, path: &str, data: Vec<u8>, perm: u32) -> u64 {
        let bits = if perm & 0o777 == 0 { 0o755 } else { perm & 0o777 };
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return 0;
        }
        let mut parent = 0u64;
        for comp in &parts[..parts.len() - 1] {
            parent = self.mkdir_path_from(parent, comp);
        }
        let name = parts[parts.len() - 1];
        if let Some(node) = self.find_child(parent, name) {
            let mut nodes = self.nodes.lock();
            if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                n.is_dir = false;
                n.data = data;
                n.perm = bits | 0o100000;
            }
            node.id
        } else {
            self.insert(parent, name, false, bits | 0o100000, data)
        }
    }

    fn mkdir_path_from(&self, parent: u64, comp: &str) -> u64 {
        if let Some(node) = self.find_child(parent, comp) {
            if node.is_dir {
                return node.id;
            }
            let mut nodes = self.nodes.lock();
            if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                n.is_dir = true;
                n.data.clear();
                n.perm = 0o755 | 0o40000;
            }
            return node.id;
        }
        self.insert(parent, comp, true, 0o755 | 0o40000, Vec::new())
    }

    fn remove_recursive(&self, id: u64) -> bool {
        if id == 0 {
            return false;
        }
        let mut nodes = self.nodes.lock();
        // Collect the subtree rooted at `id`.  `work` is the traversal
        // queue; `to_remove` accumulates the ids that must be deleted
        // (the work queue itself is drained by the loop, so using it as
        // the result set would leave every node in place).
        let mut work = Vec::new();
        let mut to_remove = Vec::new();
        work.push(id);
        to_remove.push(id);
        while let Some(cur) = work.pop() {
            for n in nodes.iter() {
                if n.parent == Some(cur) {
                    work.push(n.id);
                    to_remove.push(n.id);
                }
            }
        }
        nodes.retain(|n| !to_remove.contains(&n.id));
        true
    }

    /// Owner (uid, gid) of a node.
    pub fn owner(&self, id: u64) -> Option<(u32, u32)> {
        self.node(id).map(|n| (n.uid, n.gid))
    }

    /// Permission bits of a node.
    pub fn node_perm(&self, id: u64) -> Option<u32> {
        self.node(id).map(|n| n.perm & 0o777)
    }

    /// Change the permission bits.  `bits` is masked to the low nine bits.
    pub fn set_perm(&self, id: u64, bits: u32) -> bool {
        let mut nodes = self.nodes.lock();
        match nodes.iter_mut().find(|n| n.id == id) {
            Some(n) => {
                n.perm = (n.perm & !0o777) | (bits & 0o777);
                true
            }
            None => false,
        }
    }

    /// Change ownership.
    pub fn set_owner(&self, id: u64, uid: u32, gid: u32) -> bool {
        let mut nodes = self.nodes.lock();
        match nodes.iter_mut().find(|n| n.id == id) {
            Some(n) => {
                n.uid = uid;
                n.gid = gid;
                true
            }
            None => false,
        }
    }

    /// Add, replace or (with `bits == 0`) remove an ACL entry.
    pub fn set_acl(&self, id: u64, uid: u32, bits: u32) -> bool {
        let mut nodes = self.nodes.lock();
        match nodes.iter_mut().find(|n| n.id == id) {
            Some(n) => {
                n.acl.retain(|e| e.uid != uid);
                if bits & 0o7 != 0 {
                    n.acl.push(AclEntry { uid, bits: bits & 0o7 });
                }
                true
            }
            None => false,
        }
    }

    /// Current ACL of a node.
    pub fn acl_entries(&self, id: u64) -> Vec<AclEntry> {
        self.node(id).map(|n| n.acl).unwrap_or_default()
    }

    fn dir_entry(&self, node: &RamNode) -> DirEntry {
        // Plan 9 marks directories with the CHDIR mode bit (0x40000000) so
        // `ls -l` can render the leading `d`.
        let mode = if node.is_dir { node.perm | 0x4000_0000 } else { node.perm };
        DirEntry {
            dev: devtype::ROOT,
            qid: crate::chan::Qid::new(node.id, 0, if node.is_dir {
                qidtype::DIR
            } else {
                qidtype::FILE
            }),
            mode,
            atime: node.atime,
            mtime: node.mtime,
            length: node.data.len() as u64,
            name: node.name.as_bytes().to_vec(),
            uid: node.uid,
            gid: node.gid,
        }
    }

    /// Populate the root from a newc cpio archive.
    pub fn import_cpio(&self, archive: &[u8]) -> usize {
        let entries = crate::cpio::parse_newc(archive);
        let mut count = 0usize;
        for entry in entries {
            if entry.name == "TRAILER!!!" {
                break;
            }
            // cpio paths are relative; normalise `./` and `/` prefixes.
            let path = entry.name
                .trim_start_matches('/')
                .trim_start_matches("./")
                .trim_start_matches('.');
            if path.is_empty() || path == "." {
                continue;
            }
            if entry.is_dir {
                self.mkdir_path_mode(path, entry.mode & 0o777);
            } else {
                // The archive is borrowed; own a single copy for the VFS.
                self.add_file_mode(path, entry.data.to_vec(), entry.mode & 0o777);
            }
            count += 1;
        }
        count
    }
}

impl Dev for RootFsDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            devtype::ROOT,
            crate::chan::Qid::new(0, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<crate::chan::Qid>, DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if !node.is_dir {
            return Err(DevError::Enotdir);
        }

        if name == ".." {
            let parent_id = node.parent.unwrap_or(0);
            ch.qid = crate::chan::Qid::new(parent_id, 0, qidtype::DIR);
            return Ok(Some(ch.qid));
        }

        // Walking through a directory requires search permission on it;
        // the final component only needs to be reachable, the operation
        // performed on it is checked when it is opened.
        let who = Caller::current();
        if !permitted(&node, &who, want::EXEC) {
            return Err(DevError::Eperm);
        }

        // A missing name is reported as "not found" rather than an error so
        // that `namec` can create the entry when the caller asked for it.
        let child = match self.find_child(node.id, name) {
            Some(c) => c,
            None => return Ok(None),
        };
        ch.qid = crate::chan::Qid::new(child.id, 0, if child.is_dir {
            qidtype::DIR
        } else {
            qidtype::FILE
        });
        Ok(Some(ch.qid))
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        let who = Caller::current();
        // Plan 9 omode: 0 = OREAD, 1 = OWRITE, 2 = ORDWR, 3 = OEXEC.
        let bits = match mode & 3 {
            0 => want::READ,
            1 => want::WRITE,
            2 => want::READ | want::WRITE,
            _ => want::EXEC,
        };
        // Directories may always be opened for reading (listing); the
        // listing itself is filtered by read permission on the directory.
        if node.is_dir && bits & want::WRITE == 0 {
            return Ok(());
        }
        if !permitted(&node, &who, bits) {
            return Err(DevError::Eperm);
        }
        Ok(())
    }

    fn create(&mut self, ch: &mut Chan, name: &str, _mode: u8, perm: u32) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if !node.is_dir {
            return Err(DevError::Enotdir);
        }
        // Creating an entry modifies the directory.
        let who = Caller::current();
        if !permitted(&node, &who, want::WRITE | want::EXEC) {
            return Err(DevError::Eperm);
        }
        if self.find_child(node.id, name).is_some() {
            return Err(DevError::Eexists);
        }
        // Plan 9 DMDIR (0x80000000) in the permission bits requests a
        // directory; strip it before storing the mode.
        let is_dir = perm & 0x8000_0000 != 0;
        let mode = (perm & 0x7FF) | 0o100000;
        let id = self.insert(node.id, name, is_dir, mode, Vec::new());
        ch.qid = crate::chan::Qid::new(id, 0, if is_dir { qidtype::DIR } else { qidtype::FILE });
        Ok(())
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        let who = Caller::current();
        if !permitted(&node, &who, want::READ) {
            return Err(DevError::Eperm);
        }

        // Plan 9 directories are readable as a stream of entries.  This
        // prototype renders the names as newline-separated text so that
        // `ls` and LIST can consume it directly.
        if node.is_dir {
            let nodes = self.nodes.lock();
            let mut names: Vec<String> = nodes
                .iter()
                .filter(|n| n.parent == Some(node.id))
                .map(|n| n.name.clone())
                .collect();
            drop(nodes);
            if let Some(path) = &ch.namespace_path {
                names.extend(crate::vfs::mount_children(path));
            }
            names.sort();
            names.dedup();
            let mut text = String::new();
            for name in names {
                text.push_str(&name);
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

        let start = offset as usize;
        if start >= node.data.len() {
            return Ok(0);
        }
        let end = core::cmp::min(start + buf.len(), node.data.len());
        let n = end - start;
        buf[..n].copy_from_slice(&node.data[start..end]);
        Ok(n)
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if node.is_dir {
            return Err(DevError::Eisdir);
        }
        let who = Caller::current();
        if !permitted(&node, &who, want::WRITE) {
            return Err(DevError::Eperm);
        }
        let mut nodes = self.nodes.lock();
        let n = nodes.iter_mut().find(|n| n.id == node.id).ok_or(DevError::Enoent)?;
        let start = offset as usize;
        if start > n.data.len() {
            n.data.resize(start, 0);
        }
        n.data.resize(start + buf.len(), 0);
        n.data[start..start + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        Ok(self.dir_entry(&node))
    }

    fn truncate(&mut self, ch: &mut Chan) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if node.is_dir {
            return Err(DevError::Eisdir);
        }
        let who = Caller::current();
        if !permitted(&node, &who, want::WRITE) {
            return Err(DevError::Eperm);
        }
        let mut nodes = self.nodes.lock();
        if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
            n.data.clear();
        }
        Ok(())
    }

    fn wstat(&mut self, ch: &mut Chan, dir: &DirEntry) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        let who = Caller::current();

        // Changing the mode or the file times requires ownership (or root);
        // Plan 9 additionally lets the directory owner *chmod* a file, but
        // ownership is enough for this prototype.
        let is_owner = who.uid == 0 || who.uid == node.uid;
        if !is_owner {
            return Err(DevError::Eperm);
        }
        // Only root may give a file away.
        if dir.uid != node.uid && who.uid != 0 {
            return Err(DevError::Eperm);
        }
        if dir.gid != node.gid && who.uid != 0 && !who.in_group(dir.gid) {
            return Err(DevError::Eperm);
        }

        let name = core::str::from_utf8(&dir.name).map_err(|_| DevError::Einval)?;
        let length = usize::try_from(dir.length).map_err(|_| DevError::Einval)?;
        if length != node.data.len() && (node.is_dir || !permitted(&node, &who, want::WRITE)) {
            return Err(DevError::Eperm);
        }
        if name != node.name {
            if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\n', '\0']) {
                return Err(DevError::Einval);
            }
            let parent = node.parent.and_then(|id| self.node(id)).ok_or(DevError::Eperm)?;
            if !permitted(&parent, &who, want::WRITE | want::EXEC) {
                return Err(DevError::Eperm);
            }
        }

        let mut nodes = self.nodes.lock();
        if name != node.name && nodes.iter().any(|other| other.parent == node.parent && other.name == name) {
            return Err(DevError::Eexists);
        }
        let n = nodes.iter_mut().find(|n| n.id == node.id).ok_or(DevError::Enoent)?;
        n.data.try_reserve(length.saturating_sub(n.data.len())).map_err(|_| DevError::Enomem)?;
        n.data.resize(length, 0);
        if name != node.name {
            n.name = name.to_string();
        }
        // The mode field carries the type bits when it comes from `stat`;
        // keep only the low nine permission bits.
        n.perm = (n.perm & !0o777) | (dir.mode & 0o777);
        n.uid = dir.uid;
        n.gid = dir.gid;
        n.atime = dir.atime;
        n.mtime = dir.mtime;
        Ok(())
    }

    fn remove(&mut self, ch: &mut Chan) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if node.is_dir {
            let has_children = self.nodes.lock().iter().any(|n| n.parent == Some(node.id));
            if has_children {
                return Err(DevError::Enotdir);
            }
        }
        // Removing an entry modifies the parent directory; do the check
        // against the parent so the usual write+search bits apply.
        let who = Caller::current();
        let parent = node.parent.and_then(|p| self.node(p));
        if let Some(parent) = parent {
            if !permitted(&parent, &who, want::WRITE | want::EXEC) {
                return Err(DevError::Eperm);
            }
        } else if !permitted(&node, &who, want::WRITE) {
            return Err(DevError::Eperm);
        }
        self.remove_recursive(node.id);
        Ok(())
    }

    fn dev_char(&self) -> char {
        '/'
    }

    fn name(&self) -> &'static str {
        "rootfs"
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn core::any::Any> {
        Some(self)
    }
}

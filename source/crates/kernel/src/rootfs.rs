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
    /// File contents.
    pub data: Vec<u8>,
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
            data: Vec::new(),
        });

        let mut dev = Self {
            nodes: Spinlock::new(nodes),
            next_id: Mutex::new(1),
        };

        // Standard Plan 9 root directories.
        for path in [
            "bin", "boot", "cfg", "dev", "proc", "tmp", "usr",
            "adm", "env", "fd", "mnt", "n", "net", "rc", "srv",
            "lib", "lib/modules", "usr/glenda",
        ] {
            dev.mkdir_path(path);
        }
        dev.mkdir_path("rc/bin");
        dev
    }

    fn new_id(&self) -> u64 {
        let mut next = self.next_id.lock();
        let id = *next;
        *next += 1;
        id
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
        let mut nodes = self.nodes.lock();
        nodes.push(RamNode {
            id,
            name: name.to_string(),
            parent: Some(parent),
            is_dir,
            perm,
            data,
        });
        id
    }

    /// Create every directory component of `path`.
    pub fn mkdir_path(&self, path: &str) -> u64 {
        let mut parent = 0u64;
        for comp in path.split('/').filter(|s| !s.is_empty()) {
            if let Some(node) = self.find_child(parent, comp) {
                if !node.is_dir {
                    // Replace a file with a directory.
                    let mut nodes = self.nodes.lock();
                    if let Some(n) = nodes.iter_mut().find(|n| n.id == node.id) {
                        n.is_dir = true;
                        n.data.clear();
                        n.perm = 0o755 | 0o40000;
                    }
                }
                parent = node.id;
            } else {
                parent = self.insert(parent, comp, true, 0o755 | 0o40000, Vec::new());
            }
        }
        parent
    }

    /// Add a file at an absolute path, creating its parent directories.
    pub fn add_file(&self, path: &str, data: Vec<u8>) -> u64 {
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
                n.perm = 0o755 | 0o100000;
            }
            node.id
        } else {
            self.insert(parent, name, false, 0o755 | 0o100000, data)
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
        let mut stack = Vec::new();
        stack.push(id);
        while let Some(cur) = stack.pop() {
            for n in nodes.iter() {
                if n.parent == Some(cur) {
                    stack.push(n.id);
                }
            }
        }
        nodes.retain(|n| !stack.contains(&n.id));
        true
    }

    fn dir_entry(&self, node: &RamNode) -> DirEntry {
        DirEntry {
            dev: devtype::ROOT,
            qid: crate::chan::Qid::new(node.id, 0, if node.is_dir {
                qidtype::DIR
            } else {
                qidtype::FILE
            }),
            mode: node.perm,
            atime: 0,
            mtime: 0,
            length: node.data.len() as u64,
            name: node.name.as_bytes().to_vec(),
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
                self.mkdir_path(path);
            } else {
                self.add_file(path, entry.data);
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

        let child = self.find_child(node.id, name).ok_or(DevError::Enoent)?;
        ch.qid = crate::chan::Qid::new(child.id, 0, if child.is_dir {
            qidtype::DIR
        } else {
            qidtype::FILE
        });
        Ok(Some(ch.qid))
    }

    fn open(&mut self, ch: &mut Chan, _mode: u8) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if node.is_dir {
            Ok(())
        } else {
            Ok(())
        }
    }

    fn create(&mut self, ch: &mut Chan, name: &str, _mode: u8, perm: u32) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if !node.is_dir {
            return Err(DevError::Enotdir);
        }
        if self.find_child(node.id, name).is_some() {
            return Err(DevError::Eexists);
        }
        let id = self.insert(node.id, name, false, perm | 0o100000, Vec::new());
        ch.qid = crate::chan::Qid::new(id, 0, qidtype::FILE);
        Ok(())
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;

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
            names.sort();
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

    fn remove(&mut self, ch: &mut Chan) -> Result<(), DevError> {
        let node = self.node(ch.qid.path).ok_or(DevError::Enoent)?;
        if node.is_dir {
            let has_children = self.nodes.lock().iter().any(|n| n.parent == Some(node.id));
            if has_children {
                return Err(DevError::Enotdir);
            }
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
}

//! File/Tree Data Structures for 9P
//!
//! Implements the file tree abstraction for 9P file servers.
//! Based on Plan 9's lib9p/file.c.
//!
//! Key structures:
//! - Tree: Root of a file system tree
//! - File: Individual file/directory node
//! - Filelist: Linked list of file children


extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// QID type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qid {
    /// QID path (unique file ID)
    pub path: u64,
    /// QID version
    pub version: u32,
    /// QID type
    pub qtype: u8,
}

impl Qid {
    /// Create a new QID
    pub fn new(path: u64, version: u32, qtype: u8) -> Self {
        Self { path, version, qtype }
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        (self.qtype & 0x80) != 0
    }
}

/// QID type constants
pub mod qidtype {
    /// Directory
    pub const DIR: u8 = 0x80;
    /// Append-only
    pub const APPEND: u8 = 0x40;
    /// Exclusive access
    pub const EXCL: u8 = 0x20;
    /// Mounted channel
    pub const MOUNT: u8 = 0x10;
    /// Auth file
    pub const AUTH: u8 = 0x08;
    /// Truncated file
    pub const TRUNCATE: u8 = 0x04;
    /// Read-only
    pub const RDONLY: u8 = 0x02;
    /// Pipe/socket
    pub const PIPE: u8 = 0x01;
}

/// File mode permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode(pub u32);

impl FileMode {
    /// Directory bit
    pub const DIR: u32 = 0x80000000;
    /// Append bit
    pub const APPEND: u32 = 0x40000000;
    /// Exclusive bit
    pub const EXCL: u32 = 0x20000000;
    /// Mount bit
    pub const MOUNT: u32 = 0x10000000;
    /// Auth bit
    pub const AUTH: u32 = 0x08000000;
    /// Truncate bit
    pub const TRUNCATE: u32 = 0x04000000;
    /// Read-only bit
    pub const RDONLY: u32 = 0x02000000;
    /// Device bit
    pub const DEVICE: u32 = 0x02000000;

    /// Permission bits mask
    pub const PERM_MASK: u32 = 0xFFFF;
}

/// File metadata (Dir structure in Plan 9)
#[derive(Debug, Clone)]
pub struct Dir {
    /// File name
    pub name: String,
    /// User ID
    pub uid: String,
    /// Group ID
    pub gid: String,
    /// Last modifier ID
    pub muid: String,
    /// Mode/permissions
    pub mode: FileMode,
    /// Access time
    pub atime: u32,
    /// Modification time
    pub mtime: u32,
    /// File length (bytes)
    pub length: u64,
    /// QID
    pub qid: Qid,
}

impl Dir {
    /// Create a new directory entry
    pub fn new(name: String, uid: String, gid: String, mode: u32, qid: Qid) -> Self {
        let now = current_time();
        Self {
            name,
            uid: uid.clone(),
            gid,
            muid: uid,
            mode: FileMode(mode),
            atime: now,
            mtime: now,
            length: 0,
            qid,
        }
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        (self.mode.0 & FileMode::DIR) != 0
    }
}

/// Get current time (seconds since epoch)
pub fn current_time() -> u32 {
    CURRENT_TIME.load(Ordering::Relaxed)
}

/// Internal monotonic counter used by `current_time()`.
static CURRENT_TIME: AtomicU32 = AtomicU32::new(0);

/// Advance the in-process time counter by one second.
pub fn tick_seconds() {
    CURRENT_TIME.fetch_add(1, Ordering::Relaxed);
}

/// Set the in-process time counter to a specific value.
pub fn set_current_time(secs: u32) {
    CURRENT_TIME.store(secs, Ordering::Relaxed);
}

/// File tree node
pub struct File {
    /// Reference count
    refcount: AtomicU32,
    /// File metadata
    pub dir: Dir,
    /// Parent directory (interior mutability)
    parent: RefCell<Option<Arc<File>>>,
    /// Children (name -> File)
    children: RefCell<Vec<(String, Arc<File>)>>,
    /// File tree reference
    tree: RefCell<Option<Arc<Tree>>>,
    /// Auxiliary data (for server-specific data)
    pub aux: RefCell<Option<Box<dyn core::any::Any>>>,
    /// User data pointer
    udata: RefCell<usize>,
    /// Number of child references (including deleted)
    nxchild: AtomicU32,
    /// Number of active children
    nchild: AtomicU32,
}

impl File {
    /// Create a new file
    pub fn new(name: String, uid: String, gid: String, perm: u32, qid: Qid) -> Arc<Self> {
        Arc::new(Self {
            refcount: AtomicU32::new(0),
            dir: Dir::new(name, uid, gid, perm, qid),
            parent: RefCell::new(None),
            children: RefCell::new(Vec::new()),
            tree: RefCell::new(None),
            aux: RefCell::new(None),
            udata: RefCell::new(0),
            nxchild: AtomicU32::new(0),
            nchild: AtomicU32::new(0),
        })
    }

    /// Create a directory file
    pub fn new_dir(name: String, uid: String, gid: String, perm: u32) -> Arc<Self> {
        let qid = Qid::new(0, 0, qidtype::DIR);
        Arc::new(Self {
            refcount: AtomicU32::new(0),
            dir: Dir::new(name, uid, gid, perm | FileMode::DIR, qid),
            parent: RefCell::new(None),
            children: RefCell::new(Vec::new()),
            tree: RefCell::new(None),
            aux: RefCell::new(None),
            udata: RefCell::new(0),
            nxchild: AtomicU32::new(0),
            nchild: AtomicU32::new(0),
        })
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn decref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Relaxed)
    }

    /// Get reference count
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Relaxed)
    }

    /// Get file name
    pub fn name(&self) -> String {
        self.dir.name.clone()
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.dir.is_dir()
    }

    /// Get parent
    pub fn parent(&self) -> Option<Arc<File>> {
        self.parent.borrow().clone()
    }

    /// Set parent
    pub fn set_parent(&self, parent: Arc<File>) {
        *self.parent.borrow_mut() = Some(parent);
    }

    /// Add a child file
    pub fn add_child(&self, name: String, child: Arc<File>) {
        // Child's qid.path should be set when creating the child
        self.children.borrow_mut().push((name, child));
        self.nchild.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove a child by name
    pub fn remove_child(&self, name: &str) -> Option<Arc<File>> {
        let mut children = self.children.borrow_mut();
        if let Some(pos) = children.iter().position(|(n, _)| n == name) {
            let (_, removed) = children.remove(pos);
            self.nchild.fetch_sub(1, Ordering::Relaxed);
            self.nxchild.fetch_add(1, Ordering::Relaxed);
            Some(removed)
        } else {
            None
        }
    }

    /// Find a child by name
    pub fn child(&self, name: &str) -> Option<Arc<File>> {
        self.children.borrow()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, f)| Arc::clone(f))
    }

    /// Get all children names
    pub fn child_names(&self) -> Vec<String> {
        self.children.borrow()
            .iter()
            .filter(|(_, f)| f.refcount() > 0)
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Get number of children
    pub fn num_children(&self) -> u32 {
        self.nchild.load(Ordering::Relaxed)
    }

    /// Walk to a path from this file (deprecated - use File::walk_from instead)
    #[deprecated(since = "0.1.0", note = "use Tree::walk or File::walk_from directly")]
    pub fn walk(&self, _names: &[&str]) -> Option<Arc<File>> {
        None
    }

    /// Walk to a path starting from a given file
    pub fn walk_from(start: &Arc<File>, names: &[&str]) -> Option<Arc<File>> {
        let mut current: Arc<File> = Arc::clone(start);

        for name in names {
            current = if *name == ".." {
                match current.parent() {
                    Some(parent) => parent,
                    None => return None,
                }
            } else {
                match current.child(name) {
                    Some(child) => child,
                    None => return None,
                }
            };
        }

        Some(current)
    }

    /// Walk to a path starting from this file (helper for callers)
    pub fn walk_from_self(&self, _names: &[&str]) -> Option<Arc<File>> {
        // Cannot create Arc<File> from &self, but can start from root and walk
        None
    }

    /// Get user data pointer
    pub fn udata(&self) -> usize {
        *self.udata.borrow()
    }

    /// Set user data pointer
    pub fn set_udata(&self, data: usize) {
        *self.udata.borrow_mut() = data;
    }
}

/// File system tree
pub struct Tree {
    /// Root directory
    root: Arc<File>,
    /// Reference count
    refcount: AtomicU32,
    /// QID path generator
    qidgen: AtomicU64,
    /// QID version generator (for directories)
    dirqidgen: AtomicU64,
}

impl Tree {
    /// Create a new file system tree
    pub fn new(uid: &str, gid: &str, mode: u32, _destroy: Option<fn(&File)>) -> Arc<Self> {
        let root = File::new_dir("/".to_string(), uid.to_string(), gid.to_string(), mode);

        let tree = Arc::new(Self {
            root: Arc::clone(&root),
            refcount: AtomicU32::new(1),
            qidgen: AtomicU64::new(0),
            dirqidgen: AtomicU64::new(1),
        });

        // Set tree reference in root
        *root.tree.borrow_mut() = Some(Arc::clone(&tree));

        tree
    }

    /// Create a new tree with default settings
    pub fn new_default() -> Arc<Self> {
        Self::new("none", "none", 0o755, None)
    }

    /// Increment reference count
    pub fn incref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn decref(&self) -> u32 {
        self.refcount.fetch_sub(1, Ordering::Relaxed)
    }

    /// Get next unique QID path
    pub fn next_qid(&self) -> u64 {
        self.qidgen.fetch_add(1, Ordering::Relaxed)
    }

    /// Get next directory QID version
    pub fn next_dirqid(&self) -> u64 {
        self.dirqidgen.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a file in the tree
    pub fn create(&self, parent: &Arc<File>, name: &str, uid: &str, perm: u32) -> Result<Arc<File>, TreeError> {
        if !parent.is_dir() {
            return Err(TreeError::NotADirectory);
        }

        // Check if file already exists
        if parent.child(name).is_some() {
            return Err(TreeError::FileExists);
        }

        let qtype = if (perm & FileMode::DIR) != 0 { qidtype::DIR } else { 0 };
        let qid = Qid::new(self.next_qid(), 0, qtype);

        let file = File::new(
            name.to_string(),
            uid.to_string(),
            parent.dir.gid.clone(),
            perm,
            qid,
        );

        parent.add_child(name.to_string(), Arc::clone(&file));
        file.incref(); // Return reference
        file.incref(); // Tree reference

        Ok(file)
    }

    /// Remove a file from the tree
    pub fn remove(&self, file: &Arc<File>) -> Result<(), TreeError> {
        let parent = file.parent().ok_or(TreeError::NoParent)?;

        if parent.num_children() == 0 && !file.is_dir() {
            return Err(TreeError::HasChildren);
        }

        parent.remove_child(file.name().as_str());
        Ok(())
    }

    /// Walk a path from root
    pub fn walk(&self, path: &str) -> Option<Arc<File>> {
        if path == "/" || path.is_empty() {
            return Some(Arc::clone(&self.root));
        }

        let names: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        File::walk_from(&self.root, &names)
    }

    /// Get root file
    pub fn root(&self) -> Arc<File> {
        Arc::clone(&self.root)
    }
}

/// Tree operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// File not found
    NotFound,
    /// Not a directory
    NotADirectory,
    /// File already exists
    FileExists,
    /// Has children
    HasChildren,
    /// No parent
    NoParent,
    /// Permission denied
    PermissionDenied,
    /// Invalid name
    InvalidName,
}

impl core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TreeError::NotFound => write!(f, "file not found"),
            TreeError::NotADirectory => write!(f, "not a directory"),
            TreeError::FileExists => write!(f, "file already exists"),
            TreeError::HasChildren => write!(f, "directory has children"),
            TreeError::NoParent => write!(f, "no parent directory"),
            TreeError::PermissionDenied => write!(f, "permission denied"),
            TreeError::InvalidName => write!(f, "invalid file name"),
        }
    }
}

//! `/dev` namespace — exposes the framebuffer and input devices as
//! files that user-space 9P servers (typically `rio`, the window
//! system) can mount and serve to applications.
//!
//! Plan 9's `/dev` hierarchy looks like:
//!   /dev/draw/N  - framebuffer N
//!   /dev/mouse    - mouse events
//!   /dev/kbd      - keyboard events
//!   /dev/audio    - sound device
//!   /dev/cons     - console (text)
//!   /dev/net      - networking
//!
//! Each entry below is a *file description*: the kernel side creates
//! a file in `/dev` and registers an operations table. A 9P mount
//! server (typically running on the CPU) reads from these files and
//! re-exports them over the network to user processes.
//!
//! # Concurrency
//! All entries are protected by spinlocks; the `/dev` namespace
//! itself is a `Spinlock<DevTable>`.

use alloc::string::String;
use alloc::vec::Vec;
use plan9_common::sync::Spinlock;

/// File-type for entries in `/dev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevKind {
    /// A regular file backed by an operations table (e.g. draw).
    Regular,
    /// A character device (mouse, kbd, audio, cons).
    Character,
    /// A directory (`/dev`, `/dev/draw`).
    Directory,
}

/// Operations invoked by the 9P server when a client opens a file
/// in `/dev`. The kernel side supplies an implementation; the 9P
/// server is just a thin shim that calls into these.
pub trait DevFile: Send + Sync {
    /// Read up to `buf.len()` bytes into `buf`. Returns the number
    /// of bytes actually read, or an error code.
    fn read(&self, buf: &mut [u8]) -> usize;
    /// Write `buf.len()` bytes from `buf`. Returns the number of
    /// bytes written.
    fn write(&self, buf: &[u8]) -> usize;
    /// Optional: poll for readiness. Default impl returns 0.
    fn poll(&self) -> usize { 0 }
}

/// Static entry registered in `/dev`.
#[derive(Clone)]
pub struct DevEntry {
    /// Path relative to `/dev`, e.g. `"draw/0"` or `"mouse"`.
    pub path: String,
    /// Kind of entry.
    pub kind: DevKind,
    /// Operations table. None for pure directory entries.
    pub ops: Option<alloc::sync::Arc<dyn DevFile>>,
}

struct DevTable {
    entries: Vec<DevEntry>,
}

static DEV_TABLE: Spinlock<DevTable> = Spinlock::new(DevTable { entries: Vec::new() });

/// Register a new entry in `/dev`. Returns `false` if `path` is
/// already taken.
pub fn register(entry: DevEntry) -> bool {
    let mut g = DEV_TABLE.lock();
    if g.entries.iter().any(|e| e.path == entry.path) {
        return false;
    }
    g.entries.push(entry);
    true
}

/// Look up an entry by exact path match.
pub fn lookup(path: &str) -> Option<DevEntry> {
    DEV_TABLE.lock().entries.iter().find(|e| e.path == path).cloned()
}

/// Enumerate all entries starting with `prefix`. Used by 9P mount
/// servers when walking a directory.
pub fn list_dir(prefix: &str) -> Vec<DevEntry> {
    let needle = if prefix.is_empty() || prefix == "/" {
        String::new()
    } else {
        let mut s = String::from(prefix);
        if !s.ends_with('/') {
            s.push('/');
        }
        s
    };
    let mut out = Vec::new();
    for e in DEV_TABLE.lock().entries.iter() {
        if needle.is_empty() {
            // Top-level: anything not containing a '/'.
            if !e.path.contains('/') {
                out.push(e.clone());
            }
        } else if let Some(rest) = e.path.strip_prefix(&needle) {
            if !rest.contains('/') {
                out.push(e.clone());
            }
        }
    }
    out
}

/// Number of registered entries. Useful as a smoke test.
pub fn count() -> usize {
    DEV_TABLE.lock().entries.len()
}

/// Reset the table. Tests only.
pub fn clear() {
    DEV_TABLE.lock().entries.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    struct DummyFile;
    impl DevFile for DummyFile {
        fn read(&self, _buf: &mut [u8]) -> usize { 0 }
        fn write(&self, _buf: &[u8]) -> usize { 0 }
    }

    #[test]
    fn register_and_lookup() {
        clear();
        assert!(register(DevEntry {
            path: String::from("draw/0"),
            kind: DevKind::Character,
            ops: Some(Arc::new(DummyFile)),
        }));
        assert!(register(DevEntry {
            path: String::from("mouse"),
            kind: DevKind::Character,
            ops: Some(Arc::new(DummyFile)),
        }));
        assert!(!register(DevEntry {
            path: String::from("mouse"),
            kind: DevKind::Character,
            ops: Some(Arc::new(DummyFile)),
        }));

        let d = lookup("draw/0").expect("draw/0");
        assert_eq!(d.kind, DevKind::Character);

        let top = list_dir("");
        assert!(top.iter().any(|e| e.path == "mouse"));
        let draw = list_dir("draw");
        assert!(draw.iter().any(|e| e.path == "draw/0"));
    }
}
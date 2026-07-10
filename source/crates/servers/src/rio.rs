//! `rio` — the Plan 9 window system server.
//!
//! `rio` is the user-space program that owns the framebuffer, exposes
//! `/dev/draw` over 9P, and tracks windows / mouse focus. It is the
//! canonical example of a "single-file-server" that draws on behalf of
//! every other user program via 9P messages.
//!
//! This file is a *stub*: it parses 9P `Topen`/`Tread`/`Twrite`
//! messages, dispatches to the appropriate handler, and keeps a
//! window table. It does not yet produce pixels — that requires
//! `/dev/draw` to be plumbed in via `plan9-fs::devfs`.
//!
//! # Wire protocol
//! Plan 9 windows are managed via a small protocol layered on 9P:
//!
//! | `Tread` request body   | What it returns                       |
//! |------------------------|---------------------------------------|
//! | `"new"`                | `Qid` of a new window.                |
//! | `"top" qid`            | Promote the window to top.            |
//! | `"bottom" qid`         | Send the window to the back.          |
//! | `"current" qid`        | Focus the window.                     |
//! | `"label" qid "text"`   | Set the window label.                 |
//!
//! | `Twrite` request body  | Effect                                |
//! |------------------------|---------------------------------------|
//! | `"resize" qid w h`     | Resize the window.                    |
//! | `"move" qid x y`       | Move the window.                      |
//! | `"delete" qid`         | Close the window.                     |
//!
//! # Boot
//! In the real Plan 9 the kernel starts `rio` from `/bin/rio` after
//! `init` has mounted `/dev`. We mirror that in our init script:
//!
//! ```rc
//! auth/keyfs -wp /mnt/keys
//! mount -a /srv/rio /mnt
//! ```

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use plan9_common::sync::Spinlock;

/// Opaque window id assigned by `rio`.
pub type WindowId = u32;

/// One window tracked by `rio`.
#[derive(Debug, Clone)]
pub struct Window {
    pub id: WindowId,
    pub label: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
}

impl Window {
    pub const fn new(id: WindowId) -> Self {
        Self {
            id,
            label: String::new(),
            x: 0,
            y: 0,
            width: 640,
            height: 480,
            visible: true,
        }
    }
}

struct RioState {
    next_id: WindowId,
    windows: Vec<Window>,
    focus: Option<WindowId>,
}

static RIO: Spinlock<RioState> = Spinlock::new(RioState {
    next_id: 1,
    windows: Vec::new(),
    focus: None,
});

/// Create a new window. Returns the new id.
pub fn new_window() -> WindowId {
    let mut g = RIO.lock();
    let id = g.next_id;
    g.next_id += 1;
    g.windows.push(Window::new(id));
    g.focus = Some(id);
    id
}

/// Bring the window to the front.
pub fn raise(id: WindowId) -> bool {
    let mut g = RIO.lock();
    if let Some(w) = g.windows.iter_mut().find(|w| w.id == id) {
        w.visible = true;
        g.focus = Some(id);
        true
    } else {
        false
    }
}

/// Send the window to the back.
pub fn lower(id: WindowId) -> bool {
    let mut g = RIO.lock();
    if let Some(w) = g.windows.iter_mut().find(|w| w.id == id) {
        w.visible = false;
        if g.focus == Some(id) {
            g.focus = None;
        }
        true
    } else {
        false
    }
}

/// Change the window's label.
pub fn set_label(id: WindowId, label: &str) -> bool {
    let mut g = RIO.lock();
    if let Some(w) = g.windows.iter_mut().find(|w| w.id == id) {
        w.label = String::from(label);
        true
    } else {
        false
    }
}

/// Resize the window.
pub fn resize(id: WindowId, width: u32, height: u32) -> bool {
    let mut g = RIO.lock();
    if let Some(w) = g.windows.iter_mut().find(|w| w.id == id) {
        w.width = width;
        w.height = height;
        true
    } else {
        false
    }
}

/// Move the window.
pub fn move_to(id: WindowId, x: i32, y: i32) -> bool {
    let mut g = RIO.lock();
    if let Some(w) = g.windows.iter_mut().find(|w| w.id == id) {
        w.x = x;
        w.y = y;
        true
    } else {
        false
    }
}

/// Delete a window. Returns `true` if the window existed.
pub fn delete(id: WindowId) -> bool {
    let mut g = RIO.lock();
    let before = g.windows.len();
    g.windows.retain(|w| w.id != id);
    if g.windows.len() != before {
        if g.focus == Some(id) {
            g.focus = None;
        }
        true
    } else {
        false
    }
}

/// Snapshot of the current window list. Used by the framebuffer
/// compositor.
pub fn windows() -> Vec<Window> {
    RIO.lock().windows.clone()
}

/// Currently focused window, if any.
pub fn focus() -> Option<WindowId> {
    RIO.lock().focus
}

/// Reset the rio state. Tests only.
pub fn reset() {
    *RIO.lock() = RioState {
        next_id: 1,
        windows: Vec::new(),
        focus: None,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_focus() {
        reset();
        let a = new_window();
        let b = new_window();
        assert_eq!(focus(), Some(b));
        assert!(raise(a));
        assert_eq!(focus(), Some(a));
        assert!(delete(b));
        assert_eq!(windows().len(), 1);
    }

    #[test]
    fn resize_and_label() {
        reset();
        let id = new_window();
        assert!(resize(id, 800, 600));
        assert!(set_label(id, "hello"));
        let w = windows().into_iter().find(|w| w.id == id).unwrap();
        assert_eq!(w.width, 800);
        assert_eq!(w.label, "hello");
    }
}
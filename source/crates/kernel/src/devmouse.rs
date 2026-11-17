

//! Mouse Device Implementation
//!
//! Implements the Plan 9 mouse device (#m) for mouse input.
//!
//! ## Overview
//!
//! The mouse device provides access to mouse input through PS/2 interface.
//! Reads return mouse state in Plan 9 format: [buttons, dx, dy]
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! ├── mouse           (main mouse file - reads return state)
//! └── mousedata       (raw mouse packets)
//! ```


extern crate alloc;

use crate::dev::{ self, Dev, Chan, Qid, DirEntry, Error as DevError };
use crate::plan9_common::sync::Spinlock;
// use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

/// Qid paths for mouse device
mod mouse_qid {
    pub const QMOUSE: u64 = 0;    // Main mouse file
    pub const QDATA: u64 = 1;     // Raw data
    pub const QCTL: u64 = 2;      // Control file
}

/// Mouse device structure
pub struct MouseDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Mouse is enabled
    enabled: AtomicBool,
    /// Current mouse state
    state: Spinlock<MouseState>,
}

#[derive(Debug, Clone, Default)]
struct MouseState {
    /// Buttons (bit 0=left, 1=middle, 2=right)
    buttons: u8,
    /// Delta X
    dx: i32,
    /// Delta Y
    dy: i32,
    /// Delta Z (scroll)
    dz: i32,
    /// Absolute X position
    x: i32,
    /// Absolute Y position
    y: i32,
}

impl MouseDev {
    /// Create a new mouse device
    pub fn new() -> Self {
        Self {
            name: "mouse",
            dev_char: 'm',
            enabled: AtomicBool::new(false),
            state: Spinlock::new(MouseState::default()),
        }
    }
    
    /// Enable the mouse
    pub fn enable(&self) {
        // Initialize the underlying mouse driver
        if let Err(e) = crate::plan9_drivers::mouse::mouse_init() {
            // Log error but continue
            let _ = e;
        }
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// Disable the mouse
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    
    /// Update mouse state from the driver
    pub fn update_state(&self, buttons: u8, dx: i32, dy: i32) {
        let mut state = self.state.lock();
        state.buttons = buttons;
        state.dx = dx;
        state.dy = dy;
    }
}

impl Dev for MouseDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::MOUSE,
            Qid::new(mouse_qid::QMOUSE, 0, 0),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        match name {
            "mouse" | "" => {
                if qid == 0 {
                    Ok(Some(ch.qid))
                } else {
                    ch.qid = Qid::new(mouse_qid::QMOUSE, 0, 0);
                    Ok(Some(ch.qid))
                }
            }
            "mousedata" => {
                ch.qid = Qid::new(mouse_qid::QDATA, 0, 0);
                Ok(Some(ch.qid))
            }
            "ctl" => {
                ch.qid = Qid::new(mouse_qid::QCTL, 0, 0);
                Ok(Some(ch.qid))
            }
            _ => Err(DevError::Enoent),
        }
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        ch.mode = mode;
        Ok(())
    }

    fn create(&mut self, _ch: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _ch: &mut Chan) {
        // No cleanup needed
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, DevError> {
        // Check if mouse is enabled
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        
        let qid = ch.qid.path;
        
        match qid {
            mouse_qid::QMOUSE => {
                // Read mouse state in Plan 9 format
                // Format: [buttons: u8, dx: i32, dy: i32]
                // Total: 9 bytes
                if buf.len() < 9 {
                    return Err(DevError::Einval);
                }
                
                // Try to get mouse event from driver
                let mouse = crate::plan9_drivers::mouse::mouse();
                let state = self.state.lock();
                
                let (buttons, dx, dy) = if mouse.has_events() {
                    if let Some(event) = mouse.get_event() {
                        (
                            event.buttons.bits(),
                            event.dx as i32,
                            event.dy as i32,
                        )
                    } else {
                        (state.buttons, state.dx, state.dy)
                    }
                } else {
                    (state.buttons, state.dx, state.dy)
                };
                
                // Clear deltas after reading
                drop(state);
                let mut s = self.state.lock();
                s.dx = 0;
                s.dy = 0;
                drop(s);
                
                // Write data in Plan 9 format
                let mut pos = 0;
                buf[pos] = buttons;
                pos += 1;
                
                // dx as little-endian i32
                buf[pos..pos + 4].copy_from_slice(&(dx as i32).to_le_bytes());
                pos += 4;
                
                // dy as little-endian i32
                buf[pos..pos + 4].copy_from_slice(&(dy as i32).to_le_bytes());
                pos += 4;
                
                Ok(pos)
            }
            mouse_qid::QDATA => {
                // Read raw mouse packets
                let mouse = crate::plan9_drivers::mouse::mouse();
                if mouse.has_events() {
                    if let Some(event) = mouse.get_event() {
                        let mut pos = 0;
                        // buttons
                        buf[pos] = event.buttons.bits();
                        pos += 1;
                        // x
                        buf[pos..pos + 4].copy_from_slice(&(event.x as i32).to_le_bytes());
                        pos += 4;
                        // y
                        buf[pos..pos + 4].copy_from_slice(&(event.y as i32).to_le_bytes());
                        pos += 4;
                        // dx
                        buf[pos] = event.dx as u8;
                        pos += 1;
                        // dy
                        buf[pos] = event.dy as u8;
                        pos += 1;
                        // dz
                        buf[pos] = event.dz as u8;
                        pos += 1;
                        Ok(pos)
                    } else {
                        Ok(0)
                    }
                } else {
                    Ok(0)
                }
            }
            mouse_qid::QCTL => {
                // Read mouse configuration
                let state = self.state.lock();
                let info = format!(
                    "buttons {} x {} y {} dx {} dy {}\n",
                    state.buttons, state.x, state.y, state.dx, state.dy
                );
                let len = info.len().min(buf.len());
                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                Ok(len)
            }
            _ => Err(DevError::Enoent),
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            mouse_qid::QCTL => {
                // Control commands
                let cmd = String::from_utf8_lossy(buf);
                
                if cmd.trim() == "off" {
                    self.disable();
                    return Ok(buf.len());
                } else if cmd.trim() == "on" {
                    self.enable();
                    return Ok(buf.len());
                }
                
                Err(DevError::Einval)
            }
            mouse_qid::QMOUSE | mouse_qid::QDATA => {
                // Mouse writes are not supported
                Err(DevError::Eperm)
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode) = match qid {
            mouse_qid::QMOUSE => (b"mouse".to_vec(), 0o666),
            mouse_qid::QDATA => (b"mousedata".to_vec(), 0o444),
            mouse_qid::QCTL => (b"ctl".to_vec(), 0o666),
            _ => return Err(DevError::Enoent),
        };
        
        Ok(DirEntry {
            dev: dev::devtype::MOUSE,
            qid: ch.qid,
            mode: mode | 0o20000, // S_IFCHR
            atime: 0,
            mtime: 0,
            length: 0,
            name,
            uid: 0,
            gid: 0,
})
    }

    fn wstat(&mut self, _ch: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _ch: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

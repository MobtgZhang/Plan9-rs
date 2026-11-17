

//! Keyboard Device Implementation
//!
//! Implements the Plan 9 keyboard device (#k) for keyboard input.
//!
//! ## Overview
//!
//! The keyboard device provides access to keyboard input.
//! Reads return key codes in Plan 9 format (Rune + modifiers).
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! └── kbd              (keyboard input - reads return key codes)
//! ```


extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError};

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

/// Qid paths for keyboard device
mod kb_qid {
    pub const QKBD: u64 = 0;    // Main keyboard file
    pub const QCTL: u64 = 1;     // Control file
}

/// Keyboard device structure
pub struct KbdDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Keyboard is enabled
    enabled: AtomicBool,
    /// Current key buffer
    key_buffer: Spinlock<Vec<u16>>,
}

impl KbdDev {
    /// Create a new keyboard device
    pub fn new() -> Self {
        Self {
            name: "keyboard",
            dev_char: 'k',
            enabled: AtomicBool::new(false),
            key_buffer: Spinlock::new(Vec::new()),
        }
    }
    
    /// Enable the keyboard
    pub fn enable(&self) {
        // Initialize the underlying keyboard driver
        if let Err(e) = crate::plan9_drivers::keyboard::kbd_init() {
            // Log error but continue
            let _ = e;
        }
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// Disable the keyboard
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    
    /// Add a key to the buffer
    pub fn put_key(&self, key: u16) {
        let mut buffer = self.key_buffer.lock();
        if buffer.len() < 256 {
            buffer.push(key);
        }
    }
    
    /// Get a key from the buffer
    pub fn get_key(&self) -> Option<u16> {
        let mut buffer = self.key_buffer.lock();
        if buffer.is_empty() {
            // Try to get from driver
            let kbd = crate::plan9_drivers::keyboard::keyboard();
            if kbd.has_input() {
                if let Some(key) = kbd.get_key() {
                    return Some(key);
                }
            }
            None
        } else {
            Some(buffer.remove(0))
        }
    }
}

impl Dev for KbdDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::KB,
            Qid::new(kb_qid::QKBD, 0, 0),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        match name {
            "kbd" | "" => {
                if qid == kb_qid::QKBD {
                    Ok(Some(ch.qid))
                } else {
                    ch.qid = Qid::new(kb_qid::QKBD, 0, 0);
                    Ok(Some(ch.qid))
                }
            }
            "ctl" => {
                ch.qid = Qid::new(kb_qid::QCTL, 0, 0);
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
        // Check if keyboard is enabled
        if !self.enabled.load(Ordering::SeqCst) {
            self.enable();
        }
        
        let qid = ch.qid.path;
        
        match qid {
            kb_qid::QKBD => {
                // Read key codes from keyboard
                // Plan 9 format: each key is a 16-bit rune + modifier flags
                let mut pos = 0;
                
                while pos + 2 <= buf.len() {
                    if let Some(key) = self.get_key() {
                        // Write key as little-endian u16
                        buf[pos..pos + 2].copy_from_slice(&key.to_le_bytes());
                        pos += 2;
                    } else {
                        break;
                    }
                }
                
                Ok(pos)
            }
            kb_qid::QCTL => {
                // Read keyboard configuration
                let kbd = crate::plan9_drivers::keyboard::keyboard();
                let state = kbd.state();
                let info = format!(
                    "leds {} shift {} ctrl {} alt {} caps {} num {} scroll {}\n",
                    state.leds.bits(),
                    if state.modifiers.shift { 1 } else { 0 },
                    if state.modifiers.ctrl { 1 } else { 0 },
                    if state.modifiers.alt { 1 } else { 0 },
                    if state.modifiers.caps { 1 } else { 0 },
                    if state.modifiers.num { 1 } else { 0 },
                    if state.modifiers.scroll { 1 } else { 0 },
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
            kb_qid::QCTL => {
                // Control commands
                let cmd = String::from_utf8_lossy(buf);
                
                if cmd.trim() == "kbmap" {
                    // Load keyboard map
                    return Ok(buf.len());
                } else if cmd.starts_with("leds ") {
                    // Set LEDs: "leds caps num scroll"
                    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
                    if parts.len() >= 4 {
                        let leds = crate::plan9_drivers::keyboard::KbdLeds::new();
                        let leds = if parts[1] == "1" { leds.caps_lock() } else { leds };
                        let leds = if parts[2] == "1" { leds.num_lock() } else { leds };
                        let _leds = if parts[3] == "1" { leds.scroll_lock() } else { leds };
                        
                        // Note: keyboard LED setting would go here
                        // kbd.set_leds(leds);
                        return Ok(buf.len());
                    }
                }
                
                Err(DevError::Einval)
            }
            kb_qid::QKBD => {
                // Keyboard writes are not supported
                Err(DevError::Eperm)
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode) = match qid {
            kb_qid::QKBD => (b"kbd".to_vec(), 0o666),
            kb_qid::QCTL => (b"ctl".to_vec(), 0o666),
            _ => return Err(DevError::Enoent),
        };
        
        Ok(DirEntry {
            dev: dev::devtype::KB,
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

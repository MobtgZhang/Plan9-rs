
//! Draw Device Implementation
//!
//! Implements the Plan 9 draw device (#d) for graphics context.
//!
//! ## Overview
//!
//! The draw device provides access to graphics operations.
//! This is a simplified version that provides basic drawing framework.
//!
//! ## Namespace Structure
//!
//! ```
//! /dev/
//! ├── drawN/           (graphics contexts)
//! │   ├── new          (create new context)
//! │   ├── ctl          (configuration)
//! │   ├── data         (pixel data)
//! │   └── refresh      (refresh requests)
//! └── screen           (screen information)
//! ```

extern crate alloc;

use crate::dev::{self, Dev, Chan, Qid, DirEntry, Error as DevError, qidtype};
use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum number of draw contexts
const DRAW_MAX_CONTEXTS: usize = 16;

/// Qid paths for draw device
mod draw_qid {
    pub const QDIR: u64 = 0;
    pub const QSCREEN: u64 = 1;
    pub const QCONTEXT: u64 = 2;
    pub const QNEW: u64 = 3;
    pub const QCTL: u64 = 4;
    pub const QDATA: u64 = 5;
    pub const QREFRESH: u64 = 6;
}

/// Draw context
#[derive(Debug, Clone)]
pub struct DrawContext {
    /// Context ID
    id: u64,
    /// Screen width
    width: u32,
    /// Screen height
    height: u32,
    /// Pixel format
    format: String,
    /// Refresh flag
    needs_refresh: bool,
}

/// Screen information
#[derive(Debug, Clone, Default)]
struct ScreenInfo {
    /// Width
    width: u32,
    /// Height
    height: u32,
    /// Depth (bits per pixel)
    depth: u32,
    /// Pixel format name
    format: String,
    /// Framebuffer address
    address: usize,
    /// Framebuffer size
    size: usize,
}

/// Draw device structure
pub struct DrawDev {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// Draw contexts
    contexts: Spinlock<Vec<DrawContext>>,
    /// Next context ID
    next_id: AtomicU64,
    /// Screen information
    screen: Spinlock<ScreenInfo>,
    /// Contexts available
    available: AtomicBool,
}

impl DrawDev {
    /// Create a new draw device
    pub fn new() -> Self {
        Self {
            name: "draw",
            dev_char: 'i',
            contexts: Spinlock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            screen: Spinlock::new(ScreenInfo::default()),
            available: AtomicBool::new(false),
        }
    }
    
    /// Create a new draw context
    pub fn create_context(&self, width: u32, height: u32, format: &str) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut contexts = self.contexts.lock();
        contexts.push(DrawContext {
            id,
            width,
            height,
            format: alloc::string::String::from(format),
            needs_refresh: false,
        });
        id
    }
    
    /// Get context by ID
    pub fn get_context(&self, id: u64) -> Option<DrawContext> {
        let contexts = self.contexts.lock();
        contexts.iter().find(|c| c.id == id).cloned()
    }
    
    /// Set screen info
    pub fn set_screen(&self, width: u32, height: u32, depth: u32, format: &str) {
        let mut screen = self.screen.lock();
        screen.width = width;
        screen.height = height;
        screen.depth = depth;
        screen.format = alloc::string::String::from(format);
        drop(screen);
        self.available.store(true, Ordering::SeqCst);
    }
}

impl Dev for DrawDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            dev::devtype::DRAW,
            Qid::new(draw_qid::QDIR, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let qid = ch.qid.path;
        
        if qid == draw_qid::QDIR {
            // At top level
            match name {
                "screen" => {
                    ch.qid = Qid::new(draw_qid::QSCREEN, 0, qidtype::DIR);
                    Ok(Some(ch.qid))
                }
                "new" => {
                    ch.qid = Qid::new(draw_qid::QNEW, 0, 0);
                    Ok(Some(ch.qid))
                }
                _ => {
                    // Check for drawN context
                    if name.starts_with("draw") {
                        if let Ok(id) = name[4..].parse::<u64>() {
                            if self.get_context(id).is_some() {
                                ch.qid = Qid::new(
                                    (id << 4) | draw_qid::QCONTEXT,
                                    0, qidtype::DIR
                                );
                                return Ok(Some(ch.qid));
                            }
                        }
                    }
                    Err(DevError::Enoent)
                }
            }
        } else {
            // At context level
            let context_id = qid >> 4;
            match name {
                "ctl" => {
                    ch.qid = Qid::new((context_id << 4) | draw_qid::QCTL, 0, 0);
                    Ok(Some(ch.qid))
                }
                "data" => {
                    ch.qid = Qid::new((context_id << 4) | draw_qid::QDATA, 0, 0);
                    Ok(Some(ch.qid))
                }
                "refresh" => {
                    ch.qid = Qid::new((context_id << 4) | draw_qid::QREFRESH, 0, 0);
                    Ok(Some(ch.qid))
                }
                _ => Err(DevError::Enoent),
            }
        }
    }

    fn open(&mut self, ch: &mut Chan, mode: u8) -> Result<(), DevError> {
        let qid = ch.qid.path;
        
        // Handle 'new' - create a new context
        if qid == draw_qid::QNEW {
            let screen = self.screen.lock();
            let id = self.create_context(
                screen.width,
                screen.height,
                &screen.format,
            );
            drop(screen);
            
            // Return the new context ID in channel aux
            ch.qid = Qid::new((id << 4) | draw_qid::QCONTEXT, 0, qidtype::DIR);
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
        let qid = ch.qid.path;
        
        match qid {
            draw_qid::QSCREEN => {
                // Read screen information
                let screen = self.screen.lock();
                let info = format!(
                    "{} {} {} {}\n",
                    screen.width, screen.height, screen.depth, screen.format
                );
                let len = info.len().min(buf.len());
                buf[..len].copy_from_slice(&info.as_bytes()[..len]);
                Ok(len)
            }
            _ => {
                // For other files, return minimal data
                if buf.len() > 0 {
                    buf[0] = 0;
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        let qid = ch.qid.path;
        
        match qid {
            draw_qid::QCTL => {
                // Parse control commands
                let cmd = String::from_utf8_lossy(buf);
                
                if cmd.starts_with("screen ") {
                    // Set screen info: "screen width height depth format"
                    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
                    if parts.len() >= 5 {
                        let width = parts[1].parse().unwrap_or(800);
                        let height = parts[2].parse().unwrap_or(600);
                        let depth = parts[3].parse().unwrap_or(32);
                        let format = parts[4];
                        
                        self.set_screen(width, height, depth, format);
                        return Ok(buf.len());
                    }
                }
                
                Err(DevError::Einval)
            }
            draw_qid::QREFRESH => {
                // Acknowledge refresh
                Ok(buf.len())
            }
            _ => Err(DevError::Eperm),
        }
    }

    fn stat(&mut self, ch: &mut Chan) -> Result<DirEntry, DevError> {
        let qid = ch.qid.path;
        
        let (name, mode, _qtype) = match qid {
            draw_qid::QDIR => (b"draw".to_vec(), 0o555 | 0o40000, qidtype::DIR),
            draw_qid::QSCREEN => (b"screen".to_vec(), 0o444, 0),
            draw_qid::QNEW => (b"new".to_vec(), 0o666, 0),
            _ => (b"data".to_vec(), 0o666, 0),
        };
        
        Ok(DirEntry {
            dev: dev::devtype::DRAW,
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

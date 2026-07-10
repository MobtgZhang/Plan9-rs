//! Window Control Module
//!
//! Implements window control operations for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/wctl.c`

use super::window::{Window, WindowId, WindowState};
use super::screen::Screen;
use super::types::{Point, Rect};

/// Window control operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowOp {
    Create,
    Delete,
    Move,
    Resize,
    Hide,
    Show,
    Focus,
    Minimize,
    Maximize,
    Restore,
}

/// Window control message
#[derive(Debug)]
pub struct WindowControlMsg {
    pub op: WindowOp,
    pub window_id: Option<WindowId>,
    pub rect: Option<Rect>,
    pub arg: Option<alloc::string::String>,
}

impl WindowControlMsg {
    pub fn new(op: WindowOp) -> Self {
        Self {
            op,
            window_id: None,
            rect: None,
            arg: None,
        }
    }
    
    pub fn with_window(mut self, id: WindowId) -> Self {
        self.window_id = Some(id);
        self
    }
    
    pub fn with_rect(mut self, rect: Rect) -> Self {
        self.rect = Some(rect);
        self
    }
    
    pub fn with_arg(mut self, arg: &str) -> Self {
        self.arg = Some(alloc::string::String::from(arg));
        self
    }
}

/// Window controller
pub struct WindowController {
    /// Operation history
    history: alloc::vec::Vec<WindowControlMsg>,
    /// Undo stack position
    undo_pos: usize,
}

impl WindowController {
    /// Create new window controller
    pub fn new() -> Self {
        Self {
            history: alloc::vec::Vec::new(),
            undo_pos: 0,
        }
    }

    /// Execute window operation
    pub fn execute(&mut self, screen: &mut Screen, msg: WindowControlMsg) -> Result<(), ControllerError> {
        use std::string::String;
        
        match msg.op {
            WindowOp::Create => {
                let rect = msg.rect.unwrap_or_else(|| Rect::from_coords(100, 100, 400, 300));
                screen.add_window(rect);
                self.push_history(msg);
                Ok(())
            }
            WindowOp::Delete => {
                if let Some(id) = msg.window_id {
                    if screen.close_by_id(id) {
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("window not found"))
                    }
                } else {
                    if screen.close_current() {
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("no window to close"))
                    }
                }
            }
            WindowOp::Move => {
                if let (Some(id), Some(rect)) = (msg.window_id, msg.rect) {
                    if let Some(w) = screen.find_by_id_mut(id) {
                        w.move_to(rect.min);
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("window not found"))
                    }
                } else if let Some(w) = screen.current_mut() {
                    if let Some(rect) = msg.rect {
                        w.move_to(rect.min);
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("no rect specified"))
                    }
                } else {
                    Err(ControllerError::new("no window selected"))
                }
            }
            WindowOp::Resize => {
                if let (Some(id), Some(rect)) = (msg.window_id, msg.rect) {
                    if let Some(w) = screen.find_by_id_mut(id) {
                        w.resize(rect);
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("window not found"))
                    }
                } else if let Some(w) = screen.current_mut() {
                    if let Some(rect) = msg.rect {
                        w.resize(rect);
                        self.push_history(msg);
                        Ok(())
                    } else {
                        Err(ControllerError::new("no rect specified"))
                    }
                } else {
                    Err(ControllerError::new("no window selected"))
                }
            }
            WindowOp::Hide => {
                screen.hide_current();
                self.push_history(msg);
                Ok(())
            }
            WindowOp::Show => {
                screen.unhide_all();
                self.push_history(msg);
                Ok(())
            }
            WindowOp::Focus => {
                if let Some(id) = msg.window_id {
                    for (i, w) in screen.windows().iter().enumerate() {
                        if w.id == id {
                            screen.select(i);
                            break;
                        }
                    }
                } else {
                    screen.next();
                }
                self.push_history(msg);
                Ok(())
            }
            WindowOp::Minimize => {
                if let Some(w) = screen.current_mut() {
                    w.hide();
                    screen.next();
                    self.push_history(msg);
                    Ok(())
                } else {
                    Err(ControllerError::new("no window selected"))
                }
            }
            WindowOp::Maximize => {
                if let Some(w) = screen.current_mut() {
                    w.resize(screen.rect);
                    self.push_history(msg);
                    Ok(())
                } else {
                    Err(ControllerError::new("no window selected"))
                }
            }
            WindowOp::Restore => {
                // Would restore from minimized/maximized state
                self.push_history(msg);
                Ok(())
            }
        }
    }

    /// Push operation to history
    fn push_history(&mut self, msg: WindowControlMsg) {
        // Remove any redo history
        self.history.truncate(self.undo_pos);
        self.history.push(msg);
        self.undo_pos = self.history.len();
    }

    /// Undo last operation
    pub fn undo(&mut self, _screen: &mut Screen) {
        if self.undo_pos > 0 {
            self.undo_pos -= 1;
            // Would reverse the operation
        }
    }

    /// Redo last undone operation
    pub fn redo(&mut self, _screen: &mut Screen) {
        if self.undo_pos < self.history.len() {
            self.undo_pos += 1;
            // Would redo the operation
        }
    }

    /// Check if can undo
    pub fn can_undo(&self) -> bool {
        self.undo_pos > 0
    }

    /// Check if can redo
    pub fn can_redo(&self) -> bool {
        self.undo_pos < self.history.len()
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
        self.undo_pos = 0;
    }
}

impl Default for WindowController {
    fn default() -> Self {
        Self::new()
    }
}

/// Controller error
#[derive(Debug)]
pub struct ControllerError {
    pub message: alloc::string::String,
}

impl ControllerError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: alloc::string::String::from(msg),
        }
    }
}

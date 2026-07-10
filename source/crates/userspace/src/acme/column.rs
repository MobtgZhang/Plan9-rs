//! Column Module
//!
//! Implements the Column structure for organizing windows vertically.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/cols.c`

use crate::acme::window::{Window, Rect, Point};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global window ID counter
static WINDOW_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Get next window ID
pub fn next_window_id() -> WindowId {
    WINDOW_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Column for organizing windows
pub struct Column {
    /// Column rectangle
    pub rect: Rect,
    /// Windows in this column
    windows: alloc::vec::Vec<Window>,
    /// Current window index
    current: usize,
    /// Column number
    pub colnum: i32,
    /// Whether column is safe to delete
    safe_to_delete: bool,
}

impl Column {
    /// Create a new column
    pub fn new(rect: Rect, colnum: i32) -> Self {
        Self {
            rect,
            windows: alloc::vec::Vec::new(),
            current: 0,
            colnum,
            safe_to_delete: false,
        }
    }

    /// Create a new window
    pub fn new_window(&mut self) -> Option<&mut Window> {
        let id = next_window_id();
        let mut w = Window::new(id);
        
        // Calculate window rectangle
        let wrect = self.calc_window_rect(self.windows.len());
        w.resize(wrect, true);
        
        self.windows.push(w);
        self.current = self.windows.len() - 1;
        
        self.windows.last_mut()
    }

    /// Create window with file
    pub fn open_window(&mut self, filename: &str) -> Option<&mut Window> {
        let id = next_window_id();
        let mut w = Window::new(id);
        w.init(filename);
        
        let wrect = self.calc_window_rect(self.windows.len());
        w.resize(wrect, true);
        
        self.windows.push(w);
        self.current = self.windows.len() - 1;
        
        self.windows.last_mut()
    }

    /// Close a window
    pub fn close_window(&mut self, index: usize) -> bool {
        if index >= self.windows.len() {
            return false;
        }
        
        let w = &self.windows[index];
        if !w.close() {
            return false;
        }
        
        self.windows.remove(index);
        
        // Adjust current
        if self.current >= self.windows.len() {
            self.current = self.windows.saturating_sub(1);
        }
        
        // Recalculate window positions
        self.recalc();
        
        true
    }

    /// Get current window
    pub fn current_window(&self) -> Option<&Window> {
        self.windows.get(self.current)
    }

    /// Get current window mutably
    pub fn current_window_mut(&mut self) -> Option<&mut Window> {
        self.windows.get_mut(self.current)
    }

    /// Select window by index
    pub fn select(&mut self, index: usize) {
        if index < self.windows.len() {
            self.current = index;
            if let Some(w) = self.windows.get_mut(self.current) {
                w.active = true;
            }
        }
    }

    /// Get window by ID
    pub fn find_by_id(&self, id: WindowId) -> Option<&Window> {
        self.windows.iter().find(|w| w.id == id)
    }

    /// Get window by ID mutably
    pub fn find_by_id_mut(&mut self, id: WindowId) -> Option<&mut Window> {
        self.windows.iter_mut().find(|w| w.id == id)
    }

    /// Calculate window rectangle
    fn calc_window_rect(&self, index: usize) -> Rect {
        let n = self.windows.len().max(1);
        let height = self.rect.height() / n as i32;
        let y = self.rect.min.y + (index as i32) * height;
        
        Rect {
            min: Point { x: self.rect.min.x, y },
            max: Point { x: self.rect.max.x, y: y + height },
        }
    }

    /// Recalculate all window positions
    pub fn recalc(&mut self) {
        for (i, w) in self.windows.iter_mut().enumerate() {
            let wrect = self.calc_window_rect(i);
            w.resize(wrect, w.showtag);
        }
    }

    /// Resize column
    pub fn resize(&mut self, rect: Rect) {
        self.rect = rect;
        self.recalc();
    }

    /// Move window to another column (simplified)
    pub fn move_window(&mut self, from_index: usize, to_index: usize) -> bool {
        if from_index >= self.windows.len() || to_index >= self.windows.len() {
            return false;
        }
        
        let w = self.windows.remove(from_index);
        self.windows.insert(to_index, w);
        
        if self.current == from_index {
            self.current = to_index;
        } else if from_index < self.current && to_index >= self.current {
            self.current -= 1;
        } else if from_index > self.current && to_index <= self.current {
            self.current += 1;
        }
        
        self.recalc();
        true
    }

    /// Get number of windows
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Get windows iterator
    pub fn windows(&self) -> &[Window] {
        &self.windows
    }

    /// Get windows iterator mut
    pub fn windows_mut(&mut self) -> alloc::vec::Vec<&mut Window> {
        // Return mutable references
        // Note: This is a simplified version
        alloc::vec::Vec::new()
    }

    /// Clean up dead windows
    pub fn clean_dead_windows(&mut self) {
        self.windows.retain(|w| !w.scratch || w.body.modified);
        if self.current >= self.windows.len() {
            self.current = self.windows.saturating_sub(1);
        }
        self.recalc();
    }
}

impl Default for Column {
    fn default() -> Self {
        Self::new(Rect::default(), 0)
    }
}

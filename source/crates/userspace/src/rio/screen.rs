//! Screen Module
//!
//! Implements the Screen structure for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/wind.c`, `scrl.c`

use super::window::{Window, WindowId, WindowState, Border, WindowEvent};
use super::types::{Point, Rect, Color};

/// Screen structure
pub struct Screen {
    /// Screen rectangle
    pub rect: Rect,
    /// Windows on screen
    windows: Vec<Window>,
    /// Active window index
    current: usize,
    /// Hidden windows
    hidden: Vec<Window>,
    /// Default background color
    background: Color,
    /// Grid for snapping
    grid: i32,
}

impl Screen {
    /// Create a new screen
    pub fn new(rect: Rect) -> Self {
        Self {
            rect,
            windows: Vec::new(),
            current: 0,
            hidden: Vec::new(),
            background: Color::new(0xDD, 0xDD, 0xDD),
            grid: 1,
        }
    }

    /// Add a new window
    pub fn add_window(&mut self, rect: Rect) -> Option<&mut Window> {
        let id = self.next_window_id();
        let mut w = Window::new(id, rect);
        
        // Ensure minimum size
        if w.rect.width() < 50 {
            w.rect.max.x = w.rect.min.x + 50;
        }
        if w.rect.height() < 50 {
            w.rect.max.y = w.rect.min.y + 50;
        }
        
        self.windows.push(w);
        self.current = self.windows.len() - 1;
        self.windows[self.current].focus();
        
        self.windows.last_mut()
    }

    /// Add window with title
    pub fn add_window_titled(&mut self, rect: Rect, title: &str) -> Option<&mut Window> {
        let id = self.next_window_id();
        let mut w = Window::with_title(id, rect, title);
        
        if w.rect.width() < 50 {
            w.rect.max.x = w.rect.min.x + 50;
        }
        if w.rect.height() < 50 {
            w.rect.max.y = w.rect.min.y + 50;
        }
        
        self.windows.push(w);
        self.current = self.windows.len() - 1;
        self.windows[self.current].focus();
        
        self.windows.last_mut()
    }

    /// Close current window
    pub fn close_current(&mut self) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        
        let w = self.windows.remove(self.current);
        
        // Add to hidden list if not deleted
        if w.state != WindowState::Deleted {
            self.hidden.push(w);
        }
        
        if self.current >= self.windows.len() {
            self.current = self.windows.len().saturating_sub(1);
        }
        
        true
    }

    /// Close window by ID
    pub fn close_by_id(&mut self, id: WindowId) -> bool {
        if let Some(idx) = self.windows.iter().position(|w| w.id == id) {
            let w = self.windows.remove(idx);
            
            if w.state != WindowState::Deleted {
                self.hidden.push(w);
            }
            
            if self.current >= self.windows.len() {
                self.current = self.windows.len().saturating_sub(1);
            }
            
            true
        } else {
            false
        }
    }

    /// Get next window ID
    fn next_window_id(&self) -> WindowId {
        let max_id = self.windows.iter()
            .chain(self.hidden.iter())
            .map(|w| w.id)
            .max()
            .unwrap_or(0);
        max_id + 1
    }

    /// Find window at point
    pub fn window_at(&self, point: Point) -> Option<&Window> {
        // Search from top to bottom (reverse order)
        for w in self.windows.iter().rev() {
            if w.rect.contains(point) {
                return Some(w);
            }
        }
        None
    }

    /// Find window at point mutably
    pub fn window_at_mut(&mut self, point: Point) -> Option<&mut Window> {
        // Search from top to bottom
        let mut found_idx = None;
        for (i, w) in self.windows.iter().enumerate().rev() {
            if w.rect.contains(point) {
                found_idx = Some(i);
                break;
            }
        }
        
        if let Some(idx) = found_idx {
            self.current = idx;
            Some(&mut self.windows[idx])
        } else {
            None
        }
    }

    /// Find window by ID
    pub fn find_by_id(&self, id: WindowId) -> Option<&Window> {
        self.windows.iter().find(|w| w.id == id)
    }

    /// Find window by ID mutably
    pub fn find_by_id_mut(&mut self, id: WindowId) -> Option<&mut Window> {
        self.windows.iter_mut().find(|w| w.id == id)
    }

    /// Select window
    pub fn select(&mut self, index: usize) {
        if index < self.windows.len() {
            // Unfocus current
            if let Some(w) = self.windows.get_mut(self.current) {
                w.unfocus();
            }
            
            self.current = index;
            
            // Focus new
            if let Some(w) = self.windows.get_mut(self.current) {
                w.focus();
            }
        }
    }

    /// Get current window
    pub fn current(&self) -> Option<&Window> {
        self.windows.get(self.current)
    }

    /// Get current window mutably
    pub fn current_mut(&mut self) -> Option<&mut Window> {
        self.windows.get_mut(self.current)
    }

    /// Move to next window
    pub fn next(&mut self) {
        if self.windows.is_empty() {
            return;
        }
        
        if let Some(w) = self.windows.get_mut(self.current) {
            w.unfocus();
        }
        
        self.current = (self.current + 1) % self.windows.len();
        
        if let Some(w) = self.windows.get_mut(self.current) {
            w.focus();
        }
    }

    /// Move to previous window
    pub fn prev(&mut self) {
        if self.windows.is_empty() {
            return;
        }
        
        if let Some(w) = self.windows.get_mut(self.current) {
            w.unfocus();
        }
        
        if self.current == 0 {
            self.current = self.windows.len() - 1;
        } else {
            self.current -= 1;
        }
        
        if let Some(w) = self.windows.get_mut(self.current) {
            w.focus();
        }
    }

    /// Tile windows horizontally
    pub fn tile_horizontal(&mut self) {
        if self.windows.is_empty() {
            return;
        }
        
        let n = self.windows.len() as i32;
        let width = self.rect.width() / n;
        
        for (i, w) in self.windows.iter_mut().enumerate() {
            let x = self.rect.min.x + (i as i32) * width;
            w.resize(Rect::new(
                super::types::Point::new(x, self.rect.min.y),
                super::types::Point::new(x + width, self.rect.max.y),
            ));
            if self.grid > 1 {
                w.snap(self.grid);
            }
        }
    }

    /// Tile windows vertically
    pub fn tile_vertical(&mut self) {
        if self.windows.is_empty() {
            return;
        }
        
        let n = self.windows.len() as i32;
        let height = self.rect.height() / n;
        
        for (i, w) in self.windows.iter_mut().enumerate() {
            let y = self.rect.min.y + (i as i32) * height;
            w.resize(Rect::new(
                super::types::Point::new(self.rect.min.x, y),
                super::types::Point::new(self.rect.max.x, y + height),
            ));
            if self.grid > 1 {
                w.snap(self.grid);
            }
        }
    }

    /// Stack windows
    pub fn stack(&mut self) {
        // Just bring current to front
        if self.windows.len() > 1 {
            let w = self.windows.remove(self.current);
            self.windows.push(w);
            self.current = self.windows.len() - 1;
        }
    }

    /// Hide current window
    pub fn hide_current(&mut self) {
        if let Some(w) = self.windows.get(self.current) {
            let mut w = w.clone();
            w.hide();
            self.hidden.push(w);
        }
        self.close_current();
    }

    /// Unhide hidden windows
    pub fn unhide_all(&mut self) {
        for w in self.hidden.drain(..) {
            let mut w = w;
            w.show();
            self.windows.push(w);
        }
        if !self.windows.is_empty() {
            self.select(self.windows.len() - 1);
        }
    }

    /// Get window count
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Get all windows
    pub fn windows(&self) -> &[Window] {
        &self.windows
    }

    /// Get all windows mutably
    pub fn windows_mut(&mut self) -> &mut Vec<Window> {
        &mut self.windows
    }

    /// Set grid
    pub fn set_grid(&mut self, grid: i32) {
        self.grid = grid;
    }

    /// Refresh all windows
    pub fn refresh(&mut self, area: Rect) {
        // Would redraw windows in area
        let _ = area;
    }

    /// Check if any window is in state
    pub fn has_state(&self, state: WindowState) -> bool {
        self.windows.iter().any(|w| w.state == state)
    }

    /// Count windows in state
    pub fn count_state(&self, state: WindowState) -> usize {
        self.windows.iter().filter(|w| w.state == state).count()
    }
}

impl Default for Screen {
    fn default() -> Self {
        Self::new(Rect::default())
    }
}

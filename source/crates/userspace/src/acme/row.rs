//! Row Module
//!
//! Implements the Row structure for organizing columns horizontally.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/rows.c`

use crate::acme::column::Column;
use crate::acme::window::{Rect, Point, WindowId, Window};

/// Row for organizing columns
pub struct Row {
    /// Row rectangle
    pub rect: Rect,
    /// Columns in this row
    columns: alloc::vec::Vec<Column>,
    /// Current column index
    current: usize,
    /// Default column count
    ncol: i32,
}

impl Row {
    /// Create a new row
    pub fn new(rect: Rect) -> Self {
        Self {
            rect,
            columns: alloc::vec::Vec::new(),
            current: 0,
            ncol: 2,
        }
    }

    /// Initialize with columns
    pub fn init(&mut self, ncol: i32) {
        self.ncol = ncol;
        self.columns.clear();
        
        let col_width = self.rect.width() / ncol;
        
        for i in 0..ncol {
            let col_rect = Rect {
                min: Point {
                    x: self.rect.min.x + i * col_width,
                    y: self.rect.min.y,
                },
                max: Point {
                    x: self.rect.min.x + (i + 1) * col_width,
                    y: self.rect.max.y,
                },
            };
            self.columns.push(Column::new(col_rect, i as i32));
        }
        
        self.current = 0;
    }

    /// Create new window in current column
    pub fn new_window(&mut self) -> Option<&mut Window> {
        if self.columns.is_empty() {
            return None;
        }
        self.columns[self.current].new_window()
    }

    /// Open file in current column
    pub fn open(&mut self, filename: &str) -> Option<&mut Window> {
        if self.columns.is_empty() {
            return None;
        }
        self.columns[self.current].open_window(filename)
    }

    /// Close window by ID
    pub fn close_window(&mut self, id: WindowId) -> bool {
        for col in &mut self.columns {
            if let Some(idx) = col.windows.iter().position(|w| w.id == id) {
                return col.close_window(idx);
            }
        }
        false
    }

    /// Find window by ID
    pub fn find_window(&self, id: WindowId) -> Option<(&Window, usize, usize)> {
        for (ci, col) in self.columns.iter().enumerate() {
            if let Some((wi, w)) = col.windows.iter()
                .enumerate()
                .find(|(_, w)| w.id == id)
            {
                return Some((w, ci, wi));
            }
        }
        None
    }

    /// Find window by ID mutably
    pub fn find_window_mut(&mut self, id: WindowId) -> Option<(&mut Window, usize, usize)> {
        for (ci, col) in self.columns.iter_mut().enumerate() {
            if let Some(wi) = col.windows.iter().position(|w| w.id == id) {
                // Need to return mutable reference
                // This is a bit awkward due to Rust's borrowing rules
                let mut found = None;
                for (wi2, w) in col.windows.iter().enumerate() {
                    if w.id == id {
                        found = Some(wi2);
                        break;
                    }
                }
                if let Some(wi) = found {
                    let w = &mut col.windows[wi];
                    return Some((w, ci, wi));
                }
            }
        }
        None
    }

    /// Get current column
    pub fn current_column(&self) -> Option<&Column> {
        self.columns.get(self.current)
    }

    /// Get current column mutably
    pub fn current_column_mut(&mut self) -> Option<&mut Column> {
        self.columns.get_mut(self.current)
    }

    /// Select column by index
    pub fn select_column(&mut self, index: usize) {
        if index < self.columns.len() {
            self.current = index;
        }
    }

    /// Close a column (must have at least one column)
    pub fn close_column(&mut self, index: usize) -> bool {
        if self.columns.len() <= 1 {
            return false;
        }
        
        if index >= self.columns.len() {
            return false;
        }
        
        // Move windows to adjacent column first
        let target = if index == 0 { 1 } else { index - 1 };
        
        {
            let closing = &self.columns[index];
            let target_col = &mut self.columns[target];
            for w in closing.windows.iter() {
                let mut wcopy = Window::new(w.id);
                wcopy.body = w.body.clone();
                wcopy.tag = w.tag.clone();
                let _ = target_col.windows.push(wcopy);
            }
        }
        
        self.columns.remove(index);
        
        // Update current
        if self.current >= self.columns.len() {
            self.current = self.columns.len() - 1;
        }
        
        // Renumber columns
        for (i, col) in self.columns.iter_mut().enumerate() {
            col.colnnum = i as i32;
        }
        
        self.recalc();
        true
    }

    /// Split column
    pub fn split_column(&mut self, index: usize) -> bool {
        if index >= self.columns.len() {
            return false;
        }
        
        let col_rect = self.columns[index].rect;
        let half = col_rect.width() / 2;
        
        // Resize existing column
        self.columns[index].rect.max.x = col_rect.min.x + half;
        self.columns[index].recalc();
        
        // Create new column
        let new_rect = Rect {
            min: Point { x: col_rect.min.x + half, y: col_rect.min.y },
            max: col_rect.max,
        };
        
        let new_col = Column::new(new_rect, self.columns.len() as i32);
        self.columns.insert(index + 1, new_col);
        
        self.recalc();
        true
    }

    /// Resize row
    pub fn resize(&mut self, rect: Rect) {
        self.rect = rect;
        self.recalc();
    }

    /// Recalculate all column positions
    pub fn recalc(&mut self) {
        if self.columns.is_empty() {
            return;
        }
        
        let ncol = self.columns.len() as i32;
        let col_width = self.rect.width() / ncol;
        
        for (i, col) in self.columns.iter_mut().enumerate() {
            col.rect.min.x = self.rect.min.x + (i as i32) * col_width;
            col.rect.max.x = self.rect.min.x + ((i as i32) + 1) * col_width;
            col.rect.min.y = self.rect.min.y;
            col.rect.max.y = self.rect.max.y;
            col.recalc();
        }
    }

    /// Get number of columns
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Get total window count
    pub fn window_count(&self) -> usize {
        self.columns.iter().map(|c| c.len()).sum()
    }

    /// Get iterator over all windows
    pub fn all_windows(&self) -> alloc::vec::Vec<&Window> {
        let mut result = alloc::vec::Vec::new();
        for col in &self.columns {
            for w in &col.windows {
                result.push(w);
            }
        }
        result
    }

    /// Set current window
    pub fn set_current(&mut self, col: usize, win: usize) {
        if col < self.columns.len() && win < self.columns[col].len() {
            self.current = col;
            self.columns[col].select(win);
        }
    }

    /// Move to next window
    pub fn next_window(&mut self) {
        if self.columns.is_empty() {
            return;
        }
        
        let col = &self.columns[self.current];
        let next = col.current + 1;
        
        if next < col.len() {
            self.columns[self.current].select(next);
        } else {
            // Move to next column
            self.current = (self.current + 1) % self.columns.len();
            self.columns[self.current].select(0);
        }
    }

    /// Move to previous window
    pub fn prev_window(&mut self) {
        if self.columns.is_empty() {
            return;
        }
        
        let col = &self.columns[self.current];
        let prev = col.current.saturating_sub(1);
        
        if prev < col.current {
            self.columns[self.current].select(prev);
        } else {
            // Move to previous column
            self.current = if self.current == 0 {
                self.columns.len() - 1
            } else {
                self.current - 1
            };
            self.columns[self.current].select(
                self.columns[self.current].len().saturating_sub(1)
            );
        }
    }

    /// Load font from file (placeholder)
    pub fn loadfonts(&mut self, _filename: &str) {
        // Would load fonts from file
    }
}

impl Default for Row {
    fn default() -> Self {
        Self::new(Rect::default())
    }
}

//! Window Module
//!
//! Implements the Window structure for Acme, which contains
//! a text buffer, a tag, and handles user interaction.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/wind.c`

use crate::acme::text::Text;

/// Window ID
pub type WindowId = u64;

/// Window state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    Modified,
    Clean,
    Unread,
    BodyModified,
}

/// Window colors
#[derive(Debug, Clone, Copy)]
pub struct Colors {
    pub col_text: u32,
    pub col_back: u32,
    pub col_bord: u32,
    pub col_hilit: u32,
    pub col_error: u32,
}

/// Window structure
pub struct Window {
    /// Unique window ID
    pub id: WindowId,
    /// Body text
    pub body: Text,
    /// Tag text
    pub tag: Text,
    /// Frame rectangle
    pub frame: Rect,
    /// Body rectangle
    pub body_rect: Rect,
    /// Tag rectangle
    pub tag_rect: Rect,
    /// Whether tag is being edited
    pub showtag: bool,
    /// Whether this is a scratch window
    pub scratch: bool,
    /// Whether window is active
    pub active: bool,
    /// Whether auto-indent is enabled
    pub autoindent: bool,
    /// Insertion point
    pub lim: usize,
    /// Address string
    pub addr: alloc::string::String,
    /// Colors
    colors: Colors,
}

/// Rectangle
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub min: Point,
    pub max: Point,
}

/// Point
#[derive(Debug, Clone, Copy, Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Rect {
    /// Check if rect is empty
    pub fn is_empty(&self) -> bool {
        self.min.x >= self.max.x || self.min.y >= self.max.y
    }

    /// Get width
    pub fn width(&self) -> i32 {
        self.max.x - self.min.x
    }

    /// Get height
    pub fn height(&self) -> i32 {
        self.max.y - self.min.y
    }
}

impl Window {
    /// Create a new window
    pub fn new(id: WindowId) -> Self {
        Self {
            id,
            body: Text::new(),
            tag: Text::with_content(""),
            frame: Rect::default(),
            body_rect: Rect::default(),
            tag_rect: Rect::default(),
            showtag: true,
            scratch: false,
            active: false,
            autoindent: true,
            lim: 0,
            addr: alloc::string::String::from("0,$"),
            colors: Colors::default(),
        }
    }

    /// Create a scratch window (no file)
    pub fn scratch(id: WindowId) -> Self {
        let mut w = Self::new(id);
        w.scratch = true;
        w.showtag = false;
        w
    }

    /// Initialize window with file
    pub fn init(&mut self, filename: &str) {
        let filename = alloc::string::String::from(filename);
        
        // Load body from file
        if let Err(e) = self.body.load_file(&filename) {
            // File doesn't exist, that's OK
            let _ = e;
        }
        
        // Set up tag
        self.tag = Text::with_content(&filename);
        self.tag.insert(self.tag.len(), "\t");
        
        // Clear undo
        self.body.clear_undo();
    }

    /// Resize window
    pub fn resize(&mut self, frame: Rect, showtag: bool) {
        let tag_height = if showtag { 20 } else { 0 };
        
        self.frame = frame;
        self.showtag = showtag;
        
        if showtag {
            self.tag_rect = Rect {
                min: Point { x: frame.min.x, y: frame.min.y },
                max: Point { x: frame.max.x, y: frame.min.y + tag_height },
            };
            self.body_rect = Rect {
                min: Point { x: frame.min.x, y: frame.min.y + tag_height },
                max: Point { x: frame.max.x, y: frame.max.y },
            };
        } else {
            self.tag_rect = Rect::default();
            self.body_rect = frame;
        }
    }

    /// Get window title
    pub fn title(&self) -> alloc::string::String {
        let mut title = self.tag.get_text();
        if self.body.modified {
            title.push_str(" *");
        }
        title
    }

    /// Get filename from tag
    pub fn filename(&self) -> alloc::string::String {
        let tag = self.tag.get_text();
        tag.split_whitespace().next().unwrap_or("").to_string()
    }

    /// Check if window is modified
    pub fn is_modified(&self) -> bool {
        self.body.modified
    }

    /// Commit edits (mark as saved)
    pub fn commit(&mut self) {
        self.body.modified = false;
    }

    /// Execute command from tag
    pub fn execute(&mut self, cmd: &str) -> Result<(), alloc::string::String> {
        let cmd = cmd.trim();
        
        if cmd.starts_with("Dot=") {
            // Set address
            self.addr = alloc::string::String::from(&cmd[4..]);
            return Ok(());
        }
        
        if cmd == "Put" || cmd == "Save" {
            // Save file
            return self.body.save_file();
        }
        
        if cmd == "Undo" {
            self.body.undo();
            return Ok(());
        }
        
        if cmd == "Redo" {
            self.body.redo();
            return Ok(());
        }
        
        if cmd.starts_with("|") {
            // Pipe selection to command
            let selection = self.body.selection();
            let _ = selection;
            // Would execute command here
            return Ok(());
        }
        
        if cmd.starts_with(">") {
            // Pipe to file
            let selection = self.body.selection();
            let _ = selection;
            // Would write to file here
            return Ok(());
        }
        
        if cmd.starts_with("<") {
            // Pipe from file
            // Would read from file here
            return Ok(());
        }
        
        if cmd == "Load" {
            let filename = self.filename();
            if !filename.is_empty() {
                self.body.load_file(&filename)?;
            }
            return Ok(());
        }
        
        Err(alloc::string::String::from("unknown command"))
    }

    /// Close window
    pub fn close(&self) -> bool {
        // Check if we should prompt to save
        if self.body.modified && !self.scratch {
            // Would prompt user here
            // For now, just allow close
        }
        true
    }

    /// Mouse button handler
    pub fn mouse(&mut self, button: MouseButton, point: Point) -> Option<Action> {
        // Check which part was clicked
        if self.tag_rect.contains(point) {
            // Click in tag
            let offset = self.point_to_offset(&self.tag, point);
            self.tag.set_selection(offset, offset);
            self.tag.q0 = offset;
            
            // Double click actions
            if button == MouseButton::Double {
                // Execute command
                let cmd = self.tag.selection();
                if let Err(e) = self.execute(&cmd) {
                    return Some(Action::Error(e));
                }
                return Some(Action::Refresh);
            }
            
            Some(Action::TagClick)
        } else if self.body_rect.contains(point) {
            // Click in body
            let offset = self.point_to_offset(&self.body, point);
            self.body.set_selection(offset, offset);
            self.body.q0 = offset;
            
            Some(Action::BodyClick)
        } else {
            None
        }
    }

    /// Convert point to text offset
    fn point_to_offset(&self, text: &Text, point: Point) -> usize {
        // Simplified: just use y coordinate
        let line = (point.y / 16) as usize;
        text.offset_of_line(line)
    }

    /// Insert text at cursor
    pub fn insert(&mut self, text: &str) {
        self.body.insert(self.body.q0, text);
        self.body.q0 += text.len();
    }

    /// Delete selected text
    pub fn delete_selection(&mut self) {
        let (q0, q1) = if self.body.q0 <= self.body.q1 {
            (self.body.q0, self.body.q1)
        } else {
            (self.body.q1, self.body.q0)
        };
        self.body.delete(q0, q1);
    }

    /// Find next match
    pub fn find_next(&mut self, pattern: &str) -> bool {
        let start = if self.body.q1 <= self.body.q0 {
            self.body.q1
        } else {
            self.body.q0 + 1
        };
        
        if let Some(pos) = self.body.find(pattern, start) {
            self.body.set_selection(pos, pos + pattern.len());
            true
        } else {
            false
        }
    }

    /// Find and replace
    pub fn replace_all(&mut self, pattern: &str, replacement: &str) {
        let positions: alloc::vec::Vec<_> = self.body.find_all(pattern);
        // Replace backwards to maintain positions
        let mut offset = 0i32;
        for &pos in positions.iter().rev() {
            let pos = pos + offset as usize;
            self.body.replace(pos, pos + pattern.len(), replacement);
            offset += replacement.len() as i32 - pattern.len() as i32;
        }
    }
}

impl Rect {
    /// Check if point is inside
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.min.x && point.x < self.max.x &&
        point.y >= self.min.y && point.y < self.max.y
    }
}

impl Default for Colors {
    fn default() -> Self {
        Self {
            col_text: 0x000000,  // Black
            col_back: 0xFFFFFF,  // White
            col_bord: 0xCCCCCC,  // Light gray
            col_hilit: 0xFFFF00,  // Yellow
            col_error: 0xFF0000,  // Red
        }
    }
}

/// Mouse button
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Double,
}

/// Action result
#[derive(Debug)]
pub enum Action {
    TagClick,
    BodyClick,
    Refresh,
    Error(alloc::string::String),
}

//! Text Buffer Module
//!
//! Implements the core text buffer functionality for Acme.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/text.c`

/// Text buffer with undo support
pub struct Text {
    /// Character data (UTF-8 encoded)
    data: alloc::vec::Vec<u8>,
    /// Current cursor position (byte offset)
    pub q0: usize,
    /// Selection end position (byte offset)
    pub q1: usize,
    /// Undo history
    undo: alloc::vec::Vec<UndoOp>,
    /// Undo position
    undo_pos: usize,
    /// Modified flag
    pub modified: bool,
    /// File name
    pub filename: alloc::string::String,
}

/// Undo operation
#[derive(Debug, Clone)]
struct UndoOp {
    /// Operation type
    op_type: OpType,
    /// Position
    pos: usize,
    /// Inserted text
    inserted: alloc::vec::Vec<u8>,
    /// Deleted text
    deleted: alloc::vec::Vec<u8>,
}

/// Operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpType {
    Insert,
    Delete,
}

impl Text {
    /// Create a new empty text buffer
    pub fn new() -> Self {
        Self {
            data: alloc::vec::Vec::new(),
            q0: 0,
            q1: 0,
            undo: alloc::vec::Vec::new(),
            undo_pos: 0,
            modified: false,
            filename: alloc::string::String::new(),
        }
    }

    /// Create with initial content
    pub fn with_content(content: &str) -> Self {
        Self {
            data: content.as_bytes().to_vec(),
            q0: 0,
            q1: 0,
            undo: alloc::vec::Vec::new(),
            undo_pos: 0,
            modified: false,
            filename: alloc::string::String::new(),
        }
    }

    /// Get the number of bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the character count (Runes)
    pub fn char_len(&self) -> usize {
        // Count UTF-8 runes
        let mut count = 0;
        let mut i = 0;
        while i < self.data.len() {
            let b = self.data[i];
            if b < 0x80 {
                i += 1;
            } else if b < 0xE0 {
                i += 2;
            } else if b < 0xF0 {
                i += 3;
            } else {
                i += 4;
            }
            count += 1;
        }
        count
    }

    /// Get line count
    pub fn line_count(&self) -> usize {
        let mut count = 1;
        for &b in &self.data {
            if b == b'\n' {
                count += 1;
            }
        }
        count
    }

    /// Get line number at position
    pub fn line_at(&self, pos: usize) -> usize {
        let pos = pos.min(self.data.len());
        let mut line = 1;
        for (i, &b) in self.data.iter().enumerate() {
            if i >= pos {
                break;
            }
            if b == b'\n' {
                line += 1;
            }
        }
        line
    }

    /// Get byte offset for line number
    pub fn offset_of_line(&self, line: usize) -> usize {
        if line <= 1 {
            return 0;
        }
        let mut current_line = 1;
        for (i, &b) in self.data.iter().enumerate() {
            if current_line >= line {
                return i;
            }
            if b == b'\n' {
                current_line += 1;
            }
        }
        self.data.len()
    }

    /// Get the start of current line
    pub fn line_start(&self, pos: usize) -> usize {
        let pos = pos.min(self.data.len());
        let mut i = pos;
        while i > 0 && self.data[i - 1] != b'\n' {
            i -= 1;
        }
        i
    }

    /// Get the end of current line
    pub fn line_end(&self, pos: usize) -> usize {
        let pos = pos.min(self.data.len());
        let mut i = pos;
        while i < self.data.len() && self.data[i] != b'\n' {
            i += 1;
        }
        i
    }

    /// Insert text at position
    pub fn insert(&mut self, pos: usize, text: &str) {
        let pos = pos.min(self.data.len());
        let bytes = text.as_bytes();
        
        // Record undo
        if !bytes.is_empty() {
            self.undo.push(UndoOp {
                op_type: OpType::Insert,
                pos,
                inserted: bytes.to_vec(),
                deleted: alloc::vec::Vec::new(),
            });
            self.undo_pos += 1;
        }
        
        // Insert
        self.data.insert_from_slice(pos, bytes);
        self.modified = true;
        
        // Move cursor
        if self.q0 >= pos {
            self.q0 += bytes.len();
        }
        if self.q1 >= pos {
            self.q1 += bytes.len();
        }
    }

    /// Delete text in range [q0, q1)
    pub fn delete(&mut self, q0: usize, q1: usize) {
        let q0 = q0.min(self.data.len());
        let q1 = q1.min(self.data.len());
        if q0 >= q1 {
            return;
        }
        
        // Record undo
        let deleted = self.data[q0..q1].to_vec();
        if !deleted.is_empty() {
            self.undo.push(UndoOp {
                op_type: OpType::Delete,
                pos: q0,
                inserted: alloc::vec::Vec::new(),
                deleted,
            });
            self.undo_pos += 1;
        }
        
        // Delete
        self.data.drain(q0..q1);
        self.modified = true;
        
        // Move cursor
        if self.q0 > q1 {
            self.q0 -= q1 - q0;
        } else if self.q0 > q0 {
            self.q0 = q0;
        }
        if self.q1 > q1 {
            self.q1 -= q1 - q0;
        } else if self.q1 > q0 {
            self.q1 = q0;
        }
    }

    /// Get text as string
    pub fn get_text(&self) -> alloc::string::String {
        String::from_utf8_lossy(&self.data).into_owned()
    }

    /// Get text in range
    pub fn get_range(&self, q0: usize, q1: usize) -> alloc::string::String {
        let q0 = q0.min(self.data.len());
        let q1 = q1.min(self.data.len());
        String::from_utf8_lossy(&self.data[q0..q1]).into_owned()
    }

    /// Get selected text
    pub fn selection(&self) -> alloc::string::String {
        let (q0, q1) = if self.q0 <= self.q1 {
            (self.q0, self.q1)
        } else {
            (self.q1, self.q0)
        };
        self.get_range(q0, q1)
    }

    /// Set selection
    pub fn set_selection(&mut self, q0: usize, q1: usize) {
        self.q0 = q0.min(self.data.len());
        self.q1 = q1.min(self.data.len());
    }

    /// Select word at position
    pub fn select_word(&mut self, pos: usize) {
        let pos = pos.min(self.data.len());
        
        // Find word boundaries
        let mut start = pos;
        let mut end = pos;
        
        // Expand backwards
        while start > 0 && Self::is_word_char(self.data[start - 1]) {
            start -= 1;
        }
        
        // Expand forwards
        while end < self.data.len() && Self::is_word_char(self.data[end]) {
            end += 1;
        }
        
        self.q0 = start;
        self.q1 = end;
    }

    /// Select line at position
    pub fn select_line(&mut self, pos: usize) {
        self.q0 = self.line_start(pos);
        self.q1 = self.line_end(pos);
    }

    /// Check if byte is a word character
    fn is_word_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// Undo last operation
    pub fn undo(&mut self) -> bool {
        if self.undo_pos == 0 {
            return false;
        }
        
        self.undo_pos -= 1;
        let op = &self.undo[self.undo_pos];
        
        match op.op_type {
            OpType::Insert => {
                // Undo insertion = delete
                self.data.drain(op.pos..op.pos + op.inserted.len());
            }
            OpType::Delete => {
                // Undo deletion = insert
                self.data.insert_from_slice(op.pos, &op.deleted);
            }
        }
        
        true
    }

    /// Redo last undone operation
    pub fn redo(&mut self) -> bool {
        if self.undo_pos >= self.undo.len() {
            return false;
        }
        
        let op = &self.undo[self.undo_pos];
        
        match op.op_type {
            OpType::Insert => {
                self.data.insert_from_slice(op.pos, &op.inserted);
            }
            OpType::Delete => {
                self.data.drain(op.pos..op.pos + op.deleted.len());
            }
        }
        
        self.undo_pos += 1;
        true
    }

    /// Clear undo history
    pub fn clear_undo(&mut self) {
        self.undo.clear();
        self.undo_pos = 0;
    }

    /// Load from file
    pub fn load_file(&mut self, filename: &str) -> Result<(), alloc::string::String> {
        use std::string::String;
        // In a real implementation, this would read from the file system
        // For now, just set the filename
        self.filename = String::from(filename);
        self.modified = false;
        self.clear_undo();
        Ok(())
    }

    /// Save to file
    pub fn save_file(&mut self) -> Result<(), alloc::string::String> {
        use std::string::String;
        if self.filename.is_empty() {
            return Err(String::from("no filename"));
        }
        // In a real implementation, this would write to the file system
        self.modified = false;
        Ok(())
    }

    /// Find text
    pub fn find(&self, pattern: &str, start: usize) -> Option<usize> {
        let pattern = pattern.as_bytes();
        if pattern.is_empty() {
            return None;
        }
        
        let start = start.min(self.data.len());
        self.data[start..].windows(pattern.len())
            .position(|w| w == pattern)
            .map(|p| start + p)
    }

    /// Find all occurrences
    pub fn find_all(&self, pattern: &str) -> alloc::vec::Vec<usize> {
        let pattern = pattern.as_bytes();
        if pattern.is_empty() {
            return alloc::vec::Vec::new();
        }
        
        let mut positions = alloc::vec::Vec::new();
        let mut start = 0;
        while let Some(pos) = self.data[start..].windows(pattern.len())
            .position(|w| w == pattern)
        {
            positions.push(start + pos);
            start += pos + 1;
        }
        positions
    }

    /// Replace text in range
    pub fn replace(&mut self, q0: usize, q1: usize, text: &str) {
        self.delete(q0, q1);
        self.insert(q0, text);
    }

    /// Indent selected lines
    pub fn indent(&mut self, indent_str: &str) {
        let (q0, q1) = if self.q0 <= self.q1 {
            (self.q0, self.q1)
        } else {
            (self.q1, self.q0)
        };
        
        let line_start = self.line_start(q0);
        let line_end = self.line_end(q1);
        
        let indent_bytes = indent_str.as_bytes();
        let mut pos = line_start;
        while pos <= line_end && pos < self.data.len() {
            // Insert at beginning of each line in range
            let mut line = self.line_start(pos);
            if line >= line_end {
                break;
            }
            self.data.insert_from_slice(line, indent_bytes);
            pos = self.line_end(line + indent_bytes.len()) + 1;
        }
        
        self.modified = true;
    }

    /// Unindent selected lines
    pub fn unindent(&mut self, indent_str: &str) {
        let (q0, q1) = if self.q0 <= self.q1 {
            (self.q0, self.q1)
        } else {
            (self.q1, self.q0)
        };
        
        let line_start = self.line_start(q0);
        let line_end = self.line_end(q1);
        let indent_bytes = indent_str.as_bytes();
        
        let mut pos = line_start;
        while pos < line_end && pos < self.data.len() {
            let line = self.line_start(pos);
            if line >= line_end {
                break;
            }
            
            // Check if line starts with indent
            if self.data[line..].starts_with(indent_bytes) {
                self.data.drain(line..line + indent_bytes.len());
            }
            pos = self.line_end(line) + 1;
        }
        
        self.modified = true;
    }
}

impl Default for Text {
    fn default() -> Self {
        Self::new()
    }
}

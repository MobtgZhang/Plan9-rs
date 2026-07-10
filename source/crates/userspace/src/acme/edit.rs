//! Editor Module
//!
//! Implements text editing commands for Acme.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/edit.c`, `ecmd.c`

use crate::acme::text::Text;

/// Editor state
pub struct Editor {
    /// Default indent string
    indent: alloc::string::String,
    /// Tab width
    tabwidth: usize,
    /// Auto-indent enabled
    autoindent: bool,
    /// Wrap column
    wrapcolumn: usize,
}

impl Editor {
    /// Create a new editor
    pub fn new() -> Self {
        Self {
            indent: alloc::string::String::from("\t"),
            tabwidth: 4,
            autoindent: true,
            wrapcolumn: 0,
        }
    }

    /// Set indent string
    pub fn set_indent(&mut self, indent: &str) {
        self.indent = alloc::string::String::from(indent);
    }

    /// Set tab width
    pub fn set_tabwidth(&mut self, width: usize) {
        self.tabwidth = width;
    }

    /// Set auto-indent
    pub fn set_autoindent(&mut self, enabled: bool) {
        self.autoindent = enabled;
    }

    /// Set wrap column (0 = no wrap)
    pub fn set_wrapcolumn(&mut self, column: usize) {
        self.wrapcolumn = column;
    }

    /// Delete current line
    pub fn delete_line(text: &mut Text) {
        let q0 = text.line_start(text.q0);
        let q1 = text.line_end(text.q0) + 1;
        text.delete(q0, q1);
    }

    /// Delete to end of line
    pub fn delete_to_eol(text: &mut Text) {
        let q0 = text.q0.min(text.q1);
        let q1 = text.line_end(text.q0);
        if q1 > q0 {
            text.delete(q0, q1);
        }
    }

    /// Delete to start of line
    pub fn delete_to_bol(text: &mut Text) {
        let q0 = text.line_start(text.q0);
        let q1 = text.q0.max(text.q1);
        if q1 > q0 {
            text.delete(q0, q1);
        }
    }

    /// Delete word
    pub fn delete_word(text: &mut Text) {
        let (q0, q1) = if text.q0 <= text.q1 {
            (text.q0, text.q1)
        } else {
            (text.q1, text.q0)
        };
        
        if q0 == q1 {
            // Expand to word
            let mut start = q0;
            let mut end = q0;
            
            while start > 0 && Text::is_word_char_internal(text.get_range(start - 1, start).as_bytes()[0]) {
                start -= 1;
            }
            while end < text.len() && Text::is_word_char_internal(text.get_range(end, end + 1).as_bytes()[0]) {
                end += 1;
            }
            
            text.delete(start, end);
        } else {
            text.delete(q0, q1);
        }
    }

    /// Insert newline with indent
    pub fn insert_newline(text: &mut Text, indent: &str) {
        let pos = text.q0.max(text.q1);
        
        // Get current line's indent
        let line_start = text.line_start(pos);
        let line_text = text.get_range(line_start, pos);
        let current_indent = line_text.len() - line_text.trim_start().len();
        let current_indent_str = &line_text[..current_indent];
        
        // Insert newline + indent
        let insert = alloc::string::String::from("\n");
        let insert = if text.autoindent() {
            insert + current_indent_str
        } else {
            insert + indent
        };
        
        text.insert(pos, &insert);
        text.q0 += insert.len();
        text.q1 = text.q0;
    }

    /// Indent selected lines
    pub fn indent_selection(text: &mut Text, indent: &str) {
        let (q0, q1) = if text.q0 <= text.q1 {
            (text.q0, text.q1)
        } else {
            (text.q1, text.q0)
        };
        
        let line_start = text.line_start(q0);
        
        // Insert indent at beginning of each line in selection
        let mut pos = line_start;
        while pos <= q1 && pos < text.len() {
            text.insert(pos, indent);
            pos = text.line_end(pos + indent.len()) + 1;
        }
    }

    /// Unindent selected lines
    pub fn unindent_selection(text: &mut Text, indent: &str) {
        let (q0, q1) = if text.q0 <= text.q1 {
            (text.q0, text.q1)
        } else {
            (text.q1, text.q0)
        };
        
        let line_start = text.line_start(q0);
        let indent_bytes = indent.as_bytes();
        
        // Remove indent from each line in selection
        let mut pos = line_start;
        while pos <= q1 && pos < text.len() {
            let line_text = text.get_range(pos, text.line_end(pos));
            if line_text.starts_with(indent) {
                text.delete(pos, pos + indent.len());
            }
            pos = text.line_end(pos) + 1;
        }
    }

    /// Move line up
    pub fn move_line_up(text: &mut Text) {
        let line = text.line_at(text.q0);
        if line <= 1 {
            return;
        }
        
        let prev_start = text.offset_of_line(line - 1);
        let this_start = text.offset_of_line(line);
        let this_end = text.line_end(text.q0) + 1;
        
        let this_line = text.get_range(this_start, this_end);
        
        text.delete(this_start, this_end);
        text.insert(prev_start, &this_line);
    }

    /// Move line down
    pub fn move_line_down(text: &mut Text) {
        let line = text.line_at(text.q0);
        let total_lines = text.line_count();
        if line >= total_lines {
            return;
        }
        
        let this_start = text.offset_of_line(line);
        let this_end = text.line_end(text.q0) + 1;
        let next_start = text.offset_of_line(line + 1);
        let next_end = text.line_end(next_start) + 1;
        
        let this_line = text.get_range(this_start, this_end);
        let next_line = text.get_range(next_start, next_end.min(text.len()));
        
        text.delete(this_start, next_end);
        text.insert(this_start, &next_line);
        text.insert(this_start + next_line.len(), &this_line);
    }

    /// Duplicate line
    pub fn duplicate_line(text: &mut Text) {
        let line_start = text.line_start(text.q0);
        let line_end = text.line_end(text.q0) + 1;
        let line = text.get_range(line_start, line_end);
        text.insert(line_end, &line);
    }

    /// Comment/uncomment line
    pub fn toggle_comment(text: &mut Text, comment: &str) {
        let line_start = text.line_start(text.q0);
        let line_end = text.line_end(text.q0);
        let line = text.get_range(line_start, line_end);
        
        if line.trim_start().starts_with(comment) {
            // Uncomment
            let trimmed = line.trim_start();
            let leading = line.len() - trimmed.len();
            text.delete(line_start + leading, line_start + leading + comment.len());
        } else {
            // Comment
            text.insert(line_start + (line.len() - line.trim_start().len()), comment);
        }
    }

    /// Sort selected lines
    pub fn sort_selection(text: &mut Text) {
        let (q0, q1) = if text.q0 <= text.q1 {
            (text.q0, text.q1)
        } else {
            (text.q1, text.q0)
        };
        
        let line_start = text.line_start(q0);
        let line_end = text.line_end(q1) + 1;
        
        let content = text.get_range(line_start, line_end);
        let mut lines: Vec<&str> = content.lines().collect();
        lines.sort();
        
        let sorted = lines.join("\n");
        text.delete(line_start, line_end);
        text.insert(line_start, &sorted);
    }

    /// Reverse selected lines
    pub fn reverse_selection(text: &mut Text) {
        let (q0, q1) = if text.q0 <= text.q1 {
            (text.q0, text.q1)
        } else {
            (text.q1, text.q0)
        };
        
        let line_start = text.line_start(q0);
        let line_end = text.line_end(q1) + 1;
        
        let content = text.get_range(line_start, line_end);
        let mut lines: Vec<&str> = content.lines().collect();
        lines.reverse();
        
        let reversed = lines.join("\n");
        text.delete(line_start, line_end);
        text.insert(line_start, &reversed);
    }
}

impl Text {
    /// Check if byte is word character (internal helper)
    pub(crate) fn is_word_char_internal(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    
    /// Check auto-indent flag (placeholder)
    pub fn autoindent(&self) -> bool {
        true
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

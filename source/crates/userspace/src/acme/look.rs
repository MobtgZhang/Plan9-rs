//! Look/Search Module
//!
//! Implements text searching and lookup functionality for Acme.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/look.c`

use crate::acme::text::Text;

/// Search mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Forward,
    Backward,
    CaseSensitive,
    CaseInsensitive,
    Regex,
    WholeWord,
}

/// Search options
#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub mode: SearchMode,
    pub wrap: bool,
    pub max_matches: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            mode: SearchMode::Forward,
            wrap: true,
            max_matches: usize::MAX,
        }
    }
}

/// Search result
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub pos: usize,
    pub len: usize,
    pub line: usize,
    pub column: usize,
    pub text: alloc::string::String,
}

/// Look (search) engine
pub struct Look {
    /// Current pattern
    pattern: alloc::string::String,
    /// Options
    options: SearchOptions,
    /// Search history
    history: alloc::vec::Vec<alloc::string::String>,
}

impl Look {
    /// Create a new Look engine
    pub fn new() -> Self {
        Self {
            pattern: alloc::string::String::new(),
            options: SearchOptions::default(),
            history: alloc::vec::Vec::new(),
        }
    }

    /// Set search pattern
    pub fn set_pattern(&mut self, pattern: &str) {
        self.pattern = alloc::string::String::from(pattern);
        if !self.pattern.is_empty() && !self.history.contains(&self.pattern) {
            self.history.push(self.pattern.clone());
        }
    }

    /// Get current pattern
    pub fn get_pattern(&self) -> &str {
        &self.pattern
    }

    /// Set search mode
    pub fn set_mode(&mut self, mode: SearchMode) {
        self.options.mode = mode;
    }

    /// Set wrap option
    pub fn set_wrap(&mut self, wrap: bool) {
        self.options.wrap = wrap;
    }

    /// Search in text (forward)
    pub fn search_forward(&self, text: &Text, start: usize) -> Option<SearchResult> {
        let pattern = self.pattern.as_bytes();
        let data = &text.get_text().into_bytes();
        
        if pattern.is_empty() || start >= data.len() {
            return None;
        }
        
        let search_data = if self.options.mode == SearchMode::CaseInsensitive {
            self.to_lowercase(&data[start..])
        } else {
            data[start..].to_vec()
        };
        
        let search_pattern = if self.options.mode == SearchMode::CaseInsensitive {
            self.to_lowercase(pattern)
        } else {
            pattern.to_vec()
        };
        
        if let Some(pos) = self.find_pattern(&search_data, &search_pattern) {
            let abs_pos = start + pos;
            Some(self.create_result(text, abs_pos, pattern.len()))
        } else if self.options.wrap && start > 0 {
            // Wrap to beginning
            let search_data = if self.options.mode == SearchMode::CaseInsensitive {
                self.to_lowercase(data)
            } else {
                data.to_vec()
            };
            
            if let Some(pos) = self.find_pattern(&search_data, &search_pattern) {
                Some(self.create_result(text, pos, pattern.len()))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Search in text (backward)
    pub fn search_backward(&self, text: &Text, start: usize) -> Option<SearchResult> {
        let pattern = self.pattern.as_bytes();
        let data = &text.get_text().into_bytes();
        
        if pattern.is_empty() {
            return None;
        }
        
        let end = if start > 0 { start - 1 } else { data.len() };
        let search_data = if self.options.mode == SearchMode::CaseInsensitive {
            self.to_lowercase(&data[..end])
        } else {
            data[..end].to_vec()
        };
        
        let search_pattern = if self.options.mode == SearchMode::CaseInsensitive {
            self.to_lowercase(pattern)
        } else {
            pattern.to_vec()
        };
        
        // Search backwards by finding last occurrence
        let mut pos = search_data.len().saturating_sub(pattern.len());
        while pos > 0 {
            if self.matches_at(&search_data, &search_pattern, pos) {
                return Some(self.create_result(text, pos, pattern.len()));
            }
            pos -= 1;
        }
        
        if self.options.wrap && end < data.len() {
            // Wrap to end
            let search_data = if self.options.mode == SearchMode::CaseInsensitive {
                self.to_lowercase(data)
            } else {
                data.to_vec()
            };
            
            let mut pos = search_data.len().saturating_sub(pattern.len());
            while pos >= end {
                if self.matches_at(&search_data, &search_pattern, pos) {
                    return Some(self.create_result(text, pos, pattern.len()));
                }
                if pos == 0 { break; }
                pos -= 1;
            }
        }
        
        None
    }

    /// Find all matches
    pub fn find_all(&self, text: &Text) -> alloc::vec::Vec<SearchResult> {
        let mut results = alloc::vec::Vec::new();
        let mut pos = 0;
        
        while results.len() < self.options.max_matches {
            if let Some(result) = self.search_forward(text, pos) {
                results.push(result);
                pos = results.last().unwrap().pos + 1;
            } else {
                break;
            }
        }
        
        results
    }

    /// Replace all occurrences
    pub fn replace_all(&self, text: &mut Text, replacement: &str) -> usize {
        let results = self.find_all(text);
        let mut count = 0;
        let mut offset = 0i32;
        
        for result in results.iter().rev() {
            let pos = result.pos + offset as usize;
            text.delete(pos, pos + result.len);
            text.insert(pos, replacement);
            offset += replacement.len() as i32 - result.len as i32;
            count += 1;
        }
        
        count
    }

    /// Get search history
    pub fn get_history(&self) -> &[alloc::string::String] {
        &self.history
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Find pattern helper
    fn find_pattern(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        match self.options.mode {
            SearchMode::WholeWord => {
                let mut pos = 0;
                while pos <= data.len().saturating_sub(pattern.len()) {
                    if self.whole_word_match(data, pattern, pos) {
                        return Some(pos);
                    }
                    pos += 1;
                }
                None
            }
            _ => {
                data.windows(pattern.len())
                    .position(|w| w == pattern)
            }
        }
    }

    /// Check for whole word match
    fn whole_word_match(&self, data: &[u8], pattern: &[u8], pos: usize) -> bool {
        // Check if pattern matches at position
        if !data[pos..].starts_with(pattern) {
            return false;
        }
        
        let end_pos = pos + pattern.len();
        
        // Check character before (if exists)
        let before_ok = pos == 0 || !Self::is_word_char(data[pos - 1]);
        
        // Check character after (if exists)
        let after_ok = end_pos >= data.len() || !Self::is_word_char(data[end_pos]);
        
        before_ok && after_ok
    }

    /// Check if byte is word character
    fn is_word_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// Check if pattern matches at position
    fn matches_at(&self, data: &[u8], pattern: &[u8], pos: usize) -> bool {
        if self.options.mode == SearchMode::WholeWord {
            self.whole_word_match(data, pattern, pos)
        } else {
            data[pos..].starts_with(pattern)
        }
    }

    /// Create search result
    fn create_result(&self, text: &Text, pos: usize, len: usize) -> SearchResult {
        let line = text.line_at(pos);
        let line_start = text.offset_of_line(line);
        let column = pos - line_start;
        
        SearchResult {
            pos,
            len,
            line,
            column,
            text: text.get_range(pos, pos + len),
        }
    }

    /// Convert to lowercase
    fn to_lowercase(&self, data: &[u8]) -> alloc::vec::Vec<u8> {
        data.iter().map(|b| b.to_ascii_lowercase()).collect()
    }
}

impl Default for Look {
    fn default() -> Self {
        Self::new()
    }
}

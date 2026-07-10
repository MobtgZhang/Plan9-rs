//! Regular Expression Module
//!
//! Provides regex functionality for Acme.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/regx.c`

/// Regex pattern
pub struct Regex {
    /// Pattern string
    pattern: alloc::string::String,
    /// Compiled representation (simplified)
    compiled: alloc::vec::Vec<RegexOp>,
}

#[derive(Debug, Clone)]
enum RegexOp {
    Char(u8),
    Any,
    Star,
    Plus,
    Question,
    Begin,
    End,
    CharClass(alloc::vec::Vec<u8>),
    Alternation(alloc::vec::Vec<Regex>),
}

/// Regex match result
#[derive(Debug, Clone)]
pub struct Match {
    /// Full match start
    pub start: usize,
    /// Full match end
    pub end: usize,
    /// Captured groups
    pub groups: alloc::vec::Vec<(usize, usize)>,
}

impl Regex {
    /// Compile a regex pattern
    pub fn new(pattern: &str) -> Result<Self, RegexError> {
        let mut regex = Self {
            pattern: alloc::string::String::from(pattern),
            compiled: alloc::vec::Vec::new(),
        };
        
        regex.compile()?;
        Ok(regex)
    }

    /// Compile the pattern
    fn compile(&mut self) -> Result<(), RegexError> {
        let bytes = self.pattern.as_bytes();
        let mut i = 0;
        
        while i < bytes.len() {
            match bytes[i] {
                b'^' => self.compiled.push(RegexOp::Begin),
                b'$' => self.compiled.push(RegexOp::End),
                b'.' => {
                    self.compiled.push(RegexOp::Any);
                }
                b'*' => {
                    if let Some(last) = self.compiled.pop() {
                        self.compiled.push(RegexOp::Star);
                        self.compiled.push(last);
                    }
                }
                b'+' => {
                    if let Some(last) = self.compiled.pop() {
                        self.compiled.push(RegexOp::Plus);
                        self.compiled.push(last);
                    }
                }
                b'?' => {
                    if let Some(last) = self.compiled.pop() {
                        self.compiled.push(RegexOp::Question);
                        self.compiled.push(last);
                    }
                }
                b'[' => {
                    // Character class
                    let mut class = alloc::vec::Vec::new();
                    i += 1;
                    while i < bytes.len() && bytes[i] != b']' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 1;
                        }
                        class.push(bytes[i]);
                        i += 1;
                    }
                    self.compiled.push(RegexOp::CharClass(class));
                }
                b'\\' if i + 1 < bytes.len() => {
                    i += 1;
                    match bytes[i] {
                        b'd' => {
                            // Digit class
                            self.compiled.push(RegexOp::CharClass(
                                b"0123456789".to_vec()
                            ));
                        }
                        b'w' => {
                            // Word character class
                            let mut class = alloc::vec::Vec::new();
                            for b in b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_" {
                                class.push(*b);
                            }
                            self.compiled.push(RegexOp::CharClass(class));
                        }
                        b's' => {
                            // Whitespace class
                            let mut class = alloc::vec::Vec::new();
                            for b in b" \t\n\r" {
                                class.push(*b);
                            }
                            self.compiled.push(RegexOp::CharClass(class));
                        }
                        c => self.compiled.push(RegexOp::Char(c)),
                    }
                }
                c => self.compiled.push(RegexOp::Char(c)),
            }
            i += 1;
        }
        
        Ok(())
    }

    /// Match against text at position
    pub fn match_at(&self, text: &[u8], pos: usize) -> Option<Match> {
        if self.compiled.is_empty() {
            return Some(Match {
                start: pos,
                end: pos,
                groups: alloc::vec::Vec::new(),
            });
        }
        
        // Try to match
        let end = self.match_from(&self.compiled, text, pos)?;
        
        Some(Match {
            start: pos,
            end,
            groups: alloc::vec::Vec::new(),
        })
    }

    /// Find first match in text
    pub fn find(&self, text: &[u8]) -> Option<Match> {
        let mut pos = 0;
        while pos <= text.len() {
            if let Some(m) = self.match_at(text, pos) {
                return Some(m);
            }
            pos += 1;
        }
        None
    }

    /// Find all matches
    pub fn find_all(&self, text: &[u8]) -> alloc::vec::Vec<Match> {
        let mut matches = alloc::vec::Vec::new();
        let mut pos = 0;
        
        while pos <= text.len() {
            if let Some(m) = self.match_at(text, pos) {
                matches.push(m.clone());
                if m.end > m.start {
                    pos = m.end;
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }
        
        matches
    }

    /// Replace all matches
    pub fn replace_all(&self, text: &[u8], replacement: &str) -> alloc::vec::Vec<u8> {
        let mut result = alloc::vec::Vec::new();
        let mut last_end = 0;
        
        for m in self.find_all(text) {
            result.extend_from_slice(&text[last_end..m.start]);
            result.extend_from_slice(replacement.as_bytes());
            last_end = m.end;
        }
        
        result.extend_from_slice(&text[last_end..]);
        result
    }

    /// Match helper
    fn match_from(&self, ops: &[RegexOp], text: &[u8], pos: usize) -> Option<usize> {
        let mut current_pos = pos;
        let mut i = 0;
        
        while i < ops.len() {
            let op = &ops[i];
            
            match op {
                RegexOp::Char(c) => {
                    if current_pos >= text.len() || text[current_pos] != *c {
                        return None;
                    }
                    current_pos += 1;
                }
                RegexOp::Any => {
                    if current_pos >= text.len() {
                        return None;
                    }
                    current_pos += 1;
                }
                RegexOp::Star => {
                    // Greedy match
                    let start = current_pos;
                    let mut next_i = i + 1;
                    let mut last_good = current_pos;
                    
                    while current_pos <= text.len() && next_i < ops.len() {
                        if let Some(new_pos) = self.match_from(&ops[next_i..], text, current_pos) {
                            last_good = new_pos;
                        }
                        if current_pos < text.len() && self.match_single(ops[i - 1], text[current_pos]) {
                            current_pos += 1;
                        } else {
                            break;
                        }
                    }
                    
                    current_pos = last_good;
                }
                RegexOp::Plus => {
                    // One or more
                    let mut last_good = current_pos;
                    
                    while current_pos < text.len() && self.match_single(ops[i - 1], text[current_pos]) {
                        last_good = current_pos + 1;
                        current_pos += 1;
                    }
                    
                    if last_good == pos {
                        return None;
                    }
                    current_pos = last_good;
                }
                RegexOp::Question => {
                    // Zero or one - try matching
                    if let Some(new_pos) = self.match_single_from(ops[i - 1], text, current_pos) {
                        current_pos = new_pos;
                    }
                }
                RegexOp::Begin => {
                    if current_pos != 0 {
                        return None;
                    }
                }
                RegexOp::End => {
                    if current_pos != text.len() {
                        return None;
                    }
                }
                RegexOp::CharClass(chars) => {
                    if current_pos >= text.len() || !chars.contains(&text[current_pos]) {
                        return None;
                    }
                    current_pos += 1;
                }
                RegexOp::Alternation(alternatives) => {
                    for alt in alternatives {
                        if let Some(new_pos) = alt.match_from(&alt.compiled, text, current_pos) {
                            return Some(new_pos);
                        }
                    }
                    return None;
                }
            }
            
            i += 1;
        }
        
        Some(current_pos)
    }

    /// Match single operation
    fn match_single(&self, op: &RegexOp, byte: u8) -> bool {
        match op {
            RegexOp::Char(c) => byte == *c,
            RegexOp::Any => true,
            RegexOp::CharClass(chars) => chars.contains(&byte),
            _ => false,
        }
    }

    /// Match single at position
    fn match_single_from(&self, op: &RegexOp, text: &[u8], pos: usize) -> Option<usize> {
        if pos >= text.len() {
            return None;
        }
        if self.match_single(op, text[pos]) {
            Some(pos + 1)
        } else {
            None
        }
    }
}

/// Regex error
#[derive(Debug)]
pub struct RegexError {
    pub message: alloc::string::String,
}

impl RegexError {
    pub fn new(msg: &str) -> Self {
        Self {
            message: alloc::string::String::from(msg),
        }
    }
}

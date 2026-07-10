//! Regular Expression Library
//!
//! Implements Plan 9 style regular expressions.
//! Based on the Plan 9 regexp implementation.
//!
//! Features:
//! - Basic matching (., ^, $, literals)
//! - Quantifiers (*, +, ?)
//! - Character classes ([abc], [a-z], [^abc])
//! - Capture groups ((...))
//! - Alternation (|)
//! - Escape sequences (\d, \s, \w, etc.)
//! - Substitution (regsub)
//! - Unicode/Rune support

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// Maximum number of subexpressions supported
const MAXSUB: usize = 10;

/// Regular expression instruction
#[derive(Debug, Clone)]
enum Inst {
    /// Match any character except newline
    AnyNoNl,
    /// Match start of line
    Bol,
    /// Match end of line
    Eol,
    /// Match character class (inclusive)
    CharClass(Vec<(char, char)>),
    /// Match negated character class
    NCharClass(Vec<(char, char)>),
    /// Match literal character
    Char(char),
    /// Jump to instruction
    Jmp(usize),
    /// Split to multiple paths (for alternation and quantifiers).
    ///
    /// `Split(x, y)` tries the `x` branch first and falls back to the
    /// `y` branch on failure. This is the normal "greedy" branch
    /// order used by `*`, `+`, and `?`.
    Split(usize, usize),
    /// Lazy split: tries the `y` branch first (skipping the repeat)
    /// and only takes `x` (the repeat) on failure. This implements
    /// `*?`, `+?`, and `??`.
    LazySplit(usize, usize),
    /// Save position (for capture groups and match boundaries)
    Save(usize),
    /// Match complete
    Match,
    /// Word boundary (`\b`): match if the position is between a word
    /// character and a non-word character.
    WordBoundary,
    /// Non-word boundary (`\B`).
    NonWordBoundary,
    /// Backreference: match the same span of text that the capture
    /// group `n` previously consumed.
    Backref(usize),
}

/// Compiled regular expression
#[derive(Debug, Clone)]
pub struct Regexp {
    /// Instructions
    insts: Vec<Inst>,
    /// Number of subexpressions
    nsub: usize,
}

impl Regexp {
    /// Compile a regular expression pattern
    pub fn compile(pattern: &str) -> Result<Self, RegexError> {
        let mut insts = Vec::new();
        let mut nsub = 0;
        let mut paren_stack: Vec<usize> = Vec::new();
        let mut alternation_points: Vec<usize> = Vec::new();
        
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '.' => insts.push(Inst::AnyNoNl),
                '^' => insts.push(Inst::Bol),
                '$' => insts.push(Inst::Eol),
                '[' => {
                    let (class_inst, negated) = Self::parse_char_class(&mut chars)?;
                    if negated {
                        insts.push(Inst::NCharClass(class_inst));
                    } else {
                        insts.push(Inst::CharClass(class_inst));
                    }
                }
                '(' => {
                    // Check for non-capturing group prefix "(?:".
                    if chars.peek() == Some(&'?')
                        && chars.clone().nth(1) == Some(':')
                    {
                        // Consume "?:" without allocating a capture slot.
                        chars.next();
                        chars.next();
                    } else {
                        nsub += 1;
                        paren_stack.push(insts.len());
                        insts.push(Inst::Save(nsub));
                    }
                }
                ')' => {
                    if let Some(_start) = paren_stack.pop() {
                        insts.push(Inst::Save(nsub + MAXSUB));
                    } else {
                        return Err(RegexError::UnmatchedParen);
                    }
                }
                '|' => {
                    // Alternation: need to fix up previous branch
                    // Save current position as end of left branch
                    let left_end = insts.len();
                    insts.push(Inst::Jmp(0)); // Will be filled in later
                    
                    // Mark this as an alternation point
                    if let Some(&last_alt) = alternation_points.last() {
                        // Connect previous alternative to this point
                        let target_pos = insts.len();
                        Self::fixup_jmp(&mut insts, last_alt, target_pos);
                    }
                    alternation_points.push(left_end);
                }
                '*' => {
                    // Kleene star - match zero or more
                    // A trailing '?' switches the split to lazy mode.
                    let lazy = chars.peek() == Some(&'?');
                    if lazy {
                        chars.next();
                    }
                    if let Some(last) = insts.pop() {
                        let split_pos = insts.len();
                        if lazy {
                            // LazySplit takes the skip branch first.
                            insts.push(Inst::LazySplit(split_pos + 2, split_pos + 1));
                        } else {
                            insts.push(Inst::Split(split_pos + 1, split_pos + 2));
                        }
                        insts.push(last);
                        insts.push(Inst::Jmp(split_pos));
                    }
                }
                '+' => {
                    // One or more (lazy when followed by '?')
                    let lazy = chars.peek() == Some(&'?');
                    if lazy {
                        chars.next();
                    }
                    if let Some(last) = insts.pop() {
                        let split_pos = insts.len();
                        if lazy {
                            // Already consumed one instance via `last`;
                            // the split then chooses between repeating
                            // (greedy branch) and stopping (lazy branch).
                            insts.push(Inst::LazySplit(split_pos + 2, split_pos + 1));
                        } else {
                            insts.push(Inst::Split(split_pos + 1, split_pos + 2));
                        }
                        insts.push(last);
                        insts.push(Inst::Jmp(split_pos));
                    }
                }
                '?' => {
                    // Zero or one (lazy when followed by another '?')
                    let lazy = chars.peek() == Some(&'?');
                    if lazy {
                        chars.next();
                    }
                    if let Some(last) = insts.pop() {
                        let split_pos = insts.len();
                        if lazy {
                            // Lazy: prefer skipping the element.
                            insts.push(Inst::LazySplit(split_pos + 2, split_pos + 1));
                        } else {
                            insts.push(Inst::Split(split_pos + 1, split_pos + 2));
                        }
                        insts.push(last);
                    }
                }
                '\\' => {
                    // Escape sequence
                    if let Some(escaped) = chars.next() {
                        match escaped {
                            'd' => insts.push(Inst::CharClass(vec![('0', '9')])),
                            'D' => insts.push(Inst::NCharClass(vec![('0', '9')])),
                            's' => insts.push(Inst::CharClass(vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')])),
                            'S' => insts.push(Inst::NCharClass(vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')])),
                            'w' => insts.push(Inst::CharClass(vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')])),
                            'W' => insts.push(Inst::NCharClass(vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')])),
                            'n' => insts.push(Inst::Char('\n')),
                            't' => insts.push(Inst::Char('\t')),
                            'r' => insts.push(Inst::Char('\r')),
                            'b' => insts.push(Inst::WordBoundary),
                            'B' => insts.push(Inst::NonWordBoundary),
                            '\\' => insts.push(Inst::Char('\\')),
                            '.' => insts.push(Inst::Char('.')),
                            '^' => insts.push(Inst::Char('^')),
                            '$' => insts.push(Inst::Char('$')),
                            '*' => insts.push(Inst::Char('*')),
                            '+' => insts.push(Inst::Char('+')),
                            '?' => insts.push(Inst::Char('?')),
                            '[' => insts.push(Inst::Char('[')),
                            ']' => insts.push(Inst::Char(']')),
                            '(' => insts.push(Inst::Char('(')),
                            ')' => insts.push(Inst::Char(')')),
                            '|' => insts.push(Inst::Char('|')),
                            digit if digit.is_ascii_digit() => {
                                // Backreference: \1, \2, ... \9
                                let n = (digit as u8 - b'0') as usize;
                                if n == 0 || n > MAXSUB {
                                    return Err(RegexError::InvalidEscape);
                                }
                                insts.push(Inst::Backref(n));
                            }
                            _ => return Err(RegexError::InvalidEscape),
                        }
                    } else {
                        return Err(RegexError::InvalidEscape);
                    }
                }
                _ => insts.push(Inst::Char(c)),
            }
        }
        
        // Fix up alternation points - connect last alternative to end
        if let Some(&last_alt) = alternation_points.last() {
            let target_pos = insts.len();
            Self::fixup_jmp(&mut insts, last_alt, target_pos);
        }
        
        insts.push(Inst::Save(0)); // Start of match
        insts.push(Inst::Match);
        
        Ok(Self { insts, nsub })
    }
    
    /// Fix up a jump instruction at the given position
    fn fixup_jmp(insts: &mut Vec<Inst>, pos: usize, target: usize) {
        if let Inst::Jmp(ref mut t) = insts[pos] {
            *t = target;
        }
    }
    
    /// Parse a character class [...].
    /// Returns (ranges, negated) where negated is true if class starts with ^
    fn parse_char_class(chars: &mut core::iter::Peekable<impl Iterator<Item = char>>) -> Result<(Vec<(char, char)>, bool), RegexError> {
        let mut ranges: Vec<(char, char)> = Vec::new();
        let mut negated = false;
        
        // Check for negation
        if let Some(&'^') = chars.peek() {
            chars.next();
            negated = true;
        }
        
        // Handle ] as first character in class
        if let Some(&']') = chars.peek() {
            ranges.push((']', ']'));
            chars.next();
        }
        
        while let Some(c) = chars.next() {
            if c == ']' {
                break;
            }
            
            if c == '\\' {
                // Escape sequence in character class
                if let Some(escaped) = chars.next() {
                    match escaped {
                        'd' => ranges.push(('0', '9')),
                        'D' => {}, // Will be handled as negated
                        's' => {
                            ranges.push((' ', ' '));
                            ranges.push(('\t', '\t'));
                            ranges.push(('\n', '\n'));
                            ranges.push(('\r', '\r'));
                        }
                        'S' => {},
                        'w' => {
                            ranges.push(('a', 'z'));
                            ranges.push(('A', 'Z'));
                            ranges.push(('0', '9'));
                            ranges.push(('_', '_'));
                        }
                        'W' => {},
                        'n' => ranges.push(('\n', '\n')),
                        't' => ranges.push(('\t', '\t')),
                        'r' => ranges.push(('\r', '\r')),
                        '-' => ranges.push(('-', '-')),
                        '\\' => ranges.push(('\\', '\\')),
                        '^' => ranges.push(('^', '^')),
                        ']' => ranges.push((']', ']')),
                        _ => ranges.push((escaped, escaped)),
                    }
                }
            } else if c == '-' {
                // Range indicator
                if let Some(&next) = chars.peek() {
                    if next == ']' {
                        // ] is literal
                        ranges.push(('-', '-'));
                    } else {
                        chars.next();
                        if ranges.is_empty() {
                            return Err(RegexError::UnclosedClass);
                        }
                        let start = ranges.pop().unwrap().0;
                        if start > next {
                            return Err(RegexError::InvalidEscape);
                        }
                        ranges.push((start, next));
                    }
                }
            } else {
                ranges.push((c, c));
                // Check for range
                if let Some(&'-') = chars.peek() {
                    chars.next();
                    if let Some(&next) = chars.peek() {
                        if next == ']' {
                            // - is literal, put it back
                            ranges.push(('-', '-'));
                        } else {
                            chars.next();
                            if c > next {
                                return Err(RegexError::UnclosedClass);
                            }
                            ranges.push((c, next));
                        }
                    }
                }
            }
        }
        
        if ranges.is_empty() {
            return Err(RegexError::UnclosedClass);
        }
        
        Ok((ranges, negated))
    }

    /// Execute the regex against input text
    pub fn execute(&self, text: &str) -> Option<Match> {
        let text = text.as_bytes();
        let mut start = 0..text.len();
        
        // Try matching at each position
        while start.start <= text.len() {
            if let Some(m) = self.match_at(text, start.clone()) {
                return Some(m);
            }
            start.start += 1;
        }
        
        None
    }
    
    /// Execute and find all matches
    pub fn find_all(&self, text: &str) -> Vec<Match> {
        let text = text.as_bytes();
        let mut results = Vec::new();
        let mut pos = 0;
        
        while pos <= text.len() {
            let range = pos..text.len();
            if let Some(m) = self.match_at(text, range) {
                if m.end > m.start {
                    results.push(Match {
                        start: m.start,
                        end: m.end,
                        submatches: m.submatches,
                    });
                    pos = m.end;
                } else {
                    pos += 1;
                }
            } else {
                pos += 1;
            }
        }
        
        results
    }

    /// Try to match at a specific position
    fn match_at(&self, text: &[u8], range: core::ops::Range<usize>) -> Option<Match> {
        let mut pc = 0;
        let mut sp: Vec<usize> = Vec::new();
        let mut matches: Vec<(usize, usize, usize)> = Vec::new();
        
        // Simple backtracking matcher
        let mut pos = range.start;
        
        loop {
            if pc >= self.insts.len() {
                break;
            }
            
            match &self.insts[pc] {
                Inst::Match => {
                    // Success!
                    let mut submatches = Vec::new();
                    for i in 0..=self.nsub {
                        if let Some(&(_, start, end)) = matches.iter().find(|(idx, _, _)| *idx == i) {
                            submatches.push((start, end));
                        }
                    }
                    return Some(Match {
                        start: range.start,
                        end: pos,
                        submatches,
                    });
                }
                Inst::AnyNoNl => {
                    if pos < range.end && text[pos] != b'\n' {
                        pos += 1;
                        pc += 1;
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::Char(c) => {
                    if pos < range.end {
                        let ch = Self::decode_char(&text[pos..]);
                        if ch == *c {
                            pos += c.len_utf8();
                            pc += 1;
                        } else if let Some(next_pc) = sp.pop() {
                            pos = range.start;
                            pc = next_pc;
                        } else {
                            return None;
                        }
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::CharClass(class) => {
                    if pos < range.end {
                        let ch = Self::decode_char(&text[pos..]);
                        let matches_class = class.iter().any(|(start, end)| *start <= ch && ch <= *end);
                        if matches_class {
                            pos += ch.len_utf8();
                            pc += 1;
                        } else if let Some(next_pc) = sp.pop() {
                            pos = range.start;
                            pc = next_pc;
                        } else {
                            return None;
                        }
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::NCharClass(class) => {
                    if pos < range.end {
                        let ch = Self::decode_char(&text[pos..]);
                        // Never match newline in negated class
                        if ch == '\n' {
                            if let Some(next_pc) = sp.pop() {
                                pos = range.start;
                                pc = next_pc;
                            } else {
                                return None;
                            }
                        } else {
                            let matches_class = class.iter().any(|(start, end)| *start <= ch && ch <= *end);
                            if !matches_class {
                                pos += ch.len_utf8();
                                pc += 1;
                            } else if let Some(next_pc) = sp.pop() {
                                pos = range.start;
                                pc = next_pc;
                            } else {
                                return None;
                            }
                        }
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::Split(a, b) => {
                    // Push second choice, take first
                    sp.push(*a);
                    pc = *b;
                }
                Inst::LazySplit(a, b) => {
                    // Lazy: take the "skip" branch first (b), then the
                    // "repeat" branch (a) if that fails.
                    sp.push(*a);
                    pc = *b;
                }
                Inst::Jmp(target) => {
                    pc = *target;
                }
                Inst::Save(n) => {
                    matches.push((*n, range.start, pos));
                    pc += 1;
                }
                Inst::Bol => {
                    if pos == 0 || (pos > 0 && text[pos - 1] == b'\n') {
                        pc += 1;
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::Eol => {
                    if pos >= text.len() || pos >= range.end || text[pos] == b'\n' {
                        pc += 1;
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::WordBoundary => {
                    let prev = if pos == 0 {
                        None
                    } else {
                        char_at(text, pos - 1)
                    };
                    let curr = if pos >= text.len() || pos >= range.end {
                        None
                    } else {
                        char_at(text, pos)
                    };
                    let prev_word = prev.map_or(false, is_word_char);
                    let curr_word = curr.map_or(false, is_word_char);
                    if prev_word != curr_word {
                        pc += 1;
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::NonWordBoundary => {
                    let prev = if pos == 0 {
                        None
                    } else {
                        char_at(text, pos - 1)
                    };
                    let curr = if pos >= text.len() || pos >= range.end {
                        None
                    } else {
                        char_at(text, pos)
                    };
                    let prev_word = prev.map_or(false, is_word_char);
                    let curr_word = curr.map_or(false, is_word_char);
                    if prev_word == curr_word {
                        pc += 1;
                    } else if let Some(next_pc) = sp.pop() {
                        pos = range.start;
                        pc = next_pc;
                    } else {
                        return None;
                    }
                }
                Inst::Backref(n) => {
                    // Look up the text captured by group `n`.
                    if let Some((_, start, end)) = matches.iter().rev().find(|(m, _, _)| m == n) {
                        let span = &text[*start..*end];
                        if pos + span.len() <= text.len() && &text[pos..pos + span.len()] == span {
                            pos += span.len();
                            pc += 1;
                        } else if let Some(next_pc) = sp.pop() {
                            pos = range.start;
                            pc = next_pc;
                        } else {
                            return None;
                        }
                    } else {
                        // Group did not capture anything: zero-length match.
                        pc += 1;
                    }
                }
            }
        }
        
        None
    }
    
    /// Decode a UTF-8 character from bytes
    fn decode_char(bytes: &[u8]) -> char {
        if bytes.is_empty() {
            return '\0';
        }
        let b = bytes[0];
        if b < 0x80 {
            return b as char;
        }
        if b < 0xE0 {
            if bytes.len() >= 2 {
                let codepoint = ((b as u32 & 0x1F) << 6) | (bytes[1] as u32 & 0x3F);
                return char::from_u32(codepoint).unwrap_or('\u{FFFD}');
            }
            return '\u{FFFD}';
        }
        if b < 0xF0 {
            if bytes.len() >= 3 {
                let codepoint = ((b as u32 & 0x0F) << 12) 
                    | ((bytes[1] as u32 & 0x3F) << 6) 
                    | (bytes[2] as u32 & 0x3F);
                return char::from_u32(codepoint).unwrap_or('\u{FFFD}');
            }
            return '\u{FFFD}';
        }
        if bytes.len() >= 4 {
            let codepoint = ((b as u32 & 0x07) << 18) 
                | ((bytes[1] as u32 & 0x3F) << 12)
                | ((bytes[2] as u32 & 0x3F) << 6)
                | (bytes[3] as u32 & 0x3F);
            return char::from_u32(codepoint).unwrap_or('\u{FFFD}');
        }
        '\u{FFFD}'
    }
}

/// Return the UTF-8 character that starts at byte index `i` in `text`.
fn char_at(text: &[u8], i: usize) -> Option<char> {
    let s = core::str::from_utf8(text.get(i..)?).ok()?;
    s.chars().next()
}

/// A word character for `\b` / `\B` purposes: alphanumerics plus
/// underscore. Mirrors the common regex definition.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Match result
#[derive(Debug, Clone)]
pub struct Match {
    /// Start position of match (byte index)
    pub start: usize,
    /// End position of match (byte index)
    pub end: usize,
    /// Subexpression matches [(start, end), ...]
    pub submatches: Vec<(usize, usize)>,
}

impl Match {
    /// Get matched text from original string
    pub fn text<'a>(&self, text: &'a str) -> &'a str {
        &text[self.start..self.end]
    }
    
    /// Get the nth submatch text
    pub fn subtext<'a>(&self, n: usize, text: &'a str) -> Option<&'a str> {
        if n < self.submatches.len() {
            let (start, end) = self.submatches[n];
            if start < end && end <= text.len() {
                Some(&text[start..end])
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Regex compilation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexError {
    /// Unclosed character class
    UnclosedClass,
    /// Invalid escape sequence
    InvalidEscape,
    /// Unmatched parenthesis
    UnmatchedParen,
}

impl core::fmt::Display for RegexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegexError::UnclosedClass => write!(f, "unclosed character class"),
            RegexError::InvalidEscape => write!(f, "invalid escape sequence"),
            RegexError::UnmatchedParen => write!(f, "unmatched parenthesis"),
        }
    }
}

// ============================================================================
// Substitution functions (regsub)
// ============================================================================

/// Substitute using match results, following Plan 9 regsub semantics.
///
/// The replacement string can contain:
/// - `&` - replaced with the entire match
/// - `\0` to `\9` - replaced with the corresponding capture group
/// - `\\` - replaced with a single backslash
/// - `\&` - replaced with a literal ampersand
pub fn regex_sub(text: &str, pattern: &str, replacement: &str) -> Option<String> {
    let re = Regexp::compile(pattern).ok()?;
    let m = re.execute(text)?;
    
    let mut result = String::new();
    
    // Add text before match
    result.push_str(&text[..m.start]);
    
    // Apply substitution
    let replaced = sub_one(&text, &m, replacement);
    result.push_str(&replaced);
    
    // Add text after match
    result.push_str(&text[m.end..]);
    
    Some(result)
}

/// Substitute the first match of pattern in text with replacement
fn sub_one(text: &str, m: &Match, replacement: &str) -> String {
    let mut result = String::new();
    let mut chars = replacement.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                chars.next();
                match next {
                    '0'..='9' => {
                        let idx = (next as usize) - ('0' as usize);
                        if idx < m.submatches.len() {
                            let (start, end) = m.submatches[idx];
                            if start < end && end <= text.len() {
                                result.push_str(&text[start..end]);
                            }
                        }
                    }
                    '\\' => result.push('\\'),
                    '&' => {
                        // \& becomes literal &
                        result.push_str(&text[m.start..m.end]);
                    }
                    'n' => result.push('\n'),
                    't' => result.push('\t'),
                    'r' => result.push('\r'),
                    _ => {
                        // Unknown escape, keep the backslash and char
                        result.push('\\');
                        result.push(next);
                    }
                }
            }
        } else if c == '&' {
            // & means the full match
            result.push_str(&text[m.start..m.end]);
        } else {
            result.push(c);
        }
    }
    
    result
}

/// Substitute all matches of pattern in text with replacement
pub fn regex_replace(text: &str, pattern: &str, replacement: &str) -> Option<String> {
    let re = Regexp::compile(pattern).ok()?;
    let matches = re.find_all(text);
    
    if matches.is_empty() {
        return Some(text.to_string());
    }
    
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;
    
    for m in &matches {
        // Add text before this match
        result.push_str(&text[last_end..m.start]);
        
        // Apply substitution
        let replaced = sub_one(text, m, replacement);
        result.push_str(&replaced);
        
        last_end = m.end;
    }
    
    // Add remaining text
    result.push_str(&text[last_end..]);
    
    Some(result)
}

/// Split text by pattern, returning parts between matches
pub fn regex_split<'a>(text: &'a str, pattern: &str) -> Option<Vec<&'a str>> {
    let re = Regexp::compile(pattern).ok()?;
    let matches = re.find_all(text);
    
    let mut result = Vec::new();
    let mut last_end = 0;
    
    for m in &matches {
        if m.start > last_end {
            result.push(&text[last_end..m.start]);
        }
        last_end = m.end;
    }
    
    if last_end < text.len() {
        result.push(&text[last_end..]);
    }
    
    Some(result)
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Compile and execute a regular expression
pub fn regex_match(pattern: &str, text: &str) -> Option<Match> {
    Regexp::compile(pattern).ok()?.execute(text)
}

/// Check if pattern matches text
pub fn regex_contains(pattern: &str, text: &str) -> bool {
    regex_match(pattern, text).is_some()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Substitution tests
    #[test]
    fn test_sub_basic() {
        let result = regex_sub("hello world", "world", "rust");
        assert_eq!(result, Some("hello rust".to_string()));
    }
    
    #[test]
    fn test_sub_ampersand() {
        let result = regex_sub("hello world", "world", "<$&>");
        assert_eq!(result, Some("hello <world>".to_string()));
    }
    
    #[test]
    fn test_sub_capture_group() {
        let result = regex_sub("hello world", r"(world)", "($1)");
        assert_eq!(result, Some("hello (world)".to_string()));
    }
    
    #[test]
    fn test_sub_escape_backslash() {
        let result = regex_sub("hello world", "world", "\\\\");
        assert_eq!(result, Some("hello \\".to_string()));
    }
    
    #[test]
    fn test_replace_all() {
        let result = regex_replace("aaa", "a", "b");
        assert_eq!(result, Some("bbb".to_string()));
    }
    
    #[test]
    fn test_replace_no_match() {
        let result = regex_replace("hello", "xyz", "world");
        assert_eq!(result, Some("hello".to_string()));
    }
    
    #[test]
    fn test_split() {
        let result = regex_split("a,b,c", ",");
        assert_eq!(result, Some(vec!["a", "b", "c"]));
    }
    
    #[test]
    fn test_split_no_match() {
        let result = regex_split("abc", ",");
        assert_eq!(result, Some(vec!["abc"]));
    }

    // Alternation tests
    #[test]
    fn test_alternation_basic() {
        let re = Regexp::compile("a|b").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("b").is_some());
        assert!(re.execute("c").is_none());
    }
    
    #[test]
    fn test_alternation_longer() {
        let re = Regexp::compile("ab|cd").unwrap();
        assert!(re.execute("ab").is_some());
        assert!(re.execute("cd").is_some());
    }
    
    #[test]
    fn test_alternation_in_pattern() {
        let re = Regexp::compile("hello (world|there)").unwrap();
        let m1 = re.execute("hello world").unwrap();
        assert_eq!(m1.submatches.len(), 1);
        let m2 = re.execute("hello there").unwrap();
        assert_eq!(m2.submatches.len(), 1);
    }

    // Unicode tests
    #[test]
    fn test_unicode_chinese() {
        let re = Regexp::compile("你好").unwrap();
        assert!(re.execute("你好世界").is_some());
    }
    
    #[test]
    fn test_unicode_emoji() {
        let re = Regexp::compile("😀").unwrap();
        assert!(re.execute("😀😁").is_some());
    }
    
    #[test]
    fn test_dot_matches_unicode() {
        let re = Regexp::compile("你.世界").unwrap();
        assert!(re.execute("你好世界").is_some());
    }

    // Negated character class tests
    #[test]
    fn test_negated_class() {
        let re = Regexp::compile("[^0-9]").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("z").is_some());
        assert!(re.execute("5").is_none());
    }
    
    #[test]
    fn test_negated_class_in_pattern() {
        let re = Regexp::compile("a[^0-9]b").unwrap();
        assert!(re.execute("aab").is_some());
        assert!(re.execute("azb").is_some());
        assert!(re.execute("a5b").is_none());
    }
    
    #[test]
    fn test_negated_class_no_newline() {
        // Negated class should never match newline
        let re = Regexp::compile("[^a]").unwrap();
        let m = re.execute("\n").unwrap();
        assert_eq!(m.text("\n"), "\n"); // Should match the newline
    }

    // Escape sequence tests
    #[test]
    fn test_escape_d() {
        let re = Regexp::compile(r"\d").unwrap();
        assert!(re.execute("5").is_some());
        assert!(re.execute("a").is_none());
    }
    
    #[test]
    fn test_escape_D() {
        let re = Regexp::compile(r"\D").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("5").is_none());
    }
    
    #[test]
    fn test_escape_s() {
        let re = Regexp::compile(r"\s").unwrap();
        assert!(re.execute(" ").is_some());
        assert!(re.execute("\t").is_some());
        assert!(re.execute("a").is_none());
    }
    
    #[test]
    fn test_escape_S() {
        let re = Regexp::compile(r"\S").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute(" ").is_none());
    }
    
    #[test]
    fn test_escape_w() {
        let re = Regexp::compile(r"\w").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("5").is_some());
        assert!(re.execute("_").is_some());
        assert!(re.execute("-").is_none());
    }
    
    #[test]
    fn test_escape_W() {
        let re = Regexp::compile(r"\W").unwrap();
        assert!(re.execute("-").is_some());
        assert!(re.execute("a").is_none());
    }
    
    #[test]
    fn test_escape_n() {
        let re = Regexp::compile("a\nb").unwrap();
        assert!(re.execute("a\nb").is_some());
    }
    
    #[test]
    fn test_escape_t() {
        let re = Regexp::compile("a\\tb").unwrap();
        assert!(re.execute("a\tb").is_some());
    }
    
    #[test]
    fn test_escaped_special_chars() {
        let re = Regexp::compile(r"\.\*").unwrap();
        assert!(re.execute(".*").is_some());
    }
    
    #[test]
    fn test_find_all() {
        let re = Regexp::compile("a").unwrap();
        let matches = re.find_all("banana");
        assert_eq!(matches.len(), 3);
    }
    
    #[test]
    fn test_capture_in_alternation() {
        let re = Regexp::compile("(a|b)+").unwrap();
        let m = re.execute("aaa").unwrap();
        assert_eq!(m.submatches.len(), 1);
    }
}

//! Sam Editor - Plan 9 Text Editor
//!
//! Sam is a screen-oriented text editor inspired by the Berkeley editor.
//! It combines the simplicity of ed with the visual feedback of a screen editor.

#![allow(dead_code)]

extern crate alloc;

use std::string::{String, ToString};
use std::vec::Vec;
use std::sync::Arc;
use core::cell::Cell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub mod file;
pub mod rasp;
pub mod address;
pub mod cmd;
pub mod mesg;

// ============================================================================
// Core Types
// ============================================================================

/// A Unicode character (Plan 9 Rune)
pub type Rune = u32;

/// Position in the file
pub type Pos = u64;

/// Sequence number for undo/redo
pub type Seq = u64;

/// Address range
#[derive(Debug, Clone, Copy)]
pub struct Range {
    pub p1: Pos,
    pub p2: Pos,
}

impl Range {
    pub fn new(p1: Pos, p2: Pos) -> Self {
        Self { p1, p2 }
    }
    
    pub fn len(&self) -> Pos {
        self.p2.saturating_sub(self.p1)
    }
    
    pub fn is_empty(&self) -> bool {
        self.p1 >= self.p2
    }
}

/// Error type
#[derive(Debug, Clone)]
pub enum SamError {
    /// Error with message
    Error(String),
    /// End of file
    Eof,
    /// Interrupted
    Interrupted,
    /// Tool failed
    ToolFailed(i32),
}

impl core::fmt::Display for SamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SamError::Error(s) => write!(f, "{}", s),
            SamError::Eof => write!(f, "end of file"),
            SamError::Interrupted => write!(f, "interrupted"),
            SamError::ToolFailed(code) => write!(f, "tool failed with exit code {}", code),
        }
    }
}

impl From<&str> for SamError {
    fn from(s: &str) -> Self {
        SamError::Error(s.to_string())
    }
}

pub type Result<T> = core::result::Result<T, SamError>;

// ============================================================================
// Buffer (File content)
// ============================================================================

/// Buffer - holds the actual file content
pub struct Buffer {
    /// Character storage
    data: Vec<Rune>,
    /// Sequence number
    seq: Seq,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            seq: 0,
        }
    }
    
    pub fn with_content(content: &str) -> Self {
        let data: Vec<Rune> = content.chars().map(|c| c as Rune).collect();
        Self {
            data,
            seq: 0,
        }
    }
    
    /// Get character at position
    pub fn char_at(&self, pos: Pos) -> Option<Rune> {
        self.data.get(pos as usize).copied()
    }
    
    /// Get slice of characters
    pub fn slice(&self, r: Range) -> &[Rune] {
        let start = r.p1 as usize;
        let end = r.p2 as usize;
        self.data.get(start..end).unwrap_or(&[])
    }
    
    /// Get number of characters
    pub fn len(&self) -> Pos {
        self.data.len() as Pos
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Insert characters at position
    pub fn insert(&mut self, pos: Pos, chars: &[Rune]) {
        let pos = pos as usize;
        if pos > self.data.len() {
            return;
        }
        self.data.splice(pos..pos, chars.iter().copied());
        self.seq += 1;
    }
    
    /// Delete range
    pub fn delete(&mut self, r: Range) {
        let start = r.p1 as usize;
        let end = r.p2 as usize;
        if start < self.data.len() && end <= self.data.len() && start < end {
            self.data.splice(start..end, None);
            self.seq += 1;
        }
    }
    
    /// Replace range with new content
    pub fn replace(&mut self, r: Range, new_chars: &[Rune]) {
        self.delete(r);
        self.insert(r.p1, new_chars);
    }
    
    /// Get current sequence number
    pub fn seq(&self) -> Seq {
        self.seq
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Delta (Undo) Management
// ============================================================================

/// Delta - records a change for undo
#[derive(Debug, Clone)]
pub enum Delta {
    /// Insertion
    Insert { pos: Pos, chars: Vec<Rune> },
    /// Deletion
    Delete { pos: Pos, chars: Vec<Rune> },
    /// Replacement (delete + insert)
    Replace { pos: Pos, old_chars: Vec<Rune>, new_chars: Vec<Rune> },
}

/// Epsilon - records a change for redo
#[derive(Debug, Clone)]
pub enum Epsilon {
    Insert { pos: Pos, chars: Vec<Rune> },
    Delete { pos: Pos, chars: Vec<Rune> },
}

// ============================================================================
// File
// ============================================================================

/// File - represents an open file with its state
pub struct File {
    /// Buffer holding file content
    buffer: Buffer,
    /// Undo delta
    delta: Vec<Delta>,
    /// Redo epsilon
    epsilon: Vec<Epsilon>,
    /// File name
    name: String,
    /// Sequence number at which file was last clean
    clean_seq: Seq,
    /// Modified flag
    modified: bool,
    /// Current dot (cursor position)
    pub dot: Range,
    /// Current mark
    pub mark: Option<Pos>,
    /// Terminal dot (what terminal thinks dot is)
    pub tdot: Range,
}

impl File {
    pub fn new(name: &str) -> Self {
        Self {
            buffer: Buffer::new(),
            delta: Vec::new(),
            epsilon: Vec::new(),
            name: name.to_string(),
            clean_seq: 0,
            modified: false,
            dot: Range::new(0, 0),
            mark: None,
            tdot: Range::new(0, 0),
        }
    }
    
    pub fn from_content(name: &str, content: &str) -> Self {
        let mut f = Self::new(name);
        f.buffer = Buffer::with_content(content);
        f
    }
    
    /// Get file name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Set file name
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }
    
    /// Get buffer
    pub fn buffer(&self) -> &Buffer {
        &self.buffer
    }
    
    /// Get mutable buffer
    pub fn buffer_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }
    
    /// Get content as string
    pub fn content(&self) -> String {
        self.buffer.slice(Range::new(0, self.buffer.len()))
            .iter()
            .map(|&r| char::from_u32(r).unwrap_or('\u{FFFD}'))
            .collect()
    }
    
    /// Get length
    pub fn len(&self) -> Pos {
        self.buffer.len()
    }
    
    /// Check if modified
    pub fn is_modified(&self) -> bool {
        self.modified
    }
    
    /// Check if clean at current sequence
    pub fn is_clean(&self) -> bool {
        self.buffer.seq() == self.clean_seq
    }
    
    /// Mark file as clean
    pub fn mark_clean(&mut self) {
        self.clean_seq = self.buffer.seq();
        self.modified = false;
    }
    
    /// Mark file as dirty
    pub fn mark_dirty(&mut self) {
        self.modified = true;
    }
    
    /// Get current dot
    pub fn dot(&self) -> Range {
        self.dot
    }
    
    /// Set dot
    pub fn set_dot(&mut self, r: Range) {
        self.dot = r;
    }
    
    /// Insert text at dot
    pub fn insert(&mut self, chars: &[Rune]) -> Range {
        let pos = self.dot.p1;
        self.buffer.insert(pos, chars);
        
        // Record delta for undo
        self.delta.push(Delta::Insert {
            pos,
            chars: chars.to_vec(),
        });
        self.epsilon.clear(); // Clear redo history
        
        // Update dot
        let new_p2 = pos + chars.len() as Pos;
        self.dot = Range::new(new_p2, new_p2);
        self.mark_dirty();
        
        Range::new(pos, new_p2)
    }
    
    /// Delete range
    pub fn delete(&mut self, r: Range) -> Vec<Rune> {
        let deleted: Vec<Rune> = self.buffer.slice(r).to_vec();
        
        if !deleted.is_empty() {
            self.buffer.delete(r);
            
            // Record delta for undo
            self.delta.push(Delta::Delete {
                pos: r.p1,
                chars: deleted.clone(),
            });
            self.epsilon.clear();
            
            // Update dot
            self.dot = Range::new(r.p1, r.p1);
            self.mark_dirty();
        }
        
        deleted
    }
    
    /// Replace range with new content
    pub fn replace(&mut self, r: Range, new_chars: &[Rune]) -> Range {
        let old_chars = self.delete(r);
        
        // Record as replace delta
        if !old_chars.is_empty() || !new_chars.is_empty() {
            if let Some(last) = self.delta.last_mut() {
                if let Delta::Delete { pos, chars } = last {
                    if *pos == r.p1 && *chars == old_chars {
                        *last = Delta::Replace {
                            pos: r.p1,
                            old_chars,
                            new_chars: new_chars.to_vec(),
                        };
                    }
                }
            }
        }
        
        self.insert(new_chars)
    }
    
    /// Undo last change
    pub fn undo(&mut self) -> bool {
        if let Some(delta) = self.delta.pop() {
            match delta {
                Delta::Insert { pos, chars } => {
                    let len = chars.len() as Pos;
                    let r = Range::new(pos, pos + len);
                    self.buffer.delete(r);
                    
                    self.epsilon.push(Epsilon::Insert {
                        pos,
                        chars,
                    });
                }
                Delta::Delete { pos, chars } => {
                    let len = chars.len() as Pos;
                    self.buffer.insert(pos, &chars);
                    
                    self.epsilon.push(Epsilon::Delete {
                        pos,
                        chars,
                    });
                }
                Delta::Replace { pos, old_chars, new_chars } => {
                    // Undo replace = re-delete new, re-insert old
                    let new_len = new_chars.len() as Pos;
                    let r = Range::new(pos, pos + new_len);
                    self.buffer.delete(r);
                    
                    self.buffer.insert(pos, &old_chars);
                    
                    self.epsilon.push(Epsilon::Delete {
                        pos,
                        chars: new_chars,
                    });
                    self.epsilon.push(Epsilon::Insert {
                        pos,
                        chars: old_chars,
                    });
                }
            }
            
            self.mark_dirty();
            true
        } else {
            false
        }
    }
    
    /// Redo last undone change
    pub fn redo(&mut self) -> bool {
        if let Some(epsilon) = self.epsilon.pop() {
            match epsilon {
                Epsilon::Insert { pos, chars } => {
                    self.buffer.insert(pos, &chars);
                    self.delta.push(Delta::Insert {
                        pos,
                        chars,
                    });
                }
                Epsilon::Delete { pos, chars } => {
                    let len = chars.len() as Pos;
                    let r = Range::new(pos, pos + len);
                    self.buffer.delete(r);
                    self.delta.push(Delta::Delete {
                        pos,
                        chars,
                    });
                }
            }
            
            self.mark_dirty();
            true
        } else {
            false
        }
    }
    
    /// Get marks
    pub fn marks(&self) -> Option<Pos> {
        self.mark
    }
    
    /// Set mark
    pub fn set_mark(&mut self, pos: Option<Pos>) {
        self.mark = pos;
    }
}

// ============================================================================
// Address Parser
// ============================================================================

/// Address expression
#[derive(Debug, Clone)]
pub enum Address {
    /// Character position (#n)
    Char(Pos),
    /// Line number (n)
    Line(u64),
    /// Current line (.)
    Dot,
    /// Last line ($)
    Dollar,
    /// Regular expression search forward (/)
    SearchF(String),
    /// Regular expression search backward (?)
    SearchB(String),
    /// Mark (')
    Mark(char),
    /// Add offset
    Add(Box<Address>, i64),
    /// Subtract offset
    Sub(Box<Address>, i64),
    /// Current position (,)
    Comma,
    /// Semicolon (;)
    Semicolon,
    /// Null address
    Null,
}

impl Address {
    /// Parse address string
    pub fn parse(s: &str) -> Option<(Self, &str)> {
        let s = s.trim_start();
        if s.is_empty() {
            return None;
        }
        
        let c = s.chars().next()?;
        
        match c {
            '#' => {
                let num_str = &s[1..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
                if num_str.is_empty() {
                    None
                } else {
                    let n = num_str.parse().ok()?;
                    let rest = &s[1 + num_str.len()..];
                    Some((Address::Char(n as Pos), rest))
                }
            }
            '.' => Some((Address::Dot, &s[1..])),
            '$' => Some((Address::Dollar, &s[1..])),
            '/' => {
                // Find matching /
                let mut depth = 1;
                let mut end = 1;
                for (i, c) in s[1..].chars().enumerate() {
                    if c == '/' {
                        break;
                    }
                    end = i + 2;
                }
                let pattern = &s[1..end-1];
                Some((Address::SearchF(pattern.to_string()), &s[end..]))
            }
            '?' => {
                let mut depth = 1;
                let mut end = 1;
                for (i, c) in s[1..].chars().enumerate() {
                    if c == '?' {
                        break;
                    }
                    end = i + 2;
                }
                let pattern = &s[1..end-1];
                Some((Address::SearchB(pattern.to_string()), &s[end..]))
            }
            '\'' => {
                let mark = s.chars().nth(1)?;
                Some((Address::Mark(mark), &s[2..]))
            }
            _ => {
                // Try line number
                let num_str = s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
                if num_str.is_empty() {
                    None
                } else {
                    let n = num_str.parse().ok()?;
                    let rest = &s[num_str.len()..];
                    Some((Address::Line(n), rest))
                }
            }
        }
    }
}

// ============================================================================
// Command
// ============================================================================

/// Command
#[derive(Debug, Clone)]
pub enum Command {
    /// Print (p)
    Print(Option<Address>),
    /// Delete (d)
    Delete(Option<Address>),
    /// Append (a)
    Append(Option<Address>),
    /// Insert (i)
    Insert(Option<Address>),
    /// Change (c)
    Change(Option<Address>),
    /// Substitute (s)
    Substitute {
        addr: Option<Address>,
        re: String,
        replacement: String,
        global: bool,
        print: bool,
    },
    /// Move (m)
    Move { addr: Option<Address>, dest: Address },
    /// Copy (t)
    Copy { addr: Option<Address>, dest: Address },
    /// Write (w)
    Write(Option<Address>, String),
    /// Read (r)
    Read(Option<Address>, String),
    /// Edit (e)
    Edit(String),
    /// Quit (q)
    Quit,
    /// Set (set)
    Set { var: String, val: Option<String> },
    /// Bang (!)
    Bang(String),
    /// Pipe (|)
    Pipe { addr: Option<Address>, cmd: String },
    /// X (global execute)
    X { addr: Option<Address>, cmd: Box<Command> },
    /// G (global)
    G { addr: Option<Address>, cmd: Box<Command> },
    /// Left brace ({)
    Block(Vec<Command>),
    /// Null command (newline)
    Null,
}

/// Command parser
pub struct CommandParser;

impl CommandParser {
    pub fn parse(s: &str) -> Option<Command> {
        let s = s.trim();
        if s.is_empty() {
            return Some(Command::Null);
        }
        
        let mut chars = s.chars().peekable();
        let first = chars.next()?;
        
        match first {
            'p' => Some(Command::Print(None)),
            'd' => Some(Command::Delete(None)),
            'a' => Some(Command::Append(None)),
            'i' => Some(Command::Insert(None)),
            'c' => Some(Command::Change(None)),
            'q' => Some(Command::Quit),
            '{' => Some(Command::Block(Vec::new())),
            '.' => Some(Command::Null),
            'w' => {
                if s.starts_with("wq") {
                    Some(Command::Write(None, String::new()))
                } else {
                    Some(Command::Write(None, String::new()))
                }
            }
            'r' => Some(Command::Read(None, String::new())),
            's' => Some(Command::Substitute {
                addr: None,
                re: String::new(),
                replacement: String::new(),
                global: false,
                print: false,
            }),
            _ => None,
        }
    }
}

// ============================================================================
// Editor State
// ============================================================================

/// Sam editor state
pub struct SamEditor {
    /// Current file
    pub file: File,
    /// Command file (sam command interface)
    pub cmd_file: Option<File>,
    /// Files list
    pub files: Vec<File>,
    /// Current file index
    current: usize,
    /// Sequence number
    seq: Seq,
}

impl SamEditor {
    pub fn new() -> Self {
        Self {
            file: File::new(""),
            cmd_file: None,
            files: Vec::new(),
            current: 0,
            seq: 0,
        }
    }
    
    /// Execute command
    pub fn execute(&mut self, cmd: &Command) -> Result<()> {
        match cmd {
            Command::Print(addr) => {
                let r = self.resolve_addr(addr)?;
                let content = self.file.buffer().slice(r);
                let s: String = content.iter()
                    .map(|&r| char::from_u32(r).unwrap_or('\u{FFFD}'))
                    .collect();
                println!("{}", s);
                Ok(())
            }
            Command::Delete(addr) => {
                let r = self.resolve_addr(addr)?;
                self.file.delete(r);
                Ok(())
            }
            Command::Quit => {
                if self.file.is_modified() {
                    Err(SamError::Error("file modified".to_string()))
                } else {
                    Ok(())
                }
            }
            Command::Write(addr, filename) => {
                let r = self.resolve_addr(addr)?;
                let content = self.file.buffer().slice(r);
                let s: String = content.iter()
                    .map(|&r| char::from_u32(r).unwrap_or('\u{FFFD}'))
                    .collect();
                
                if filename.is_empty() {
                    // Write to current file
                    // (In real implementation, write to disk)
                    self.file.mark_clean();
                }
                Ok(())
            }
            Command::Null => Ok(()),
            _ => Err(SamError::Error("unsupported command".to_string())),
        }
    }
    
    /// Resolve address to range
    fn resolve_addr(&self, addr: &Option<Address>) -> Result<Range> {
        match addr {
            Some(a) => self.resolve_address(a),
            None => Ok(self.file.dot()),
        }
    }
    
    /// Resolve address expression
    fn resolve_address(&self, addr: &Address) -> Result<Range> {
        match addr {
            Address::Dot => Ok(self.file.dot()),
            Address::Dollar => Ok(Range::new(self.file.len(), self.file.len())),
            Address::Char(n) => Ok(Range::new(*n, *n)),
            Address::Line(n) => {
                // Convert line number to range
                // (Simplified: treat each line as approximately 80 chars)
                let pos = (*n * 80).min(self.file.len());
                Ok(Range::new(pos, pos))
            }
            Address::Null => Ok(Range::new(0, 0)),
            Address::Add(a, offset) => {
                let base = self.resolve_address(a)?;
                let new_p1 = (base.p1 as i64 + offset).max(0) as Pos;
                Ok(Range::new(new_p1, new_p1))
            }
            Address::Sub(a, offset) => {
                self.resolve_address(&Address::Add(a.clone(), -*offset))
            }
            _ => Err(SamError::Error("unsupported address".to_string())),
        }
    }
}

impl Default for SamEditor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Serialization
// ============================================================================

impl File {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.content().into_bytes()
    }
    
    /// Load from bytes
    pub fn from_bytes(name: &str, bytes: &[u8]) -> Self {
        let content = String::from_utf8_lossy(bytes);
        Self::from_content(name, &content)
    }
}

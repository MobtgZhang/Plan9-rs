//! Plumber Rules Parser
//!
//! Implements the parsing of plumber rules files.
//! Rules define how messages are routed between applications.
//!
//! Reference: Plan 9 `sys/src/cmd/plumb/rules.c`

#![allow(unused)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Rule object types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleObject {
    Arg,
    Attr,
    Data,
    Dst,
    Plumb,
    Src,
    Type,
    Wdir,
}

impl RuleObject {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "arg" => Some(Self::Arg),
            "attr" => Some(Self::Attr),
            "data" => Some(Self::Data),
            "dst" => Some(Self::Dst),
            "plumb" => Some(Self::Plumb),
            "src" => Some(Self::Src),
            "type" => Some(Self::Type),
            "wdir" => Some(Self::Wdir),
            _ => None,
        }
    }
}

/// Rule verb types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerb {
    Add,
    Client,
    Delete,
    Is,
    IsDir,
    IsFile,
    Matches,
    Set,
    Start,
    To,
}

impl RuleVerb {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "add" => Some(Self::Add),
            "client" => Some(Self::Client),
            "delete" => Some(Self::Delete),
            "is" => Some(Self::Is),
            "isdir" => Some(Self::IsDir),
            "isfile" => Some(Self::IsFile),
            "matches" => Some(Self::Matches),
            "set" => Some(Self::Set),
            "start" => Some(Self::Start),
            "to" => Some(Self::To),
            _ => None,
        }
    }
}

/// A single rule action
#[derive(Debug, Clone)]
pub enum RuleAction {
    To(String),
    Start { cmd: String, args: Vec<String> },
    Set { name: String, value: String },
    Add { name: String, value: String },
    Delete(String),
}

/// A parsed rule condition
#[derive(Debug, Clone)]
pub struct RuleCondition {
    pub object: RuleObject,
    pub verb: RuleVerb,
    pub arg: String,
    pub is_quoted: bool,
}

/// A complete plumber rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
    pub line_number: usize,
}

impl Rule {
    pub fn new(line: usize) -> Self {
        Self {
            src: None,
            dst: None,
            conditions: Vec::new(),
            actions: Vec::new(),
            line_number: line,
        }
    }
}

/// Rules file parser
pub struct RulesParser {
    rules: Vec<Rule>,
    line: usize,
    pos: usize,
    input: Vec<u8>,
}

impl RulesParser {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            line: 1,
            pos: 0,
            input: Vec::new(),
        }
    }

    pub fn parse_str(&mut self, s: &str) -> Result<&[Rule], crate::error::PlumbError> {
        self.input = s.as_bytes().to_vec();
        self.pos = 0;
        self.line = 1;
        self.rules.clear();

        while self.pos < self.input.len() {
            self.skip_whitespace_and_comments();
            if self.pos >= self.input.len() {
                break;
            }
            let _ = self.parse_rule();
        }

        Ok(&self.rules)
    }

    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    fn skip_whitespace_and_comments(&mut self) {
        while self.pos < self.input.len() {
            let c = self.input[self.pos] as char;
            if c == '#' {
                while self.pos < self.input.len() && self.input[self.pos] as char != '\n' {
                    self.pos += 1;
                }
            } else if c.is_ascii_whitespace() {
                if c == '\n' {
                    self.line += 1;
                }
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input.get(self.pos).map(|&c| c as char)
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.peek_char();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn parse_rule(&mut self) -> Result<(), crate::error::PlumbError> {
        let start_line = self.line;
        let mut rule = Rule::new(start_line);

        // Parse source port (optional)
        self.skip_whitespace_and_comments();
        if let Some(c) = self.peek_char() {
            if c == '/' {
                self.pos += 1;
                rule.src = Some(self.parse_ident()?);
            }
        }

        // Parse destination port (optional)
        self.skip_whitespace_and_comments();
        if let Some(c) = self.peek_char() {
            if c == '/' {
                self.pos += 1;
                rule.dst = Some(self.parse_ident()?);
            }
        }

        // Parse conditions
        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.input.len() {
                break;
            }

            let c = self.peek_char().ok_or_else(|| 
                crate::error::PlumbError::InvalidMessage(
                    "Unexpected end of input".to_string()))?;

            if c == '\n' || c == '\r' {
                self.next_char();
                self.line += 1;
                break;
            }

            // Check for action separator
            if c == '|' {
                break;
            }

            // Parse condition
            if let Ok(condition) = self.parse_condition() {
                rule.conditions.push(condition);
            } else {
                break;
            }
        }

        // Parse actions after '|'
        self.skip_whitespace_and_comments();
        if let Some(c) = self.peek_char() {
            if c == '|' {
                self.pos += 1;
            }
        }

        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.input.len() {
                break;
            }

            let c = self.peek_char().ok_or_else(|| 
                crate::error::PlumbError::InvalidMessage(
                    "Unexpected end".to_string()))?;

            if c == '\n' || c == '\r' || c == '#' {
                break;
            }

            if let Ok(action) = self.parse_action() {
                rule.actions.push(action);
            } else {
                break;
            }
        }

        // Skip trailing whitespace and newline
        self.skip_whitespace_and_comments();

        if !rule.conditions.is_empty() || !rule.actions.is_empty() {
            self.rules.push(rule);
        }

        Ok(())
    }

    fn parse_ident(&mut self) -> Result<String, crate::error::PlumbError> {
        let mut result = String::new();
        while let Some(c) = self.peek_char() {
            if c.is_alphanumeric() || c == '_' || c == '/' {
                result.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        if result.is_empty() {
            return Err(crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Expected identifier")));
        }
        Ok(result)
    }

    fn parse_condition(&mut self) -> Result<RuleCondition, crate::error::PlumbError> {
        let obj_str = self.parse_ident()
            .map_err(|_| crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Expected object")))?;
        
        let object = RuleObject::from_str(&obj_str)
            .ok_or_else(|| crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Unknown object: ") + &obj_str))?;

        self.skip_whitespace_and_comments();

        let verb_str = self.parse_ident()
            .map_err(|_| crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Expected verb")))?;
        
        let verb = RuleVerb::from_str(&verb_str)
            .ok_or_else(|| crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Unknown verb: ") + &verb_str))?;

        self.skip_whitespace_and_comments();

        // Parse argument
        let arg = if let Some(c) = self.peek_char() {
            if c == '"' {
                self.pos += 1;
                let s = self.parse_quoted_string()?;
                s
            } else if c == '\'' {
                self.pos += 1;
                let s = self.parse_single_quoted_string()?;
                s
            } else if !c.is_ascii_whitespace() && c != '|' && c != '\n' && c != '\r' {
                self.parse_ident().unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(RuleCondition {
            object,
            verb,
            arg,
            is_quoted: false,
        })
    }

    fn parse_quoted_string(&mut self) -> Result<String, crate::error::PlumbError> {
        let mut result = String::new();
        while let Some(c) = self.peek_char() {
            if c == '"' {
                self.pos += 1;
                break;
            }
            if c == '\\' && self.pos + 1 < self.input.len() {
                self.pos += 1;
                let escaped = self.input[self.pos] as char;
                result.push(escaped);
                self.pos += 1;
                continue;
            }
            if c == '\n' {
                return Err(crate::error::PlumbError::InvalidMessage(
                    alloc::string::String::from("Unclosed string")));
            }
            result.push(c);
            self.pos += 1;
        }
        Ok(result)
    }

    fn parse_single_quoted_string(&mut self) -> Result<String, crate::error::PlumbError> {
        let mut result = String::new();
        while let Some(c) = self.peek_char() {
            if c == '\'' {
                self.pos += 1;
                break;
            }
            if c == '\n' {
                return Err(crate::error::PlumbError::InvalidMessage(
                    alloc::string::String::from("Unclosed string")));
            }
            result.push(c);
            self.pos += 1;
        }
        Ok(result)
    }

    fn parse_action(&mut self) -> Result<RuleAction, crate::error::PlumbError> {
        let keyword = self.parse_ident()
            .map_err(|_| crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Expected action")))?;

        self.skip_whitespace_and_comments();

        match keyword.as_str() {
            "to" => {
                let dest = self.parse_ident().unwrap_or_default();
                Ok(RuleAction::To(dest))
            }
            "start" => {
                let mut args = Vec::new();
                loop {
                    self.skip_whitespace_and_comments();
                    if let Some(c) = self.peek_char() {
                        if c == '\n' || c == '\r' || c == '#' {
                            break;
                        }
                        if c == '"' {
                            self.pos += 1;
                            args.push(self.parse_quoted_string().unwrap_or_default());
                        } else {
                            args.push(self.parse_ident().unwrap_or_default());
                        }
                    } else {
                        break;
                    }
                }
                if args.is_empty() {
                    return Err(crate::error::PlumbError::InvalidMessage(
                        alloc::string::String::from("start requires command")));
                }
                let cmd = args.remove(0);
                Ok(RuleAction::Start { cmd, args })
            }
            "set" | "add" => {
                let name = self.parse_ident().unwrap_or_default();
                self.skip_whitespace_and_comments();
                let value = if let Some(c) = self.peek_char() {
                    if c == '"' {
                        self.pos += 1;
                        self.parse_quoted_string().unwrap_or_default()
                    } else {
                        self.parse_ident().unwrap_or_default()
                    }
                } else {
                    String::new()
                };
                if keyword == "set" {
                    Ok(RuleAction::Set { name, value })
                } else {
                    Ok(RuleAction::Add { name, value })
                }
            }
            "delete" => {
                let name = self.parse_ident().unwrap_or_default();
                Ok(RuleAction::Delete(name))
            }
            _ => Err(crate::error::PlumbError::InvalidMessage(
                alloc::string::String::from("Unknown action: ") + &keyword)),
        }
    }
}

impl Default for RulesParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Default plumber rules
pub const DEFAULT_RULES: &str = r#"
# Default plumber rules

type is text
data matches '([^ ]+)'
start window -c Acme -r $1

type is text
data matches '(/[^ ]+)'
start window -c Acme -r $1
"#;

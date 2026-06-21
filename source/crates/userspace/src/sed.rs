//! sed - Stream editor
//!
//! This is a simplified implementation of the POSIX/Plan 9 sed utility.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use regex_lite::Regex;

#[derive(Debug, Clone)]
pub enum SedCommand {
    Substitute {
        pattern: Regex,
        replacement: String,
        global: bool,
        ignore_case: bool,
        print_on_match: bool,
    },
    Delete,
    Print,
    Append(String),
    Insert(String),
    Change(String),
    Quit,
    Next,
    Read(String),
    Write(String),
}

#[derive(Debug, Clone)]
pub struct Address {
    pub line_number: Option<usize>,
    pub regex: Option<Regex>,
    pub last_line: bool,
}

impl Address {
    pub fn matches(&self, line_number: usize, content: &str) -> bool {
        if self.last_line {
            return true;
        }
        if let Some(n) = self.line_number {
            return line_number == n;
        }
        if let Some(ref re) = self.regex {
            return re.is_match(content);
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct SedCommandSpec {
    pub address: Option<Address>,
    pub command: SedCommand,
}

pub struct Sed {
    commands: Vec<SedCommandSpec>,
    pattern_buffer: Vec<String>,
    auto_print: bool,
    line_number: usize,
}

impl Sed {
    pub fn new() -> Self {
        Sed {
            commands: Vec::new(),
            pattern_buffer: Vec::new(),
            auto_print: true,
            line_number: 0,
        }
    }
    
    pub fn add_command(&mut self, spec: SedCommandSpec) {
        self.commands.push(spec);
    }
    
    pub fn parse_script(&mut self, script: &str) -> Result<(), String> {
        let script = script.trim();
        
        let mut pos = 0;
        let chars: Vec<char> = script.chars().collect();
        
        while pos < chars.len() {
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }
            
            if pos >= chars.len() {
                break;
            }
            
            let (cmd, new_pos) = Self::parse_command(script, pos)?;
            self.add_command(cmd);
            pos = new_pos;
            
            while pos < chars.len() && (chars[pos] == ';' || chars[pos] == '\n') {
                pos += 1;
            }
        }
        
        Ok(())
    }
    
    fn parse_command(script: &str, mut pos: usize) -> Result<(SedCommandSpec, usize), String> {
        let chars: Vec<char> = script.chars().collect();
        
        let mut address = None;
        
        if chars[pos].is_ascii_digit() || chars[pos] == '$' || chars[pos] == '/' {
            let (addr, new_pos) = Self::parse_address(script, pos)?;
            address = Some(addr);
            pos = new_pos;
        }
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        if pos >= chars.len() {
            return Err("Unexpected end of script".to_string());
        }
        
        let cmd_char = chars[pos];
        pos += 1;
        
        let command = match cmd_char {
            's' => {
                let (pattern, replacement, flags, new_pos) = Self::parse_substitute(script, pos)?;
                pos = new_pos;
                SedCommand::Substitute {
                    pattern,
                    replacement,
                    global: flags.contains('g'),
                    ignore_case: flags.contains('i'),
                    print_on_match: flags.contains('p'),
                }
            }
            'd' => SedCommand::Delete,
            'p' => SedCommand::Print,
            'q' => SedCommand::Quit,
            'Q' => SedCommand::Quit,
            'n' => SedCommand::Next,
            'D' => SedCommand::Delete,
            'N' => SedCommand::Next,
            'a' => {
                let text = Self::parse_text_arg(script, pos)?;
                SedCommand::Append(text)
            }
            'i' => {
                let text = Self::parse_text_arg(script, pos)?;
                SedCommand::Insert(text)
            }
            'c' => {
                let text = Self::parse_text_arg(script, pos)?;
                SedCommand::Change(text)
            }
            'r' => {
                let filename = Self::parse_filename(script, pos)?;
                pos += filename.len();
                while pos < chars.len() && (chars[pos] == ';' || chars[pos] == '\n') {
                    pos += 1;
                }
                SedCommand::Read(filename)
            }
            'w' => {
                let filename = Self::parse_filename(script, pos)?;
                pos += filename.len();
                while pos < chars.len() && (chars[pos] == ';' || chars[pos] == '\n') {
                    pos += 1;
                }
                SedCommand::Write(filename)
            }
            'y' => {
                let (from, to, new_pos) = Self::parse_translate(script, pos)?;
                pos = new_pos;
                Self::build_translate_command(from, to)?
            }
            'l' => SedCommand::Print,
            'h' | 'H' => return Err("Hold space not implemented".to_string()),
            'g' | 'G' => return Err("Hold space not implemented".to_string()),
            'x' => return Err("Hold space not implemented".to_string()),
            _ => return Err(format!("Unknown sed command: {}", cmd_char)),
        };
        
        Ok((SedCommandSpec { address, command }, pos))
    }
    
    fn parse_address(script: &str, mut pos: usize) -> Result<(Address, usize), String> {
        let chars: Vec<char> = script.chars().collect();
        
        if script[pos..].starts_with('$') {
            pos += 1;
            return Ok((Address { line_number: None, regex: None, last_line: true }, pos));
        }
        
        if script[pos..].starts_with('/') {
            let end = script[pos+1..].find('/').ok_or("Unterminated regex in address")?;
            let pattern = &script[pos+1..pos+1+end];
            let re = Regex::new(pattern).map_err(|e| format!("Invalid regex: {}", e))?;
            pos += end + 2;
            return Ok((Address { line_number: None, regex: Some(re), last_line: false }, pos));
        }
        
        let mut num_str = String::new();
        while pos < chars.len() && chars[pos].is_ascii_digit() {
            num_str.push(chars[pos]);
            pos += 1;
        }
        
        if num_str.is_empty() {
            return Err("Expected address".to_string());
        }
        
        let line_number = num_str.parse::<usize>().map_err(|_| "Invalid line number")?;
        Ok((Address { line_number: Some(line_number), regex: None, last_line: false }, pos))
    }
    
    fn parse_substitute(script: &str, mut pos: usize) -> Result<(Regex, String, char, usize), String> {
        let chars: Vec<char> = script.chars().collect();
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        if pos >= chars.len() {
            return Err("Expected pattern for substitute command".to_string());
        }
        
        let delim = chars[pos];
        pos += 1;
        
        let mut pattern_str = String::new();
        let mut escaped = false;
        
        while pos < chars.len() {
            if escaped {
                match chars[pos] {
                    'n' => pattern_str.push('\n'),
                    't' => pattern_str.push('\t'),
                    _ => pattern_str.push(chars[pos]),
                }
                escaped = false;
                pos += 1;
                continue;
            }
            
            if chars[pos] == '\\' {
                escaped = true;
                pos += 1;
                continue;
            }
            
            if chars[pos] == delim {
                pos += 1;
                break;
            }
            
            pattern_str.push(chars[pos]);
            pos += 1;
        }
        
        let pattern = Regex::new(&pattern_str).map_err(|e| format!("Invalid regex: {}", e))?;
        
        let mut replacement = String::new();
        escaped = false;
        
        while pos < chars.len() && chars[pos] != delim {
            if escaped {
                match chars[pos] {
                    '0' => replacement.push('\0'),
                    'n' => replacement.push('\n'),
                    't' => replacement.push('\t'),
                    '&' => replacement.push('&'),
                    '\\' => replacement.push('\\'),
                    _ => {
                        replacement.push('\\');
                        replacement.push(chars[pos]);
                    }
                }
                escaped = false;
            } else if chars[pos] == '\\' {
                escaped = true;
            } else {
                replacement.push(chars[pos]);
            }
            pos += 1;
        }
        
        if pos < chars.len() && chars[pos] == delim {
            pos += 1;
        }
        
        let mut flags = ' ';
        while pos < chars.len() && !chars[pos].is_whitespace() && chars[pos] != ';' && chars[pos] != '\n' {
            flags = chars[pos];
            pos += 1;
        }
        
        Ok((pattern, replacement, flags, pos))
    }
    
    fn parse_text_arg(script: &str, mut pos: usize) -> Result<String, usize> {
        let chars: Vec<char> = script.chars().collect();
        
        while pos < chars.len() && (chars[pos].is_whitespace() || chars[pos] == '\\' && pos + 1 < chars.len() && chars[pos + 1] == '\n') {
            if chars[pos] == '\\' {
                pos += 2;
            } else {
                pos += 1;
            }
        }
        
        let mut text = String::new();
        while pos < chars.len() && chars[pos] != '\n' {
            text.push(chars[pos]);
            pos += 1;
        }
        
        Ok(text)
    }
    
    fn parse_filename(script: &str, mut pos: usize) -> Result<String, usize> {
        let chars: Vec<char> = script.chars().collect();
        
        while pos < chars.len() && (chars[pos].is_whitespace() || chars[pos] == '\\' && pos + 1 < chars.len() && chars[pos + 1] == '\n') {
            if chars[pos] == '\\' {
                pos += 2;
            } else {
                pos += 1;
            }
        }
        
        let mut filename = String::new();
        while pos < chars.len() && chars[pos] != ';' && chars[pos] != '\n' {
            filename.push(chars[pos]);
            pos += 1;
        }
        
        Ok(filename.trim().to_string())
    }
    
    fn parse_translate(script: &str, mut pos: usize) -> Result<(String, String, usize), String> {
        let chars: Vec<char> = script.chars().collect();
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        if pos >= chars.len() {
            return Err("Expected delimiter for translate command".to_string());
        }
        
        let delim = chars[pos];
        pos += 1;
        
        let mut from = String::new();
        let mut escaped = false;
        
        while pos < chars.len() {
            if escaped {
                match chars[pos] {
                    'n' => from.push('\n'),
                    't' => from.push('\t'),
                    _ => from.push(chars[pos]),
                }
                escaped = false;
                pos += 1;
                continue;
            }
            
            if chars[pos] == '\\' {
                escaped = true;
                pos += 1;
                continue;
            }
            
            if chars[pos] == delim {
                pos += 1;
                break;
            }
            
            from.push(chars[pos]);
            pos += 1;
        }
        
        let mut to = String::new();
        escaped = false;
        
        while pos < chars.len() && chars[pos] != delim {
            if escaped {
                match chars[pos] {
                    'n' => to.push('\n'),
                    't' => to.push('\t'),
                    _ => to.push(chars[pos]),
                }
                escaped = false;
            } else if chars[pos] == '\\' {
                escaped = true;
            } else {
                to.push(chars[pos]);
            }
            pos += 1;
        }
        
        if pos < chars.len() && chars[pos] == delim {
            pos += 1;
        }
        
        Ok((from, to, pos))
    }
    
    fn build_translate_command(from: String, to: String) -> Result<SedCommand, String> {
        if from.len() != to.len() {
            return Err("Strings for y command must have the same length".to_string());
        }
        
        let mapping: std::collections::HashMap<char, char> = from.chars()
            .zip(to.chars())
            .collect();
        
        Ok(SedCommand::Substitute {
            pattern: Regex::new(&format!("[{}]", regex_lite::escape(&from))).unwrap(),
            replacement: to,
            global: true,
            ignore_case: false,
            print_on_match: false,
        })
    }
    
    pub fn run(&mut self, input: &str) -> Result<String, String> {
        let mut output = String::new();
        self.pattern_buffer.clear();
        
        let lines: Vec<&str> = input.lines().collect();
        let total_lines = lines.len();
        
        for (i, line) in lines.iter().enumerate() {
            self.line_number = i + 1;
            self.process_line(line, &mut output, i == total_lines - 1)?;
        }
        
        Ok(output)
    }
    
    fn process_line(&mut self, line: &str, output: &mut String, is_last: bool) -> Result<(), String> {
        let mut current_line = line.to_string();
        let mut line_deleted = false;
        let mut printed = false;
        
        for spec in &self.commands {
            if let Some(ref addr) = spec.address {
                if !addr.matches(self.line_number, &current_line) {
                    continue;
                }
            }
            
            match &spec.command {
                SedCommand::Substitute { pattern, replacement, global, ignore_case: _, print_on_match } => {
                    if pattern.is_match(&current_line) {
                        if *global {
                            current_line = pattern.replace_all(&current_line, replacement.as_str()).to_string();
                        } else {
                            current_line = pattern.replace(&current_line, replacement.as_str()).to_string();
                        }
                        if *print_on_match && self.auto_print && !printed {
                            output.push_str(&current_line);
                            output.push('\n');
                            printed = true;
                        }
                    }
                }
                SedCommand::Delete => {
                    line_deleted = true;
                    break;
                }
                SedCommand::Print => {
                    if self.auto_print && !printed {
                        output.push_str(&current_line);
                        output.push('\n');
                        printed = true;
                    }
                }
                SedCommand::Append(text) => {
                    output.push_str(text);
                    output.push('\n');
                }
                SedCommand::Insert(text) => {
                    output.push_str(text);
                    output.push('\n');
                }
                SedCommand::Change(text) => {
                    output.push_str(text);
                    output.push('\n');
                    line_deleted = true;
                    break;
                }
                SedCommand::Quit => {
                    return Ok(());
                }
                SedCommand::Next => {
                }
                SedCommand::Read(filename) => {
                    if let Ok(content) = std::fs::read_to_string(filename) {
                        output.push_str(&content);
                        if !content.ends_with('\n') {
                            output.push('\n');
                        }
                    }
                }
                SedCommand::Write(filename) => {
                    if let Ok(mut file) = std::fs::File::create(filename) {
                        let _ = file.write_all(current_line.as_bytes());
                        let _ = file.write_all(b"\n");
                    }
                }
            }
        }
        
        if !line_deleted && self.auto_print && !printed {
            output.push_str(&current_line);
            output.push('\n');
        }
        
        Ok(())
    }
}

/// Run sed with the given script and input
pub fn run_sed(script: &str, input: &str) -> Result<String, String> {
    let mut sed = Sed::new();
    sed.parse_script(script)?;
    sed.run(input)
}

/// Main sed function
pub fn main_sed(args: &[String]) -> i32 {
    let mut script = String::new();
    let mut input_file = None;
    let mut output_file = None;
    let mut suppress_auto_print = false;
    let mut use_extended = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => suppress_auto_print = true,
            "-E" | "-e" => {
                if i + 1 < args.len() {
                    if !script.is_empty() {
                        script.push(';');
                    }
                    script.push_str(&args[i + 1]);
                    i += 1;
                }
            }
            "-i" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    output_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if args[i].starts_with('-') && args[i].len() > 1 {
                    if !script.is_empty() {
                        script.push(';');
                    }
                    script.push_str(&args[i][1..]);
                } else if script.is_empty() {
                    script = args[i].clone();
                } else if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else {
                    eprintln!("sed: extra operand '{}'", args[i]);
                    return 1;
                }
            }
        }
        i += 1;
    }
    
    if script.is_empty() {
        eprintln!("Usage: sed [-n] [-E] [-e script] [file...]");
        return 1;
    }
    
    let input = if let Some(ref filename) = input_file {
        match std::fs::read_to_string(filename) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sed: cannot read {}: {}", filename, e);
                return 1;
            }
        }
    } else {
        io::read_to_string(io::stdin()).unwrap_or_default()
    };
    
    match run_sed(&script, &input) {
        Ok(result) => {
            if let Some(ref filename) = output_file {
                if let Err(e) = std::fs::write(filename, &result) {
                    eprintln!("sed: cannot write {}: {}", filename, e);
                    return 1;
                }
            } else {
                print!("{}", result);
            }
            0
        }
        Err(e) => {
            eprintln!("sed: {}", e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute() {
        let result = run_sed("s/hello/world/", "hello world").unwrap();
        assert!(result.contains("world"));
    }

    #[test]
    fn test_global_substitute() {
        let result = run_sed("s/o/a/g", "hello").unwrap();
        assert_eq!(result.trim(), "hella");
    }

    #[test]
    fn test_delete() {
        let result = run_sed("2d", "line1\nline2\nline3").unwrap();
        assert!(result.contains("line1"));
        assert!(!result.contains("line2"));
        assert!(result.contains("line3"));
    }

    #[test]
    fn test_print() {
        let result = run_sed("2p", "line1\nline2\nline3").unwrap();
        let lines: Vec<&str> = result.trim().lines().collect();
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_address() {
        let result = run_sed("3s/foo/bar/", "foo\nfoo\nfoo\nfoo").unwrap();
        let lines: Vec<&str> = result.trim().lines().collect();
        assert_eq!(lines[0], "foo");
        assert_eq!(lines[1], "foo");
        assert_eq!(lines[2], "bar");
        assert_eq!(lines[3], "foo");
    }

    #[test]
    fn test_regex_address() {
        let result = run_sed("/foo/s/bar/baz/", "foo\nbar\nfoo\nbaz").unwrap();
        let lines: Vec<&str> = result.trim().lines().collect();
        assert_eq!(lines[0], "baz");
        assert_eq!(lines[1], "bar");
        assert_eq!(lines[2], "baz");
        assert_eq!(lines[3], "baz");
    }
}

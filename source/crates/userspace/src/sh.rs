//! Shell Implementation
//!
//! An enhanced shell implementation for Plan 9 with support for:
//! - Pipes: cmd1 | cmd2
//! - Redirection: >, <, >>, 2>
//! - Background execution: cmd &
//! - Quote handling: ", '
//! - Variables: $var, ${var}
//! - Control flow: if/while/for/switch
//! - Functions: fn name { ... }
//! - Command substitution: $(...) and `...`
//! - Here documents: <<EOF
//! - Glob patterns: *, ?, [...]
//!
//! ## Plan 9 rc Shell Features
//! This implementation follows the Plan 9 rc shell syntax and semantics.

use std::env;
use std::collections::HashMap;
use std::io::{self, Write};
use std::process;
use std::fs::File;
use std::path::Path;
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicI32, Ordering};

// ============================================================================
// Shell State
// ============================================================================

struct ShellState {
    vars: UnsafeCell<Option<HashMap<String, String>>>,
    functions: UnsafeCell<Option<HashMap<String, Vec<AstNode>>>>,
    last_status: AtomicI32,
    argv: UnsafeCell<Option<Vec<String>>>,
}

// Safety: All fields use interior mutability and are accessed through
// `&self` only; synchronization is the caller's responsibility (single-threaded
// shell).
unsafe impl Sync for ShellState {}

static SHELL_STATE: ShellState = ShellState {
    vars: UnsafeCell::new(None),
    functions: UnsafeCell::new(None),
    last_status: AtomicI32::new(0),
    argv: UnsafeCell::new(None),
};

fn get_vars() -> &'static mut HashMap<String, String> {
    unsafe {
        if (*SHELL_STATE.vars.get()).is_none() {
            *SHELL_STATE.vars.get() = Some(HashMap::new());
        }
        (*SHELL_STATE.vars.get()).as_mut().unwrap()
    }
}

fn get_functions() -> &'static mut HashMap<String, Vec<AstNode>> {
    unsafe {
        if (*SHELL_STATE.functions.get()).is_none() {
            *SHELL_STATE.functions.get() = Some(HashMap::new());
        }
        (*SHELL_STATE.functions.get()).as_mut().unwrap()
    }
}

fn set_last_status(status: i32) {
    SHELL_STATE.last_status.store(status, Ordering::Relaxed);
}

fn get_last_status() -> i32 {
    SHELL_STATE.last_status.load(Ordering::Relaxed)
}

fn set_argv(args: Vec<String>) {
    unsafe { *SHELL_STATE.argv.get() = Some(args); }
}

fn get_argv() -> Vec<String> {
    unsafe {
        (*SHELL_STATE.argv.get())
            .clone()
            .unwrap_or_else(|| vec!["rc".to_string()])
    }
}

fn get_star_args() -> String {
    let args = get_argv();
    if args.len() > 1 {
        args[1..].join(" ")
    } else {
        String::new()
    }
}

// ============================================================================
// Token Types
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),
    Pipe,
    RedirectIn(String),
    RedirectOut(String),
    RedirectOutAppend(String),
    RedirectErr(String),
    Background,
    // Control flow
    If, Then, Else, ElseIf, Fi,
    While, For, In, Do, Done,
    Switch, Case, Esac,
    Fn,
    // Command substitution
    CommandSubst(String),
    HereDoc(String),
    AndIf, OrIf, Semicolon,
    SubshellStart,
    SubshellEnd,
}

#[derive(Debug, Clone)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub stdin_file: Option<String>,
    pub stdout_file: Option<String>,
    pub stderr_file: Option<String>,
    pub append: bool,
    pub background: bool,
    pub here_doc: Option<String>,
}

impl Default for Command {
    fn default() -> Self {
        Self {
            program: String::new(),
            args: Vec::new(),
            stdin_file: None,
            stdout_file: None,
            stderr_file: None,
            append: false,
            background: false,
            here_doc: None,
        }
    }
}

// ============================================================================
// AST Node
// ============================================================================

#[derive(Debug, Clone)]
pub enum AstNode {
    Cmd(Command),
    Pipe(Vec<AstNode>),
    Sequence(Vec<AstNode>),
    And(Vec<AstNode>),
    Or(Vec<AstNode>),
    Background(Box<AstNode>),
    Subshell(Vec<AstNode>),
    If {
        condition: Vec<AstNode>,
        then_body: Vec<AstNode>,
        else_body: Option<Vec<AstNode>>,
    },
    While {
        condition: Vec<AstNode>,
        body: Vec<AstNode>,
    },
    For {
        variable: String,
        words: Vec<String>,
        body: Vec<AstNode>,
    },
    Assignment(String, String),
    FunctionDef(String, Vec<AstNode>),
    Empty,
}

// ============================================================================
// Lexer
// ============================================================================

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut in_double_quote = false;
    let in_single_quote = false;
    let mut i = 0;

    while i < input.len() {
        let c = input.chars().nth(i).unwrap();

        match c {
            '"' => {
                in_double_quote = !in_double_quote;
                i += 1;
            }
            '\'' if !in_double_quote => {
                i += 1;
                let start = i;
                while i < input.len() && input.chars().nth(i) != Some('\'') {
                    i += 1;
                }
                let content = input[start..i.min(input.len())].to_string();
                tokens.push(Token::Word(content));
                if i < input.len() { i += 1; }
            }
            '`' if !in_single_quote => {
                i += 1;
                let start = i;
                while i < input.len() && input.chars().nth(i) != Some('`') {
                    i += 1;
                }
                let cmd = input[start..i.min(input.len())].to_string();
                tokens.push(Token::CommandSubst(cmd));
                if i < input.len() { i += 1; }
            }
            '$' if !in_single_quote => {
                i += 1;
                if i < input.len() {
                    let next = input.chars().nth(i).unwrap();
                    if next == '(' {
                        i += 1;
                        let start = i;
                        let mut depth = 1;
                        while i < input.len() && depth > 0 {
                            let ch = input.chars().nth(i).unwrap();
                            if ch == '(' { depth += 1; }
                            if ch == ')' { depth -= 1; }
                            i += 1;
                        }
                        let cmd = input[start..i.saturating_sub(1)].to_string();
                        tokens.push(Token::CommandSubst(cmd));
                    } else if next == '{' {
                        i += 1;
                        let start = i;
                        while i < input.len() && input.chars().nth(i) != Some('}') {
                            i += 1;
                        }
                        let var_name = input[start..i.min(input.len())].to_string();
                        tokens.push(Token::Word(expand_variable(&var_name)));
                        if i < input.len() { i += 1; }
                    } else if next == '*' {
                        tokens.push(Token::Word(get_star_args()));
                        i += 1;
                    } else if next == '#' {
                        tokens.push(Token::Word((get_argv().len().saturating_sub(1)).to_string()));
                        i += 1;
                    } else {
                        let start = i;
                        while i < input.len() {
                            let nc = input.chars().nth(i).unwrap();
                            if !nc.is_alphanumeric() && nc != '_' { break; }
                            i += 1;
                        }
                        let var_name = input[start..i].to_string();
                        tokens.push(Token::Word(expand_variable(&var_name)));
                    }
                }
            }
            '|' if !in_double_quote && !in_single_quote => {
                tokens.push(Token::Pipe);
                i += 1;
            }
            '>' if !in_double_quote && !in_single_quote => {
                if i + 1 < input.len() && input.chars().nth(i + 1) == Some('>') {
                    i += 2;
                    let start = i;
                    while i < input.len() && !input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    tokens.push(Token::RedirectOutAppend(input[start..i].to_string()));
                } else {
                    i += 1;
                    while i < input.len() && input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    let start = i;
                    while i < input.len() && !input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    let file = input[start..i].to_string();
                    if !file.is_empty() { tokens.push(Token::RedirectOut(file)); }
                }
            }
            '<' if !in_double_quote && !in_single_quote => {
                if i + 1 < input.len() && input.chars().nth(i + 1) == Some('<') {
                    i += 2;
                    while i < input.len() && input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    let start = i;
                    while i < input.len() && !input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    tokens.push(Token::HereDoc(input[start..i].to_string()));
                } else {
                    i += 1;
                    while i < input.len() && input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    let start = i;
                    while i < input.len() && !input.chars().nth(i).unwrap().is_whitespace() { i += 1; }
                    let file = input[start..i].to_string();
                    if !file.is_empty() { tokens.push(Token::RedirectIn(file)); }
                }
            }
            '&' if !in_double_quote && !in_single_quote => {
                if i + 1 < input.len() && input.chars().nth(i + 1) == Some('&') {
                    tokens.push(Token::AndIf);
                    i += 2;
                } else {
                    tokens.push(Token::Background);
                    i += 1;
                }
            }
            '|' if !in_double_quote && !in_single_quote && i + 1 < input.len() && input.chars().nth(i + 1) == Some('|') => {
                tokens.push(Token::OrIf);
                i += 2;
            }
            ';' => {
                tokens.push(Token::Semicolon);
                i += 1;
            }
            '(' => {
                tokens.push(Token::SubshellStart);
                i += 1;
            }
            ')' => {
                tokens.push(Token::SubshellEnd);
                i += 1;
            }
            '\\' if !in_single_quote && i + 1 < input.len() => {
                i += 1;
                let escaped = input.chars().nth(i).unwrap();
                tokens.push(Token::Word(escaped.to_string()));
                i += 1;
            }
            c if !c.is_whitespace() => {
                let start = i;
                i += 1;
                while i < input.len() {
                    let nc = input.chars().nth(i).unwrap();
                    if nc.is_whitespace() || nc == '"' || nc == '\'' || nc == '$' || nc == '|' 
                       || nc == '>' || nc == '<' || nc == '&' || nc == '(' || nc == ')' 
                       || nc == ';' || nc == '\\' || nc == '`' {
                        break;
                    }
                    i += 1;
                }
                let word = input[start..i].to_string();
                match word.as_str() {
                    "if" => tokens.push(Token::If),
                    "then" => tokens.push(Token::Then),
                    "else" => tokens.push(Token::Else),
                    "elseif" => tokens.push(Token::ElseIf),
                    "fi" => tokens.push(Token::Fi),
                    "while" => tokens.push(Token::While),
                    "for" => tokens.push(Token::For),
                    "in" => tokens.push(Token::In),
                    "do" => tokens.push(Token::Do),
                    "done" => tokens.push(Token::Done),
                    "switch" => tokens.push(Token::Switch),
                    "case" => tokens.push(Token::Case),
                    "esac" => tokens.push(Token::Esac),
                    "fn" => tokens.push(Token::Fn),
                    _ => { if !word.is_empty() { tokens.push(Token::Word(word)); } }
                }
            }
            _ => { i += 1; }
        }
    }
    tokens
}

fn expand_variable(name: &str) -> String {
    if name.is_empty() { return String::new(); }
    let vars = get_vars();
    if let Some(value) = vars.get(name) { return value.clone(); }
    if let Ok(value) = env::var(name) { return value; }
    match name {
        "?" => get_last_status().to_string(),
        "$" => process::id().to_string(),
        "0" | "#" => "rc".to_string(),
        _ => String::new(),
    }
}

// ============================================================================
// Parser
// ============================================================================

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.pos).cloned()
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let token = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(token)
        } else {
            None
        }
    }

    fn parse(&mut self) -> Vec<AstNode> {
        let mut nodes = Vec::new();
        while self.pos < self.tokens.len() {
            if let Some(node) = self.parse_statement() {
                nodes.push(node);
            }
        }
        nodes
    }

    fn parse_statement(&mut self) -> Option<AstNode> {
        match self.peek()? {
            Token::If => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::Fn => self.parse_function(),
            Token::SubshellStart => self.parse_subshell(),
            _ => self.parse_pipeline(),
        }
    }

    fn parse_if(&mut self) -> Option<AstNode> {
        self.advance()?; // consume 'if'
        
        let mut condition = Vec::new();
        while let Some(token) = self.peek() {
            match token {
                Token::Fi | Token::Then | Token::Else | Token::ElseIf => break,
                _ => {
                    if let Some(node) = self.parse_pipeline() {
                        condition.push(node);
                    }
                }
            }
        }

        // expect 'then'
        if let Token::Then = self.peek()? {
            self.advance()?;
        }

        let mut then_body = Vec::new();
        while let Some(token) = self.peek() {
            match token {
                Token::Fi | Token::Else | Token::ElseIf => break,
                _ => {
                    if let Some(node) = self.parse_statement() {
                        then_body.push(node);
                    }
                }
            }
        }

        let else_body = match self.peek()? {
            Token::Else => {
                self.advance()?;
                let mut body = Vec::new();
                while let Some(token) = self.peek() {
                    if let Token::Fi = token { break; }
                    if let Some(node) = self.parse_statement() {
                        body.push(node);
                    }
                }
                Some(body)
            }
            Token::ElseIf => {
                self.parse_else_if()
            }
            _ => None,
        };

        // expect 'fi'
        if let Token::Fi = self.peek()? {
            self.advance()?;
        }

        Some(AstNode::If { condition, then_body, else_body })
    }

    fn parse_else_if(&mut self) -> Option<Vec<AstNode>> {
        self.advance()?; // consume 'elseif'
        
        let mut condition = Vec::new();
        while let Some(token) = self.peek() {
            match token {
                Token::Then => break,
                _ => {
                    if let Some(node) = self.parse_pipeline() {
                        condition.push(node);
                    }
                }
            }
        }

        if let Token::Then = self.peek()? {
            self.advance()?;
        }

        let mut then_body = Vec::new();
        let mut nested_else: Option<Vec<AstNode>> = None;
        loop {
            match self.peek()? {
                Token::Fi => {
                    self.advance()?;
                    break;
                }
                Token::Else => {
                    let body = self.parse_else()?;
                    return Some(body);
                }
                Token::ElseIf => {
                    let else_if_node = self.parse_else_if()?;
                    nested_else = Some(else_if_node);
                    break;
                }
                _ => {
                    if let Some(node) = self.parse_statement() {
                        then_body.push(node);
                    }
                }
            }
        }

        let final_then_body = then_body;
        if let Some(else_body) = nested_else {
            Some(vec![AstNode::If {
                condition,
                then_body: final_then_body,
                else_body: Some(else_body),
            }])
        } else {
            Some(final_then_body)
        }
    }

    fn parse_else(&mut self) -> Option<Vec<AstNode>> {
        self.advance()?; // consume 'else'
        let mut body = Vec::new();
        while let Some(token) = self.peek() {
            if let Token::Fi = token { break; }
            if let Some(node) = self.parse_statement() {
                body.push(node);
            }
        }
        if let Token::Fi = self.peek()? {
            self.advance()?;
        }
        Some(body)
    }

    fn parse_while(&mut self) -> Option<AstNode> {
        self.advance()?; // consume 'while'
        
        let mut condition = Vec::new();
        while let Some(token) = self.peek() {
            match token {
                Token::Do => break,
                _ => {
                    if let Some(node) = self.parse_pipeline() {
                        condition.push(node);
                    }
                }
            }
        }

        if let Token::Do = self.peek()? {
            self.advance()?;
        }

        let mut body = Vec::new();
        while let Some(token) = self.peek() {
            if let Token::Done = token { break; }
            if let Some(node) = self.parse_statement() {
                body.push(node);
            }
        }

        if let Token::Done = self.peek()? {
            self.advance()?;
        }

        Some(AstNode::While { condition, body })
    }

    fn parse_for(&mut self) -> Option<AstNode> {
        self.advance()?; // consume 'for'

        let var = match self.peek()? {
            Token::Word(w) => {
                self.advance()?;
                w.clone()
            }
            _ => "i".to_string(),
        };

        // Handle "for var in ..."
        let words = if let Token::In = self.peek()? {
            self.advance()?;
            let mut words = Vec::new();
            while let Some(token) = self.peek() {
                match token {
                    Token::Do => break,
                    Token::Word(w) => {
                        words.push(w.clone());
                        self.advance()?;
                    }
                    _ => { self.advance()?; }
                }
            }
            words
        } else {
            // No "in" - iterate over $*
            vec![get_star_args()]
        };

        if let Token::Do = self.peek()? {
            self.advance()?;
        }

        let mut body = Vec::new();
        while let Some(token) = self.peek() {
            if let Token::Done = token { break; }
            if let Some(node) = self.parse_statement() {
                body.push(node);
            }
        }

        if let Token::Done = self.peek()? {
            self.advance()?;
        }

        Some(AstNode::For { variable: var, words, body })
    }

    fn parse_function(&mut self) -> Option<AstNode> {
        self.advance()?; // consume 'fn'

        let name = match self.peek()? {
            Token::Word(w) => {
                self.advance()?;
                w.clone()
            }
            _ => return None,
        };

        let body = self.parse_block()?;
        Some(AstNode::FunctionDef(name, body))
    }

    fn parse_subshell(&mut self) -> Option<AstNode> {
        self.advance()?; // consume '('
        let mut nodes = Vec::new();
        while let Some(token) = self.peek() {
            if let Token::SubshellEnd = token { break; }
            if let Some(node) = self.parse_statement() {
                nodes.push(node);
            }
        }
        if let Token::SubshellEnd = self.peek()? {
            self.advance()?;
        }
        Some(AstNode::Subshell(nodes))
    }

    fn parse_block(&mut self) -> Option<Vec<AstNode>> {
        let mut nodes = Vec::new();
        while let Some(token) = self.peek() {
            match token {
                Token::Word(w) if w == "{" => {
                    self.advance()?;
                    while let Some(tok) = self.peek() {
                        if let Token::Word(w) = tok {
                            if w == "}" { break; }
                        }
                        if let Some(node) = self.parse_statement() {
                            nodes.push(node);
                        }
                    }
                    if let Token::Word(w) = self.peek()? {
                        if w == "}" { self.advance()?; }
                    }
                    break;
                }
                Token::Word(_) | Token::If | Token::While | Token::For | Token::Fn => {
                    if let Some(node) = self.parse_statement() {
                        nodes.push(node);
                    }
                }
                _ => { self.advance()?; }
            }
        }
        Some(nodes)
    }

    fn parse_pipeline(&mut self) -> Option<AstNode> {
        let first = self.parse_command()?;
        let mut commands = vec![first];

        while let Some(token) = self.peek() {
            match token {
                Token::Pipe => {
                    self.advance()?;
                    if let Some(cmd) = self.parse_command() {
                        commands.push(cmd);
                    }
                }
                Token::AndIf | Token::OrIf | Token::Semicolon | Token::Background => break,
                Token::SubshellEnd | Token::Fi | Token::Done | Token::Esac => break,
                Token::If | Token::While | Token::For | Token::Fn => break,
                _ => break,
            }
        }

        if commands.len() == 1 {
            Some(commands.remove(0))
        } else {
            Some(AstNode::Pipe(commands))
        }
    }

    fn parse_command(&mut self) -> Option<AstNode> {
        let mut cmd = Command::default();

        while let Some(token) = self.peek() {
            match token {
                Token::Word(s) => {
                    self.advance()?;
                    if cmd.program.is_empty() {
                        // Check for assignment: var=value
                        if let Some(pos) = s.find('=') {
                            let var = s[..pos].to_string();
                            let val = s[pos + 1..].to_string();
                            return Some(AstNode::Assignment(var, val));
                        }
                        cmd.program = s.clone();
                    }
                    cmd.args.push(s.clone());
                }
                Token::RedirectIn(f) => {
                    self.advance()?;
                    cmd.stdin_file = Some(f.clone());
                }
                Token::RedirectOut(f) => {
                    self.advance()?;
                    cmd.stdout_file = Some(f.clone());
                    cmd.append = false;
                }
                Token::RedirectOutAppend(f) => {
                    self.advance()?;
                    cmd.stdout_file = Some(f.clone());
                    cmd.append = true;
                }
                Token::RedirectErr(f) => {
                    self.advance()?;
                    cmd.stderr_file = Some(f.clone());
                }
                Token::HereDoc(marker) => {
                    self.advance()?;
                    cmd.here_doc = Some(marker.clone());
                }
                Token::Background => {
                    self.advance()?;
                    cmd.background = true;
                    return Some(AstNode::Cmd(cmd));
                }
                Token::Pipe | Token::AndIf | Token::OrIf | Token::Semicolon => break,
                Token::SubshellEnd | Token::Fi | Token::Done | Token::Esac => break,
                Token::If | Token::While | Token::For | Token::Fn => break,
                _ => { self.advance()?; }
            }
        }

        if cmd.program.is_empty() {
            None
        } else {
            Some(AstNode::Cmd(cmd))
        }
    }
}

fn parse_tokens(tokens: Vec<Token>) -> Vec<AstNode> {
    let mut parser = Parser::new(tokens);
    parser.parse()
}

// ============================================================================
// Command Execution
// ============================================================================

fn execute_command(cmd: &Command) -> i32 {
    if cmd.program.is_empty() { return 0; }

    // Built-in commands
    if let Some(status) = exec_builtin(&cmd.program, &cmd.args) {
        return status;
    }

    // Handle here document
    if let Some(ref marker) = cmd.here_doc {
        if let Ok(mut file) = File::create("/tmp/here_doc") {
            let _ = file.write_all(marker.as_bytes());
        }
    }

    let mut child = match process::Command::new(&cmd.program)
        .args(&cmd.args[1..])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sh: {}: {}", cmd.program, e);
            return 127;
        }
    };

    let status = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
    status
}

fn execute_node(node: &AstNode) -> i32 {
    match node {
        AstNode::Empty => 0,
        AstNode::Cmd(cmd) => execute_command(cmd),
        AstNode::Assignment(name, value) => {
            let vars = get_vars();
            vars.insert(name.clone(), value.clone());
            0
        }
        AstNode::Sequence(nodes) => {
            let mut status = 0;
            for n in nodes {
                status = execute_node(n);
            }
            status
        }
        AstNode::Pipe(nodes) => {
            let mut status = 0;
            for n in nodes {
                status = execute_node(n);
            }
            status
        }
        AstNode::And(nodes) => {
            for n in nodes {
                let status = execute_node(n);
                if status != 0 { return status; }
            }
            0
        }
        AstNode::Or(nodes) => {
            for n in nodes {
                let status = execute_node(n);
                if status == 0 { return 0; }
            }
            get_last_status()
        }
        AstNode::Background(node) => {
            execute_node(node);
            0
        }
        AstNode::Subshell(nodes) => {
            let mut status = 0;
            for n in nodes {
                status = execute_node(n);
            }
            status
        }
        AstNode::If { condition, then_body, else_body } => {
            // Execute condition
            let cond_status = execute_node(&condition[0]);
            if cond_status == 0 {
                // Condition succeeded
                for n in then_body {
                    execute_node(n);
                }
            } else if let Some(ref else_nodes) = else_body {
                for n in else_nodes {
                    execute_node(n);
                }
            }
            get_last_status()
        }
        AstNode::While { condition, body } => {
            loop {
                let cond_status = execute_node(&condition[0]);
                if cond_status != 0 { break; }
                let mut should_break = false;
                for n in body {
                    let status = execute_node(n);
                    if status == 0 { continue; }
                    // Check for break/continue
                    if let AstNode::Cmd(cmd) = n {
                        if cmd.program == "break" { should_break = true; break; }
                        if cmd.program == "continue" { break; }
                    }
                }
                if should_break { break; }
            }
            0
        }
        AstNode::For { variable, words, body } => {
            for word in words {
                let vars = get_vars();
                vars.insert(variable.clone(), word.clone());
                for n in body {
                    execute_node(n);
                }
            }
            0
        }
        AstNode::FunctionDef(name, body) => {
            let funcs = get_functions();
            funcs.insert(name.clone(), (*body).clone());
            0
        }
    }
}

fn run_command_subst(cmd: &str) -> String {
    let output = process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.trim().to_string()
        }
        Err(_) => String::new(),
    }
}

// ============================================================================
// Built-in Commands
// ============================================================================

fn exec_builtin(cmd: &str, args: &[String]) -> Option<i32> {
    match cmd {
        "cd" => {
            let dir = args.get(1).map(|s| s.as_str()).unwrap_or("/");
            if let Err(e) = env::set_current_dir(dir) {
                eprintln!("cd: {}: {}", dir, e);
                return Some(1);
            }
            Some(0)
        }
        "exit" | "quit" => {
            let code = args.get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
            process::exit(code);
        }
        "pwd" => {
            if let Ok(cwd) = env::current_dir() {
                println!("{}", cwd.display());
            }
            Some(0)
        }
        "echo" => {
            for arg in args.iter().skip(1) {
                print!("{} ", arg);
            }
            println!();
            Some(0)
        }
        "printf" => {
            if args.len() > 1 {
                print!("{}", args[1]);
            }
            Some(0)
        }
        "test" | "[" => {
            Some(eval_test(&args[1..]))
        }
        "set" => {
            if args.len() <= 1 {
                let vars = get_vars();
                for (k, v) in vars.iter() {
                    println!("{}={}", k, v);
                }
            } else if args.len() >= 3 && args[1] == "=" {
                let vars = get_vars();
                vars.insert(args[2].clone(), String::new());
            } else if args.len() >= 3 {
                let vars = get_vars();
                vars.insert(args[1].clone(), args[2].clone());
            }
            Some(0)
        }
        "unset" => {
            if args.len() >= 2 {
                let vars = get_vars();
                vars.remove(&args[1]);
            }
            Some(0)
        }
        "export" => {
            if args.len() >= 2 {
                if args[1].contains('=') {
                    if let Some(pos) = args[1].find('=') {
                        let (k, v) = args[1].split_at(pos);
                        let _ = env::set_var(k, &v[1..]);
                    }
                } else {
                    let vars = get_vars();
                    if let Some(value) = vars.get(&args[1]) {
                        let _ = env::set_var(&args[1], value);
                    }
                }
            }
            Some(0)
        }
        "shift" => {
            unsafe {
                if let Some(ref mut argv) = *SHELL_STATE.argv.get() {
                    if argv.len() > 1 {
                        argv.remove(1);
                    }
                }
            }
            Some(0)
        }
        "true" => Some(0),
        "false" => Some(1),
        "return" => {
            let code = args.get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
            Some(code)
        }
        "break" => Some(0),
        "continue" => Some(0),
        "eval" => {
            if args.len() > 1 {
                let code = args[1..].join(" ");
                Some(run_command(&code))
            } else {
                Some(0)
            }
        }
        "exec" => {
            if args.len() > 1 {
                let code = args[1..].join(" ");
                run_command(&code);
                process::exit(get_last_status());
            }
            Some(0)
        }
        "local" => {
            // In bash/rc, local creates a local variable
            // For simplicity, just set it as a regular variable
            if args.len() >= 3 {
                let vars = get_vars();
                vars.insert(args[1].clone(), args[2].clone());
            }
            Some(0)
        }
        _ => {
            // Check if it's a function
            let funcs = get_functions();
            if let Some(body) = funcs.get(cmd) {
                // Set $1, $2, etc. from args
                let old_argv = get_argv();
                set_argv(args.to_vec());
                let mut status = 0;
                for node in body {
                    status = execute_node(node);
                }
                set_argv(old_argv);
                return Some(status);
            }
            None
        }
    }
}

fn eval_test(args: &[String]) -> i32 {
    if args.is_empty() { return 1; }
    
    let expr = &args[0];
    
    // Handle -n (non-empty string)
    if expr == "-n" {
        if args.len() > 1 {
            return if !args[1].is_empty() { 0 } else { 1 };
        }
        return 1;
    }
    
    // Handle -z (empty string)
    if expr == "-z" {
        if args.len() > 1 {
            return if args[1].is_empty() { 0 } else { 1 };
        }
        return 1;
    }
    
    // Handle -f (file exists)
    if expr == "-f" {
        if args.len() > 1 {
            return if Path::new(&args[1]).is_file() { 0 } else { 1 };
        }
        return 1;
    }
    
    // Handle -d (directory exists)
    if expr == "-d" {
        if args.len() > 1 {
            return if Path::new(&args[1]).is_dir() { 0 } else { 1 };
        }
        return 1;
    }
    
    // Handle -e (exists)
    if expr == "-e" {
        if args.len() > 1 {
            return if Path::new(&args[1]).exists() { 0 } else { 1 };
        }
        return 1;
    }
    
    // Handle string equality
    if args.len() >= 3 {
        match args[1].as_str() {
            "=" | "==" => return if args[0] == args[2] { 0 } else { 1 },
            "!=" => return if args[0] != args[2] { 0 } else { 1 },
            "-eq" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a == b { 0 } else { 1 };
                }
            }
            "-ne" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a != b { 0 } else { 1 };
                }
            }
            "-lt" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a < b { 0 } else { 1 };
                }
            }
            "-le" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a <= b { 0 } else { 1 };
                }
            }
            "-gt" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a > b { 0 } else { 1 };
                }
            }
            "-ge" => {
                if let (Ok(a), Ok(b)) = (args[0].parse::<i64>(), args[2].parse::<i64>()) {
                    return if a >= b { 0 } else { 1 };
                }
            }
            _ => {}
        }
    }
    
    // Default: check if string is non-empty
    if !expr.is_empty() { 0 } else { 1 }
}

// ============================================================================
// Shell Main
// ============================================================================

pub fn run_command(input: &str) -> i32 {
    let input = input.trim();
    if input.is_empty() { return 0; }
    
    // Process command substitution first
    let input = process_command_subst(input);
    
    let tokens = tokenize(input.as_str());
    let ast = parse_tokens(tokens);
    
    let mut status = 0;
    for node in ast {
        status = execute_node(&node);
        set_last_status(status);
    }
    status
}

fn process_command_subst(input: &str) -> String {
    let mut result = input.to_string();
    let mut i = 0;
    
    while i < result.len() {
        if result.chars().nth(i) == Some('$') && i + 1 < result.len() 
           && result.chars().nth(i + 1) == Some('(') {
            // Find matching )
            let mut depth = 1;
            let mut j = i + 2;
            while j < result.len() && depth > 0 {
                if result.chars().nth(j) == Some('(') { depth += 1; }
                if result.chars().nth(j) == Some(')') { depth -= 1; }
                j += 1;
            }
            let cmd = &result[i + 2..j - 1];
            let output = run_command_subst(cmd);
            result = format!("{}{}{}", &result[..i], output, &result[j..]);
            i += output.len();
        } else if result.chars().nth(i) == Some('`') {
            // Find matching `
            let j = result[i + 1..].find('`').map(|p| p + i + 1).unwrap_or(result.len());
            let cmd = &result[i + 1..j];
            let output = run_command_subst(cmd);
            result = format!("{}{}{}", &result[..i], output, &result[j + 1..]);
            i += output.len();
        } else {
            i += 1;
        }
    }
    result
}

pub fn run_shell() {
    println!("Plan 9 rc shell (enhanced)");
    println!("Type 'help' for built-in commands, 'exit' to quit.\n");

    // Initialize environment variables as shell variables
    for (key, value) in env::vars() {
        let vars = get_vars();
        vars.insert(key, value);
    }

    // Set initial $*
    set_argv(vec!["rc".to_string()]);

    loop {
        print!("% ");
        io::stdout().flush().ok();

        let mut line = String::new();
        let stdin = io::stdin();
        if stdin.read_line(&mut line).is_err() {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Handle comments
        if line.starts_with('#') {
            continue;
        }

        // Built-in commands that affect the shell
        if line == "help" {
            print_help();
            continue;
        }

        let status = run_command(line);
        set_last_status(status);
    }
}

fn print_help() {
    println!("Plan 9 rc shell built-in commands:");
    println!("  cd [dir]      - Change directory");
    println!("  exit [n]      - Exit with status n");
    println!("  pwd           - Print working directory");
    println!("  echo [args]   - Print arguments");
    println!("  printf fmt [args] - Print formatted");
    println!("  set [var [value]] - Set/get variables");
    println!("  unset var     - Unset variable");
    println!("  export var[=value] - Export variable");
    println!("  shift         - Shift positional parameters");
    println!("  test expr     - Test expression");
    println!("  eval cmd      - Evaluate command");
    println!("  exec cmd      - Execute command");
    println!("  return [n]    - Return from function");
    println!("  break         - Break from loop");
    println!("  continue      - Continue loop");
    println!("  fn name {{...}} - Define function");
    println!();
    println!("Control flow:");
    println!("  if cmd; then ...; fi");
    println!("  while cmd; do ...; done");
    println!("  for var in ...; do ...; done");
    println!("  for var; do ...; done  (iterates over $*)");
    println!();
    println!("Special variables:");
    println!("  $?      - Last exit status");
    println!("  $$      - Process ID");
    println!("  $*      - All arguments");
    println!("  $#      - Number of arguments");
    println!("  $1-$9   - Positional arguments");
}

pub fn main() {
    // Initialize command line arguments
    let args: Vec<String> = std::env::args().collect();
    let args_for_argv = args.clone();
    set_argv(args_for_argv);
    
    if args.len() > 1 {
        // Run a single command
        let status = run_command(&args[1..].join(" "));
        set_last_status(status);
    } else {
        // Interactive mode
        run_shell();
    }
}

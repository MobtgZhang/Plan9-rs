//! awk - Pattern scanning and processing language
//!
//! This is a simplified implementation of AWK for Plan 9.

use std::collections::HashMap;
use std::io::{self};

#[derive(Debug, Clone)]
pub enum AwkValue {
    Number(f64),
    String(String),
}

impl AwkValue {
    fn to_number(&self) -> f64 {
        match self {
            AwkValue::Number(n) => *n,
            AwkValue::String(s) => s.parse().unwrap_or(0.0),
        }
    }
    
    fn to_string(&self) -> String {
        match self {
            AwkValue::Number(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    (*n as i64).to_string()
                } else {
                    n.to_string()
                }
            }
            AwkValue::String(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AwkRecord {
    pub fields: Vec<String>,
    pub nr: usize,
    pub fnr: usize,
    pub f0: String,
}

impl AwkRecord {
    fn new(line: &str, fs: &str, nr: usize, fnr: usize) -> Self {
        let fields = if fs == " " {
            line.split_whitespace().map(|s| s.to_string()).collect()
        } else if fs.len() == 1 {
            line.split(fs.chars().next().unwrap()).map(|s| s.to_string()).collect()
        } else {
            vec![line.to_string()]
        };
        
        AwkRecord {
            fields,
            nr,
            fnr,
            f0: line.to_string(),
        }
    }
    
    pub fn get_field(&self, index: usize) -> String {
        if index == 0 {
            self.f0.clone()
        } else if index <= self.fields.len() {
            self.fields[index - 1].clone()
        } else {
            String::new()
        }
    }
}

#[derive(Debug, Clone)]
pub enum AwkPattern {
    All,
    Expression(AwkExpression),
    Regex(String, bool),
    Begin,
    End,
}

#[derive(Debug, Clone)]
pub enum AwkExpression {
    Binary(Box<AwkExpression>, AwkOp, Box<AwkExpression>),
    Unary(AwkUnaryOp, Box<AwkExpression>),
    Field(String),
    Variable(String),
    Number(f64),
    String(String),
    Regex(String),
    Bool(bool),
    Array(String, Option<Box<AwkExpression>>),
}

#[derive(Debug, Clone)]
pub enum AwkOp {
    Add, Sub, Mul, Div, Mod, Power,
    Equal, NotEqual, Less, Greater, LessEq, GreaterEq,
    Match, NotMatch,
    And, Or,
    In,
}

#[derive(Debug, Clone)]
pub enum AwkUnaryOp {
    Not, Neg,
}

#[derive(Debug, Clone)]
pub enum AwkAction {
    Print(Vec<AwkPrintItem>),
    Printf(String, Vec<AwkExpression>),
    Assignment(String, AwkExpression),
    If(AwkExpression, Vec<AwkAction>),
    IfElse(AwkExpression, Vec<AwkAction>, Vec<AwkAction>),
    While(AwkExpression, Vec<AwkAction>),
    For(AwkForInit, AwkExpression, AwkExpression, Vec<AwkAction>),
    Break,
    Continue,
    Return(Option<AwkExpression>),
    Delete(String, Option<AwkExpression>),
    Expression(AwkExpression),
}

#[derive(Debug, Clone)]
pub enum AwkForInit {
    Assignment(String, AwkExpression),
    Expression(AwkExpression),
}

#[derive(Debug, Clone)]
pub enum AwkPrintItem {
    Expression(AwkExpression),
    File(String),
}

#[derive(Debug, Clone)]
pub struct AwkRule {
    pub pattern: AwkPattern,
    pub actions: Vec<AwkAction>,
}

#[derive(Debug, Clone)]
pub struct AwkOptions {
    pub program: String,
    pub input_files: Vec<String>,
    pub field_separator: String,
    pub record_separator: String,
    pub output_field_separator: String,
    pub output_record_separator: String,
}

impl Default for AwkOptions {
    fn default() -> Self {
        AwkOptions {
            program: String::new(),
            input_files: Vec::new(),
            field_separator: " ".to_string(),
            record_separator: "\n".to_string(),
            output_field_separator: " ".to_string(),
            output_record_separator: "\n".to_string(),
        }
    }
}

pub struct Awk {
    program: Vec<AwkRule>,
    vars: HashMap<String, AwkValue>,
    arrays: HashMap<String, HashMap<String, AwkValue>>,
    opts: AwkOptions,
}

impl Awk {
    pub fn new(opts: AwkOptions) -> Self {
        let mut awk = Awk {
            program: Vec::new(),
            vars: HashMap::new(),
            arrays: HashMap::new(),
            opts,
        };
        awk.init_vars();
        awk
    }

    /// Borrow the associative-array table used for `arr[key]` expressions.
    pub fn arrays(&self) -> &HashMap<String, HashMap<String, AwkValue>> {
        &self.arrays
    }

    /// Mutable access to the associative-array table. Used by future
    /// array assignment rules to populate `arr[key]` cells.
    pub fn arrays_mut(&mut self) -> &mut HashMap<String, HashMap<String, AwkValue>> {
        &mut self.arrays
    }
    
    fn init_vars(&mut self) {
        self.vars.insert("FS".to_string(), AwkValue::String(self.opts.field_separator.clone()));
        self.vars.insert("RS".to_string(), AwkValue::String(self.opts.record_separator.clone()));
        self.vars.insert("OFS".to_string(), AwkValue::String(self.opts.output_field_separator.clone()));
        self.vars.insert("ORS".to_string(), AwkValue::String(self.opts.output_record_separator.clone()));
        self.vars.insert("NF".to_string(), AwkValue::Number(0.0));
        self.vars.insert("NR".to_string(), AwkValue::Number(0.0));
        self.vars.insert("FNR".to_string(), AwkValue::Number(0.0));
    }
    
    pub fn parse(&mut self, program: &str) -> Result<(), String> {
        let program = program.trim();
        
        let mut pos = 0;
        let chars: Vec<char> = program.chars().collect();
        
        while pos < chars.len() {
            let (rule, new_pos) = Self::parse_rule(program, pos)?;
            self.program.push(rule);
            pos = new_pos;
            
            while pos < chars.len() && (chars[pos] == ';' || chars[pos] == '\n') {
                pos += 1;
            }
        }
        
        Ok(())
    }
    
    fn parse_rule(program: &str, mut pos: usize) -> Result<(AwkRule, usize), String> {
        let chars: Vec<char> = program.chars().collect();
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        let _start_pos = pos;
        
        let mut pattern: AwkPattern = AwkPattern::All;
        
        if pos < chars.len() {
            if program[pos..].starts_with("BEGIN") {
                pattern = AwkPattern::Begin;
                pos += 5;
            } else if program[pos..].starts_with("END") {
                pattern = AwkPattern::End;
                pos += 3;
            } else if chars[pos] == '/' {
                let end = program[pos..].find('/').ok_or("Unterminated regex")?;
                let regex = program[pos+1..pos+end].to_string();
                pattern = AwkPattern::Regex(regex, false);
                pos += end + 1;
            }
        }
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        let mut actions = Vec::new();
        
        if pos < chars.len() && chars[pos] == '{' {
            pos += 1;
            let (action_list, new_pos) = Self::parse_action_block(program, pos)?;
            actions = action_list;
            pos = new_pos;
        } else if matches!(pattern, AwkPattern::All) {
            actions.push(AwkAction::Print(Vec::new()));
        }
        
        Ok((AwkRule { pattern, actions }, pos))
    }
    
    fn parse_action_block(program: &str, mut pos: usize) -> Result<(Vec<AwkAction>, usize), String> {
        let mut actions = Vec::new();
        let chars: Vec<char> = program.chars().collect();
        let len = chars.len();
        
        while pos < len && chars[pos] != '}' {
            while pos < len && chars[pos].is_whitespace() {
                pos += 1;
            }
            
            if pos < len && chars[pos] == '}' {
                break;
            }
            
            let (action, new_pos) = Self::parse_action(program, pos)?;
            actions.push(action);
            pos = new_pos;
            
            while pos < len && (chars[pos] == ';' || chars[pos] == '\n') {
                pos += 1;
            }
        }
        
        if pos < len && chars[pos] == '}' {
            pos += 1;
        }
        
        Ok((actions, pos))
    }
    
    fn parse_action(program: &str, mut pos: usize) -> Result<(AwkAction, usize), String> {
        let chars: Vec<char> = program.chars().collect();
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        if program[pos..].starts_with("print") {
            let (items, new_pos) = Self::parse_print_statement(program, pos + 5)?;
            return Ok((AwkAction::Print(items), new_pos));
        }
        
        if program[pos..].starts_with("if") {
            return Self::parse_if_statement(program, pos);
        }
        
        if program[pos..].starts_with("while") {
            return Self::parse_while_statement(program, pos);
        }
        
        if program[pos..].starts_with("for") {
            return Self::parse_for_statement(program, pos);
        }
        
        if program[pos..].starts_with("break") {
            return Ok((AwkAction::Break, pos + 5));
        }
        
        if program[pos..].starts_with("continue") {
            return Ok((AwkAction::Continue, pos + 8));
        }
        
        let (expr, new_pos) = Self::parse_expression(program, pos)?;
        Ok((AwkAction::Expression(expr), new_pos))
    }
    
    fn parse_print_statement(program: &str, mut pos: usize) -> Result<(Vec<AwkPrintItem>, usize), String> {
        let chars: Vec<char> = program.chars().collect();
        let mut items = Vec::new();
        
        while pos < chars.len() && chars[pos] != ';' && chars[pos] != '\n' && chars[pos] != '}' {
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }
            
            if pos >= chars.len() || chars[pos] == ';' || chars[pos] == '\n' || chars[pos] == '}' {
                break;
            }
            
            let (item, new_pos) = Self::parse_print_item(program, pos)?;
            items.push(item);
            pos = new_pos;
            
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }
            
            if pos < chars.len() && chars[pos] == ',' {
                pos += 1;
                while pos < chars.len() && chars[pos].is_whitespace() {
                    pos += 1;
                }
            }
        }
        
        Ok((items, pos))
    }
    
    fn parse_print_item(program: &str, pos: usize) -> Result<(AwkPrintItem, usize), String> {
        let chars: Vec<char> = program.chars().collect();
        
        if chars[pos] == '>' || chars[pos] == '-' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
            let arrow_len = if chars[pos] == '-' { 2 } else { 1 };
            let mut end = pos + arrow_len;
            while end < chars.len() && chars[end].is_whitespace() {
                end += 1;
            }
            let file_start = end;
            while end < chars.len() && !chars[end].is_whitespace() && chars[end] != ';' && chars[end] != '}' {
                end += 1;
            }
            let filename = program[file_start..end].trim().to_string();
            return Ok((AwkPrintItem::File(filename), end));
        }
        
        let (expr, new_pos) = Self::parse_expression(program, pos)?;
        Ok((AwkPrintItem::Expression(expr), new_pos))
    }
    
    fn parse_if_statement(program: &str, _pos: usize) -> Result<(AwkAction, usize), String> {
        let program = program.trim_start_matches("if");
        let mut pos = 0;
        let chars: Vec<char> = program.chars().collect();
        
        while pos < chars.len() && chars[pos] != '(' {
            pos += 1;
        }
        pos += 1;
        
        let (cond, _) = Self::parse_expression(program, pos)?;
        
        while pos < chars.len() && chars[pos] != ')' {
            pos += 1;
        }
        pos += 1;
        
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        let (then_actions, new_pos) = Self::parse_action_block(program, pos)?;
        let mut then_end = new_pos;
        
        while then_end < chars.len() && (chars[then_end] == ';' || chars[then_end].is_whitespace()) {
            then_end += 1;
        }
        
        let mut else_actions = Vec::new();
        let mut else_end = then_end;
        
        if program[then_end..].trim_start_matches("else").starts_with("else") {
            else_end = then_end + 4;
            while else_end < chars.len() && chars[else_end].is_whitespace() {
                else_end += 1;
            }
            let (actions, end) = Self::parse_action_block(program, else_end)?;
            else_actions = actions;
            else_end = end;
        }
        
        if else_actions.is_empty() {
            Ok((AwkAction::If(cond, then_actions), then_end))
        } else {
            Ok((AwkAction::IfElse(cond, then_actions, else_actions), else_end))
        }
    }
    
    fn parse_while_statement(_program: &str, _pos: usize) -> Result<(AwkAction, usize), String> {
        Err("while not implemented".to_string())
    }
    
    fn parse_for_statement(_program: &str, _pos: usize) -> Result<(AwkAction, usize), String> {
        Err("for not implemented".to_string())
    }
    
    fn parse_expression(program: &str, pos: usize) -> Result<(AwkExpression, usize), String> {
        let program = program[pos..].trim_start();
        let chars: Vec<char> = program.chars().collect();
        
        let mut end = 0;
        let mut paren_depth = 0;
        let mut in_string = false;
        let mut string_char = ' ';
        
        while end < chars.len() {
            let c = chars[end];
            
            if in_string {
                if c == '\\' && end + 1 < chars.len() {
                    end += 2;
                    continue;
                }
                if c == string_char {
                    in_string = false;
                }
                end += 1;
                continue;
            }
            
            if c == '"' || c == '\'' {
                in_string = true;
                string_char = c;
                end += 1;
                continue;
            }
            
            match c {
                '(' => paren_depth += 1,
                ')' => {
                    if paren_depth == 0 {
                        break;
                    }
                    paren_depth -= 1;
                }
                ' ' | '\t' | '\n' | '\r' if paren_depth == 0 => break,
                '>' | '<' | '=' | '!' | '+' | '-' | '*' | '/' | '%' | '^' if paren_depth == 0 => break,
                ';' | '}' => break,
                _ => {}
            }
            end += 1;
        }
        
        let expr_str = program[..end].trim();
        
        if expr_str.is_empty() {
            return Ok((AwkExpression::Bool(false), pos));
        }
        
        let expr = Self::parse_simple_expression(expr_str)?;
        Ok((expr, pos + end))
    }
    
    fn parse_simple_expression(expr: &str) -> Result<AwkExpression, String> {
        let expr = expr.trim();
        
        if let Some(idx) = expr.find("&&") {
            let left = Self::parse_simple_expression(&expr[..idx])?;
            let right = Self::parse_simple_expression(&expr[idx+2..])?;
            return Ok(AwkExpression::Binary(Box::new(left), AwkOp::And, Box::new(right)));
        }
        
        if let Some(idx) = expr.find("||") {
            let left = Self::parse_simple_expression(&expr[..idx])?;
            let right = Self::parse_simple_expression(&expr[idx+2..])?;
            return Ok(AwkExpression::Binary(Box::new(left), AwkOp::Or, Box::new(right)));
        }
        
        if let Some(idx) = expr.find("~") {
            let left = Self::parse_simple_expression(&expr[..idx])?;
            let right = Self::parse_simple_expression(&expr[idx+1..])?;
            return Ok(AwkExpression::Binary(Box::new(left), AwkOp::Match, Box::new(right)));
        }
        
        if let Some(idx) = expr.find("!~") {
            let left = Self::parse_simple_expression(&expr[..idx])?;
            let right = Self::parse_simple_expression(&expr[idx+2..])?;
            return Ok(AwkExpression::Binary(Box::new(left), AwkOp::NotMatch, Box::new(right)));
        }
        
        for (op_str, op) in [
            ("==", AwkOp::Equal),
            ("!=", AwkOp::NotEqual),
            ("<=", AwkOp::LessEq),
            (">=", AwkOp::GreaterEq),
            ("<", AwkOp::Less),
            (">", AwkOp::Greater),
            ("+", AwkOp::Add),
            ("-", AwkOp::Sub),
            ("*", AwkOp::Mul),
            ("/", AwkOp::Div),
            ("%", AwkOp::Mod),
            ("^", AwkOp::Power),
        ] {
            if let Some(idx) = expr.find(op_str) {
                let left = Self::parse_simple_expression(&expr[..idx])?;
                let right = Self::parse_simple_expression(&expr[idx + op_str.len()..])?;
                return Ok(AwkExpression::Binary(Box::new(left), op, Box::new(right)));
            }
        }
        
        if expr.starts_with('(') && expr.ends_with(')') {
            return Self::parse_simple_expression(&expr[1..expr.len()-1]);
        }
        
        if expr.starts_with('$') {
            if let Ok(_n) = expr[1..].parse::<usize>() {
                return Ok(AwkExpression::Field(expr.to_string()));
            }
        }
        
        if let Ok(n) = expr.parse::<f64>() {
            return Ok(AwkExpression::Number(n));
        }
        
        if (expr.starts_with('"') && expr.ends_with('"')) ||
           (expr.starts_with('\'') && expr.ends_with('\'')) {
            let s = &expr[1..expr.len()-1];
            return Ok(AwkExpression::String(s.to_string()));
        }
        
        Ok(AwkExpression::Variable(expr.to_string()))
    }
    
    pub fn run(&mut self, input: &str) -> Result<String, String> {
        let mut output = String::new();

        // Collect Begin actions first to release the immutable borrow on self
        let begin_actions: Vec<Vec<AwkAction>> = self.program.iter()
            .filter(|r| matches!(r.pattern, AwkPattern::Begin))
            .map(|r| r.actions.clone())
            .collect();
        for actions in &begin_actions {
            self.execute_actions(actions, &mut output)?;
        }

        let rs = self.vars.get("RS")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "\n".to_string());

        for record_str in input.split(&rs).filter(|s| !s.is_empty()) {
            self.vars.insert("FNR".to_string(), AwkValue::Number(
                self.vars.get("FNR").map(|v| v.to_number()).unwrap_or(0.0) + 1.0
            ));
            self.vars.insert("NR".to_string(), AwkValue::Number(
                self.vars.get("NR").map(|v| v.to_number()).unwrap_or(0.0) + 1.0
            ));

            let fs = self.vars.get("FS")
                .map(|v| v.to_string())
                .unwrap_or_else(|| " ".to_string());

            let fnr = self.vars.get("FNR").map(|v| v.to_number()).unwrap_or(1.0) as usize;
            let nr = self.vars.get("NR").map(|v| v.to_number()).unwrap_or(1.0) as usize;

            let record = AwkRecord::new(record_str, &fs, nr, fnr);
            let nf = record.fields.len();
            self.vars.insert("NF".to_string(), AwkValue::Number(nf as f64));

            for (i, field) in record.fields.iter().enumerate() {
                self.vars.insert(format!("${}", i + 1), AwkValue::String(field.clone()));
            }
            self.vars.insert("$0".to_string(), AwkValue::String(record.f0.clone()));

            let matches = match &self.program[0].pattern {
                AwkPattern::All => true,
                AwkPattern::Begin | AwkPattern::End => false,
                AwkPattern::Expression(_) => true,
                AwkPattern::Regex(_, _) => true,
            };

            if matches {
                // Collect main actions first
                let main_actions: Vec<Vec<AwkAction>> = self.program.iter()
                    .filter(|r| !matches!(r.pattern, AwkPattern::Begin | AwkPattern::End))
                    .map(|r| r.actions.clone())
                    .collect();
                for actions in &main_actions {
                    self.execute_actions(actions, &mut output)?;
                }
            }
        }

        let end_actions: Vec<Vec<AwkAction>> = self.program.iter()
            .filter(|r| matches!(r.pattern, AwkPattern::End))
            .map(|r| r.actions.clone())
            .collect();
        for actions in &end_actions {
            self.execute_actions(actions, &mut output)?;
        }

        Ok(output)
    }
    
    fn execute_actions(&mut self, actions: &[AwkAction], output: &mut String) -> Result<(), String> {
        for action in actions {
            match action {
                AwkAction::Print(items) => {
                    let ofs = self.vars.get("OFS")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| " ".to_string());
                    let ors = self.vars.get("ORS")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "\n".to_string());
                    
                    let parts: Vec<String> = items.iter()
                        .filter_map(|item| {
                            match item {
                                AwkPrintItem::Expression(expr) => {
                                    Some(self.evaluate_expression(expr).to_string())
                                }
                                AwkPrintItem::File(_) => None,
                            }
                        })
                        .collect();
                    
                    output.push_str(&parts.join(&ofs));
                    output.push_str(&ors);
                }
                AwkAction::Expression(expr) => {
                    self.evaluate_expression(expr);
                }
                _ => {}
            }
        }
        Ok(())
    }
    
    fn evaluate_expression(&mut self, expr: &AwkExpression) -> AwkValue {
        match expr {
            AwkExpression::Number(n) => AwkValue::Number(*n),
            AwkExpression::String(s) => AwkValue::String(s.clone()),
            AwkExpression::Bool(b) => AwkValue::String(b.to_string()),
            AwkExpression::Variable(name) => {
                if let Some(v) = self.vars.get(name) {
                    v.clone()
                } else if name == "NF" {
                    AwkValue::Number(self.vars.get("NF").map(|v| v.to_number()).unwrap_or(0.0))
                } else if name == "NR" {
                    AwkValue::Number(self.vars.get("NR").map(|v| v.to_number()).unwrap_or(0.0))
                } else if name == "FNR" {
                    AwkValue::Number(self.vars.get("FNR").map(|v| v.to_number()).unwrap_or(0.0))
                } else if name == "FS" {
                    AwkValue::String(self.vars.get("FS").map(|v| v.to_string()).unwrap_or_default())
                } else if name == "RS" {
                    AwkValue::String(self.vars.get("RS").map(|v| v.to_string()).unwrap_or_default())
                } else if name == "OFS" {
                    AwkValue::String(self.vars.get("OFS").map(|v| v.to_string()).unwrap_or_default())
                } else if name == "ORS" {
                    AwkValue::String(self.vars.get("ORS").map(|v| v.to_string()).unwrap_or_default())
                } else {
                    AwkValue::Number(0.0)
                }
            }
            AwkExpression::Field(name) => {
                if let Ok(idx) = name[1..].parse::<usize>() {
                    let f0 = self.vars.get("$0").map(|v| v.to_string()).unwrap_or_default();
                    let fs = self.vars.get("FS").map(|v| v.to_string()).unwrap_or_else(|| " ".to_string());
                    let fields: Vec<&str> = if fs == " " {
                        f0.split_whitespace().collect()
                    } else {
                        f0.split(|c| c == fs.chars().next().unwrap()).collect()
                    };
                    if idx > 0 && idx <= fields.len() {
                        AwkValue::String(fields[idx - 1].to_string())
                    } else {
                        AwkValue::String(String::new())
                    }
                } else {
                    self.vars.get(name).cloned().unwrap_or(AwkValue::String(String::new()))
                }
            }
            AwkExpression::Binary(left, op, right) => {
                let l = self.evaluate_expression(left);
                let r = self.evaluate_expression(right);
                match op {
                    AwkOp::Add => AwkValue::Number(l.to_number() + r.to_number()),
                    AwkOp::Sub => AwkValue::Number(l.to_number() - r.to_number()),
                    AwkOp::Mul => AwkValue::Number(l.to_number() * r.to_number()),
                    AwkOp::Div => AwkValue::Number(l.to_number() / r.to_number()),
                    AwkOp::Mod => AwkValue::Number(l.to_number() % r.to_number()),
                    AwkOp::Power => AwkValue::Number(l.to_number().powf(r.to_number())),
                    AwkOp::Equal => AwkValue::String((l.to_number() == r.to_number()).to_string()),
                    AwkOp::NotEqual => AwkValue::String((l.to_number() != r.to_number()).to_string()),
                    AwkOp::Less => AwkValue::String((l.to_number() < r.to_number()).to_string()),
                    AwkOp::Greater => AwkValue::String((l.to_number() > r.to_number()).to_string()),
                    AwkOp::LessEq => AwkValue::String((l.to_number() <= r.to_number()).to_string()),
                    AwkOp::GreaterEq => AwkValue::String((l.to_number() >= r.to_number()).to_string()),
                    _ => AwkValue::String(String::new()),
                }
            }
            _ => AwkValue::String(String::new()),
        }
    }
}

/// Run awk with the given program and input
pub fn run_awk(program: &str, input: &str) -> Result<String, String> {
    let opts = AwkOptions {
        program: program.to_string(),
        input_files: Vec::new(),
        ..Default::default()
    };
    
    let mut awk = Awk::new(opts);
    awk.parse(program)?;
    awk.run(input)
}

/// Main awk function
pub fn main_awk(args: &[String]) -> i32 {
    let mut opts = AwkOptions::default();
    let mut i = 1;
    
    while i < args.len() && args[i].starts_with('-') {
        match args[i].as_str() {
            "-F" => {
                if i + 1 < args.len() {
                    opts.field_separator = args[i + 1].clone();
                    i += 1;
                }
            }
            "-v" => {
                if i + 1 < args.len() {
                    let var_def = &args[i + 1];
                    if let Some(pos) = var_def.find('=') {
                        opts.field_separator.push_str(&var_def[..pos]);
                    }
                    i += 1;
                }
            }
            _ => {
                if args[i].len() > 1 {
                    opts.program.push_str(&args[i][1..]);
                }
            }
        }
        i += 1;
    }
    
    if opts.program.is_empty() && i < args.len() {
        opts.program = args[i].clone();
        i += 1;
    }
    
    let input: String;
    if i < args.len() {
        let filename = &args[i];
        input = match std::fs::read_to_string(filename) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("awk: cannot read {}: {}", filename, e);
                return 1;
            }
        };
    } else {
        input = io::read_to_string(io::stdin()).unwrap_or_default();
    }
    
    match run_awk(&opts.program, &input) {
        Ok(output) => {
            print!("{}", output);
            0
        }
        Err(e) => {
            eprintln!("awk: {}", e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_all() {
        let result = run_awk("{ print }", "hello\nworld\n").unwrap();
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn test_print_field() {
        let result = run_awk("{ print $1 }", "hello world\n").unwrap();
        assert!(result.trim() == "hello");
    }

    #[test]
    fn test_begin() {
        let result = run_awk("BEGIN { print \"start\" }", "").unwrap();
        assert!(result.contains("start"));
    }

    #[test]
    fn test_field_separator() {
        let result = run_awk("-F: { print $1 }", "a:b:c\n").unwrap();
        assert!(result.trim() == "a");
    }

    #[test]
    fn test_nr_variable() {
        let result = run_awk("{ print NR }", "line1\nline2\nline3\n").unwrap();
        let lines: Vec<&str> = result.trim().lines().collect();
        assert_eq!(lines, vec!["1", "2", "3"]);
    }
}


//! Plumber Message Matcher
//!
//! Implements the matching logic for plumber rules.
//!
//! Reference: Plan 9 `sys/src/cmd/plumb/match.c`

#![allow(unused)]

use alloc::string::ToString;
use alloc::vec::Vec;
use crate::error::PlumbError;
use crate::message::Plumbmsg;
use crate::rules::{Rule, RuleAction, RuleCondition, RuleObject, RuleVerb};

/// Match result
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub rule: Rule,
    pub substitutions: Vec<alloc::string::String>,
    pub modified_msg: Option<Plumbmsg>,
}

/// Match engine for rules
pub struct Matcher {
    rules: Vec<Rule>,
}

impl Matcher {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn match_message(&self, msg: &Plumbmsg) -> Result<Option<MatchResult>, PlumbError> {
        for rule in &self.rules {
            if let Some(result) = self.try_rule(rule, msg)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    fn try_rule(&self, rule: &Rule, msg: &Plumbmsg) -> Result<Option<MatchResult>, PlumbError> {
        // Check source filter
        if let Some(ref src) = rule.src {
            if &msg.src != src {
                return Ok(None);
            }
        }

        // Check destination filter
        if let Some(ref dst) = rule.dst {
            if &msg.dst != dst {
                return Ok(None);
            }
        }

        // Check all conditions
        let mut substitutions = Vec::new();
        for cond in &rule.conditions {
            if !self.check_condition(cond, msg, &mut substitutions)? {
                return Ok(None);
            }
        }

        Ok(Some(MatchResult {
            rule: rule.clone(),
            substitutions,
            modified_msg: None,
        }))
    }

    fn check_condition(
        &self,
        cond: &RuleCondition,
        msg: &Plumbmsg,
        subs: &mut Vec<alloc::string::String>,
    ) -> Result<bool, PlumbError> {
        match cond.verb {
            RuleVerb::Is => self.check_is(&cond.object, &cond.arg, msg),
            RuleVerb::IsFile => self.check_is_file(&cond.object, msg),
            RuleVerb::IsDir => self.check_is_dir(&cond.object, msg),
            RuleVerb::Matches => self.check_matches(&cond.object, &cond.arg, msg, subs),
            _ => Ok(true),
        }
    }

    fn check_is(&self, obj: &RuleObject, arg: &str, msg: &Plumbmsg) -> Result<bool, PlumbError> {
        let value = self.get_object_value(obj, msg)?;
        Ok(value == arg)
    }

    fn check_is_file(&self, obj: &RuleObject, msg: &Plumbmsg) -> Result<bool, PlumbError> {
        let value = self.get_object_value(obj, msg)?;
        Ok(value.starts_with('/') || value.starts_with("./"))
    }

    fn check_is_dir(&self, obj: &RuleObject, msg: &Plumbmsg) -> Result<bool, PlumbError> {
        let value = self.get_object_value(obj, msg)?;
        Ok(value.ends_with('/'))
    }

    fn check_matches(
        &self,
        obj: &RuleObject,
        pattern: &str,
        msg: &Plumbmsg,
        subs: &mut Vec<alloc::string::String>,
    ) -> Result<bool, PlumbError> {
        let value = self.get_object_value(obj, msg)?;
        
        if self.simple_match(pattern, &value) {
            self.extract_groups(pattern, &value, subs);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_object_value(&self, obj: &RuleObject, msg: &Plumbmsg) -> Result<alloc::string::String, PlumbError> {
        match obj {
            RuleObject::Arg => {
                let data = core::str::from_utf8(&msg.data).unwrap_or("");
                Ok(alloc::string::String::from(data.split_whitespace().next().unwrap_or("")))
            }
            RuleObject::Data => Ok(core::str::from_utf8(&msg.data).unwrap_or("").to_string()),
            RuleObject::Dst => Ok(msg.dst.clone()),
            RuleObject::Src => Ok(msg.src.clone()),
            RuleObject::Type => Ok(msg.mtype.clone()),
            RuleObject::Wdir => Ok(msg.wdir.clone().unwrap_or_default()),
            _ => Ok(alloc::string::String::new()),
        }
    }

    fn simple_match(&self, pattern: &str, text: &str) -> bool {
        if pattern.contains('*') || pattern.contains('?') {
            // Simple glob matching
            let parts: Vec<&str> = pattern.split(|c| c == '*' || c == '?').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                return true;
            }
            let mut pos = 0;
            for part in &parts {
                if let Some(found) = text[pos..].find(part) {
                    pos += found + part.len();
                } else {
                    return false;
                }
            }
            true
        } else {
            text.contains(pattern)
        }
    }

    fn extract_groups(&self, pattern: &str, _text: &str, subs: &mut Vec<alloc::string::String>) {
        // Extract capture groups from pattern
        let mut paren_depth = 0;
        let mut group_start = None;
        
        for (i, c) in pattern.chars().enumerate() {
            match c {
                '(' => {
                    if paren_depth == 0 {
                        group_start = Some(i);
                    }
                    paren_depth += 1;
                }
                ')' => {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        if group_start.is_some() {
                            subs.push(alloc::string::String::from("$"));
                        }
                        group_start = None;
                    }
                }
                _ => {}
            }
        }
    }

    pub fn execute_actions(
        &self,
        rule: &Rule,
        msg: &Plumbmsg,
        subs: &[alloc::string::String],
    ) -> Result<Plumbmsg, PlumbError> {
        let mut result = msg.clone();

        for action in &rule.actions {
            match action {
                RuleAction::To(port) => {
                    result.dst = port.clone();
                }
                RuleAction::Start { cmd, args } => {
                    let expanded_args = self.expand_args(args, subs);
                    let _ = (cmd, expanded_args);
                }
                RuleAction::Set { name, value } => {
                    let _ = (name, self.expand_string(value, subs));
                }
                RuleAction::Add { name, value } => {
                    let _ = (name, self.expand_string(value, subs));
                }
                RuleAction::Delete(_) => {}
            }
        }

        Ok(result)
    }

    fn expand_args(&self, args: &[alloc::string::String], subs: &[alloc::string::String]) -> Vec<alloc::string::String> {
        args.iter()
            .map(|arg| self.expand_string(arg, subs))
            .collect()
    }

    fn expand_string(&self, s: &alloc::string::String, subs: &[alloc::string::String]) -> alloc::string::String {
        let mut result = alloc::string::String::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        
        while i < bytes.len() {
            if bytes[i] == b'$' && i + 1 < bytes.len() {
                let next = bytes[i + 1];
                if next == b'$' {
                    result.push('$');
                    i += 2;
                } else if next.is_ascii_digit() {
                    let idx = (next - b'0') as usize;
                    if idx < subs.len() {
                        result.push_str(&subs[idx]);
                    }
                    i += 2;
                } else {
                    result.push(bytes[i] as char);
                    i += 1;
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
        
        result
    }
}

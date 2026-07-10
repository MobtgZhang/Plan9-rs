//! Plumber Daemon
//!
//! The main plumber daemon that routes messages between applications.
//!
//! Reference: Plan 9 `sys/src/cmd/plumb/plumber.c`

#![allow(unused)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::error::PlumbError;
use crate::message::Plumbmsg;
use crate::rules::{Rule, RulesParser, DEFAULT_RULES};
use crate::matcher::Matcher;

/// Plumber daemon state
pub struct Plumber {
    rules_parser: RulesParser,
    matcher: Matcher,
    mount_point: String,
    clients: Vec<ClientConn>,
    running: bool,
}

#[derive(Debug, Clone)]
struct ClientConn {
    id: u64,
    port: String,
    connected: bool,
}

impl Plumber {
    pub fn new() -> Self {
        let mut parser = RulesParser::new();
        let _ = parser.parse_str(DEFAULT_RULES);
        let rules_copy = parser.get_rules().to_vec();

        Self {
            rules_parser: parser,
            matcher: Matcher::new(rules_copy),
            mount_point: "/mnt/plumb".to_string(),
            clients: Vec::new(),
            running: false,
        }
    }

    pub fn with_rules(rules: &str) -> Result<Self, PlumbError> {
        let mut parser = RulesParser::new();
        parser.parse_str(rules)?;
        let rules_copy = parser.get_rules().to_vec();

        Ok(Self {
            rules_parser: parser,
            matcher: Matcher::new(rules_copy),
            mount_point: "/mnt/plumb".to_string(),
            clients: Vec::new(),
            running: false,
        })
    }

    pub fn load_rules(&mut self, rules: &str) -> Result<(), PlumbError> {
        self.rules_parser.parse_str(rules)?;
        self.matcher = Matcher::new(self.rules_parser.get_rules().to_vec());
        Ok(())
    }

    pub fn add_client(&mut self, port: String) -> u64 {
        let id = self.clients.len() as u64;
        self.clients.push(ClientConn {
            id,
            port,
            connected: true,
        });
        id
    }

    pub fn remove_client(&mut self, id: u64) {
        self.clients.retain(|c| c.id != id);
    }

    pub fn send(&mut self, msg: Plumbmsg) -> Result<(), PlumbError> {
        if let Some(result) = self.matcher.match_message(&msg)? {
            let new_msg = self.matcher.execute_actions(&result.rule, &msg, &result.substitutions)?;
            self.deliver(new_msg)?;
        }
        Ok(())
    }

    fn deliver(&self, msg: Plumbmsg) -> Result<(), PlumbError> {
        let dst = msg.dst.as_str();
        
        for client in &self.clients {
            if client.port == dst && client.connected {
                return Ok(());
            }
        }
        
        Err(PlumbError::DestinationNotFound(dst.to_string()))
    }

    pub fn broadcast(&self, msg: Plumbmsg) -> Result<(), PlumbError> {
        for client in &self.clients {
            if client.connected {
                let _ = client;
            }
        }
        Ok(())
    }

    pub fn run(&mut self) {
        self.running = true;
        while self.running {
            self.process_events();
        }
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    fn process_events(&mut self) {
        // Event processing placeholder
    }

    pub fn client_count(&self) -> usize {
        self.clients.iter().filter(|c| c.connected).count()
    }

    pub fn get_rules(&self) -> &[Rule] {
        self.rules_parser.get_rules()
    }
}

impl Default for Plumber {
    fn default() -> Self {
        Self::new()
    }
}

/// Plumber filesystem entry
#[derive(Debug, Clone)]
pub struct PlumbFsEntry {
    pub name: String,
    pub qid: u64,
    pub mode: u32,
}

impl PlumbFsEntry {
    pub fn new(name: &str, qid: u64, mode: u32) -> Self {
        Self {
            name: name.to_string(),
            qid,
            mode,
        }
    }
}

/// Plumber filesystem
pub struct PlumbFs {
    pub entries: Vec<PlumbFsEntry>,
    pub plumber: Plumber,
}

impl PlumbFs {
    pub fn new(plumber: Plumber) -> Self {
        let mut entries = Vec::new();
        
        entries.push(PlumbFsEntry::new("rules", 0, 0o644));
        entries.push(PlumbFsEntry::new("rules/send", 1, 0o222));
        entries.push(PlumbFsEntry::new("send", 2, 0o222));
        entries.push(PlumbFsEntry::new("acme", 3, 0o666));
        entries.push(PlumbFsEntry::new("edit", 4, 0o666));
        
        Self { entries, plumber }
    }

    pub fn read(&self, qid: u64, offset: u64, _count: usize) -> Result<Vec<u8>, PlumbError> {
        match qid {
            0 => {
                let rules = self.plumber.get_rules();
                // Simple representation of rules
                let mut content = alloc::string::String::new();
                for rule in rules {
                    content.push_str("rule\n");
                }
                Ok(content.as_bytes()[offset as usize..].to_vec())
            }
            _ => Err(PlumbError::InvalidMessage(
                alloc::string::String::from("Unknown file"))),
        }
    }

    pub fn write(&self, qid: u64, data: &[u8]) -> Result<usize, PlumbError> {
        match qid {
            0 | 1 | 2 => Ok(data.len()),
            _ => Err(PlumbError::InvalidMessage(
                alloc::string::String::from("Unknown file"))),
        }
    }
}

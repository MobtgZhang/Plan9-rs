//! Factotum - Key Management Daemon
//!
//! Factotum is a key daemon that manages authentication keys for Plan 9.
//! It handles login, authentication, and key management.

use std::env;

// ============================================================================
// Key Types and Structures
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    P9auth,      // Plan 9 authentication
    P9sk1,       // SSH-style authentication
    P9plain,     // Plain text (deprecated)
    Crypto,       // Cryptographic keys
    Secstore,    // Secure storage
}

impl KeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "p9auth" => Some(KeyType::P9auth),
            "p9sk1" => Some(KeyType::P9sk1),
            "p9plain" => Some(KeyType::P9plain),
            "crypto" => Some(KeyType::Crypto),
            "secstore" => Some(KeyType::Secstore),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::P9auth => "p9auth",
            KeyType::P9sk1 => "p9sk1",
            KeyType::P9plain => "p9plain",
            KeyType::Crypto => "crypto",
            KeyType::Secstore => "secstore",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Key {
    pub keytype: KeyType,
    pub user: String,
    pub domain: String,
    pub proto: String,
    pub env: Vec<(String, String)>,
}

impl Key {
    pub fn new(keytype: KeyType, user: &str, domain: &str) -> Self {
        Key {
            keytype,
            user: user.to_string(),
            domain: domain.to_string(),
            proto: String::new(),
            env: Vec::new(),
        }
    }

    pub fn with_proto(mut self, proto: &str) -> Self {
        self.proto = proto.to_string();
        self
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }
}

// ============================================================================
// Factotum Options
// ============================================================================

#[derive(Debug, Clone)]
pub struct FactotumOptions {
    pub action: FactotumAction,
    pub debug: bool,
    pub verbose: bool,
    pub keyfile: Option<String>,
    pub auth: bool,
    pub add: bool,
    pub remove: bool,
    pub list: bool,
}

#[derive(Debug, Clone)]
pub enum FactotumAction {
    Start,      // Start factotum daemon
    Add,        // Add a key
    Remove,     // Remove a key
    List,       // List keys
    Get,        // Get a key
    Test,       // Test authentication
    Help,
}

impl Default for FactotumOptions {
    fn default() -> Self {
        FactotumOptions {
            action: FactotumAction::Start,
            debug: false,
            verbose: false,
            keyfile: None,
            auth: false,
            add: false,
            remove: false,
            list: false,
        }
    }
}

impl FactotumOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = FactotumOptions::default();

        for arg in args {
            match arg.as_str() {
                "-d" | "--debug" => opts.debug = true,
                "-v" | "--verbose" => opts.verbose = true,
                "-a" | "--auth" => opts.auth = true,
                "add" => {
                    opts.add = true;
                    opts.action = FactotumAction::Add;
                }
                "remove" | "del" | "delete" => {
                    opts.remove = true;
                    opts.action = FactotumAction::Remove;
                }
                "list" | "ls" => {
                    opts.list = true;
                    opts.action = FactotumAction::List;
                }
                "get" => opts.action = FactotumAction::Get,
                "test" => opts.action = FactotumAction::Test,
                "-k" | "--keyfile" => {
                    // Keyfile would be set in next iteration
                }
                "-h" | "--help" | "help" => opts.action = FactotumAction::Help,
                _ if arg.starts_with("-k=") => {
                    opts.keyfile = Some(arg[3..].to_string());
                }
                _ => {}
            }
        }

        opts
    }
}

// ============================================================================
// Key Store (Simulated)
// ============================================================================

struct KeyStore {
    keys: Vec<Key>,
}

impl KeyStore {
    fn new() -> Self {
        KeyStore { keys: Vec::new() }
    }

    fn add_key(&mut self, key: Key) {
        self.keys.push(key);
    }

    fn remove_key(&mut self, keytype: &KeyType, user: &str) -> bool {
        let pos = self.keys.iter().position(|k| {
            k.keytype == *keytype && k.user == user
        });
        if let Some(idx) = pos {
            self.keys.remove(idx);
            true
        } else {
            false
        }
    }

    fn list_keys(&self) {
        println!("KEYTYPE\tUSER\t\tDOMAIN\tPROTO");
        println!("-------\t----\t\t------\t-----");
        for key in &self.keys {
            println!("{}\t{}\t\t{}\t{}",
                    key.keytype.as_str(),
                    key.user,
                    key.domain,
                    key.proto);
        }
    }

    fn get_key(&self, keytype: &KeyType, user: &str) -> Option<&Key> {
        self.keys.iter().find(|k| {
            k.keytype == *keytype && k.user == user
        })
    }
}

// ============================================================================
// Implementation
// ============================================================================

pub fn run_factotum(args: &[String]) -> i32 {
    let opts = FactotumOptions::parse(args);

    match opts.action {
        FactotumAction::Help => {
            print_usage();
            0
        }
        FactotumAction::List => {
            let store = KeyStore::new();
            // In real implementation, keys would be loaded from persistent storage
            println!("Factotum key database (simulated)");
            println!("No keys loaded. Use 'factotum add' to add keys.");
            0
        }
        FactotumAction::Add => {
            if opts.verbose {
                println!("Adding key to factotum...");
            }
            // In real implementation, this would interact with the running factotum
            println!("Key added (simulated)");
            0
        }
        FactotumAction::Remove => {
            if opts.verbose {
                println!("Removing key from factotum...");
            }
            println!("Key removed (simulated)");
            0
        }
        FactotumAction::Get => {
            println!("Getting key (simulated)");
            0
        }
        FactotumAction::Test => {
            println!("Testing authentication (simulated)");
            0
        }
        FactotumAction::Start => {
            if opts.verbose {
                println!("Starting factotum daemon...");
            }
            println!("factotum: daemon mode not supported in standalone mode");
            println!("Factotum provides key management for Plan 9 authentication.");
            println!("");
            print_usage();
            0
        }
    }
}

fn print_usage() {
    println!("Usage: factotum [options] [action]");
    println!("");
    println!("Actions:");
    println!("  add         Add a key");
    println!("  remove      Remove a key");
    println!("  list        List all keys");
    println!("  get         Get a specific key");
    println!("  test        Test authentication");
    println!("");
    println!("Options:");
    println!("  -d, --debug    Enable debug mode");
    println!("  -v, --verbose  Verbose output");
    println!("  -a, --auth     Authenticate");
    println!("  -k, --keyfile  Specify key file");
    println!("  -h, --help     Show this help");
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_factotum(&args);
    std::process::exit(status);
}

//! Secstore - Secure Storage
//!
//! Secstore provides secure storage for sensitive data.

use std::env;

// ============================================================================
// Secstore Options
// ============================================================================

#[derive(Debug, Clone)]
pub struct SecstoreOptions {
    pub action: String,
    pub user: Option<String>,
    pub file: Option<String>,
    pub secret: Option<String>,
    pub debug: bool,
    pub verbose: bool,
    pub force: bool,
}

impl Default for SecstoreOptions {
    fn default() -> Self {
        SecstoreOptions {
            action: "help".to_string(),
            user: None,
            file: None,
            secret: None,
            debug: false,
            verbose: false,
            force: false,
        }
    }
}

impl SecstoreOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = SecstoreOptions::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-u" | "--user" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.user = Some(args[i].clone());
                    }
                }
                "--file" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.file = Some(args[i].clone());
                    }
                }
                "-s" | "--secret" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.secret = Some(args[i].clone());
                    }
                }
                "--debug" => opts.debug = true,
                "--verbose" => opts.verbose = true,
                "--force" => opts.force = true,
                "put" => opts.action = "put".to_string(),
                "get" => opts.action = "get".to_string(),
                "delete" => opts.action = "delete".to_string(),
                "list" => opts.action = "list".to_string(),
                "whoami" => opts.action = "whoami".to_string(),
                "-h" | "--help" | "help" => opts.action = "help".to_string(),
                _ => {}
            }
            i += 1;
        }

        opts
    }
}

// ============================================================================
// Implementation
// ============================================================================

pub fn run_secstore(args: &[String]) -> i32 {
    let opts = SecstoreOptions::parse(args);

    match opts.action.as_str() {
        "help" => {
            print_usage();
            0
        }
        "put" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let file = opts.file.as_deref().unwrap_or("");
            let secret = opts.secret.as_deref().unwrap_or("");

            if opts.verbose {
                println!("Storing secret for user: {}", user);
                if !file.is_empty() {
                    println!("From file: {}", file);
                }
            }

            if secret.is_empty() && file.is_empty() {
                eprintln!("secstore: No secret or file specified");
                return 1;
            }

            println!("Secret stored successfully (simulated)");
            0
        }
        "get" => {
            let user = opts.user.as_deref().unwrap_or("default");

            if opts.verbose {
                println!("Retrieving secret for user: {}", user);
            }

            // Simulated retrieval
            if opts.file.is_some() {
                println!("Secret retrieved and written to file (simulated)");
            } else {
                println!("Secret: [retrieved but not displayed for security]");
            }
            0
        }
        "delete" => {
            let user = opts.user.as_deref().unwrap_or("default");

            if opts.verbose {
                println!("Deleting secret for user: {}", user);
            }

            if !opts.force {
                println!("Use -f to confirm deletion");
                return 1;
            }

            println!("Secret deleted successfully (simulated)");
            0
        }
        "list" => {
            let user = opts.user.as_deref().unwrap_or("");

            if opts.verbose {
                println!("Listing secrets for user: {}", user);
            }

            println!("Stored secrets:");
            println!("  default");
            println!("  ssh_key");
            println!("  api_token");
            0
        }
        "whoami" => {
            let user = opts.user.as_deref().unwrap_or("default");
            println!("{}", user);
            0
        }
        _ => {
            print_usage();
            1
        }
    }
}

fn print_usage() {
    println!("Usage: secstore [options] [action]");
    println!("");
    println!("Actions:");
    println!("  put       Store a secret");
    println!("  get       Retrieve a secret");
    println!("  delete    Delete a secret");
    println!("  list      List stored secrets");
    println!("  whoami    Show current user");
    println!("");
    println!("Options:");
    println!("  -u, --user    User name");
    println!("  -f, --file    File containing secret");
    println!("  -s, --secret  Secret value (not recommended)");
    println!("  -d, --debug   Enable debug mode");
    println!("  -v, --verbose Verbose output");
    println!("  -f, --force   Force operation");
    println!("  -h, --help    Show this help");
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_secstore(&args);
    std::process::exit(status);
}

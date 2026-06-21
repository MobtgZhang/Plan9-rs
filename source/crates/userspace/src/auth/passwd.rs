//! Passwd Command
//!
//! Change user password for Plan 9.

use std::env;
use std::io::{self, Write};

// ============================================================================
// Passwd Options
// ============================================================================

#[derive(Debug, Clone)]
pub struct PasswdOptions {
    pub user: Option<String>,
    pub debug: bool,
    pub verbose: bool,
    pub delete: bool,
    pub lock: bool,
    pub unlock: bool,
    pub minlen: Option<usize>,
    pub warndays: Option<usize>,
    pub inactive: Option<usize>,
}

impl Default for PasswdOptions {
    fn default() -> Self {
        PasswdOptions {
            user: None,
            debug: false,
            verbose: false,
            delete: false,
            lock: false,
            unlock: false,
            minlen: None,
            warndays: None,
            inactive: None,
        }
    }
}

impl PasswdOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = PasswdOptions::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--debug" => opts.debug = true,
                "--verbose" => opts.verbose = true,
                "--delete" => opts.delete = true,
                "--lock" => opts.lock = true,
                "--unlock" => opts.unlock = true,
                "-m" | "--minlen" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.minlen = args[i].parse().ok();
                    }
                }
                "-w" | "--warndays" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.warndays = args[i].parse().ok();
                    }
                }
                "-i" | "--inactive" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.inactive = args[i].parse().ok();
                    }
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ if !args[i].starts_with('-') && opts.user.is_none() => {
                    opts.user = Some(args[i].clone());
                }
                _ => {}
            }
            i += 1;
        }

        opts
    }
}

// ============================================================================
// Password Operations
// ============================================================================

fn get_password(prompt: &str) -> Option<String> {
    print!("{}", prompt);
    io::stdout().flush().ok();

    let mut password = String::new();
    if io::stdin().read_line(&mut password).is_ok() {
        Some(password.trim().to_string())
    } else {
        None
    }
}

fn verify_current_password(user: &str) -> bool {
    // Simulated password verification
    if user == "root" {
        // In a real system, this would check against /adm/passwd
        true
    } else {
        true
    }
}

fn update_password(user: &str, new_password: &str) -> Result<(), &'static str> {
    // Simulated password update
    if new_password.len() < 6 {
        return Err("Password too short (minimum 6 characters)");
    }

    // In real implementation, this would update the password database
    println!("Password updated successfully for user: {}", user);
    Ok(())
}

// ============================================================================
// Implementation
// ============================================================================

pub fn run_passwd(args: &[String]) -> i32 {
    let opts = PasswdOptions::parse(args);

    // Get target user
    let user = if let Some(ref u) = opts.user {
        u.clone()
    } else {
        // Get current user from environment
        std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
    };

    if opts.debug {
        println!("Changing password for user: {}", user);
    }

    // Handle special operations
    if opts.delete {
        println!("Deleting password for user: {} (simulated)", user);
        return 0;
    }

    if opts.lock {
        println!("Locking account: {} (simulated)", user);
        return 0;
    }

    if opts.unlock {
        println!("Unlocking account: {} (simulated)", user);
        return 0;
    }

    // Verify current password
    if !verify_current_password(&user) {
        eprintln!("passwd: Authentication failure");
        return 1;
    }

    // Get new password
    let new_pass = match get_password("Enter new password: ") {
        Some(p) => p,
        None => {
            eprintln!("passwd: Failed to read new password");
            return 1;
        }
    };

    // Confirm new password
    let confirm_pass = match get_password("Retype new password: ") {
        Some(p) => p,
        None => {
            eprintln!("passwd: Failed to confirm password");
            return 1;
        }
    };

    // Verify passwords match
    if new_pass != confirm_pass {
        eprintln!("passwd: Passwords do not match");
        return 1;
    }

    // Check minimum length
    if let Some(minlen) = opts.minlen {
        if new_pass.len() < minlen {
            eprintln!("passwd: Password too short (minimum {} characters)", minlen);
            return 1;
        }
    }

    // Update password
    match update_password(&user, &new_pass) {
        Ok(()) => {
            if opts.verbose {
                println!("Password changed successfully");
            }
            0
        }
        Err(e) => {
            eprintln!("passwd: {}", e);
            1
        }
    }
}

fn print_usage() {
    println!("Usage: passwd [options] [user]");
    println!("");
    println!("Options:");
    println!("  -d, --delete     Delete password for the account");
    println!("  -l, --lock       Lock the account");
    println!("  -u, --unlock     Unlock the account");
    println!("  -m, --minlen N   Set minimum password length");
    println!("  -w, --warndays N Set number of days to warn before expiry");
    println!("  -i, --inactive N Set days after expiry before account is disabled");
    println!("  -d, --debug      Enable debug mode");
    println!("  -v, --verbose    Verbose output");
    println!("  -h, --help       Show this help");
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_passwd(&args);
    std::process::exit(status);
}

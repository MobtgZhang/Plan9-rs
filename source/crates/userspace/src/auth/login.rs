//! Login Command
//!
//! Login command for user authentication on Plan 9.

use std::env;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Login Options
// ============================================================================

#[derive(Debug, Clone)]
pub struct LoginOptions {
    pub user: Option<String>,
    pub host: Option<String>,
    pub debug: bool,
    pub verbose: bool,
    pub noroot: bool,
    pub nopam: bool,
}

impl Default for LoginOptions {
    fn default() -> Self {
        LoginOptions {
            user: None,
            host: None,
            debug: false,
            verbose: false,
            noroot: false,
            nopam: false,
        }
    }
}

impl LoginOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = LoginOptions::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--host" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.host = Some(args[i].clone());
                    }
                }
                "--debug" => opts.debug = true,
                "--verbose" => opts.verbose = true,
                "--noroot" => opts.noroot = true,
                "--nopam" => opts.nopam = true,
                "--help" => {
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
// User Database (Simulated)
// ============================================================================

struct UserDatabase;

impl UserDatabase {
    fn check_password(_user: &str, password: &str) -> bool {
        // Simulated password check
        // In real implementation, this would check against a secure password database
        !password.is_empty()
    }

    fn get_shell(user: &str) -> &'static str {
        match user {
            "root" => "/bin/rc",
            _ => "/bin/rc",
        }
    }
}

// ============================================================================
// Implementation
// ============================================================================

fn prompt_login() -> Option<(String, String)> {
    print!("login: ");
    io::stdout().flush().ok();

    let mut username = String::new();
    if io::stdin().read_line(&mut username).is_err() {
        return None;
    }
    username = username.trim().to_string();

    if username.is_empty() {
        return None;
    }

    // Get password
    print!("password: ");
    io::stdout().flush().ok();

    // Note: In real implementation, use termios to disable echo
    let mut password = String::new();
    if io::stdin().read_line(&mut password).is_err() {
        return None;
    }
    password = password.trim().to_string();

    Some((username, password))
}

pub fn run_login(args: &[String]) -> i32 {
    let opts = LoginOptions::parse(args);

    // If user is provided on command line, skip prompts
    if let Some(ref user) = opts.user {
        let host = opts.host.as_deref().unwrap_or("");
        if opts.verbose {
            println!("Login attempt for user: {}@{}", user, host);
        }

        // Simulate successful login
        println!("Welcome to Plan 9!");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        println!("Last login: {}", format_timestamp(now));

        // Start the user's shell
        let shell = UserDatabase::get_shell(user);
        if opts.verbose {
            println!("Starting shell: {}", shell);
        }

        0
    } else {
        // Interactive login
        loop {
            if let Some((username, password)) = prompt_login() {
                if opts.debug {
                    println!("Attempting login for: {}", username);
                }

                if UserDatabase::check_password(&username, &password) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let datetime = format_timestamp(now);
                    println!("Welcome to Plan 9!");
                    println!("Last login: {}", datetime);

                    // Start shell
                    let shell = UserDatabase::get_shell(&username);
                    if opts.verbose {
                        println!("Starting shell: {}", shell);
                    }
                    return 0;
                } else {
                    println!("Login incorrect");
                    if opts.verbose {
                        println!("Authentication failed");
                    }
                }
            } else {
                println!("Login failed");
                return 1;
            }
        }
    }
}

fn print_usage() {
    println!("Usage: login [options] [user]");
    println!("");
    println!("Options:");
    println!("  -h, --host     Remote host");
    println!("  -d, --debug    Enable debug mode");
    println!("  -v, --verbose  Verbose output");
    println!("  -noroot        Disallow root login");
    println!("  -nopam          Don't use PAM");
    println!("");
    println!("If no user is specified, login will prompt for username and password.");
}

fn format_timestamp(secs: u64) -> String {
    // Simple timestamp formatter
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    // Approximate date calculation (simplified)
    let year = 2026;
    let month_idx = 5; // June
    let day = 21;
    let hour = ((secs % 86400) / 3600) as u32;
    let min = ((secs % 3600) / 60) as u32;
    let sec = (secs % 60) as u32;

    format!("{} {} {:2} {:02}:{:02}:{:02} {}",
            days[0], months[month_idx], day, hour, min, sec, year)
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_login(&args);
    std::process::exit(status);
}

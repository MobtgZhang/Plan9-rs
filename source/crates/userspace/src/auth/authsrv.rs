//! Authsrv - Authentication Server
//!
//! Authsrv provides authentication services for Plan 9 networks.

use std::env;

// ============================================================================
// Authentication Messages
// ============================================================================

#[derive(Debug, Clone)]
pub enum AuthOp {
    Auth,
    AuthInfo,
    ChangeSecret,
    AddUser,
    RemoveUser,
    CheckUser,
}

impl AuthOp {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "auth" => Some(AuthOp::Auth),
            "authinfo" => Some(AuthOp::AuthInfo),
            "changesecret" => Some(AuthOp::ChangeSecret),
            "adduser" => Some(AuthOp::AddUser),
            "removeuser" => Some(AuthOp::RemoveUser),
            "checkuser" => Some(AuthOp::CheckUser),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub op: AuthOp,
    pub user: String,
    pub domain: String,
    pub chal: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub ok: bool,
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}

// ============================================================================
// Authsrv Options
// ============================================================================

#[derive(Debug, Clone)]
pub struct AuthsrvOptions {
    pub action: String,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub port: u16,
    pub debug: bool,
    pub verbose: bool,
}

impl Default for AuthsrvOptions {
    fn default() -> Self {
        AuthsrvOptions {
            action: "help".to_string(),
            user: None,
            domain: None,
            host: None,
            port: 567,
            debug: false,
            verbose: false,
        }
    }
}

impl AuthsrvOptions {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = AuthsrvOptions::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--host" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.host = Some(args[i].clone());
                    }
                }
                "-p" | "--port" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.port = args[i].parse().unwrap_or(567);
                    }
                }
                "-d" | "--debug" => opts.debug = true,
                "-v" | "--verbose" => opts.verbose = true,
                "auth" => opts.action = "auth".to_string(),
                "authinfo" => opts.action = "authinfo".to_string(),
                "adduser" => opts.action = "adduser".to_string(),
                "removeuser" => opts.action = "removeuser".to_string(),
                "checkuser" => opts.action = "checkuser".to_string(),
                "server" => opts.action = "server".to_string(),
                _ if !args[i].starts_with('-') && opts.user.is_none() => {
                    opts.user = Some(args[i].clone());
                }
                _ if !args[i].starts_with('-') && opts.domain.is_none() => {
                    opts.domain = Some(args[i].clone());
                }
                _ => {}
            }
            i += 1;
        }

        opts
    }
}

// ============================================================================
// Authentication Functions
// ============================================================================

fn simulate_auth(user: &str, domain: &str) -> AuthResponse {
    if user.is_empty() {
        return AuthResponse {
            ok: false,
            token: None,
            error: Some("Empty username".to_string()),
        };
    }

    // Simulate successful authentication
    AuthResponse {
        ok: true,
        token: Some(vec![0x01, 0x02, 0x03, 0x04]),
        error: None,
    }
}

fn simulate_authinfo(user: &str, domain: &str) {
    println!("Authinfo for user: {}", user);
    println!("Domain: {}", domain);
    println!("Secret required: yes");
    println!("Key file: /mnt/factotum/keys");
}

fn simulate_adduser(user: &str, domain: &str) {
    println!("Adding user: {}@{}", user, domain);
    println!("User added successfully (simulated)");
}

fn simulate_removeuser(user: &str, domain: &str) {
    println!("Removing user: {}@{}", user, domain);
    println!("User removed successfully (simulated)");
}

fn simulate_checkuser(user: &str, domain: &str) {
    println!("Checking user: {}@{}", user, domain);
    println!("User exists: yes (simulated)");
}

// ============================================================================
// Implementation
// ============================================================================

pub fn run_authsrv(args: &[String]) -> i32 {
    let opts = AuthsrvOptions::parse(args);

    match opts.action.as_str() {
        "help" => {
            print_usage();
            0
        }
        "auth" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let domain = opts.domain.as_deref().unwrap_or("");

            if opts.verbose {
                println!("Authenticating user: {}@{}", user, domain);
            }

            let response = simulate_auth(user, domain);

            if response.ok {
                if opts.verbose {
                    println!("Authentication successful!");
                    if let Some(token) = response.token {
                        println!("Token: {:02x?}", token);
                    }
                } else {
                    println!("Authentication OK");
                }
                0
            } else {
                eprintln!("Authentication failed: {:?}", response.error);
                1
            }
        }
        "authinfo" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let domain = opts.domain.as_deref().unwrap_or("");
            simulate_authinfo(user, domain);
            0
        }
        "adduser" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let domain = opts.domain.as_deref().unwrap_or("");
            simulate_adduser(user, domain);
            0
        }
        "removeuser" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let domain = opts.domain.as_deref().unwrap_or("");
            simulate_removeuser(user, domain);
            0
        }
        "checkuser" => {
            let user = opts.user.as_deref().unwrap_or("default");
            let domain = opts.domain.as_deref().unwrap_or("");
            simulate_checkuser(user, domain);
            0
        }
        "server" => {
            println!("Starting authsrv server...");
            println!("This would start the authentication server in daemon mode.");
            1
        }
        _ => {
            print_usage();
            1
        }
    }
}

fn print_usage() {
    println!("Usage: authsrv [options] [action] [user] [domain]");
    println!("");
    println!("Actions:");
    println!("  auth          Authenticate a user");
    println!("  authinfo      Get authentication info for a user");
    println!("  adduser       Add a new user");
    println!("  removeuser    Remove a user");
    println!("  checkuser     Check if a user exists");
    println!("  server        Start the authsrv server");
    println!("");
    println!("Options:");
    println!("  -h, --host     Server host");
    println!("  -p, --port     Server port (default: 567)");
    println!("  -d, --debug    Enable debug mode");
    println!("  -v, --verbose  Verbose output");
    println!("");
    println!("Examples:");
    println!("  authsrv auth glenda plan9");
    println!("  authsrv authinfo glenda");
    println!("  authsrv adduser newuser");
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_authsrv(&args);
    std::process::exit(status);
}

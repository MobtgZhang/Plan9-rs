//! Make Directory Command
//!
//! Implementation of the mkdir command.

use std::env;
use std::fs;
use std::path::Path;

// ============================================================================
// Options
// ============================================================================

/// Command options
#[derive(Debug, Clone, Default)]
pub struct MkdirOptions {
    pub parents: bool,  // -p: create parent directories
    pub mode: u32,      // -m: set permission mode
}

impl MkdirOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = MkdirOptions {
            parents: false,
            mode: 0o755,
        };
        let mut paths = Vec::new();
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "-p" => opts.parents = true,
                "-m" => {
                    if i + 1 < args.len() {
                        i += 1;
                        if let Ok(m) = u32::from_str_radix(&args[i], 8) {
                            opts.mode = m;
                        }
                    }
                }
                _ if !args[i].starts_with('-') => {
                    paths.push(args[i].clone());
                }
                _ => {}
            }
            i += 1;
        }

        (opts, paths)
    }
}

/// Create a directory
fn make_dir(path: &str, opts: &MkdirOptions) -> std::io::Result<()> {
    let path = Path::new(path);

    if opts.parents {
        fs::create_dir_all(path)?;
    } else {
        fs::create_dir(path)?;
    }

    Ok(())
}

/// Run mkdir command
pub fn run_mkdir(args: &[String]) -> i32 {
    let (opts, paths) = MkdirOptions::parse(args);

    if paths.is_empty() {
        eprintln!("mkdir: missing operand");
        return 1;
    }

    let mut status = 0;

    for path in &paths {
        if let Err(e) = make_dir(path, &opts) {
            eprintln!("mkdir: cannot create directory '{}': {}", path, e);
            status = 1;
        }
    }

    status
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_mkdir(&args[1..]);
    std::process::exit(status);
}

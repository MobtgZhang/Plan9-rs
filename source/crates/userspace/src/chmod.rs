//! Change Mode Command
//!
//! Implementation of the chmod command.

use std::env;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ============================================================================
// Options
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ChmodOptions {
    pub recursive: bool,
}

impl ChmodOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = ChmodOptions::default();
        let mut paths = Vec::new();

        for arg in args {
            match arg.as_str() {
                "-R" | "--recursive" => opts.recursive = true,
                _ if arg.starts_with('-') => {}
                _ => paths.push(arg.clone()),
            }
        }

        (opts, paths)
    }
}

/// Run chmod command
pub fn run_chmod(args: &[String]) -> i32 {
    let (opts, paths) = ChmodOptions::parse(args);

    if paths.len() < 2 {
        eprintln!("chmod: missing operand");
        return 1;
    }

    let mode_str = &paths[0];
    let files = &paths[1..];

    // Parse octal mode
    let mode = match u32::from_str_radix(mode_str, 8) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("chmod: invalid mode: '{}'", mode_str);
            return 1;
        }
    };

    let mut status = 0;

    for file in files {
        let path = Path::new(file);

        #[cfg(unix)]
        {
            if let Err(e) = fs::set_permissions(path, PermissionsExt::from_mode(mode)) {
                eprintln!("chmod: cannot change '{}': {}", file, e);
                status = 1;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            let _ = mode;
            eprintln!("chmod: not supported on this platform");
            status = 1;
        }
    }

    status
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_chmod(&args[1..]);
    std::process::exit(status);
}

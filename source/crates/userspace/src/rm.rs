//! Remove Files Command
//!
//! Implementation of the rm command.

use std::env;
use std::fs;
use std::path::Path;

// ============================================================================
// Options
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct RmOptions {
    pub force: bool,
    pub recursive: bool,
    pub verbose: bool,
}

impl RmOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = RmOptions::default();
        let mut paths = Vec::new();

        for arg in args {
            match arg.as_str() {
                "-f" | "--force" => opts.force = true,
                "-r" | "-R" | "--recursive" => opts.recursive = true,
                "-v" | "--verbose" => opts.verbose = true,
                _ if arg.starts_with('-') => {}
                _ => paths.push(arg.clone()),
            }
        }

        (opts, paths)
    }
}

fn remove_path(path: &str, opts: &RmOptions) -> std::io::Result<()> {
    let path = Path::new(path);

    if path.is_dir() {
        if !opts.recursive {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot remove a directory without -r flag",
            ));
        }
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    if opts.verbose {
        println!("removed '{}'", path.display());
    }

    Ok(())
}

pub fn run_rm(args: &[String]) -> i32 {
    let (opts, paths) = RmOptions::parse(args);

    if paths.is_empty() {
        eprintln!("rm: missing operand");
        return 1;
    }

    let mut status = 0;

    for path in &paths {
        if let Err(e) = remove_path(path, &opts) {
            if !opts.force || e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("rm: cannot remove '{}': {}", path, e);
                status = 1;
            }
        }
    }

    status
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_rm(&args[1..]);
    std::process::exit(status);
}

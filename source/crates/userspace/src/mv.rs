//! Move Files Command
//!
//! Implementation of the mv command.

use std::env;
use std::fs;
use std::path::Path;

// ============================================================================
// Options
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct MvOptions {
    pub force: bool,
    pub verbose: bool,
}

impl MvOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = MvOptions::default();
        let mut paths = Vec::new();

        for arg in args {
            match arg.as_str() {
                "-f" | "--force" => opts.force = true,
                "-v" | "--verbose" => opts.verbose = true,
                _ if arg.starts_with('-') => {}
                _ => paths.push(arg.clone()),
            }
        }

        (opts, paths)
    }
}

/// Move/rename a file or directory
fn move_path(src: &str, dst: &str, _opts: &MvOptions) -> std::io::Result<()> {
    let src_path = Path::new(src);
    let dst_path = Path::new(dst);

    if !src_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("'{}': no such file or directory", src),
        ));
    }

    // Try to rename
    fs::rename(src_path, dst_path)?;

    Ok(())
}

pub fn run_mv(args: &[String]) -> i32 {
    let (opts, paths) = MvOptions::parse(args);

    if paths.len() < 2 {
        eprintln!("mv: missing file operand");
        return 1;
    }

    let sources = &paths[..paths.len() - 1];
    let dest = &paths[paths.len() - 1];

    let mut status = 0;

    for src in sources {
        if let Err(e) = move_path(src, dest, &opts) {
            eprintln!("mv: cannot move '{}': {}", src, e);
            status = 1;
        }
    }

    status
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_mv(&args[1..]);
    std::process::exit(status);
}

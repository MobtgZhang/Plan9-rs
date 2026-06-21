//! Create Links Command
//!
//! Implementation of the ln command.

use std::env;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::symlink;

#[derive(Debug, Clone, Default)]
pub struct LnOptions {
    pub symbolic: bool,
    pub force: bool,
    pub verbose: bool,
}

impl LnOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = LnOptions::default();
        let mut paths = Vec::new();

        for arg in args {
            match arg.as_str() {
                "-s" | "--symbolic" => opts.symbolic = true,
                "-f" | "--force" => opts.force = true,
                "-v" | "--verbose" => opts.verbose = true,
                _ if arg.starts_with('-') => {}
                _ => paths.push(arg.clone()),
            }
        }

        (opts, paths)
    }
}

pub fn run_ln(args: &[String]) -> i32 {
    let (opts, paths) = LnOptions::parse(args);

    if paths.len() != 2 {
        eprintln!("ln: missing destination operand");
        return 1;
    }

    let src = &paths[0];
    let dst = &paths[1];

    let src_path = Path::new(src);
    let dst_path = Path::new(dst);

    // Remove existing destination if force
    if opts.force && dst_path.exists() {
        let _ = fs::remove_file(dst_path);
    }

    #[cfg(unix)]
    {
        if opts.symbolic {
            if let Err(e) = symlink(src_path, dst_path) {
                eprintln!("ln: cannot create symbolic link '{}': {}", dst, e);
                return 1;
            }
        } else {
            if let Err(e) = fs::hard_link(src_path, dst_path) {
                eprintln!("ln: cannot create link '{}': {}", dst, e);
                return 1;
            }
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("ln: hard links not supported on this platform");
        return 1;
    }

    if opts.verbose {
        println!("'{}' -> '{}'", dst, src);
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_ln(&args[1..]);
    std::process::exit(status);
}

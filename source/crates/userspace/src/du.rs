//! Disk Usage Command
//!
//! Implementation of the du command.

use std::env;
use std::fs;

pub fn run_du(args: &[String]) -> i32 {
    let mut human = false;
    let mut summarize = false;
    let mut paths = vec!["."];

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--human-readable" => human = true,
            "-s" | "--summarize" => summarize = true,
            _ if !args[i].starts_with('-') => {
                paths.clear();
                paths.push(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    for path in paths {
        if let Ok(entries) = fs::read_dir(path) {
            let mut total = 0u64;
            for entry in entries.flatten() {
                let metadata = entry.metadata().ok();
                if let Some(m) = metadata {
                    let size = m.len();
                    total += size;
                    if !summarize {
                        println!("{}\t{}", size / 1024, entry.path().display());
                    }
                }
            }
            if summarize {
                println!("{}\t{}", total / 1024, path);
            }
        }
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_du(&args);
    std::process::exit(status);
}

//! Disk Usage Command
//!
//! Implementation of the du command.

use std::env;
use std::fs;
use std::format;

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
                        println!("{}\t{}", format_size(size, human), entry.path().display());
                    }
                }
            }
            if summarize {
                println!("{}\t{}", format_size(total, human), path);
            }
        }
    }

    0
}

fn format_size(bytes: u64, human: bool) -> String {
    if !human {
        return format!("{}", bytes / 1024);
    }
    const UNITS: &[&str] = &["K", "M", "G", "T", "P"];
    let mut size = bytes as f64;
    let mut unit = "K";
    for u in UNITS {
        if size < 1024.0 {
            unit = u;
            break;
        }
        size /= 1024.0;
        unit = u;
    }
    format!("{:.1}{}", size, unit)
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_du(&args);
    std::process::exit(status);
}

//! Tail Command
//!
//! Implementation of the tail command.

use std::env;
use std::io::{self, BufRead};

pub fn run_tail(args: &[String]) -> i32 {
    let mut lines = 10;
    let mut paths = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                if i + 1 < args.len() {
                    i += 1;
                    if let Ok(n) = args[i].parse() {
                        lines = n;
                    }
                }
            }
            _ if args[i].starts_with("-n") => {
                if let Ok(n) = args[i][2..].parse() {
                    lines = n;
                }
            }
            _ if !args[i].starts_with('-') => {
                paths.push(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    let all_lines: Vec<String>;

    if paths.is_empty() || paths[0] == "-" {
        let stdin = io::stdin();
        let reader = BufRead::lines(io::BufReader::new(stdin.lock()));
        all_lines = reader.filter_map(Result::ok).collect();
    } else {
        match std::fs::File::open(paths[0]) {
            Ok(file) => {
                let reader = BufRead::lines(io::BufReader::new(file));
                all_lines = reader.filter_map(Result::ok).collect();
            }
            Err(e) => {
                eprintln!("tail: {}: {}", paths[0], e);
                return 1;
            }
        }
    }

    // Print last N lines
    let start = if all_lines.len() > lines {
        all_lines.len() - lines
    } else {
        0
    };

    for line in &all_lines[start..] {
        println!("{}", line);
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_tail(&args);
    std::process::exit(status);
}

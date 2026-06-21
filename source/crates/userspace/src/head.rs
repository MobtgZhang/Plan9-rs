//! Head Command
//!
//! Implementation of the head command.

use std::env;
use std::io::{self, BufRead};

pub fn run_head(args: &[String]) -> i32 {
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

    let read_from = if paths.is_empty() || paths[0] == "-" {
        Box::new(io::stdin().lock()) as Box<dyn BufRead>
    } else {
        match std::fs::File::open(paths[0]) {
            Ok(f) => Box::new(io::BufReader::new(f)),
            Err(e) => {
                eprintln!("head: {}: {}", paths[0], e);
                return 1;
            }
        }
    };

    let mut reader = read_from;
    let mut line = String::new();
    let mut count = 0;

    while count < lines {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                print!("{}", line);
                count += 1;
            }
            Err(e) => {
                eprintln!("head: {}", e);
                return 1;
            }
        }
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_head(&args);
    std::process::exit(status);
}

//! Sort Command
//!
//! Implementation of the sort command.

use std::env;
use std::io::{self, BufRead};

pub fn run_sort(args: &[String]) -> i32 {
    let mut numeric = false;
    let mut reverse = false;
    let mut unique = false;

    let mut paths = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--numeric" => numeric = true,
            "-r" | "--reverse" => reverse = true,
            "-u" | "--unique" => unique = true,
            _ if !args[i].starts_with('-') => {
                paths.push(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    // Read all lines
    let mut lines: Vec<String>;

    if paths.is_empty() || paths[0] == "-" {
        let stdin = io::stdin();
        let reader = io::BufReader::new(stdin.lock());
        lines = reader.lines().map_while(Result::ok).collect();
    } else {
        lines = Vec::new();
        for path in &paths {
            if let Ok(file) = std::fs::File::open(path) {
                let reader = io::BufReader::new(file);
                lines.extend(reader.lines().map_while(Result::ok));
            }
        }
    }

    // Sort
    if numeric {
        lines.sort_by(|a, b| {
            let a_num: f64 = a.parse().unwrap_or(0.0);
            let b_num: f64 = b.parse().unwrap_or(0.0);
            if reverse { b_num.partial_cmp(&a_num).unwrap() } else { a_num.partial_cmp(&b_num).unwrap() }
        });
    } else {
        lines.sort();
        if reverse {
            lines.reverse();
        }
    }

    // Unique
    if unique {
        lines.dedup();
    }

    // Output
    for line in &lines {
        println!("{}", line);
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_sort(&args);
    std::process::exit(status);
}

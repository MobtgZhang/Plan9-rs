//! Uniq Command
//!
//! Implementation of the uniq command.

use std::env;
use std::io::{self, BufRead};

pub fn run_uniq(args: &[String]) -> i32 {
    let mut count = false;
    let mut show_unique = false;
    let mut show_duplicates = false;

    let mut paths = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--count" => count = true,
            "-u" | "--unique" => show_unique = true,
            "-d" | "--repeated" => show_duplicates = true,
            _ if !args[i].starts_with('-') => {
                paths.push(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    // Read all lines
    let lines: Vec<String>;

    if paths.is_empty() || paths[0] == "-" {
        let stdin = io::stdin();
        let reader = io::BufReader::new(stdin.lock());
        lines = reader.lines().map_while(Result::ok).collect();
    } else {
        let mut all_lines = Vec::new();
        for path in &paths {
            if let Ok(file) = std::fs::File::open(path) {
                let reader = io::BufReader::new(file);
                all_lines.extend(reader.lines().map_while(Result::ok));
            }
        }
        lines = all_lines;
    }

    if lines.is_empty() {
        return 0;
    }

    // Process
    let mut current = lines[0].clone();
    let mut current_count = 1u64;

    for line in &lines[1..] {
        if line == &current {
            current_count += 1;
        } else {
            // Output previous
            let should_show = (!show_unique && !show_duplicates) ||
                           (show_unique && current_count == 1) ||
                           (show_duplicates && current_count > 1);

            if should_show {
                if count {
                    println!("{:>7} {}", current_count, current);
                } else {
                    println!("{}", current);
                }
            }

            current = line.clone();
            current_count = 1;
        }
    }

    // Output last
    let should_show = (!show_unique && !show_duplicates) ||
                      (show_unique && current_count == 1) ||
                      (show_duplicates && current_count > 1);

    if should_show {
        if count {
            println!("{:>7} {}", current_count, current);
        } else {
            println!("{}", current);
        }
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_uniq(&args);
    std::process::exit(status);
}

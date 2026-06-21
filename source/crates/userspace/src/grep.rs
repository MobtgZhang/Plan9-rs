//! Grep Command - Pattern Matching
//!
//! Implementation of the grep command with basic regex support.

use std::env;
use std::io::{self, BufRead};

pub fn run_grep(args: &[String]) -> i32 {
    let mut ignore_case = false;
    let mut invert = false;
    let mut count_only = false;
    let mut quiet = false;
    let mut pattern_idx = None;
    let mut paths = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--ignore-case" => ignore_case = true,
            "-v" | "--invert-match" => invert = true,
            "-c" | "--count" => count_only = true,
            "-q" | "--quiet" | "--silent" => quiet = true,
            _ if args[i].starts_with("-") => {}
            _ if pattern_idx.is_none() => {
                pattern_idx = Some(i);
            }
            _ => {
                paths.push(&args[i]);
            }
        }
        i += 1;
    }

    let pattern = match pattern_idx {
        Some(idx) => args[idx].clone(),
        None => {
            eprintln!("grep: no pattern specified");
            return 1;
        }
    };

    let search_in = if paths.is_empty() || paths[0] == "-" {
        let stdin = io::stdin();
        let lock = stdin.lock();
        vec![(None, Box::new(lock) as Box<dyn BufRead>)]
    } else {
        paths.iter()
            .filter_map(|p| {
                std::fs::File::open(p).ok()
                    .map(|f| (Some(p.to_string()), Box::new(io::BufReader::new(f)) as Box<dyn BufRead>))
            })
            .collect()
    };

    let mut total_matches = 0usize;

    for (name, mut reader) in search_in {
        let mut matches = 0;
        let mut line_num = 0;
        let mut line = String::new();

        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            line_num += 1;
            let _ = line_num;  // suppress unused warning
            let pattern_lower = if ignore_case { pattern.to_lowercase() } else { pattern.clone() };
            let line_lower = if ignore_case { line.to_lowercase() } else { line.clone() };

            let found = line_lower.contains(&pattern_lower);
            let do_print = if invert { !found } else { found };

            if found {
                matches += 1;
            }

            if do_print {
                if !count_only && !quiet {
                    if let Some(ref n) = name {
                        print!("{}:", n);
                    }
                    if !line.ends_with('\n') {
                        print!("{}{}", line.trim_end(), "\n");
                    } else {
                        print!("{}", line);
                    }
                }
            }

            line.clear();
        }

        if count_only {
            if let Some(ref n) = name {
                println!("{}:{}", n, matches);
            } else {
                println!("{}", matches);
            }
        }

        total_matches += matches;
    }

    if quiet && total_matches > 0 {
        return 0;
    }

    if total_matches > 0 { 0 } else { 1 }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_grep(&args);
    std::process::exit(status);
}

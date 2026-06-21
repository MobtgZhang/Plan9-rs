//! Cut Command
//!
//! Implementation of the cut command.

use std::env;
use std::io::{self, BufRead, Write};

pub fn run_cut(args: &[String]) -> i32 {
    let mut fields: Option<Vec<usize>> = None;
    let mut delimiter = "\t";
    let mut paths = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--fields" => {
                if i + 1 < args.len() {
                    i += 1;
                    fields = Some(args[i].split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect());
                }
            }
            "-d" | "--delimiter" => {
                if i + 1 < args.len() {
                    i += 1;
                    delimiter = &args[i];
                }
            }
            _ if !args[i].starts_with('-') => {
                paths.push(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    let fields = fields.unwrap_or_else(|| vec![1]);

    let read_from: Box<dyn BufRead> = if paths.is_empty() || paths[0] == "-" {
        Box::new(io::stdin().lock())
    } else {
        match std::fs::File::open(paths[0]) {
            Ok(f) => Box::new(io::BufReader::new(f)),
            Err(e) => {
                eprintln!("cut: {}: {}", paths[0], e);
                return 1;
            }
        }
    };

    let mut stdout = io::stdout();
    let mut line = String::new();
    let mut reader = read_from;

    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let parts: Vec<&str> = line.split(delimiter).collect();
        let mut first = true;

        for &f in &fields {
            if f > 0 && f <= parts.len() {
                if !first {
                    print!("{}", delimiter);
                }
                print!("{}", parts[f - 1].trim_end());
                first = false;
            }
        }
        println!();

        line.clear();
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_cut(&args);
    std::process::exit(status);
}

//! Translate Command
//!
//! Implementation of the tr command.

use std::env;
use std::io::{self, Read, Write};

pub fn run_tr(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("tr: missing operand");
        return 1;
    }

    let set1 = &args[1];
    let set2 = if args.len() >= 3 { &args[2] } else { "" };

    let mut stdin = io::stdin();
    let mut input = Vec::new();
    if stdin.read_to_end(&mut input).is_err() {
        return 1;
    }

    let mut output = Vec::new();

    // Simple character translation
    let trans: Vec<(char, char)> = set1.chars()
        .zip(set2.chars())
        .collect();

    for byte in input {
        let c = byte as char;
        let mut replaced = false;

        for &(from, to) in &trans {
            if c == from {
                output.push(to as u8);
                replaced = true;
                break;
            }
        }

        if !replaced {
            output.push(byte);
        }
    }

    io::stdout().write_all(&output).ok();
    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_tr(&args);
    std::process::exit(status);
}

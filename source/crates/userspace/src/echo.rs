//! Echo Command
//!
//! Implementation of the echo command.

use std::env;

pub fn run_echo(args: &[String]) -> i32 {
    let mut no_newline = false;
    let mut i = 1;

    if i < args.len() && args[i] == "-n" {
        no_newline = true;
        i += 1;
    }

    for j in i..args.len() {
        if j > i {
            print!(" ");
        }
        print!("{}", args[j]);
    }

    if !no_newline {
        println!();
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_echo(&args);
    std::process::exit(status);
}

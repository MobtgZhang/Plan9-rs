//! Process Status Command
//!
//! Implementation of the ps command.

use std::env;

pub fn run_ps(args: &[String]) -> i32 {
    let show_all = args.iter().any(|a| a == "-e" || a == "-A");

    println!("  PID TTY      TIME CMD");
    println!("{:>5} ??      00:00:00 ps", std::process::id());

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_ps(&args);
    std::process::exit(status);
}

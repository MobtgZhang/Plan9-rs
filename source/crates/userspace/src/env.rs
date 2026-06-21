//! Environment Command
//!
//! Implementation of the env command.

use std::env;

pub fn run_env(_args: &[String]) -> i32 {
    for (key, value) in env::vars() {
        println!("{}={}", key, value);
    }
    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_env(&args);
    std::process::exit(status);
}

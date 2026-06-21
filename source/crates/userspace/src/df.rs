//! Disk Free Command
//!
//! Implementation of the df command.

use std::env;

pub fn run_df(_args: &[String]) -> i32 {
    println!("Filesystem      1024-blocks      Used Available Use% Mounted on");
    println!("tmpfs                  1024         0      1024   0% /tmp");
    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_df(&args);
    std::process::exit(status);
}

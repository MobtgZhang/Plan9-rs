//! Change Group Command
//!
//! Implementation of the chgrp command.

use std::env;

pub fn run_chgrp(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("chgrp: missing operand");
        return 1;
    }

    eprintln!("chgrp: not fully implemented");
    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_chgrp(&args[1..]);
    std::process::exit(status);
}

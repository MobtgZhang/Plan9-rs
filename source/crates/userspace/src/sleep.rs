//! Sleep Command
//!
//! Implementation of the sleep command.

use std::env;

pub fn run_sleep(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("sleep: missing operand");
        return 1;
    }

    match args[1].parse::<f64>() {
        Ok(secs) => {
            let ms = (secs * 1000.0) as u64;
            std::thread::sleep(std::time::Duration::from_millis(ms));
            0
        }
        Err(_) => {
            eprintln!("sleep: invalid time interval: '{}'", args[1]);
            1
        }
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_sleep(&args);
    std::process::exit(status);
}

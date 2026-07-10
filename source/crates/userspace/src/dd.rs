//! Data Copy Command
//!
//! Implementation of the dd command.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};

pub fn run_dd(args: &[String]) -> i32 {
    let mut input_file = None;
    let mut output_file = None;
    let mut block_size: usize = 512;
    let mut count = None;

    let mut i = 1;
    while i < args.len() {
        if let Some((key, value)) = args[i].split_once('=') {
            match key {
                "if" => input_file = Some(value.to_string()),
                "of" => output_file = Some(value.to_string()),
                "bs" => { block_size = value.parse().unwrap_or(512); }
                "count" => count = value.parse().ok(),
                _ => {}
            }
        }
        i += 1;
    }

    // Open input
    let mut input: Box<dyn Read> = if let Some(ref f) = input_file {
        match File::open(f) {
            Ok(file) => Box::new(file),
            Err(e) => {
                eprintln!("dd: {}: {}", f, e);
                return 1;
            }
        }
    } else {
        Box::new(io::stdin())
    };

    // Open output
    let mut output: Box<dyn Write> = if let Some(ref f) = output_file {
        match File::create(f) {
            Ok(file) => Box::new(file),
            Err(e) => {
                eprintln!("dd: {}: {}", f, e);
                return 1;
            }
        }
    } else {
        Box::new(io::stdout())
    };

    let mut buffer = vec![0u8; block_size];
    let mut total_bytes = 0u64;
    let max_count = count.unwrap_or(usize::MAX);
    let mut blocks_read = 0usize;

    loop {
        if blocks_read >= max_count {
            break;
        }

        let bytes_read = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("dd: read error: {}", e);
                return 1;
            }
        };

        blocks_read += 1;

        if let Err(e) = output.write_all(&buffer[..bytes_read]) {
            eprintln!("dd: write error: {}", e);
            return 1;
        }

        total_bytes += bytes_read as u64;
    }

    eprintln!("{} bytes copied", total_bytes);
    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_dd(&args);
    std::process::exit(status);
}

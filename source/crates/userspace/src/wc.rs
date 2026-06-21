//! Word Count Command
//!
//! Implementation of the wc command.

use std::env;
use std::io::{self, BufRead};

pub struct WcStats {
    pub lines: u64,
    pub words: u64,
    pub chars: u64,
}

impl WcStats {
    fn new() -> Self {
        WcStats { lines: 0, words: 0, chars: 0 }
    }
}

pub fn run_wc(args: &[String]) -> i32 {
    let mut total_stats = WcStats::new();
    let mut status = 0;

    if args.len() <= 1 || args[1] == "-" {
        let stdin = io::stdin();
        let stats = count_reader(stdin.lock());
        stats.print(None);
        total_stats.add(&stats);
    } else {
        for path in &args[1..] {
            match count_file(path) {
                Ok(stats) => {
                    stats.print(Some(path));
                    total_stats.add(&stats);
                }
                Err(e) => {
                    eprintln!("wc: {}: {}", path, e);
                    status = 1;
                }
            }
        }

        if args.len() > 2 {
            total_stats.print(Some("total"));
        }
    }

    status
}

fn count_reader<R: BufRead>(mut reader: R) -> WcStats {
    let mut stats = WcStats::new();
    let mut line = String::new();

    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        stats.lines += 1;
        stats.chars += line.len() as u64;
        stats.words += line.split_whitespace().count() as u64;
        line.clear();
    }

    stats
}

fn count_file(path: &str) -> io::Result<WcStats> {
    let file = std::fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    Ok(count_reader(reader))
}

impl WcStats {
    fn add(&mut self, other: &WcStats) {
        self.lines += other.lines;
        self.words += other.words;
        self.chars += other.chars;
    }

    fn print(&self, name: Option<&str>) {
        print!("{:>7} {:>7} {:>7}", self.lines, self.words, self.chars);
        if let Some(n) = name {
            print!(" {}", n);
        }
        println!();
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_wc(&args);
    std::process::exit(status);
}

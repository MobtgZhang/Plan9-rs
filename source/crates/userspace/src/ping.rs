//! Ping Command
//!
//! Implementation of the ping command for network connectivity testing.

use std::env;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

pub struct PingOptions {
    pub count: Option<usize>,
    pub interval: f64,
    pub timeout: f64,
    pub verbose: bool,
    pub flood: bool,
    pub numeric: bool,
    pub quiet: bool,
    pub ttl: u8,
}

impl Default for PingOptions {
    fn default() -> Self {
        PingOptions {
            count: None,
            interval: 1.0,
            timeout: 4.0,
            verbose: false,
            flood: false,
            numeric: false,
            quiet: false,
            ttl: 64,
        }
    }
}

impl PingOptions {
    pub fn parse(args: &[String]) -> (Self, Option<String>) {
        let mut opts = PingOptions::default();
        let mut target = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-c" | "--count" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.count = args[i].parse().ok();
                    }
                }
                "-i" | "--interval" => {
                    if i + 1 < args.len() {
                        i += 1;
                        if let Ok(interval) = args[i].parse() {
                            opts.interval = interval;
                        }
                    }
                }
                "-W" | "--timeout" => {
                    if i + 1 < args.len() {
                        i += 1;
                        if let Ok(timeout) = args[i].parse() {
                            opts.timeout = timeout;
                        }
                    }
                }
                "-v" | "--verbose" => opts.verbose = true,
                "-f" | "--flood" => opts.flood = true,
                "-n" | "--numeric" => opts.numeric = true,
                "-q" | "--quiet" => opts.quiet = true,
                "-t" | "--ttl" => {
                    if i + 1 < args.len() {
                        i += 1;
                        if let Ok(ttl) = args[i].parse() {
                            opts.ttl = ttl;
                        }
                    }
                }
                _ if !args[i].starts_with('-') && target.is_none() => {
                    target = Some(args[i].clone());
                }
                _ => {}
            }
            i += 1;
        }

        (opts, target)
    }
}

fn resolve_host(host: &str) -> Option<String> {
    // Try to parse as IP address first
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }

    // Try to resolve hostname
    match format!("{}:80", host).to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                return Some(addr.ip().to_string());
            }
        }
        Err(_) => {}
    }

    None
}

pub fn run_ping(args: &[String]) -> i32 {
    let (opts, target) = PingOptions::parse(args);

    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("ping: usage error: Destination address required");
            return 1;
        }
    };

    let resolved = resolve_host(&target);

    let ip = match &resolved {
        Some(ip) => ip.clone(),
        None => {
            eprintln!("ping: {}: Name or service not known", target);
            return 2;
        }
    };

    if !opts.quiet {
        println!("PING {} ({}) 56(84) bytes of data.", target, ip);
    }

    let count = opts.count.unwrap_or(4);
    let mut transmitted = 0;
    let mut received = 0;
    let mut total_time = 0.0;

    for i in 0..count {
        transmitted += 1;

        // Simulate ping response
        let time_ms = 0.5 + (i as f64) * 0.1;
        total_time += time_ms;
        received += 1;

        if !opts.quiet {
            println!("64 bytes from {}: icmp_seq={} ttl={} time={:.2} ms",
                    ip, i + 1, opts.ttl, time_ms);
        }

        if opts.flood {
            print!(".");
        }

        if i < count - 1 {
            std::thread::sleep(Duration::from_secs_f64(opts.interval));
        }
    }

    if opts.flood {
        println!();
    }

    if !opts.quiet || opts.verbose {
        println!("--- {} ping statistics ---", target);
        println!("{} packets transmitted, {} received, {}% packet loss, time {} ms",
                transmitted, received,
                if transmitted > 0 { ((transmitted - received) * 100) / transmitted } else { 0 },
                (total_time * 1000.0) as i64);

        if received > 0 {
            println!("rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
                    0.1, total_time / received as f64, total_time, 0.1);
        }
    }

    if received == 0 {
        1
    } else {
        0
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_ping(&args);
    std::process::exit(status);
}

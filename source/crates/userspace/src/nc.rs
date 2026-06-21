//! Netcat Command
//!
//! Implementation of the nc (netcat) command for network connections and port scanning.

use std::env;
use std::net::{TcpStream, TcpListener, SocketAddr};
use std::io::{self, Read, Write};
use std::time::Duration;

pub struct NcOptions {
    pub listen: bool,
    pub verbose: bool,
    pub numeric: bool,
    pub timeout: Option<u64>,
    pub port: Option<u16>,
    pub tcp: bool,
    pub udp: bool,
    pub keep_open: bool,
    pub zero: bool,
    pub exec: Option<String>,
}

impl Default for NcOptions {
    fn default() -> Self {
        NcOptions {
            listen: false,
            verbose: false,
            numeric: false,
            timeout: None,
            port: None,
            tcp: true,
            udp: false,
            keep_open: false,
            zero: false,
            exec: None,
        }
    }
}

impl NcOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = NcOptions::default();
        let mut targets = Vec::new();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-l" | "--listen" => opts.listen = true,
                "-v" | "--verbose" => opts.verbose = true,
                "-n" | "--numeric" => opts.numeric = true,
                "-4" => {}  // IPv4 only
                "-6" => {}  // IPv6 only
                "-u" | "--udp" => {
                    opts.udp = true;
                    opts.tcp = false;
                }
                "-t" | "--tcp" => {
                    opts.tcp = true;
                    opts.udp = false;
                }
                "-k" | "--keep-open" => opts.keep_open = true,
                "-z" | "--zero" => opts.zero = true,
                "-w" | "--wait" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.timeout = args[i].parse().ok();
                    }
                }
                "-p" | "--local-port" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.port = args[i].parse().ok();
                    }
                }
                "-e" | "--exec" => {
                    if i + 1 < args.len() {
                        i += 1;
                        opts.exec = Some(args[i].clone());
                    }
                }
                _ if !args[i].starts_with('-') => {
                    targets.push(args[i].clone());
                }
                _ => {}
            }
            i += 1;
        }

        (opts, targets)
    }
}

fn handle_connection(stream: &mut std::net::TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 8192];

    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                std::io::stdout().write_all(&buffer[..n])?;
                std::io::stdout().flush()?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

pub fn run_nc(args: &[String]) -> i32 {
    let (opts, targets) = NcOptions::parse(args);

    if opts.listen {
        // Server mode
        let port = opts.port.unwrap_or(0);

        if opts.verbose {
            println!("Listening on [::]:{}", port);
        }

        let addr: SocketAddr = if opts.udp {
            format!("0.0.0.0:{}", port).parse().unwrap()
        } else {
            format!("0.0.0.0:{}", port).parse().unwrap()
        };

        if opts.tcp {
            match TcpListener::bind(addr) {
                Ok(listener) => {
                    for stream in listener.incoming() {
                        match stream {
                            Ok(mut stream) => {
                                if opts.verbose {
                                    println!("Connection from {:?}", stream.peer_addr());
                                }
                                if let Err(e) = handle_connection(&mut stream) {
                                    if opts.verbose {
                                        eprintln!("Error: {}", e);
                                    }
                                }
                                if !opts.keep_open {
                                    break;
                                }
                            }
                            Err(e) => {
                                if opts.verbose {
                                    eprintln!("Connection failed: {}", e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("nc: {}", e);
                    return 1;
                }
            }
        }
    } else {
        // Client mode
        if targets.is_empty() {
            eprintln!("nc: missing target");
            return 1;
        }

        let target = &targets[0];
        let port = targets.get(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);

        if port == 0 {
            eprintln!("nc: missing port number");
            return 1;
        }

        let address = format!("{}:{}", target, port);

        if opts.verbose {
            println!("Connection to {} port {}", target, port);
        }

        if opts.zero {
            println!("Connection successful!");
            return 0;
        }

        match address.parse::<SocketAddr>() {
            Ok(_) => {
                match TcpStream::connect_timeout(
                    &address.parse().unwrap(),
                    Duration::from_secs(opts.timeout.unwrap_or(10))
                ) {
                    Ok(mut stream) => {
                        if let Err(e) = handle_connection(&mut stream) {
                            if opts.verbose {
                                eprintln!("Error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("nc: {}", e);
                        return 1;
                    }
                }
            }
            Err(_) => {
                eprintln!("nc: invalid address");
                return 1;
            }
        }
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_nc(&args);
    std::process::exit(status);
}

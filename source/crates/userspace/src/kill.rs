//! Kill Command
//!
//! Implementation of the kill command.

use std::env;

pub fn run_kill(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("kill: no process specified");
        return 1;
    }

    let signal = if args[1] == "-l" {
        println!(" 1) SIGHUP       2) SIGINT       3) SIGQUIT");
        println!(" 4) SIGILL       5) SIGTRAP      6) SIGABRT");
        println!(" 7) SIGBUS       8) SIGFPE       9) SIGKILL");
        println!("10) SIGUSR1     11) SIGSEGV     12) SIGUSR2");
        println!("13) SIGPIPE     14) SIGALRM     15) SIGTERM");
        return 0;
    } else {
        15  // SIGTERM
    };

    if let Ok(pid) = args[1].parse::<u32>() {
        println!("kill: signal {} sent to process {}", signal, pid);
    }

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_kill(&args);
    std::process::exit(status);
}

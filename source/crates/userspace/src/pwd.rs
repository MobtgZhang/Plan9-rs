//! Print Working Directory Command
//!
//! Implementation of the pwd command.


pub fn run_pwd() -> i32 {
    match std::env::current_dir() {
        Ok(path) => {
            println!("{}", path.display());
            0
        }
        Err(e) => {
            eprintln!("pwd: {}", e);
            1
        }
    }
}

pub fn main() {
    let status = run_pwd();
    std::process::exit(status);
}

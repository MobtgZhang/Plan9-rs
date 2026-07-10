use plan9_userspace::awk::main_awk;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(main_awk(&args));
}

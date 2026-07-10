use plan9_userspace::ip::run_ip;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(run_ip(&args));
}

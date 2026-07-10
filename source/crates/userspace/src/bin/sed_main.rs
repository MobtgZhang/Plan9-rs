use plan9_userspace::sed::main_sed;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(main_sed(&args));
}

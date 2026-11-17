#![no_std]
#![no_main]

//! Bare-metal entry stub for the `sleep` command.

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    let code = cmd::sleep::main(argc as usize, argv as *const *const u8);
    cmd::syscall::exit(code)
}

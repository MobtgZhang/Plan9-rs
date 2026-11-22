#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    cmd::syscall::exit(cmd::network::snoopy(argc as usize, argv as *const *const u8))
}

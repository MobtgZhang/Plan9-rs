#![no_std]
#![no_main]

//! Bare-metal entry stub for the `rc` shell (the Plan 9 terminal shell).

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    cmd::rc::entry(argc, argv)
}

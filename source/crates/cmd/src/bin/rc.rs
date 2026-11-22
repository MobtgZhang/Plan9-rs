#![no_std]
#![no_main]

extern crate alloc;

#[path = "../rc.rs"]
mod rc;

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

static mut HEAP: [u8; 512 * 1024] = [0; 512 * 1024];

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    unsafe {
        ALLOCATOR.lock().init(core::ptr::addr_of_mut!(HEAP).cast(), 512 * 1024);
    }
    cmd::syscall::exit(rc::main(argc as usize, argv as *const *const u8))
}

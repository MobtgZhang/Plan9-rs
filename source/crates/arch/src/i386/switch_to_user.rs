//! i386 user-mode entry stub (not a supported target).
#![allow(dead_code)]

pub const USER_CS: u16 = 0x1B;
pub const USER_DS: u16 = 0x23;
pub const USER_RFLAGS_INIT: u64 = 0x202;

/// Set the trap-frame page consumed by the next `switch_to_user` (no-op).
pub fn set_switch_frame(_frame_phys: u64) {}

/// Build the user frame (no-op stub).
pub unsafe fn build_user_frame(_frame_page: u64, _entry: u64, _user_sp: u64, _user_root: u64) {}

/// Switch to user mode via IRET (stub; not a supported target).
///
/// # Safety
/// Never returns.
pub unsafe fn switch_to_user_trampoline(pml4_phys: u64, _frame_ptr: u64) -> ! {
    super::mmu::cr3_write(plan9_common::types::PhysAddr::new(pml4_phys));
    // IRET to PLV3 is set up by boot code; this stub halts.
    loop {
        super::cpu::hlt();
    }
}

/// Resume a user process after a trap (stub; not a supported target).
///
/// # Safety
/// Never returns.
pub unsafe fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> ! {
    switch_to_user_trampoline(pml4_phys, frame_ptr)
}

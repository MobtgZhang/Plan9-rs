//! AArch64 user-mode entry — the equivalent of the x86_64 IRET
//! trampoline.
//!
//! The kernel runs at EL1. `switch_to_user` installs the user address
//! space root (TTBR0_EL1), then performs an `eret` into EL0:
//!
//!   * ELR_EL1  = user entry point
//!   * SPSR_EL1 = 0b0100 (EL0h, SP_EL0 active, DAIF all masked? no —
//!     we leave DAIF inherited: SPSR bit2 = 0 selects EL0, bits 9:6 = 0
//!     so DAIF are *cleared* i.e. interrupts enabled on return)
//!   * SP_EL0   = user stack pointer
//!
//! After the `eret`, exceptions are vectored through VBAR_EL1 and the
//! kernel continues to run on its identity mapping plus the TTBR1
//! direct-map window (both supervisor-only), exactly like the x86_64
//! kernel's clone-the-kernel-half design.

extern crate plan9_common;


use crate::write_sysreg;

/// Initial user PSTATE: EL0 with SP_EL0, all DAIF inherited cleared
/// (interrupts enabled). Bits: [3:0]=0b0100 EL0h, [9:6]=0 DAIF clear.
pub const USER_PSTATE_INIT: u64 = 0b0100;

/// Selectors kept for API parity with the x86_64 module (AArch64 has no
/// GDT; these are informational only).
pub const USER_DS: u16 = 0;
pub const USER_CS: u16 = 0;

/// User RFLAGS equivalent (DAIF mask state) — kept for API parity.
pub const USER_RFLAGS_INIT: u64 = 0;

/// Build the user trap frame on `frame_page` (one fresh 4 KiB page).
///
/// Layout (64-byte header consumed by `switch_to_user_trampoline`):
///   [0] scratch        (consumed by the trampoline)
///   [1] entry (ELR)
///   [2] pstate (SPSR)
///   [3] user stack pointer (SP_EL0)
///   [4] user root table (TTBR0_EL1)
#[inline]
pub unsafe fn build_user_frame(
    frame_page: u64,
    entry: u64,
    user_sp: u64,
    user_root: u64,
) {
    let fp = frame_page as *mut u64;
    fp.add(0).write_volatile(0);
    fp.add(1).write_volatile(entry);
    fp.add(2).write_volatile(USER_PSTATE_INIT);
    fp.add(3).write_volatile(user_sp);
    fp.add(4).write_volatile(user_root);
}

/// Switch to user mode.
///
/// `pml4_phys` is the physical address of the user root table (L0),
/// `frame_ptr` the physical address of the frame built by
/// [`build_user_frame`].
///
/// # Safety
/// Never returns; the CPU leaves EL1 via `eret`.
pub unsafe fn switch_to_user_trampoline(pml4_phys: u64, frame_ptr: u64) -> ! {
    // 1. Install the user root table.
    write_sysreg!("TTBR0_EL1", pml4_phys);
    super::cpu::dsb_sy();
    super::cpu::isb();

    // 2. Load the frame contents.
    let fp = frame_ptr as *const u64;
    let entry = fp.add(1).read_volatile();
    let pstate = fp.add(2).read_volatile();
    let user_sp = fp.add(3).read_volatile();

    // 3. Eret into EL0.
    core::arch::asm!(
        "msr sp_el0, {sp}",
        "msr elr_el1, {pc}",
        "msr spsr_el1, {ps}",
        "eret",
        sp = in(reg) user_sp,
        pc = in(reg) entry,
        ps = in(reg) pstate,
        options(noreturn, nostack)
    );
}

/// Resume a user process after a kernel-mode syscall/trap.
///
/// `frame_ptr` points to a full trap frame saved by the vector entry
/// code; `pml4_phys` is the process root table. Equivalent to the x86
/// `kernel_resume_user(frame_ptr, pml4_phys)` used after a syscall.
///
/// # Safety
/// Never returns.
pub unsafe fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> ! {
    write_sysreg!("TTBR0_EL1", pml4_phys);
    super::cpu::dsb_sy();
    // The trap frame ends with { pc, pstate, sp } — restore and eret.
    core::arch::asm!(
        // frame_ptr is in x0 (SysV-ish: first argument).
        "mov x19, x0",
        // Restore general registers x0-x18 (skip x19 = frame base).
        "ldp x0, x1, [x19]",
        "ldp x2, x3, [x19, #16]",
        "ldp x4, x5, [x19, #32]",
        "ldp x6, x7, [x19, #48]",
        "ldp x8, x9, [x19, #64]",
        "ldp x10, x11, [x19, #80]",
        "ldp x12, x13, [x19, #96]",
        "ldp x14, x15, [x19, #112]",
        "ldp x16, x17, [x19, #128]",
        "ldp x18, x20, [x19, #144]",
        "ldp x21, x22, [x19, #160]",
        "ldp x23, x24, [x19, #176]",
        "ldp x25, x26, [x19, #192]",
        "ldp x27, x28, [x19, #208]",
        "ldp x29, x30, [x19, #224]",
        // pc, pstate, sp are the last three words.
        "ldr x20, [x19, #248]",  // pc
        "ldr x21, [x19, #256]",  // pstate
        "ldr x22, [x19, #264]",  // sp
        "msr elr_el1, x20",
        "msr spsr_el1, x21",
        "msr sp_el0, x22",
        "eret",
        in("x0") frame_ptr,
        options(noreturn, nostack)
    );
}

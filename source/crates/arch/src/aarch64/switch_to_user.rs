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
/// Initial SPSR for user mode.
///
/// Bits [3:0] = 0b0000 selects EL0t (user mode with SP_EL0).  With no
/// DAIF bits set, interrupts are enabled on the ERET.  (0b0100 would be
/// EL1t — the kernel must never ERET into EL1 to run user code.)
pub const USER_PSTATE_INIT: u64 = 0b0000;

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
    // The kernel runs without ASIDs, so every root-table switch MUST be
    // followed by a full TLB invalidate: stale entries tagged by the old
    // root (e.g. a forked parent's stack pages) would otherwise keep
    // translating user VAs to the *previous* process's frames.
    super::mmu::flush_tlb();
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
/// `frame_ptr` points to a full 272-byte trap frame saved by the vector
/// entry code (x0..x30 at [8*i], PC at [248], PSTATE at [256], user SP
/// at [264]); `pml4_phys` is the process root table. Equivalent to the
/// x86 `kernel_resume_user(frame_ptr, pml4_phys)` used after a syscall.
///
/// # Safety
/// Never returns.
pub unsafe fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> ! {
    write_sysreg!("TTBR0_EL1", pml4_phys);
    super::cpu::dsb_sy();
    // Same constraint as `switch_to_user_trampoline`: no ASIDs means a
    // root-table switch is only safe after a full TLB invalidate. This
    // is the exact path a forked child takes for its first user-mode
    // resume, where stale parent entries would redirect the child's
    // stack writes into the parent's frames.
    super::mmu::flush_tlb();
    super::cpu::isb();
    core::arch::asm!(
        // The frame base lives in x20; its saved value ([base+160]) is
        // reloaded last, after every other read through the base.
        "mov x20, x0",
        "ldp x0, x1, [x20]",
        "ldp x2, x3, [x20, #16]",
        "ldp x4, x5, [x20, #32]",
        "ldp x6, x7, [x20, #48]",
        "ldp x8, x9, [x20, #64]",
        "ldp x10, x11, [x20, #80]",
        "ldp x12, x13, [x20, #96]",
        "ldp x14, x15, [x20, #112]",
        "ldp x16, x17, [x20, #128]",
        "ldp x18, x19, [x20, #144]",
        "ldr x21, [x20, #168]",
        // Stage user SP/PC/PSTATE and install them into the system
        // registers *immediately* — eret is the only consumer, and doing
        // the msr's up front frees x22/x23/x24 for the user-value reload
        // below.  (The staging registers are user-visible callee-saved
        // registers; leaving SP/PC/PSTATE in them destroyed the user's
        // own x22/x23/x24 on every syscall return — the same bug
        // RESTORE_AND_ERET in boot.S already fixed for the trap path.)
        "ldr x22, [x20, #264]",  // user SP
        "ldr x23, [x20, #248]",  // PC
        "ldr x24, [x20, #256]",  // PSTATE
        "msr sp_el0, x22",
        "msr elr_el1, x23",
        "msr spsr_el1, x24",
        "ldp x22, x23, [x20, #176]",  // the user's own x22/x23
        "ldr x24, [x20, #192]",       // the user's own x24
        "ldp x25, x26, [x20, #200]",
        "ldp x27, x28, [x20, #216]",
        "ldr x29, [x20, #232]",
        "ldr x30, [x20, #240]",
        "ldr x20, [x20, #160]",  // x20 last (base no longer needed)
        "eret",
        in("x0") frame_ptr,
        options(noreturn, nostack)
    );
}

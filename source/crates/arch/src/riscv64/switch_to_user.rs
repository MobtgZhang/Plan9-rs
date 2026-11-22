//! RISC-V user-mode entry — the equivalent of the x86_64 IRET
//! trampoline.
//!
//! The kernel runs in S-mode; user code in U-mode. `sret` returns:
//!   * sepc    = user entry point
//!   * sstatus = SPP=0 (U-mode), SPIE=0, SIE=0
//!   * sp      = user stack pointer
//!
//! The user root table (satp) is switched before the `sret`; the kernel
//! keeps running on its identity mapping (cloned into every user root,
//! mirroring the x86_64 clone-the-kernel-half design) and the
//! high-half direct map.

extern crate plan9_common;

/// Initial `sstatus` for user entry: SPP=0 (U-mode), SPIE=0, i.e. 0.
/// `sret` copies SPIE into SIE. The supervisor timer can interrupt U-mode
/// even when SIE is clear, while S-mode can run with interrupts masked.
pub const USER_SSTATUS_INIT: u64 = 0;

/// Selectors kept for API parity with the x86_64 module.
pub const USER_DS: u16 = 0;
pub const USER_CS: u16 = 0;
pub const USER_RFLAGS_INIT: u64 = USER_SSTATUS_INIT;

/// Build the user frame on `frame_page` (layout matches aarch64):
///   [0] scratch, [1] entry (sepc), [2] sstatus, [3] user sp,
///   [4] user root table (satp PPN base).
#[inline]
pub unsafe fn build_user_frame(frame_page: u64, entry: u64, user_sp: u64, user_root: u64) {
    let fp = frame_page as *mut u64;
    fp.add(0).write_volatile(0);
    fp.add(1).write_volatile(entry);
    fp.add(2).write_volatile(USER_SSTATUS_INIT);
    fp.add(3).write_volatile(user_sp);
    fp.add(4).write_volatile(user_root);
}

/// Switch to user mode.
///
/// # Safety
/// Never returns; the CPU leaves S-mode via `sret`.
pub unsafe fn switch_to_user_trampoline(pml4_phys: u64, frame_ptr: u64) -> ! {
    // 1. Install the user root table (satp + sfence).
    super::mmu::cr3_write(plan9_common::types::PhysAddr::new(pml4_phys));

    // 2. Load the frame contents.
    let fp = frame_ptr as *const u64;
    let entry = fp.add(1).read_volatile();
    let sstatus = fp.add(2).read_volatile();
    let user_sp = fp.add(3).read_volatile();

    // 3. Sret into U-mode.
    core::arch::asm!(
        "csrw sepc, {pc}",
        "csrw sstatus, {ss}",
        "mv sp, {sp}",
        "sret",
        pc = in(reg) entry,
        ss = in(reg) sstatus,
        sp = in(reg) user_sp,
        options(noreturn, nostack)
    );
}

// boot.S keeps the supervisor trap frame here; `sscratch` must point at it
// whenever user code runs, because the trap entry swaps sp <-> sscratch as
// its very first instruction.  Every path that resumes user mode through
// this function bypasses boot.S's exit restore, so it is redone here.
extern "C" {
    static _user_trap_area: u8;
}

/// Resume a user process after a kernel-mode syscall/trap.
///
/// Trap-frame layout (written by the vector save code):
///   * x0–x31 general registers at frame offsets `8 * n`
///     (x2 holds the user stack pointer as captured at trap time)
///   * `sepc` at offset 256
///   * `sstatus` at offset 264
///
/// Restore order: sepc/sstatus are written to their CSRs first to free
/// the t1/t2 temporaries; x5 (t0, the frame base) is reloaded last via a
/// self-referential load.
///
/// # Safety
/// Never returns.
pub unsafe fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> ! {
    // Re-point sscratch at the supervisor trap frame (see above); leaving
    // it as the previous process's user sp would make the next trap save
    // its frame onto a U-mode page — which faults (S-mode, SUM=0) and
    // recurses into the trap entry forever, silently.  boot.S defines the
    // frame as the top 34 slots (272 bytes) of the 8 KiB trap area.
    core::arch::asm!(
        "csrw sscratch, {ft}",
        ft = in(reg) core::ptr::addr_of!(_user_trap_area) as usize + 8192 - 34 * 8,
        options(nomem, nostack)
    );
    super::mmu::cr3_write(plan9_common::types::PhysAddr::new(pml4_phys));
    core::arch::asm!(
        "mv t0, a0",
        // sepc / sstatus → CSRs, then reuse t1/t2 for x6/x7.
        "ld t1, 256(t0)",
        "csrw sepc, t1",
        "ld t1, 48(t0)",        // x6
        "ld t2, 264(t0)",
        "csrw sstatus, t2",
        "ld t2, 56(t0)",        // x7
        // User stack pointer (x2), then x3/x4.
        "ld sp, 16(t0)",
        "ld gp, 24(t0)",        // x3
        "ld tp, 32(t0)",        // x4
        // x8–x27 (s0..s1, a0..a7, s2..s11).
        "ld s0, 64(t0)",
        "ld s1, 72(t0)",
        "ld a0, 80(t0)",
        "ld a1, 88(t0)",
        "ld a2, 96(t0)",
        "ld a3, 104(t0)",
        "ld a4, 112(t0)",
        "ld a5, 120(t0)",
        "ld a6, 128(t0)",
        "ld a7, 136(t0)",
        "ld s2, 144(t0)",
        "ld s3, 152(t0)",
        "ld s4, 160(t0)",
        "ld s5, 168(t0)",
        "ld s6, 176(t0)",
        "ld s7, 184(t0)",
        "ld s8, 192(t0)",
        "ld s9, 200(t0)",
        "ld s10, 208(t0)",
        "ld s11, 216(t0)",
        // x28–x31 (t3..t6) — self-referential loads are safe.
        "ld t3, 224(t0)",
        "ld t4, 232(t0)",
        "ld t5, 240(t0)",
        "ld t6, 248(t0)",
        // x1 (ra) and finally x5 (t0, the frame base itself).
        "ld ra, 8(t0)",
        "ld t0, 40(t0)",
        "sret",
        in("a0") frame_ptr,
        options(noreturn, nostack)
    );
}

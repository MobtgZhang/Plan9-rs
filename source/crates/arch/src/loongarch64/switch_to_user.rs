//! LoongArch64 user-mode entry — the equivalent of the x86_64 IRET
//! trampoline.
//!
//! The kernel runs at PLV0; user code at PLV3. An `ertn` returns from
//! "exception" state into user mode:
//!   * ERA   = user entry point
//!   * PRMD  = PPLV[1:0] = 3 (return to PLV3), PIE = 1 (interrupts on)
//!   * $sp   = user stack pointer (LoongArch has a single GPR file —
//!     the kernel's $sp simply becomes the user's stack pointer)
//!
//! The page-mapped user address space root is installed via CSR.PGDL
//! before the `ertn`; the kernel keeps running in the cached DMW0
//! window, which is visible to every address space (the LoongArch
//! analogue of the x86_64 kernel-half cloning).

extern crate plan9_common;

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::{csr, csr_write};
use super::mmu::{cr3_write, flush_tlb};
use plan9_common::types::PhysAddr;

extern "C" {
    /// The user trap frame area defined by boot.S (8 KiB in .bss; the top
    /// 272 bytes are the frame, the rest is the handler's scratch stack).
    static _user_trap_area: u8;
}

/// Initial PRMD for user entry: PPLV = 0b11 (PLV3), PIE = 1.
pub const USER_PRMD_INIT: u64 = 0b111;

/// Selectors kept for API parity with the x86_64 module (LoongArch has
/// no segment selectors; these are informational only).
pub const USER_DS: u16 = 0;
pub const USER_CS: u16 = 0;
pub const USER_RFLAGS_INIT: u64 = USER_PRMD_INIT;

/// Trap-frame page pending installation (set before `switch_to_user`).
static NEXT_FRAME: AtomicU64 = AtomicU64::new(0);

/// Set the trap-frame page consumed by the next `switch_to_user`.
pub fn set_switch_frame(frame_phys: u64) {
    NEXT_FRAME.store(frame_phys, Ordering::Relaxed);
}

/// Build the user frame on `frame_page` (layout matches aarch64):
///   [0] scratch, [1] entry (ERA), [2] prmd, [3] user sp,
///   [4] user root table (PGDL).
#[inline]
pub unsafe fn build_user_frame(frame_page: u64, entry: u64, user_sp: u64, user_root: u64) {
    let fp = frame_page as *mut u64;
    fp.add(0).write_volatile(0);
    fp.add(1).write_volatile(entry);
    fp.add(2).write_volatile(USER_PRMD_INIT);
    fp.add(3).write_volatile(user_sp);
    fp.add(4).write_volatile(user_root);
}

/// Switch to user mode.
///
/// `pml4_phys` is the physical address of the user page-table root
/// (installed into CSR.PGDL), `frame_ptr` the physical address of the
/// frame built by [`build_user_frame`].
///
/// # Safety
/// Never returns; the CPU leaves PLV0 via `ertn`.
pub unsafe fn switch_to_user_trampoline(pml4_phys: u64, frame_ptr: u64) -> ! {
    // 1. Install the user root table and flush the TLB.
    cr3_write(PhysAddr::new(pml4_phys));

    // 2. Load the frame contents.
    let fp = frame_ptr as *const u64;
    let entry = fp.add(1).read_volatile();
    let prmd = fp.add(2).read_volatile();
    let user_sp = fp.add(3).read_volatile();

    // 3. Ert into PLV3: set $sp, ERA, PRMD, then `ertn`.  The registers
    // are pinned ($a0-$a2 = $r4-$r6, dead in this never-returning
    // context) so the allocator cannot hand out $r3 (the user sp) for
    // an operand.
    core::arch::asm!(
        "or $r3, $r4, $r0",
        "csrwr $r5, 0x6",
        "csrwr $r6, 0x1",
        "ertn",
        in("$r4") user_sp,
        in("$r5") entry,
        in("$r6") prmd,
        options(noreturn, nostack)
    );
}

/// Resume a user process after a kernel-mode syscall/trap.
///
/// The trap frame layout (written by the vector save code):
///   * $r1–$r31 general registers at frame offsets `8 * (n - 1)`
///     ($r3 holds the user stack pointer as captured at trap time)
///   * ERA  at offset 248 (31 × 8)
///   * PRMD at offset 256 (32 × 8)
///
/// Restore order: the frame base is kept in $t0 ($r12) and restored
/// last; ERA/PRMD are written to their CSRs through $t1 ($r13).
///
/// # Safety
/// Never returns.
pub unsafe fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> ! {
    // Boot.S's trap frame: _user_trap_area + 8192 - 272 (the top 34 u64
    // slots of the 8 KiB area, 16-byte aligned).
    let trap_frame_base = core::ptr::addr_of!(_user_trap_area) as u64 + 7920;
    core::arch::asm!(
        // Switch the page-table root: PGDL := child PML4 physical address.
        "csrwr $a0, 0x19",
        // Make the new PGDL and TLB flush visible before touching any
        // memory through the new page tables.
        "dbar 0",
        "invtlb 0, $zero, $zero",
        // KS0 := user trap frame base — the next trap from user mode
        // swaps it with the user $sp (mirrors riscv64's sscratch).
        "csrwr $r13, 0x30",
        // $r12 = SavedUserFrame pointer.  General registers $r1–$r11 and
        // $r13–$r31 (skip $r12 = base; $r3 = user sp comes last).
        "ld.d $r1,  $r12, 0",
        "ld.d $r2,  $r12, 8",
        "ld.d $r3,  $r12, 16",   // user stack pointer
        "ld.d $r4,  $r12, 24",
        "ld.d $r5,  $r12, 32",
        "ld.d $r6,  $r12, 40",
        "ld.d $r7,  $r12, 48",
        "ld.d $r8,  $r12, 56",
        "ld.d $r9,  $r12, 64",
        "ld.d $r10, $r12, 72",
        "ld.d $r11, $r12, 80",
        "ld.d $r14, $r12, 104",
        "ld.d $r15, $r12, 112",
        "ld.d $r16, $r12, 120",
        "ld.d $r17, $r12, 128",
        "ld.d $r18, $r12, 136",
        "ld.d $r19, $r12, 144",
        "ld.d $r20, $r12, 152",
        "ld.d $r21, $r12, 160",
        "ld.d $r22, $r12, 168",
        "ld.d $r23, $r12, 176",
        "ld.d $r24, $r12, 184",
        "ld.d $r25, $r12, 192",
        "ld.d $r26, $r12, 200",
        "ld.d $r27, $r12, 208",
        "ld.d $r28, $r12, 216",
        "ld.d $r29, $r12, 224",
        "ld.d $r30, $r12, 232",
        "ld.d $r31, $r12, 240",
        // ERA and PRMD via $t1 ($r13), then restore the user value.
        "ld.d $r13, $r12, 248",
        "csrwr $r13, 0x6",
        "ld.d $r13, $r12, 256",
        "csrwr $r13, 0x1",
        "ld.d $r13, $r12, 96",
        // Finally the frame base register itself, then return.
        "ld.d $r12, $r12, 88",
        "ertn",
        in("$a0") pml4_phys,
        in("$r12") frame_ptr,
        in("$r13") trap_frame_base,
        options(noreturn, nostack)
    );
}

/// Re-exported for the facade: write a raw PRMD value.
pub fn write_prmd(val: u64) {
    csr_write::<{ csr::PRMD }>(val);
    flush_tlb();
}

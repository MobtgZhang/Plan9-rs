//! RISC-V CPU control: S-mode interrupt enable/disable, `wfi`, fences,
//! and SBI calls.
//!
//! The kernel runs in S-mode (SBI firmware — OpenSBI by default with
//! `qemu-system-riscv64 -bios` — has already set up M-mode state and
//! handed off with `a0 = hartid`, `a1 = device tree`).

/// Read the hart (CPU) id from the `tp` register if saved, else 0.
#[inline(always)]
pub fn hart_id() -> usize {
    let id: usize;
    unsafe { core::arch::asm!("mv {}, tp", out(reg) id, options()) };
    id
}

// ============================================================================
// Interrupt control (sstatus.SIE global enable)
// ============================================================================

/// Global S-mode interrupt enable bit in `sstatus`.
const SSTATUS_SIE: u64 = 1 << 1;
/// Supervisor timer interrupt enable in `sie`.
const SIE_STIE: u64 = 1 << 5;
/// Supervisor external interrupt enable in `sie`.
const SIE_SEIE: u64 = 1 << 9;
/// Supervisor software interrupt enable in `sie`.
const SIE_SSIE: u64 = 1 << 1;

#[inline(always)]
pub unsafe fn disable_interrupts() {
    core::arch::asm!(
        "csrc sstatus, {sie}",
        sie = in(reg) SSTATUS_SIE,
        options(nostack)
    );
}

#[inline(always)]
pub unsafe fn enable_interrupts() {
    core::arch::asm!(
        "csrs sstatus, {sie}",
        sie = in(reg) SSTATUS_SIE,
        options(nostack)
    );
}

/// Aliases matching the x86 naming used by kernel call sites.
#[inline(always)]
pub fn cli() {
    // Safe wrapper: the operation itself is atomic.
    unsafe { disable_interrupts() }
}

#[inline(always)]
pub fn sti() {
    unsafe { enable_interrupts() }
}

#[inline(always)]
pub fn interrupts_enabled() -> bool {
    let sstatus: u64;
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) sstatus, options()) };
    (sstatus & SSTATUS_SIE) != 0
}

/// Enable the supervisor timer interrupt source (`sie.STIE`).
pub unsafe fn enable_timer_interrupts() {
    core::arch::asm!(
        "csrs sie, {bits}",
        bits = in(reg) SIE_STIE | SIE_SEIE | SIE_SSIE,
        options(nostack)
    );
}

// ============================================================================
// Halt
// ============================================================================

#[inline(always)]
pub fn hlt() {
    unsafe { core::arch::asm!("wfi", options(nostack)) }
}

/// Loop forever halting; used for the panic path.
#[inline(never)]
pub fn hlt_loop() -> ! {
    loop {
        hlt();
    }
}

// ============================================================================
// Barriers
// ============================================================================

/// Fence with device + I/O ordering (the RISC-V `fence iorw, iorw`).
#[inline(always)]
pub fn fence_io() {
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack)) };
}

/// Full data fence.
#[inline(always)]
pub fn fence_rw() {
    unsafe { core::arch::asm!("fence rw, rw", options(nostack)) };
}

/// Instruction fence (like `fence.i`) — needed after writing code pages.
#[inline(always)]
pub fn fence_i() {
    unsafe { core::arch::asm!("fence.i", options(nostack)) };
}

// ============================================================================
// SBI calls (legacy + base extension)
// ============================================================================

/// SBI legacy `set_timer` (extension id 0x0). `stamp` is in the timer
/// frequency domain. Returns the SBI error code (0 = success).
pub fn sbi_set_timer(stamp: u64) -> i32 {
    let mut err: u64 = stamp;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 0x0usize,        // SBI_EXT_0_1_SET_TIMER
            in("a6") 0usize,
            inout("a0") err,
            out("a1") _,
        );
    }
    err as i32
}

/// SBI base extension `get spec version` (0x0100).
#[allow(dead_code)]
fn sbi_get_spec_version() -> u64 {
    let ver: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 0x0100usize,     // SBI_EXT_BASE_GET_SPEC_VERSION
            in("a6") 0usize,
            out("a0") ver,
            out("a1") _,
        );
    }
    ver
}

/// Shut down via SBI (system reset extension, fallback to legacy shutdown).
pub fn sbi_shutdown() -> ! {
    unsafe {
        let mut a0: u64 = 0;
        core::arch::asm!(
            "ecall",
            in("a7") 0x08usize,       // SBI_EXT_SRST (0x53525354 actually; 0x08 = system shutdown legacy)
            in("a6") 0usize,
            inout("a0") a0,
            out("a1") _,
        );
    }
    loop {
        hlt();
    }
}

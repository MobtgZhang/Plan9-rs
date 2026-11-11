//! AArch64 CPU control: interrupt (DAIF) management, cache and TLB
//! maintenance, and the halt/wfi primitives.
//!
//! All privileged instructions for the whole kernel live here so that no
//! `core::arch::asm!` blocks are needed outside the `plan9_arch` crate.

/// Read the current exception level (3 = highest).
#[inline(always)]
pub fn current_el() -> u32 {
    let el: u64;
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el, options()) };
    ((el >> 2) & 0x3) as u32
}

// ============================================================================
// Interrupt control (DAIF flag)
// ============================================================================

#[inline(always)]
pub unsafe fn disable_interrupts() {
    core::arch::asm!("msr daifset, #0xF", options(nostack));
}

#[inline(always)]
pub unsafe fn enable_interrupts() {
    core::arch::asm!("msr daifclr, #0xF", options(nostack));
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
    let daif: u64;
    unsafe { core::arch::asm!("mrs {}, DAIF", out(reg) daif, options()) };
    // Any of I(7)/F(6) unmasked means some interrupts are enabled.
    (daif & ((1 << 7) | (1 << 6))) != ((1 << 7) | (1 << 6))
}

// ============================================================================
// Halt / wait
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
// Memory barriers / cache maintenance
// ============================================================================

/// Full system data + instruction synchronization barrier.
#[inline(always)]
pub fn dsb_sy() {
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

/// Instruction synchronization barrier.
#[inline(always)]
pub fn isb() {
    unsafe { core::arch::asm!("isb", options(nostack)) };
}

/// Data memory barrier.
#[inline(always)]
pub fn dmb_sy() {
    unsafe { core::arch::asm!("dmb sy", options(nostack)) };
}

// ============================================================================
// System register helpers (used by mmu.rs / timer.rs)
// ============================================================================

/// Read a 64-bit system register by name (compile-time string).
#[macro_export]
macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        unsafe { core::arch::asm!(concat!("mrs {v}, ", $name), v = out(reg) v, options(nostack)) };
        v
    }};
}

/// Write a 64-bit system register by name (compile-time string).
#[macro_export]
macro_rules! write_sysreg {
    ($name:literal, $val:expr) => {{
        let v = $val as u64;
        unsafe { core::arch::asm!(concat!("msr ", $name, ", {v}"), v = in(reg) v, options(nostack)) };
    }};
}

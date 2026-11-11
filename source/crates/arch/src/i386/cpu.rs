//! i386 CPU control (32-bit protected mode).
#![allow(dead_code)]

#[inline(always)]
pub unsafe fn cli() {
    core::arch::asm!("cli", options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn sti() {
    core::arch::asm!("sti", options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn disable_interrupts() { cli() }
#[inline(always)]
pub unsafe fn enable_interrupts() { sti() }

#[inline(always)]
pub fn interrupts_enabled() -> bool {
    let flags: u32;
    unsafe { core::arch::asm!("pushfl; popl {f}", f = out(reg) flags, options()) };
    (flags & (1 << 9)) != 0 // EFLAGS.IF
}

#[inline(always)]
pub fn hlt() {
    unsafe { core::arch::asm!("hlt", options(nostack)) }
}

#[inline(never)]
pub fn hlt_loop() -> ! {
    loop { hlt(); }
}

#[inline(always)]
pub fn cr0_read() -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("mov {v}, cr0", v = out(reg) v, options()) };
    v
}

#[inline(always)]
pub unsafe fn cr3_write(pa: u32) {
    core::arch::asm!("mov cr3, {v}", v = in(reg) pa, options());
}

#[inline(always)]
pub fn cr3_read() -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("mov {v}, cr3", v = out(reg) v, options()) };
    v
}

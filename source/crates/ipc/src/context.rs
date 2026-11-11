//! Thread context switching for Plan 9 style threading
//!
//! Provides low-level context save/restore primitives for user-space threading.
//! On x86_64, this uses inline assembly for setjmp/longjmp-like semantics.

#![allow(dead_code)]

use crate::stack::ThreadStack;

/// Saved thread context (registers and stack pointer)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ThreadContext {
    /// Callee-saved registers (rbx, rbp, r12-r15)
    pub rbx: usize,
    pub rbp: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
    /// Stack pointer
    pub rsp: usize,
    /// Instruction pointer (for longjmp target)
    pub rip: usize,
}

impl ThreadContext {
    /// Create an uninitialized context
    pub const fn empty() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
        }
    }
}

/// Save the current thread context.
///
/// Returns 0 on first call, non-zero when returning via `thread_context_restore`.
pub fn thread_context_save(ctx: &mut ThreadContext) -> usize {
    unsafe { thread_context_save_asm(ctx) }
}

/// Restore a saved thread context.
///
/// This does not return to the caller; execution resumes at the saved `rip`.
pub unsafe fn thread_context_restore(ctx: &ThreadContext) -> ! {
    thread_context_restore_asm(ctx);
    core::hint::unreachable_unchecked()
}

/// Initialize a context to start executing `entry` on `stack`.
pub unsafe fn thread_context_init(
    ctx: &mut ThreadContext,
    entry: fn() -> !,
    stack: &ThreadStack,
) {
    ctx.rsp = stack.top() as usize;
    ctx.rip = entry as usize;
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn thread_context_save_asm(ctx: &mut ThreadContext) -> usize {
    let mut result: usize = 0;
    core::arch::asm!(
        "mov [rdi + 0x00], rbx",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], r12",
        "mov [rdi + 0x18], r13",
        "mov [rdi + 0x20], r14",
        "mov [rdi + 0x28], r15",
        "lea rax, [rsp + 8]",
        "mov [rdi + 0x30], rax",
        "mov [rdi + 0x38], rcx",
        "xor eax, eax",
        in("rdi") ctx,
        out("rcx") result,
        options(nostack, preserves_flags)
    );
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn thread_context_restore_asm(ctx: &ThreadContext) {
    core::arch::asm!(
        "mov rbx, [rdi + 0x00]",
        "mov rbp, [rdi + 0x08]",
        "mov r12, [rdi + 0x10]",
        "mov r13, [rdi + 0x18]",
        "mov r14, [rdi + 0x20]",
        "mov r15, [rdi + 0x28]",
        "mov rsp, [rdi + 0x30]",
        "jmp [rdi + 0x38]",
        in("rdi") ctx,
        options(noreturn, nostack)
    );
}

// ---------------------------------------------------------------------------
// AArch64: callee-saved x19–x24 onto the six callee slots, sp, and x30 (LR)
// as the "instruction pointer" slot.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn thread_context_save_asm(ctx: &mut ThreadContext) -> usize {
    let result: usize;
    core::arch::asm!(
        "str x19, [x10, #0]",
        "str x20, [x10, #8]",
        "str x21, [x10, #16]",
        "str x22, [x10, #24]",
        "str x23, [x10, #32]",
        "str x24, [x10, #40]",
        "mov x9, sp",
        "str x9, [x10, #48]",
        "str x30, [x10, #56]",
        "mov {res}, #0",
        in("x10") ctx as *mut ThreadContext as u64,
        res = out(reg) result,
        lateout("x9") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn thread_context_restore_asm(ctx: &ThreadContext) {
    core::arch::asm!(
        "ldr x19, [x10, #0]",
        "ldr x20, [x10, #8]",
        "ldr x21, [x10, #16]",
        "ldr x22, [x10, #24]",
        "ldr x23, [x10, #32]",
        "ldr x24, [x10, #40]",
        "ldr x9, [x10, #48]",
        "mov sp, x9",
        "ldr x30, [x10, #56]",
        "ret",
        in("x10") ctx as *const ThreadContext as u64,
        options(noreturn, nostack)
    );
}

// ---------------------------------------------------------------------------
// RISC-V (RV64): callee-saved s1–s6 onto the six slots, sp, and ra.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn thread_context_save_asm(ctx: &mut ThreadContext) -> usize {
    let result: usize;
    core::arch::asm!(
        "sd s1, 0(t0)",
        "sd s2, 8(t0)",
        "sd s3, 16(t0)",
        "sd s4, 24(t0)",
        "sd s5, 32(t0)",
        "sd s6, 40(t0)",
        "sd sp, 48(t0)",
        "sd ra, 56(t0)",
        "li {res}, 0",
        in("t0") ctx as *mut ThreadContext as usize,
        res = out(reg) result,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn thread_context_restore_asm(ctx: &ThreadContext) {
    core::arch::asm!(
        "ld s1, 0(t0)",
        "ld s2, 8(t0)",
        "ld s3, 16(t0)",
        "ld s4, 24(t0)",
        "ld s5, 32(t0)",
        "ld s6, 40(t0)",
        "ld sp, 48(t0)",
        "ld ra, 56(t0)",
        "ret",
        in("t0") ctx as *const ThreadContext as usize,
        options(noreturn, nostack)
    );
}

// ---------------------------------------------------------------------------
// LoongArch64: callee-saved $s0–$s5 ($r23–$r28) onto the six slots, $r3
// (sp, LLVM-reserved so a literal write is safe), and $r1 (ra).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
unsafe fn thread_context_save_asm(ctx: &mut ThreadContext) -> usize {
    let result: usize;
    core::arch::asm!(
        "st.d $r23, $r12, 0",
        "st.d $r24, $r12, 8",
        "st.d $r25, $r12, 16",
        "st.d $r26, $r12, 24",
        "st.d $r27, $r12, 32",
        "st.d $r28, $r12, 40",
        "st.d $r3,  $r12, 48",
        "st.d $r1,  $r12, 56",
        "addi.d {res}, $r0, 0",
        in("$r12") ctx as *mut ThreadContext as u64,
        res = out(reg) result,
        options()
    );
    result
}

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
unsafe fn thread_context_restore_asm(ctx: &ThreadContext) {
    core::arch::asm!(
        "ld.d $r23, $r12, 0",
        "ld.d $r24, $r12, 8",
        "ld.d $r25, $r12, 16",
        "ld.d $r26, $r12, 24",
        "ld.d $r27, $r12, 32",
        "ld.d $r28, $r12, 40",
        "ld.d {t},  $r12, 48",
        "or $r3, {t}, $r0",
        "ld.d {r},  $r12, 56",
        "jirl $r0, {r}, 0",
        t = out(reg) _,
        r = out(reg) _,
        in("$r12") ctx as *const ThreadContext as u64,
        options(nostack)
    );
    core::hint::unreachable_unchecked()
}

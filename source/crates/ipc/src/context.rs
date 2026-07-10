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

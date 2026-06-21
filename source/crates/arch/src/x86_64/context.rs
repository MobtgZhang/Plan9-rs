//! Context switching implementation for x86_64
//!
//! This module provides setjmp/longjmp style context switching for the scheduler.
//! It uses inline assembly to save and restore callee-saved registers.

use core::arch::global_asm;

// ============================================================================
// Label Structure (compatible with kernel's Label)
// ============================================================================

/// Scheduler context label (must match kernel's Label)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Label {
    /// Callee-saved register RBX
    pub rbx: u64,
    /// Callee-saved register RBP
    pub rbp: u64,
    /// Callee-saved register R12
    pub r12: u64,
    /// Callee-saved register R13
    pub r13: u64,
    /// Callee-saved register R14
    pub r14: u64,
    /// Callee-saved register R15
    pub r15: u64,
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
}

impl Label {
    /// Create a new empty label
    pub const fn new() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            sp: 0,
            pc: 0,
        }
    }

    /// Check if the label has been set
    pub fn is_set(&self) -> bool {
        self.sp != 0 || self.pc != 0
    }
}

// ============================================================================
// Context Structure
// ============================================================================

/// Context for context switching (setjmp/longjmp style)
/// Stores the minimal state needed to restore execution
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Context {
    /// Callee-saved register RBX
    pub rbx: u64,
    /// Callee-saved register RBP
    pub rbp: u64,
    /// Callee-saved register R12
    pub r12: u64,
    /// Callee-saved register R13
    pub r13: u64,
    /// Callee-saved register R14
    pub r14: u64,
    /// Callee-saved register R15
    pub r15: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Return address / program counter
    pub ret: u64,
}

impl Context {
    /// Create a new context with a given entry point and stack
    ///
    /// # Safety
    /// The entry function must have the correct signature and the stack
    /// must be properly aligned and large enough.
    pub unsafe fn new(entry: fn(), stack_top: u64) -> Self {
        let mut ctx = Self::default();

        // Stack grows downward, reserve space for return address
        ctx.rsp = stack_top - 8;

        // Set return address to entry point
        ctx.ret = entry as u64;

        // Callee-saved registers initialized to 0
        ctx.rbp = 0;

        ctx
    }

    /// Create a context for a kernel function
    pub fn new_kernel(entry: fn(), stack_top: u64) -> Self {
        unsafe { Self::new(entry, stack_top) }
    }

    /// Check if the context has been initialized
    pub fn is_initialized(&self) -> bool {
        self.rsp != 0 || self.ret != 0
    }

    /// Convert from Label
    pub fn from_label(label: &Label) -> Self {
        Self {
            rbx: label.rbx,
            rbp: label.rbp,
            r12: label.r12,
            r13: label.r13,
            r14: label.r14,
            r15: label.r15,
            rsp: label.sp,
            ret: label.pc,
        }
    }

    /// Convert to Label
    pub fn to_label(&self) -> Label {
        Label {
            rbx: self.rbx,
            rbp: self.rbp,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            sp: self.rsp,
            pc: self.ret,
        }
    }
}

// ============================================================================
// Assembly Helper Functions
// ============================================================================

/// Save current context to the given Context structure
/// Returns 0 on first call, 1 if returning from a restore
///
/// This implements the "save" part of setjmp
#[inline(always)]
pub unsafe fn save_context(ctx: &mut Context) -> i32 {
    let result: i32;
    core::arch::asm!(
        // Save callee-saved registers
        "mov [rdi + 0], rbx",
        "mov [rdi + 8], rbp",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        // Save stack pointer
        "mov [rdi + 48], rsp",
        // Get return address (pushed by call)
        "mov rax, [rsp]",
        "mov [rdi + 56], rax",
        // Return 0
        "xor eax, eax",
        // Output
        out("rax") result,
        // Input - ctx pointer in rdi
        in("rdi") ctx as *mut Context as u64,
        // Clobbers
        clobber_abi("C"),
    );
    result
}

/// Restore context and return
/// If val is 0, returns 1 instead (like longjmp)
///
/// This implements the "restore" part of longjmp
/// Does NOT return normally - jumps to the saved context
#[inline(always)]
pub unsafe fn restore_context(ctx: &Context, val: i32) -> ! {
    let non_zero = if val == 0 { 1i32 } else { val };

    core::arch::asm!(
        // Restore callee-saved registers
        "mov rbx, [rdi + 0]",
        "mov rbp, [rdi + 8]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        // Restore stack pointer
        "mov rsp, [rdi + 48]",
        // Push return address
        "push qword ptr [rdi + 56]",
        // Set return value
        "mov eax, esi",
        // Return (jumps to saved PC)
        "ret",
        // Input
        in("rdi") ctx as *const Context as u64,
        in("esi") non_zero,
        options(noreturn),
    );
}

// ============================================================================
// Setjmp/Longjmp Implementation
// ============================================================================

/// Plan 9 style setjmp
/// Saves the current execution context into buf
/// Returns 0 when called normally, 1 when returning from longjmp
#[inline(always)]
pub unsafe fn setjmp(buf: &mut Context) -> i32 {
    save_context(buf)
}

/// Plan 9 style longjmp
/// Restores the context saved by setjmp
/// If val is 0, returns 1 instead
/// Does not return normally
#[inline(always)]
pub unsafe fn longjmp(buf: &Context, val: i32) -> ! {
    restore_context(buf, val)
}

/// Convenience function to jump to a context
/// Similar to longjmp but doesn't check for 0
#[inline(always)]
pub unsafe fn goto_context(ctx: &Context) -> ! {
    core::arch::asm!(
        // Restore callee-saved registers
        "mov rbx, [rdi + 0]",
        "mov rbp, [rdi + 8]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        // Restore stack pointer
        "mov rsp, [rdi + 48]",
        // Push return address
        "push qword ptr [rdi + 56]",
        // Return (jumps to saved PC)
        "ret",
        in("rdi") ctx as *const Context as u64,
        options(noreturn),
    );
}

/// Save scheduler context (Label) from a process
///
/// # Safety
/// This function manipulates the process's scheduler context
pub unsafe fn procsave(sched_ctx: &mut Label) {
    let mut ctx = Context::from_label(sched_ctx);
    save_context(&mut ctx);
    *sched_ctx = ctx.to_label();
}

/// Restore scheduler context (Label) for a process
///
/// # Safety
/// This function manipulates the process's scheduler context
pub unsafe fn procrestore(sched_ctx: &Label) {
    // TODO: Restore FPU state when we have fpsave/fprestore support
    let _ = sched_ctx;
}

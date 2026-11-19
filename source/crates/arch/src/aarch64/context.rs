//! AArch64 context save/restore (setjmp/longjmp style) — mirrors the
//! x86_64 `context` module exactly so the scheduler's
//! architecture-neutral code compiles unchanged.
//!
//! Physical register ↔ slot mapping:
//!   * `rbx` ← x19   (callee-saved)
//!   * `rbp` ← x20
//!   * `r12` ← x21
//!   * `r13` ← x22
//!   * `r14` ← x23
//!   * `r15` ← x24
//!   * `r25`-`r28` ← x25-x28 (callee-saved, AArch64-only)
//!   * `rsp` ← SP_EL1 (kernel stack pointer)
//!   * `ret` ← x30 (LR — the "return address" analog of x86 `[rsp]`)

// ============================================================================
// Label Structure (compatible with kernel's Label)
// ============================================================================

/// Scheduler context label (must match kernel's Label)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Label {
    /// Callee-saved register x19
    pub rbx: u64,
    /// Callee-saved register x20
    pub rbp: u64,
    /// Callee-saved register x21
    pub r12: u64,
    /// Callee-saved register x22
    pub r13: u64,
    /// Callee-saved register x23
    pub r14: u64,
    /// Callee-saved register x24
    pub r15: u64,
    /// Callee-saved register x25
    pub r25: u64,
    /// Callee-saved register x26
    pub r26: u64,
    /// Callee-saved register x27
    pub r27: u64,
    /// Callee-saved register x28
    pub r28: u64,
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
}

impl Label {
    /// Create a new empty label
    pub const fn new() -> Self {
        Self { rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0,
               r25: 0, r26: 0, r27: 0, r28: 0,
               sp: 0, pc: 0 }
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
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Context {
    /// Callee-saved register x19
    pub rbx: u64,
    /// Callee-saved register x20
    pub rbp: u64,
    /// Callee-saved register x21
    pub r12: u64,
    /// Callee-saved register x22
    pub r13: u64,
    /// Callee-saved register x23
    pub r14: u64,
    /// Callee-saved register x24
    pub r15: u64,
    /// Callee-saved register x25
    pub r25: u64,
    /// Callee-saved register x26
    pub r26: u64,
    /// Callee-saved register x27
    pub r27: u64,
    /// Callee-saved register x28
    pub r28: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Return address / program counter
    pub ret: u64,
}

impl Context {
    /// Create a context with a given entry point and stack
    ///
    /// # Safety
    /// The entry function must have the correct signature and the stack
    /// must be properly aligned and large enough.
    pub unsafe fn new(entry: fn(), stack_top: u64) -> Self {
        let mut ctx = Self::default();
        // Stack grows downward; the saved "return address" is placed
        // where `ret` will read it.
        ctx.rsp = stack_top - 16;
        ctx.ret = entry as u64;
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
            r25: label.r25,
            r26: label.r26,
            r27: label.r27,
            r28: label.r28,
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
            r25: self.r25,
            r26: self.r26,
            r27: self.r27,
            r28: self.r28,
            sp: self.rsp,
            pc: self.ret,
        }
    }
}

// ============================================================================
// Assembly Helper Functions
// ============================================================================

/// Save current context to the given Context structure.
/// Returns 0 on first call; 1 if returning from a restore (setjmp).
#[inline(always)]
pub unsafe fn save_context(ctx: &mut Context) -> i32 {
    let result: i32;
    core::arch::asm!(
        // Save the AArch64 callee-saved registers.
        "str x19, [{ctx}, #0]",
        "str x20, [{ctx}, #8]",
        "str x21, [{ctx}, #16]",
        "str x22, [{ctx}, #24]",
        "str x23, [{ctx}, #32]",
        "str x24, [{ctx}, #40]",
        "str x25, [{ctx}, #64]",
        "str x26, [{ctx}, #72]",
        "str x27, [{ctx}, #80]",
        "str x28, [{ctx}, #88]",
        // Save stack pointer.
        "mov x9, sp",
        "str x9, [{ctx}, #48]",
        // Save LR (return address analog of x86 `[rsp]`).
        "str x30, [{ctx}, #56]",
        // Return 0.
        "mov {res:w}, #0",
        res = out(reg) result,
        ctx = in(reg) ctx as *mut Context as u64,
        lateout("x9") _,
    );
    result
}

/// Restore context and return with value `non_zero` (longjmp).
/// Does NOT return normally — jumps to the saved context.
#[inline(always)]
pub unsafe fn restore_context(ctx: &Context, non_zero: i32) -> ! {
    core::arch::asm!(
        // Restore callee-saved registers.
        "ldr x19, [{ctx}, #0]",
        "ldr x20, [{ctx}, #8]",
        "ldr x21, [{ctx}, #16]",
        "ldr x22, [{ctx}, #24]",
        "ldr x23, [{ctx}, #32]",
        "ldr x24, [{ctx}, #40]",
        "ldr x25, [{ctx}, #64]",
        "ldr x26, [{ctx}, #72]",
        "ldr x27, [{ctx}, #80]",
        "ldr x28, [{ctx}, #88]",
        // Restore stack pointer.
        "ldr x9, [{ctx}, #48]",
        "mov sp, x9",
        // Restore return address and return with value in x0.
        "ldr x30, [{ctx}, #56]",
        "mov w0, {v:w}",
        "ret",
        v = in(reg) non_zero,
        ctx = in(reg) ctx as *const Context as u64,
        options(noreturn),
    );
}

// ============================================================================
// Setjmp/Longjmp Implementation
// ============================================================================

/// Plan 9 style setjmp. Returns 0 normally, 1 after a longjmp.
#[inline(always)]
pub unsafe fn setjmp(buf: &mut Context) -> i32 {
    save_context(buf)
}

/// Plan 9 style longjmp. If `val` is 0, the resumed setjmp returns 1.
#[inline(always)]
pub unsafe fn longjmp(buf: &Context, val: i32) -> ! {
    let non_zero = if val == 0 { 1 } else { val };
    restore_context(buf, non_zero)
}

/// Convenience: jump to a context without a return value.
#[inline(always)]
pub unsafe fn goto_context(ctx: &Context) -> ! {
    restore_context(ctx, 1)
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
    // AArch64 has no FPU task-switched bit; NEON state saving is handled
    // by the trap path (CPACR_EL1) when FPU support is enabled.
    let _ = sched_ctx;
}

// ============================================================================
// FPU State Management (AArch64: FPU/NEON via FPU registers)
// ============================================================================

/// FPU state size for the AArch64 full register file (32 × 128-bit
/// vector registers + FPCR/FPSR).
pub const FPU_STATE_SIZE: usize = 32 * 16 + 16;

/// FPU state buffer; must be 16-byte aligned.
#[repr(align(16))]
pub struct FpuState {
    pub data: [u8; FPU_STATE_SIZE],
}

impl FpuState {
    pub fn new() -> Self { Self { data: [0; FPU_STATE_SIZE] } }
    pub fn init(&mut self) { self.data = [0; FPU_STATE_SIZE]; }
}

impl Default for FpuState {
    fn default() -> Self { Self::new() }
}

/// Save FPU/NEON state using `stp q0-q31` (assumes FPU traps disabled).
///
/// # Safety
/// Buffer must be 16-byte aligned and at least FPU_STATE_SIZE bytes.
#[inline]
pub unsafe fn fpsave(state: &mut FpuState) {
    let ptr = state.data.as_mut_ptr() as u64;
    core::arch::asm!(
        "stp q0,  q1,  [{p}, #0]",
        "stp q2,  q3,  [{p}, #32]",
        "stp q4,  q5,  [{p}, #64]",
        "stp q6,  q7,  [{p}, #96]",
        "stp q8,  q9,  [{p}, #128]",
        "stp q10, q11, [{p}, #160]",
        "stp q12, q13, [{p}, #192]",
        "stp q14, q15, [{p}, #224]",
        "stp q16, q17, [{p}, #256]",
        "stp q18, q19, [{p}, #288]",
        "stp q20, q21, [{p}, #320]",
        "stp q22, q23, [{p}, #352]",
        "stp q24, q25, [{p}, #384]",
        "stp q26, q27, [{p}, #416]",
        "stp q28, q29, [{p}, #448]",
        "stp q30, q31, [{p}, #480]",
        "mrs x9, fpsr",
        "mrs x10, fpcr",
        "add x11, {p}, #512",
        "stp x9, x10, [x11]",
        p = in(reg) ptr,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        options(nostack)
    );
}

/// Restore FPU/NEON state.
///
/// # Safety
/// Buffer must contain a previously saved FPU state.
#[inline]
pub unsafe fn fprestore(state: &FpuState) {
    let ptr = state.data.as_ptr() as u64;
    core::arch::asm!(
        "ldp q0,  q1,  [{p}, #0]",
        "ldp q2,  q3,  [{p}, #32]",
        "ldp q4,  q5,  [{p}, #64]",
        "ldp q6,  q7,  [{p}, #96]",
        "ldp q8,  q9,  [{p}, #128]",
        "ldp q10, q11, [{p}, #160]",
        "ldp q12, q13, [{p}, #192]",
        "ldp q14, q15, [{p}, #224]",
        "ldp q16, q17, [{p}, #256]",
        "ldp q18, q19, [{p}, #288]",
        "ldp q20, q21, [{p}, #320]",
        "ldp q22, q23, [{p}, #352]",
        "ldp q24, q25, [{p}, #384]",
        "ldp q26, q27, [{p}, #416]",
        "ldp q28, q29, [{p}, #448]",
        "ldp q30, q31, [{p}, #480]",
        "add x11, {p}, #512",
        "ldp x9, x10, [x11]",
        "msr fpsr, x9",
        "msr fpcr, x10",
        p = in(reg) ptr,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        options(nostack)
    );
}

/// Save FPU state for the current process.
///
/// # Safety
/// Should only be called in kernel mode.
pub unsafe fn save_fpu_state(state: &mut FpuState) { fpsave(state) }

/// Restore FPU state for the current process.
///
/// # Safety
/// Should only be called in kernel mode.
pub unsafe fn restore_fpu_state(state: &FpuState) { fprestore(state) }

/// Initialize FPU for a new process: disable FPU traps at EL1/EL0 so
/// the process can use NEON.
///
/// # Safety
/// Should only be called in kernel mode.
pub unsafe fn init_fpu() {
    // CPACR_EL1: FPEN = 0b11 (no traps at any exception level).
    core::arch::asm!(
        "mrs x9, cpacr_el1",
        "orr x9, x9, #(3 << 20)",
        "msr cpacr_el1, x9",
        "isb",
        options(nostack)
    );
}

/// Check whether FPU instructions trap (CPACR_EL1.FPEN != 0b11).
pub fn fpu_used_since_switch() -> bool {
    let cpacr: u64;
    unsafe { core::arch::asm!("mrs {0}, cpacr_el1", out(reg) cpacr, options(nostack)) };
    (cpacr & (0b11 << 20)) != (0b11 << 20)
}

/// Clear the FPU trap state (enable FP at all levels).
pub fn clear_fpu_task_switched() {
    unsafe { init_fpu() };
}

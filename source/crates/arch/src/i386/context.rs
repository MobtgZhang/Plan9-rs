//! i386 context save/restore (setjmp/longjmp style) — mirrors the x86_64
//! `context` module with 32-bit registers.
#![allow(dead_code)]

// ============================================================================
// Label Structure (compatible with kernel's Label)
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Label {
    pub rbx: u32,
    pub rbp: u32,
    pub r12: u32, // unused on i386 (kept for shape parity)
    pub r13: u32, // unused on i386
    pub r14: u32, // unused on i386
    pub r15: u32, // unused on i386
    pub sp: u32,
    pub pc: u32,
}

impl Label {
    pub const fn new() -> Self {
        Self { rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, sp: 0, pc: 0 }
    }
    pub fn is_set(&self) -> bool { self.sp != 0 || self.pc != 0 }
}

// ============================================================================
// Context Structure
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Context {
    pub rbx: u32,
    pub rbp: u32,
    pub r12: u32,
    pub r13: u32,
    pub r14: u32,
    pub r15: u32,
    pub rsp: u32,
    pub ret: u32,
}

impl Context {
    /// Create a context with a given entry point and stack.
    ///
    /// # Safety
    /// The entry function must have the correct signature and the stack
    /// must be properly aligned and large enough.
    pub unsafe fn new(entry: fn(), stack_top: u64) -> Self {
        let mut ctx = Self::default();
        ctx.rsp = (stack_top - 16) as u32;
        ctx.ret = entry as u64 as u32;
        ctx
    }

    pub fn new_kernel(entry: fn(), stack_top: u64) -> Self {
        unsafe { Self::new(entry, stack_top) }
    }

    pub fn is_initialized(&self) -> bool { self.rsp != 0 || self.ret != 0 }

    pub fn from_label(label: &Label) -> Self {
        Self {
            rbx: label.rbx, rbp: label.rbp, r12: label.r12, r13: label.r13,
            r14: label.r14, r15: label.r15, rsp: label.sp, ret: label.pc,
        }
    }

    pub fn to_label(&self) -> Label {
        Label {
            rbx: self.rbx, rbp: self.rbp, r12: self.r12, r13: self.r13,
            r14: self.r14, r15: self.r15, sp: self.rsp, pc: self.ret,
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
        "mov [edi+0], ebx",
        "mov [edi+4], ebp",
        "mov [edi+8], esi",
        "mov [edi+12], eax",   // r12 slot: esi on i386
        "mov [edi+20], esp",
        "mov [edi+24], ecx",   // return address placeholder
        "xor eax, eax",
        "mov {res}, eax",
        res = out(reg) result,
        ctx = in(reg) ctx as *mut Context as u32,
        options(),
    );
    result
}

/// Restore context and return with value `non_zero` (longjmp).
#[inline(always)]
pub unsafe fn restore_context(ctx: &Context, non_zero: i32) -> ! {
    core::arch::asm!(
        "mov esp, [eax+20]",
        "mov eax, {v}",
        "jmp [eax+24]",
        v = in(reg) non_zero,
        ctx = in(reg) ctx as *const Context as u32,
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

/// Save scheduler context (Label) from a process.
///
/// # Safety
/// This function manipulates the process's scheduler context.
pub unsafe fn procsave(sched_ctx: &mut Label) {
    let mut ctx = Context::from_label(sched_ctx);
    save_context(&mut ctx);
    *sched_ctx = ctx.to_label();
}

/// Restore scheduler context (Label) for a process.
///
/// # Safety
/// This function manipulates the process's scheduler context.
pub unsafe fn procrestore(sched_ctx: &Label) {
    let _ = sched_ctx; // i386 has no FPU task-switched bit handling here
}

// ============================================================================
// FPU State Management (x87)
// ============================================================================

/// x87 state: 512 bytes covers fsave/fxsave(32-bit) layouts.
pub const FPU_STATE_SIZE: usize = 512;

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

/// Save x87 state with fsave.
///
/// # Safety
/// Buffer must be aligned and at least FPU_STATE_SIZE bytes.
#[inline]
pub unsafe fn fpsave(state: &mut FpuState) {
    core::arch::asm!(
        "fsave [{}]",
        in(reg) state.data.as_mut_ptr() as u32,
        options(nostack)
    );
}

/// Restore x87 state with frstor.
///
/// # Safety
/// Buffer must contain a previously saved FPU state.
#[inline]
pub unsafe fn fprestore(state: &FpuState) {
    core::arch::asm!(
        "frstor [{}]",
        in(reg) state.data.as_ptr() as u32,
        options(nostack)
    );
}

/// Save FPU state for the current process.
///
/// # Safety
/// Only call in kernel mode.
pub unsafe fn save_fpu_state(state: &mut FpuState) { fpsave(state) }

/// Restore FPU state for the current process.
///
/// # Safety
/// Only call in kernel mode.
pub unsafe fn restore_fpu_state(state: &FpuState) { fprestore(state) }

/// Initialize FPU for a new process (enable via CR0.EM/MP clearing).
///
/// # Safety
/// Only call in kernel mode.
pub unsafe fn init_fpu() {
    core::arch::asm!(
        "clts",
        options(nostack)
    );
}

/// Check whether the FPU is usable (CR0.TS clear).
pub fn fpu_used_since_switch() -> bool {
    let cr0: u32;
    unsafe { core::arch::asm!("mov {v}, cr0", v = out(reg) cr0, options()) };
    (cr0 & (1 << 3)) == 0 // CR0.TS
}

/// Clear the task-switched bit (CLTS).
pub fn clear_fpu_task_switched() {
    unsafe { init_fpu() };
}

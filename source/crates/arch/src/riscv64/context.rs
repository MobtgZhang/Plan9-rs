//! RISC-V context save/restore (setjmp/longjmp style) — mirrors the
//! x86_64 `context` module exactly so the scheduler's
//! architecture-neutral code compiles unchanged.
//!
//! Physical register ↔ slot mapping (RISC-V callee-saved set):
//!   * `rbx` ← s1 (x9)
//!   * `rbp` ← s2 (x18)
//!   * `r12` ← s3 (x19)
//!   * `r13` ← s4 (x20)
//!   * `r14` ← s5 (x21)
//!   * `r15` ← s6 (x22)
//!   * `rsp` ← sp (kernel stack pointer)
//!   * `ret` ← ra (x1 — the "return address" analog of x86 `[rsp]`)

// ============================================================================
// Label Structure (compatible with kernel's Label)
// ============================================================================

/// Scheduler context label (must match kernel's Label)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Label {
    /// Callee-saved register s1
    pub rbx: u64,
    /// Callee-saved register s2
    pub rbp: u64,
    /// Callee-saved register s3
    pub r12: u64,
    /// Callee-saved register s4
    pub r13: u64,
    /// Callee-saved register s5
    pub r14: u64,
    /// Callee-saved register s6
    pub r15: u64,
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
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
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,
    pub ret: u64,
}

impl Context {
    /// Create a context with a given entry point and stack.
 ///
    /// # Safety
    /// The entry function must have the correct signature and the stack
    /// must be properly aligned and large enough.
    pub unsafe fn new(entry: fn(), stack_top: u64) -> Self {
        let mut ctx = Self::default();
        ctx.rsp = stack_top - 16;
        ctx.ret = entry as u64;
        ctx
    }

    pub fn new_kernel(entry: fn(), stack_top: u64) -> Self {
        unsafe { Self::new(entry, stack_top) }
    }

    pub fn is_initialized(&self) -> bool { self.rsp != 0 || self.ret != 0 }

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

/// Save current context to the given Context structure.
/// Returns 0 on first call; 1 if returning from a restore (setjmp).
#[inline(always)]
pub unsafe fn save_context(ctx: &mut Context) -> i32 {
    let result: i32;
    core::arch::asm!(
        "sd s1, 0({ctx})",
        "sd s2, 8({ctx})",
        "sd s3, 16({ctx})",
        "sd s4, 24({ctx})",
        "sd s5, 32({ctx})",
        "sd s6, 40({ctx})",
        "sd sp, 48({ctx})",
        "sd ra, 56({ctx})",
        "li {res}, 0",
        res = out(reg) result,
        ctx = in(reg) ctx as *mut Context as u64,
    );
    result
}

/// Restore context and return with value `non_zero` (longjmp).
#[inline(always)]
pub unsafe fn restore_context(ctx: &Context, non_zero: i32) -> ! {
    core::arch::asm!(
        "ld s1, 0({ctx})",
        "ld s2, 8({ctx})",
        "ld s3, 16({ctx})",
        "ld s4, 24({ctx})",
        "ld s5, 32({ctx})",
        "ld s6, 40({ctx})",
        "ld sp, 48({ctx})",
        "ld ra, 56({ctx})",
        "mv a0, {v}",
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

/// Save scheduler context (Label) from a process.
///
/// # Safety
/// Manipulates the process's scheduler context.
pub unsafe fn procsave(sched_ctx: &mut Label) {
    let mut ctx = Context::from_label(sched_ctx);
    save_context(&mut ctx);
    *sched_ctx = ctx.to_label();
}

/// Restore scheduler context (Label) for a process.
///
/// # Safety
/// Manipulates the process's scheduler context.
pub unsafe fn procrestore(sched_ctx: &Label) {
    // RISC-V has no FPU task-switched bit; vector/FPU state is handled
    // by the trap path (sstatus.FS) when FPU support is enabled.
    let _ = sched_ctx;
}

// ============================================================================
// FPU State Management (AArch64: F/D extension registers f0-f31)
// ============================================================================

/// FPU state size: 32 × 64-bit FP registers + fflags/frm/fcsr.
pub const FPU_STATE_SIZE: usize = 32 * 8 + 8;

/// FPU state buffer; must be 8-byte aligned.
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

/// Save FPU state (`fsd f0-f31` + fcsr).
///
/// # Safety
/// Buffer must be aligned and at least FPU_STATE_SIZE bytes; FPU must
/// be enabled in `sstatus.FS`.
#[inline]
pub unsafe fn fpsave(state: &mut FpuState) {
    let ptr = state.data.as_mut_ptr() as u64;
    core::arch::asm!(
        ".option push",
        ".option arch, +d",
        "fsd f0,  0({p})",
        "fsd f1,  8({p})",
        "fsd f2,  16({p})",
        "fsd f3,  24({p})",
        "fsd f4,  32({p})",
        "fsd f5,  40({p})",
        "fsd f6,  48({p})",
        "fsd f7,  56({p})",
        "fsd f8,  64({p})",
        "fsd f9,  72({p})",
        "fsd f10, 80({p})",
        "fsd f11, 88({p})",
        "fsd f12, 96({p})",
        "fsd f13, 104({p})",
        "fsd f14, 112({p})",
        "fsd f15, 120({p})",
        "fsd f16, 128({p})",
        "fsd f17, 136({p})",
        "fsd f18, 144({p})",
        "fsd f19, 152({p})",
        "fsd f20, 160({p})",
        "fsd f21, 168({p})",
        "fsd f22, 176({p})",
        "fsd f23, 184({p})",
        "fsd f24, 192({p})",
        "fsd f25, 200({p})",
        "fsd f26, 208({p})",
        "fsd f27, 216({p})",
        "fsd f28, 224({p})",
        "fsd f29, 232({p})",
        "fsd f30, 240({p})",
        "fsd f31, 248({p})",
        "frcsr {t}",            // fcsr
        "sd {t}, 256({p})",
        ".option pop",
        t = out(reg) _,
        p = in(reg) ptr,
        options(nostack)
    );
}

/// Restore FPU state.
///
/// # Safety
/// Buffer must contain a previously saved FPU state.
#[inline]
pub unsafe fn fprestore(state: &FpuState) {
    let ptr = state.data.as_ptr() as u64;
    core::arch::asm!(
        ".option push",
        ".option arch, +d",
        "fld f0,  0({p})",
        "fld f1,  8({p})",
        "fld f2,  16({p})",
        "fld f3,  24({p})",
        "fld f4,  32({p})",
        "fld f5,  40({p})",
        "fld f6,  48({p})",
        "fld f7,  56({p})",
        "fld f8,  64({p})",
        "fld f9,  72({p})",
        "fld f10, 80({p})",
        "fld f11, 88({p})",
        "fld f12, 96({p})",
        "fld f13, 104({p})",
        "fld f14, 112({p})",
        "fld f15, 120({p})",
        "fld f16, 128({p})",
        "fld f17, 136({p})",
        "fld f18, 144({p})",
        "fld f19, 152({p})",
        "fld f20, 160({p})",
        "fld f21, 168({p})",
        "fld f22, 176({p})",
        "fld f23, 184({p})",
        "fld f24, 192({p})",
        "fld f25, 200({p})",
        "fld f26, 208({p})",
        "fld f27, 216({p})",
        "fld f28, 224({p})",
        "fld f29, 232({p})",
        "fld f30, 240({p})",
        "fld f31, 248({p})",
        "ld {t}, 256({p})",
        "fscsr x0, {t}",
        ".option pop",
        t = out(reg) _,
        p = in(reg) ptr,
        options(nostack)
    );
}

/// Save FPU state for the current process.
///
/// # Safety
/// Only call in kernel mode.
#[cfg(target_feature = "d")]
pub unsafe fn save_fpu_state(state: &mut FpuState) { fpsave(state) }

/// Restore FPU state for the current process.
///
/// # Safety
/// Only call in kernel mode.
#[cfg(target_feature = "d")]
pub unsafe fn restore_fpu_state(state: &FpuState) { fprestore(state) }

/// Initialize FPU for a new process: set `sstatus.FS` = Dirty (0b11) so
/// the process can use FP without an illegal-instruction trap.
///
/// # Safety
/// Only call in kernel mode.
pub unsafe fn init_fpu() {
    core::arch::asm!(
        "csrs sstatus, {mask}",
        mask = in(reg) 3usize << 13,
        options(nostack)
    );
}

/// Check whether FPU instructions trap (sstatus.FS == Off).
pub unsafe fn probe_double() -> bool {
    let supported: usize;
    core::arch::asm!(
        "csrrci {status}, sstatus, 2",
        "la {vector}, 2f",
        "csrrw {vector}, stvec, {vector}",
        "li {scratch}, 0x6000",
        "csrs sstatus, {scratch}",
        "li {supported}, 1",
        ".option push",
        ".option arch, +d",
        "fmv.d.x f0, zero",
        ".option pop",
        "j 3f",
        ".balign 4",
        "2:",
        "li {supported}, 0",
        "la {scratch}, 3f",
        "csrw sepc, {scratch}",
        "sret",
        "3:",
        "csrw stvec, {vector}",
        "csrw sstatus, {status}",
        supported = out(reg) supported,
        status = out(reg) _,
        vector = out(reg) _,
        scratch = out(reg) _,
        options(nostack),
    );
    if supported != 0 {
        init_fpu();
        true
    } else {
        false
    }
}

pub fn fpu_used_since_switch() -> bool {
    let sstatus: u64;
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) sstatus, options()) };
    (sstatus & (0b11 << 13)) != 0
}

/// Clear the FPU trap state (enable FP).
#[cfg(target_feature = "d")]
pub fn clear_fpu_task_switched() {
    unsafe { init_fpu() };
}

//! LoongArch64 context save/restore (setjmp/longjmp style) — mirrors the
//! x86_64 `context` module exactly so the scheduler's
//! architecture-neutral code compiles unchanged.
//!
//! Physical register ↔ slot mapping (LoongArch callee-saved set):
//!   * `rbx` ← $s0 ($r23)
//!   * `rbp` ← $s1 ($r24)
//!   * `r12` ← $s2 ($r25)
//!   * `r13` ← $s3 ($r26)
//!   * `r14` ← $s4 ($r27)
//!   * `r15` ← $s5 ($r28)
//!   * `rsp` ← $sp ($r3)
//!   * `ret` ← $ra ($r1 — the "return address" analog of x86 `[rsp]`)

// ============================================================================
// Label Structure (compatible with kernel's Label)
// ============================================================================

/// Scheduler context label (must match kernel's Label)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Label {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub sp: u64,
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
        "st.d $r23, {ctx}, 0",   // s0  → rbx
        "st.d $r24, {ctx}, 8",   // s1  → rbp
        "st.d $r25, {ctx}, 16",  // s2  → r12
        "st.d $r26, {ctx}, 24",  // s3  → r13
        "st.d $r27, {ctx}, 32",  // s4  → r14
        "st.d $r28, {ctx}, 40",  // s5  → r15
        "st.d $r3,  {ctx}, 48",  // sp
        "st.d $r1,  {ctx}, 56",  // ra
        "addi.d {res}, $r0, 0",
        res = out(reg) result,
        ctx = in(reg) ctx as *mut Context as u64,
        options(),
    );
    result
}

/// Restore context and return with value `non_zero` (longjmp).
#[inline(always)]
pub unsafe fn restore_context(ctx: &Context, non_zero: i32) -> ! {
    core::arch::asm!(
        "ld.d $r23, {ctx}, 0",
        "ld.d $r24, {ctx}, 8",
        "ld.d $r25, {ctx}, 16",
        "ld.d $r26, {ctx}, 24",
        "ld.d $r27, {ctx}, 32",
        "ld.d $r28, {ctx}, 40",
        // Return address into a temporary, stack pointer into another.
        // $r3 (sp) is a reserved register, so LLVM never allocates the
        // {pc} / {spv} / {ctx} operands to it — the literal writes below
        // cannot clobber them.
        "ld.d {pc},  {ctx}, 56",
        "ld.d {spv}, {ctx}, 48",
        // Return value in $a0 ($r4) for the resumed setjmp.
        "or $r4, {v}, $r0",
        "or $r3, {spv}, $r0",
        "jirl $r0, {pc}, 0",
        pc = out(reg) _,
        spv = out(reg) _,
        v = in(reg) non_zero,
        ctx = in(reg) ctx as *const Context as u64,
        options(nostack),
    );
    core::hint::unreachable_unchecked()
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
    // LoongArch has no FPU task-switched bit; FPU/LSX state is managed
    // through CSR.EUEN by the trap path.
    let _ = sched_ctx;
}

// ============================================================================
// FPU State Management (LoongArch: FP registers f0-f31)
// ============================================================================

/// FPU state size: 32 × 8-byte FP registers + fcsr/fcc registers.
pub const FPU_STATE_SIZE: usize = 32 * 8 + 8;

/// FPU state buffer; 16-byte aligned for future LSX (128-bit) storage.
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

/// Save FPU state (`fst.d f0-f31` + fcsr). Requires CSR.EUEN.FPE set.
///
/// # Safety
/// Buffer must be aligned and at least FPU_STATE_SIZE bytes.
#[inline]
pub unsafe fn fpsave(state: &mut FpuState) {
    let ptr = state.data.as_mut_ptr() as u64;
    core::arch::asm!(
        "fst.d $f0,  {p}, 0",
        "fst.d $f1,  {p}, 8",
        "fst.d $f2,  {p}, 16",
        "fst.d $f3,  {p}, 24",
        "fst.d $f4,  {p}, 32",
        "fst.d $f5,  {p}, 40",
        "fst.d $f6,  {p}, 48",
        "fst.d $f7,  {p}, 56",
        "fst.d $f8,  {p}, 64",
        "fst.d $f9,  {p}, 72",
        "fst.d $f10, {p}, 80",
        "fst.d $f11, {p}, 88",
        "fst.d $f12, {p}, 96",
        "fst.d $f13, {p}, 104",
        "fst.d $f14, {p}, 112",
        "fst.d $f15, {p}, 120",
        "fst.d $f16, {p}, 128",
        "fst.d $f17, {p}, 136",
        "fst.d $f18, {p}, 144",
        "fst.d $f19, {p}, 152",
        "fst.d $f20, {p}, 160",
        "fst.d $f21, {p}, 168",
        "fst.d $f22, {p}, 176",
        "fst.d $f23, {p}, 184",
        "fst.d $f24, {p}, 192",
        "fst.d $f25, {p}, 200",
        "fst.d $f26, {p}, 208",
        "fst.d $f27, {p}, 216",
        "fst.d $f28, {p}, 224",
        "fst.d $f29, {p}, 232",
        "fst.d $f30, {p}, 240",
        "fst.d $f31, {p}, 248",
        "movfcsr2gr {t}, $fcsr0",
        "st.d {t}, {p}, 256",
        t = out(reg) _,
        p = in(reg) ptr,
        options(nostack)
    );
}

/// Restore FPU state (`fld.d f0-f31` + fcsr).
///
/// # Safety
/// Buffer must contain a previously saved FPU state.
#[inline]
pub unsafe fn fprestore(state: &FpuState) {
    let ptr = state.data.as_ptr() as u64;
    core::arch::asm!(
        "fld.d $f0,  {p}, 0",
        "fld.d $f1,  {p}, 8",
        "fld.d $f2,  {p}, 16",
        "fld.d $f3,  {p}, 24",
        "fld.d $f4,  {p}, 32",
        "fld.d $f5,  {p}, 40",
        "fld.d $f6,  {p}, 48",
        "fld.d $f7,  {p}, 56",
        "fld.d $f8,  {p}, 64",
        "fld.d $f9,  {p}, 72",
        "fld.d $f10, {p}, 80",
        "fld.d $f11, {p}, 88",
        "fld.d $f12, {p}, 96",
        "fld.d $f13, {p}, 104",
        "fld.d $f14, {p}, 112",
        "fld.d $f15, {p}, 120",
        "fld.d $f16, {p}, 128",
        "fld.d $f17, {p}, 136",
        "fld.d $f18, {p}, 144",
        "fld.d $f19, {p}, 152",
        "fld.d $f20, {p}, 160",
        "fld.d $f21, {p}, 168",
        "fld.d $f22, {p}, 176",
        "fld.d $f23, {p}, 184",
        "fld.d $f24, {p}, 192",
        "fld.d $f25, {p}, 200",
        "fld.d $f26, {p}, 208",
        "fld.d $f27, {p}, 216",
        "fld.d $f28, {p}, 224",
        "fld.d $f29, {p}, 232",
        "fld.d $f30, {p}, 240",
        "fld.d $f31, {p}, 248",
        "ld.d {t}, {p}, 256",
        "movgr2fcsr $fcsr0, {t}",
        t = out(reg) _,
        p = in(reg) ptr,
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

/// Initialize FPU for a new process: set CSR.EUEN.FPE (bit 0) so FP
/// instructions do not raise the FPE (disabled) exception.
///
/// # Safety
/// Only call in kernel mode.
pub unsafe fn init_fpu() {
    super::cpu::csr_xchg::<{ super::cpu::csr::EUEN }, 0x1>(0x1);
}

/// Check whether FPU instructions are enabled (CSR.EUEN.FPE == 1).
pub fn fpu_used_since_switch() -> bool {
    (super::cpu::csr_read::<{ super::cpu::csr::EUEN }>() & 0x1) != 0
}

/// Clear the FPU trap state (enable FP).
pub fn clear_fpu_task_switched() {
    unsafe { init_fpu() };
}

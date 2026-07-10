//! Context switching implementation for x86_64
//!
//! This module provides setjmp/longjmp style context switching for the scheduler.
//! It uses inline assembly to save and restore callee-saved registers.

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
    // FPU state will be restored via fpsave/fprestore in the context switch path
    // For now, just ensure FPU is in a clean state
    let _ = sched_ctx;
}

// ============================================================================
// FPU State Management (x87 + SSE)
// ============================================================================

/// FPU state size for FXSAVE/FXRSTOR (512 bytes)
pub const FPU_STATE_SIZE: usize = 512;

/// FPU state buffer for saving/restoring floating point state
/// Must be 16-byte aligned for FXSAVE/FXRSTOR
#[repr(align(16))]
pub struct FpuState {
    /// FPU state data
    pub data: [u8; FPU_STATE_SIZE],
}

impl FpuState {
    /// Create a new FPU state buffer
    pub fn new() -> Self {
        Self { data: [0; FPU_STATE_SIZE] }
    }

    /// Initialize FPU state to default values
    pub fn init(&mut self) {
        self.data = [0; FPU_STATE_SIZE];
    }
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// Save FPU state using FXSAVE instruction
///
/// Saves x87 FPU, MMX, and SSE state to the buffer.
/// The buffer must be 16-byte aligned and at least 512 bytes.
///
/// # Safety
/// - Buffer must be properly aligned (16 bytes)
/// - Buffer must be at least FPU_STATE_SIZE bytes
/// - Should only be called in kernel mode
#[inline]
pub unsafe fn fpsave(state: &mut FpuState) {
    core::arch::asm!(
        "fxsave64 [{0}]",
        in(reg) state.data.as_ptr(),
        options(nostack, preserves_flags)
    );
}

/// Restore FPU state using FXRSTOR instruction
///
/// Restores x87 FPU, MMX, and SSE state from the buffer.
///
/// # Safety
/// - Buffer must be properly aligned (16 bytes)
/// - Buffer must be at least FPU_STATE_SIZE bytes
/// - Buffer must contain valid FPU state from a previous fpsave
/// - Should only be called in kernel mode
#[inline]
pub unsafe fn fprestore(state: &mut FpuState) {
    core::arch::asm!(
        "fxrstor64 [{0}]",
        in(reg) state.data.as_ptr(),
        options(nostack, preserves_flags)
    );
}

/// Save FPU state for the current process
///
/// This should be called when switching away from a process
/// that has used floating point instructions.
///
/// # Safety
/// - Should only be called in kernel mode
/// - Process must have used FPU since last save
pub unsafe fn save_fpu_state(state: &mut FpuState) {
    fpsave(state);
}

/// Restore FPU state for the current process
///
/// This should be called when switching to a process
/// that will use floating point instructions.
///
/// # Safety
/// - Should only be called in kernel mode
/// - State must have been saved previously for this process
pub unsafe fn restore_fpu_state(state: &mut FpuState) {
    fprestore(state);
}

/// Initialize FPU for a new process
///
/// Sets up the FPU to a known clean state.
///
/// # Safety
/// - Should only be called in kernel mode
pub unsafe fn init_fpu() {
    // FNINIT initializes FPU without checking for pending exceptions
    core::arch::asm!("fninit", options(nostack));
}

/// Check if FPU has been used since last save
///
/// On x86_64, we can check the TS (Task Switched) bit in CR0.
/// If set, the FPU state needs to be saved before switching away.
///
/// # Safety
/// - Should only be called in kernel mode
pub fn fpu_used_since_switch() -> bool {
    // Read CR0 and check TS bit (bit 3)
    let cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {0}, cr0",
            out(reg) cr0,
            options(nostack, preserves_flags)
        );
    }
    (cr0 & (1 << 3)) != 0
}

/// Clear the FPU task-switched flag
///
/// After saving FPU state, clear the TS bit so we don't
/// take a #NM exception on the next FPU instruction.
///
/// # Safety
/// - Should only be called in kernel mode
pub fn clear_fpu_task_switched() {
    let cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {0}, cr0",
            out(reg) cr0,
            options(nostack, preserves_flags)
        );
    }
    let cr0 = cr0 & !(1 << 3);
    unsafe {
        core::arch::asm!(
            "mov cr0, {0}",
            in(reg) cr0,
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpu_state_size() {
        assert_eq!(FPU_STATE_SIZE, 512);
    }

    #[test]
    fn test_fpu_state_alignment() {
        // FpuState must be 16-byte aligned for FXSAVE/FXRSTOR
        let state = FpuState::new();
        let addr = state.data.as_ptr() as usize;
        assert_eq!(addr % 16, 0, "FpuState should be 16-byte aligned");
    }

    #[test]
    fn test_fpu_state_init() {
        let mut state = FpuState::new();
        state.init();
        // After init, all bytes should be 0
        assert!(state.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_label_creation() {
        let label = Label::new();
        assert!(!label.is_set());
    }

    #[test]
    fn test_context_from_label() {
        let mut label = Label::new();
        label.rbx = 1;
        label.rbp = 2;
        label.sp = 0x1000;
        label.pc = 0x2000;

        let ctx = Context::from_label(&label);
        assert_eq!(ctx.rbx, 1);
        assert_eq!(ctx.rbp, 2);
        assert_eq!(ctx.rsp, 0x1000);
        assert_eq!(ctx.ret, 0x2000);
    }

    #[test]
    fn test_context_to_label() {
        let ctx = Context {
            rbx: 1,
            rbp: 2,
            r12: 3,
            r13: 4,
            r14: 5,
            r15: 6,
            rsp: 0x1000,
            ret: 0x2000,
        };

        let label = ctx.to_label();
        assert_eq!(label.rbx, 1);
        assert_eq!(label.rbp, 2);
        assert_eq!(label.sp, 0x1000);
        assert_eq!(label.pc, 0x2000);
    }
}

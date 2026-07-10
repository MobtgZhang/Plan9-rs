//! Register structures for x86_64
//!
//! Plus the `switch_to_user` helper that drops from Ring 0 to Ring 3 via
//! an `iretq` frame.

// ============================================================================
// Saved register frame
// ============================================================================

/// User registers on interrupt/trap
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Frame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip:    u64,
    pub cs:     u64,
    pub rflags: u64,
    pub rsp:    u64,
    pub ss:     u64,
}

// ============================================================================
// Ring 3 entry
// ============================================================================

/// Segment selectors we install in the GDT (see gdt.rs). Hardcoded here so
/// the ring-3 switch path doesn't depend on any other module's link order.
const SEL_USER_DS: u64 = 0x18 | 3;
const SEL_USER_CS: u64 = 0x20 | 3;

/// Transfer control from Ring 0 to a user-mode process at `entry` with the
/// user stack pointer set to `user_sp`. The new PML4 physical address
/// (`user_pml4`) is loaded into CR3 first.
///
/// # Safety
/// Caller must ensure:
///   * `user_pml4` is a valid PML4 built for the user process (i.e. it
///     contains the kernel mappings in the high half).
///   * `entry` is a valid virtual address in the user half of the new
///     address space.
///   * `user_sp` is a valid user stack pointer (the user page table maps
///     it).
///   * All general-purpose registers are set up so the new process can
///     make progress.
///
/// This function never returns.
pub unsafe fn switch_to_user(
    entry: u64,
    user_sp: u64,
    user_pml4: u64,
    rdi: u64,
    rsi: u64,
) -> ! {
    let rflags: u64 = 0x202; // IF=1, reserved bit 1 set.
    core::arch::asm!(
        // 1. Switch to the user's address space.
        "mov cr3, {pml4}",
        // 2. Push a synthetic iret frame. The order on the stack must be
        //    exactly the order iretq pops: SS, RSP, RFLAGS, CS, RIP.
        "push {sel_ss}",
        "push {rsp}",
        "push {rflags}",
        "push {sel_cs}",
        "push {rip}",
        // 3. Set up the first user-mode arguments.
        "mov rdi, {arg0}",
        "mov rsi, {arg1}",
        // 4. Switch to Ring 3.
        "iretq",
        pml4   = in(reg) user_pml4,
        sel_ss = const SEL_USER_DS,
        sel_cs = const SEL_USER_CS,
        rsp    = in(reg) user_sp,
        rflags = in(reg) rflags,
        rip    = in(reg) entry,
        arg0   = in(reg) rdi,
        arg1   = in(reg) rsi,
        options(noreturn),
    );
}
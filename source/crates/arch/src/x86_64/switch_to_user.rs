//! Ring-0 to ring-3 transition support.

extern "C" {
    /// Switch into user mode. See `switch_to_user.S` for the
    /// register and stack conventions.
    ///
    /// # Safety
    /// `pml4_phys` (rdi) is the physical address of the new PML4 and
    /// `frame_ptr` (rsi) is a kernel-mapped page containing the IRET frame
    /// (scratch, RIP, CS, RFLAGS, RSP, SS), exactly as documented in
    /// `switch_to_user.S`.
    pub fn switch_to_user_trampoline(pml4_phys: u64, frame_ptr: u64) -> !;

    /// Resume a saved user-mode frame. `frame_ptr` points at a
    /// `SavedUserFrame` (R15 first, IRET frame at offset 80). Never returns.
    pub fn kernel_resume_user(frame_ptr: u64, pml4_phys: u64) -> !;
}

/// User data-segment selector: index 5 | TI=0 | RPL=3 = 0x2B.
pub const USER_DS: u16 = 0x2B;
/// User code-segment selector: index 4 | TI=0 | RPL=3 = 0x23.
pub const USER_CS: u16 = 0x23;

/// Initial user-mode RFLAGS: IF set, IOPL=0, no other flags.
pub const USER_RFLAGS_INIT: u64 = 1 << 9;
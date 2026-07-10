//! Ring-0 to ring-3 transition support.

extern "C" {
    /// Switch into user mode. See `switch_to_user.S` for the
    /// register and stack conventions.
    ///
    /// # Safety
    /// The kernel stack must contain the IRET frame (SS, RSP, RFLAGS,
    /// CS, RIP) and a scratch slot above it, exactly as documented
    /// in `switch_to_user.S`. The new PML4 (`rdi` argument) must
    /// already have the user half populated.
    pub fn switch_to_user_trampoline(pml4_phys: u64) -> !;
}

/// User data-segment selector: index 4 | TI=0 | RPL=3 = 0x2B.
pub const USER_DS: u16 = 0x2B;
/// User code-segment selector: index 5 | TI=0 | RPL=3 = 0x33.
pub const USER_CS: u16 = 0x33;

/// Initial user-mode RFLAGS: IF set, IOPL=0, no other flags.
pub const USER_RFLAGS_INIT: u64 = 1 << 9;
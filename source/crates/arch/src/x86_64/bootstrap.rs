//! Distinguishes the two early-init code paths.
//!
//! `GrubLongMode` is the path the Multiboot2 entry actually uses: GRUB
//! hands us a working 64-bit environment, so we only need GDT + IDT +
//! segment reload — paging is already enabled and identity-mapped.
//!
//! `RawBios` is a placeholder for a hypothetical BIOS/handover path
//! where the kernel has to build its own page tables before enabling
//! long mode; not currently invoked but kept so future refactors that
//! want to drop GRUB don't have to invent the enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// GRUB loaded us; long mode + paging are already on.
    GrubLongMode,
    /// Legacy BIOS / handover; we have to build our own page tables.
    RawBios,
}

#[inline]
pub fn early_init_for(_mode: BootMode) {
    // Both modes currently share the same sequence: GDT -> reload
    // segments -> IDT. The variant exists so a future RawBios path
    // can insert `paging_init::early_paging_init()` before the
    // segment reload without disturbing GRUB users.
    //
    // SAFETY: each of these is called exactly once at boot, while we
    // are still single-threaded and not yet handling interrupts. They
    // write to static CPU tables and call into `lgdt`/`lidt`.
    unsafe {
        crate::x86_64::gdt::gdt_init();
        crate::x86_64::gdt::reload_segments();
        crate::x86_64::idt::idt_init();
    }
}

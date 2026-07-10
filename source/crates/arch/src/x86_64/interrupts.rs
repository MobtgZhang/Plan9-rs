//! Interrupt enumeration and gate-type constants for x86_64.
//!
//! The actual IDT layout, installation, and handlers live in
//! `super::idt`. This module only exposes the small set of constants
//! that other crates (kernel, drivers) need without having to drag
//! in the IDT implementation.

/// Number of IDT entries (256 for x86_64)
pub const IDT_ENTRIES: usize = 256;

/// IDT entry size in bytes
pub const IDT_ENTRY_SIZE: usize = 16;

/// IDT limit (size - 1)
pub const IDT_LIMIT: u16 = (IDT_ENTRIES * IDT_ENTRY_SIZE - 1) as u16;

/// Exception vector numbers
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Exception {
    DivideError = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTss = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    X87FloatingPoint = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SimdFloatingPoint = 19,
}

/// Hardware interrupt vector base (IRQ 0-15 maps to 32-47)
pub const IRQ_BASE: u8 = 32;

/// IRQ numbers
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Irq {
    Timer = 0,
    Keyboard = 1,
    Cascade = 2,
    Com2 = 3,
    Com1 = 4,
    FloppyDisk = 6,
    Lpt1 = 7,
    Rtc = 8,
    Ps2Mouse = 12,
    Fpu = 13,
    PrimaryAta = 14,
    SecondaryAta = 15,
}

/// IDT gate types
pub mod gate_type {
    /// 32-bit interrupt gate (clears IF on entry)
    pub const INTERRUPT_GATE: u8 = 0x8E;
    /// 32-bit trap gate (does not clear IF)
    pub const TRAP_GATE: u8 = 0x8F;
}

/// Send End-Of-Interrupt to the LAPIC.
///
/// # Safety
/// Must be called exactly once per interrupt handled. The LAPIC base
/// must already be mapped (the kernel does this during ACPI init).
#[cfg(target_arch = "x86_64")]
pub unsafe fn end_of_interrupt() {
    // LAPIC EOI register is at offset 0xB0 from the LAPIC base.
    let lapic_base = crate::x86_64::lapic_base();
    core::ptr::write_volatile(lapic_base as *mut u32, 0);
}
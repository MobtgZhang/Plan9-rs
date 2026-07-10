//! Local APIC (LAPIC) driver for x86_64
//!
//! This module provides functions for programming the Local APIC,
//! which handles timer interrupts and inter-processor interrupts.

use alloc::boxed::Box;
// use alloc::vec::Vec;
use crate::plan9_common::types::PhysAddr;

// ============================================================================
// LAPIC Registers
// ============================================================================

/// LAPIC register offsets (from MMIO base)
#[allow(dead_code)]
mod lapic_regs {
    // Registers are at 4-byte offsets
    pub const ID: usize = 0x0020;        // LAPIC ID
    pub const VERSION: usize = 0x0030;    // LAPIC Version
    pub const TPR: usize = 0x0080;        // Task Priority Register
    pub const APR: usize = 0x0090;        // Arbitration Priority Register
    pub const PPR: usize = 0x00A0;        // Processor Priority Register
    pub const EOI: usize = 0x00B0;        // End of Interrupt
    pub const RRD: usize = 0x00C0;        // Remote Read
    pub const LDR: usize = 0x00D0;        // Logical Destination Register
    pub const DFR: usize = 0x00E0;        // Destination Format Register
    pub const SVR: usize = 0x00F0;        // Spurious Interrupt Vector Register
    pub const ISR_BASE: usize = 0x0100;   // In-Service Register (256 bits)
    pub const TMR_BASE: usize = 0x0180;  // Trigger Mode Register
    pub const IRR_BASE: usize = 0x0200;   // Interrupt Request Register
    pub const ESR: usize = 0x0280;        // Error Status Register
    pub const LVT_CMCI: usize = 0x02F0;  // LVT CMCI
    pub const ICR_LOW: usize = 0x0300;    // Interrupt Command Register (low)
    pub const ICR_HIGH: usize = 0x0310;  // Interrupt Command Register (high)
    pub const LVT_TIMER: usize = 0x0320;  // LVT Timer
    pub const LVT_THERMAL: usize = 0x0330; // LVT Thermal Sensor
    pub const LVT_PERFMON: usize = 0x0340; // LVT Performance Monitoring
    pub const LVT_LINT0: usize = 0x0350;  // LVT LINT0
    pub const LVT_LINT1: usize = 0x0360;  // LVT LINT1
    pub const LVT_ERROR: usize = 0x0370;   // LVT Error
    pub const TIMER_INITIAL: usize = 0x0380; // Initial Count Register
    pub const TIMER_CURRENT: usize = 0x0390; // Current Count Register
    pub const TIMER_DIVIDE: usize = 0x03E0; // Divide Configuration Register
}

/// LAPIC base address (typically at 0xFEE00000)
const LAPIC_BASE_DEFAULT: u64 = 0xFEE00000;

/// Spurious vector for LAPIC
const LAPIC_SPURIOUS_VECTOR: u32 = 0xFF;

/// LAPIC timer mode
#[derive(Debug, Clone, Copy)]
pub enum LapicTimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

/// LAPIC driver state
pub struct Lapic {
    base: PhysAddr,
}

impl Lapic {
    /// Create a new LAPIC driver
    pub fn new(base: PhysAddr) -> Self {
        Self { base }
    }

    /// Default LAPIC
    pub fn default() -> Self {
        Self::new(PhysAddr::new(LAPIC_BASE_DEFAULT))
    }

    /// Read a LAPIC register
    #[inline(always)]
    fn read(&self, reg: usize) -> u32 {
        let addr = self.base.as_u64() + reg as u64;
        unsafe { *(addr as *const u32) }
    }

    /// Write a LAPIC register
    #[inline(always)]
    fn write(&self, reg: usize, value: u32) {
        let addr = self.base.as_u64() + reg as u64;
        unsafe { *(addr as *mut u32) = value; }
    }

    /// Get LAPIC ID
    pub fn id(&self) -> u32 {
        (self.read(lapic_regs::ID) >> 24) as u32
    }

    /// Get LAPIC version
    pub fn version(&self) -> u32 {
        self.read(lapic_regs::VERSION) & 0xFF
    }

    /// Get maximum LVT entry
    pub fn max_lvt_entry(&self) -> u32 {
        (self.read(lapic_regs::VERSION) >> 16) & 0xFF
    }

    /// Send End of Interrupt
    #[inline(always)]
    pub fn eoi(&self) {
        self.write(lapic_regs::EOI, 0);
    }

    /// Initialize the LAPIC
    pub fn init(&self) {
        // Enable the LAPIC
        let svr = self.read(lapic_regs::SVR);
        self.write(
            lapic_regs::SVR,
            (svr & !0xFF) | LAPIC_SPURIOUS_VECTOR | (1 << 8),
        );

        // Configure the timer
        self.init_timer();

        // Mask LINT0 and LINT1 (we'll use the timer for now)
        self.write(lapic_regs::LVT_LINT0, 1 << 16);  // Mask
        self.write(lapic_regs::LVT_LINT1, 1 << 16);  // Mask

        // Mask the performance monitoring counter
        self.write(lapic_regs::LVT_PERFMON, 1 << 16);

        // Mask the thermal sensor
        self.write(lapic_regs::LVT_THERMAL, 1 << 16);

        // Mask the CMCI
        self.write(lapic_regs::LVT_CMCI, 1 << 16);

        // Mask the error interrupt
        self.write(lapic_regs::LVT_ERROR, 1 << 16);

        // Clear any pending errors
        self.write(lapic_regs::ESR, 0);
    }

    /// Initialize the LAPIC timer
    pub fn init_timer(&self) {
        // Set divide register to 1
        self.write(lapic_regs::TIMER_DIVIDE, 0x0B); // Divide by 1

        // Set the timer vector (typically IRQ0 = vector 32)
        // Mode: 0 = one-shot, 1 = periodic
        let timer_mode = LapicTimerMode::Periodic;
        let mode_bits = match timer_mode {
            LapicTimerMode::OneShot => 0x00000,
            LapicTimerMode::Periodic => 0x20000,
            LapicTimerMode::TscDeadline => 0x40000,
        };

        // Timer vector = 32 (IRQ0)
        self.write(
            lapic_regs::LVT_TIMER,
            32 | mode_bits | (1 << 16), // Initially masked
        );
    }

    /// Start the LAPIC timer with a given count
    pub fn start_timer(&self, count: u32) {
        // Set initial count
        self.write(lapic_regs::TIMER_INITIAL, count);

        // Unmask the timer
        let lvt = self.read(lapic_regs::LVT_TIMER);
        self.write(lapic_regs::LVT_TIMER, lvt & !(1 << 16));
    }

    /// Stop the LAPIC timer
    pub fn stop_timer(&self) {
        // Mask the timer
        let lvt = self.read(lapic_regs::LVT_TIMER);
        self.write(lapic_regs::LVT_TIMER, lvt | (1 << 16));

        // Set initial count to 0
        self.write(lapic_regs::TIMER_INITIAL, 0);
    }

    /// Get current timer count
    pub fn timer_current(&self) -> u32 {
        self.read(lapic_regs::TIMER_CURRENT)
    }

    /// Send IPI (Inter-Processor Interrupt)
    pub fn send_ipi(&self, dest: u32, vector: u8) {
        // Set destination
        self.write(lapic_regs::ICR_HIGH, dest << 24);

        // Set vector and trigger mode
        // Fixed delivery (0), physical destination
        let command = (vector as u32) | (0 << 8) | (0 << 11) | (0 << 15) | (0 << 14);
        self.write(lapic_regs::ICR_LOW, command | (1 << 14)); // Assert
    }

    /// Broadcast SIPI (Startup IPI) to wake up other CPUs
    pub fn broadcast_sipi(&self, vector: u8) {
        self.send_ipi(0xFF, vector);
    }
}

// ============================================================================
// Global LAPIC Instance
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static LAPIC: AtomicPtr<Lapic> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the LAPIC
pub fn init_lapic() {
    let lapic = Box::new(Lapic::default());
    let ptr = Box::into_raw(lapic);
    LAPIC.store(ptr, Ordering::SeqCst);
    
    unsafe {
        (*ptr).init();
    }
}

/// Get the LAPIC instance
pub fn lapic() -> &'static Lapic {
    unsafe { &*LAPIC.load(Ordering::SeqCst) }
}

/// Send EOI to the LAPIC
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn eoi() {
    // LAPIC is at a fixed address, so we can use a simple inline function
    unsafe {
        core::arch::asm!(
            "mov dword ptr [0xFEE000B0], 0",
            options(nostack, preserves_flags)
        );
    }
}

/// Stub EOI for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn eoi() {
    // No LAPIC on non-x86_64 architectures
}

// ============================================================================
// Legacy PIC (8259A) Functions (for compatibility)
// ============================================================================

/// Initialize the legacy 8259A PIC
#[cfg(target_arch = "x86_64")]
pub fn pic_init() {
    // Mask all interrupts on the PIC
    unsafe {
        core::arch::asm!(
            "mov al, 0xFF",
            "out 0xA1, al",  // Mask PIC2
            "out 0x21, al",  // Mask PIC1
            options(nostack, preserves_flags)
        );
    }

    // Initialize PIC1
    unsafe {
        core::arch::asm!(
            "mov al, 0x11",  // ICW1: Init + ICW4
            "out 0x20, al",  // PIC1 command
            "nop",
            "mov al, 0x20",  // ICW2: Vector 0x20 (IRQ0)
            "out 0x21, al",  // PIC1 data
            "mov al, 0x04",  // ICW3: PIC1 has IRQ2
            "out 0x21, al",  // PIC1 data
            "mov al, 0x01",  // ICW4: 8086 mode
            "out 0x21, al",  // PIC1 data
            options(nostack, preserves_flags)
        );
    }

    // Initialize PIC2
    unsafe {
        core::arch::asm!(
            "mov al, 0x11",  // ICW1: Init + ICW4
            "out 0xA0, al",  // PIC2 command
            "nop",
            "mov al, 0x28",  // ICW2: Vector 0x28 (IRQ8)
            "out 0xA1, al",  // PIC2 data
            "mov al, 0x02",  // ICW3: PIC2 at IRQ2
            "out 0xA1, al",  // PIC2 data
            "mov al, 0x01",  // ICW4: 8086 mode
            "out 0xA1, al",  // PIC2 data
            options(nostack, preserves_flags)
        );
    }

    // Mask all interrupts
    unsafe {
        core::arch::asm!(
            "mov al, 0xFF",
            "out 0x21, al",  // PIC1
            "out 0xA1, al",  // PIC2
            options(nostack, preserves_flags)
        );
    }
}

/// Stub PIC init for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_init() {
    // No legacy PIC on non-x86_64 architectures
}

/// Send EOI to the legacy PIC
#[cfg(target_arch = "x86_64")]
pub fn pic_eoi(irq: u8) {
    if irq >= 8 {
        // End interrupt on PIC2
        unsafe {
            core::arch::asm!(
                "mov al, 0x20",
                "out 0xA0, al",
                options(nostack, preserves_flags)
            );
        }
    }
    // End interrupt on PIC1
    unsafe {
        core::arch::asm!(
            "mov al, 0x20",
            "out 0x20, al",
            options(nostack, preserves_flags)
        );
    }
}

/// Stub PIC EOI for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_eoi(_irq: u8) {
    // No legacy PIC on non-x86_64 architectures
}

/// Enable an IRQ on the PIC
///
/// This function enables a specific IRQ line on the 8259 PIC.
/// The IRQ number must be between 0 and 15 (IRQ0-IRQ15).
///
/// On the master PIC (IRQ 0-7), the corresponding bit in port 0x21 is cleared.
/// On the slave PIC (IRQ 8-15), the corresponding bit in port 0xA1 is cleared.
#[cfg(target_arch = "x86_64")]
pub fn pic_enable_irq(irq: u8) {
    if irq > 15 {
        return;
    }

    let irqbit: u8;
    let port: u16;

    if irq < 8 {
        // Master PIC (IRQ 0-7)
        irqbit = 1 << irq;
        port = 0x21;
    } else {
        // Slave PIC (IRQ 8-15)
        irqbit = 1 << (irq - 8);
        port = 0xA1;
    }

    unsafe {
        let port_val = port as u32;
        let mask_val = irqbit;
        core::arch::asm!(
            "in al, dx",
            "not al",
            "and al, {mask}",
            "not al",
            "out dx, al",
            in("dx") port_val,
            mask = in(reg_byte) mask_val,
            options(nostack, preserves_flags)
        );
    }
}

/// Disable an IRQ on the PIC
///
/// This function disables a specific IRQ line on the 8259 PIC.
/// The IRQ number must be between 0 and 15 (IRQ0-IRQ15).
///
/// On the master PIC (IRQ 0-7), the corresponding bit in port 0x21 is set.
/// On the slave PIC (IRQ 8-15), the corresponding bit in port 0xA1 is set.
#[cfg(target_arch = "x86_64")]
pub fn pic_disable_irq(irq: u8) {
    if irq > 15 {
        return;
    }

    let irqbit: u8;
    let port: u16;

    if irq < 8 {
        // Master PIC (IRQ 0-7)
        irqbit = 1 << irq;
        port = 0x21;
    } else {
        // Slave PIC (IRQ 8-15)
        irqbit = 1 << (irq - 8);
        port = 0xA1;
    }

    unsafe {
        let port_val = port as u32;
        let mask_val = irqbit;
        core::arch::asm!(
            "in al, dx",
            "or al, {mask}",
            "out dx, al",
            in("dx") port_val,
            mask = in(reg_byte) mask_val,
            options(nostack, preserves_flags)
        );
    }
}

/// Get the current PIC interrupt mask
///
/// Returns a 16-bit mask representing the current state of both PICs:
/// - Bits 0-7: Master PIC (IRQ0-IRQ7), 1 = masked, 0 = enabled
/// - Bits 8-15: Slave PIC (IRQ8-IRQ15), 1 = masked, 0 = enabled
#[cfg(target_arch = "x86_64")]
pub fn pic_get_mask() -> u16 {
    let master: u8;
    let slave: u8;

    unsafe {
        core::arch::asm!(
            "in al, 0x21",
            "mov {master}, al",
            "in al, 0xA1",
            "mov {slave}, al",
            master = out(reg_byte) master,
            slave = out(reg_byte) slave,
            options(nostack, preserves_flags)
        );
    }

    (master as u16) | ((slave as u16) << 8)
}

/// Set the PIC interrupt mask directly
///
/// Takes a 16-bit mask representing the desired state of both PICs:
/// - Bits 0-7: Master PIC (IRQ0-IRQ7), 1 = masked, 0 = enabled
/// - Bits 8-15: Slave PIC (IRQ8-IRQ15), 1 = masked, 0 = enabled
#[cfg(target_arch = "x86_64")]
pub fn pic_set_mask(mask: u16) {
    let low = (mask & 0xFF) as u8;
    let high = ((mask >> 8) & 0xFF) as u8;

    unsafe {
        core::arch::asm!(
            "mov al, {low}",
            "out 0x21, al",
            "mov al, {high}",
            "out 0xA1, al",
            low = in(reg_byte) low,
            high = in(reg_byte) high,
            options(nostack, preserves_flags)
        );
    }
}

/// Stub PIC enable_irq for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_enable_irq(_irq: u8) {
    // No legacy PIC on non-x86_64 architectures
}

/// Stub PIC disable_irq for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_disable_irq(_irq: u8) {
    // No legacy PIC on non-x86_64 architectures
}

/// Stub PIC get_mask for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_get_mask() -> u16 {
    0xFFFF // All masked
}

/// Stub PIC set_mask for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn pic_set_mask(_mask: u16) {
    // No legacy PIC on non-x86_64 architectures
}

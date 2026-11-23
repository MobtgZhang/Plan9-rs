//! Interrupt Descriptor Table for x86_64
//!
//! Each `IdtEntry` describes one of the 256 possible entries (0..=255).
//! Exception stubs distinguish user faults from fatal kernel exceptions
//! and dispatch to the kernel with the vector and CPU-supplied frame.

use core::mem::size_of;

use crate::x86_64::gdt::SEL_KERNEL_CS;
use crate::x86_64::x86_64_asm::lidt;

/// 16-byte IDT gate descriptor (64-bit interrupt/trap gate).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IdtEntry {
    /// Bits 0..16 of the handler address.
    pub offset_low: u16,
    /// Code-segment selector (must be a kernel CS).
    pub selector: u16,
    /// IST index (0 = no IST, 1..7 = use ISTn).
    pub ist: u8,
    /// Type/attributes. 0x8E = present, ring 0, 64-bit interrupt gate.
    pub type_attr: u8,
    /// Bits 16..32 of the handler address.
    pub offset_mid: u16,
    /// Bits 32..64 of the handler address.
    pub offset_high: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

impl IdtEntry {
    pub const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    pub fn set_handler(&mut self, handler: u64, selector: u16, ist: u8, type_attr: u8) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.selector = selector;
        self.ist = ist;
        self.type_attr = type_attr;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = ((handler >> 32) & 0xFFFF_FFFF) as u32;
        self.reserved = 0;
    }
}

/// Full IDT (256 entries × 16 bytes = 4 KiB) — fits in one page.
#[repr(C, align(16))]
pub struct IdtTable {
    pub entries: [IdtEntry; 256],
}

impl IdtTable {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::null(); 256],
        }
    }
}

/// IDTR pointer (limit:u16, base:u64).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IdtPointer {
    pub limit: u16,
    pub base: u64,
}

// Symbols provided by `idt_asm.S`. Each one is the entry point of the
// stub for the matching vector number.
extern "C" {
    static __isr_stub_0:  u8;
    static __isr_stub_1:  u8;
    static __isr_stub_2:  u8;
    static __isr_stub_3:  u8;
    static __isr_stub_4:  u8;
    static __isr_stub_5:  u8;
    static __isr_stub_6:  u8;
    static __isr_stub_7:  u8;
    static __isr_stub_8:  u8;
    static __isr_stub_10: u8;
    static __isr_stub_11: u8;
    static __isr_stub_12: u8;
    static __isr_stub_13: u8;
    static __isr_stub_14: u8;
    static __isr_stub_16: u8;
    static __isr_stub_17: u8;
    static __isr_stub_18: u8;
    static __isr_stub_19: u8;
    static __isr_stub_20: u8;
    static __isr_stub_30: u8;
    static __isr_stub_num_stubs: u8; // sentinel: number of stubs we emitted

    // Hardware IRQ stubs supplied by idt_asm.S.
    static __irq_stub_32: u8;
    static __irq_stub_33: u8;
    static __irq_stub_34: u8;
    static __irq_stub_35: u8;
    static __irq_stub_36: u8;
    static __irq_stub_37: u8;
    static __irq_stub_38: u8;
    static __irq_stub_39: u8;
    static __irq_stub_40: u8;
    static __irq_stub_41: u8;
    static __irq_stub_42: u8;
    static __irq_stub_43: u8;
    static __irq_stub_44: u8;
    static __irq_stub_45: u8;
    static __irq_stub_46: u8;
    static __irq_stub_47: u8;
}

/// Statically allocated IDT.
static mut IDT: IdtTable = IdtTable::new();

/// Install the IDT and call `lidt` so the CPU dispatches future exceptions
/// through our stubs.
///
/// # Safety
/// Call only on the boot CPU, before secondary CPUs or interrupts can use
/// the table, and after loading the GDT and reloading segment registers.
pub unsafe fn idt_init() {
    // Direct serial byte output without macros.
    unsafe fn dbg(b: u8) {
        core::arch::asm!(
            "mov r10w, dx",
            "mov dx, 0x3F8",
            "mov al, {v}",
            "out dx, al",
            "mov dx, r10w",
            v = in(reg_byte) b,
            out("r10") _,
            options(nostack, preserves_flags),
        );
    }
    unsafe { dbg(b'0'); }
    // Each (vector, stub_symbol) pair below corresponds to one entry in
    // `idt_asm.S`. We resolve the stub address via the `extern` declarations
    // at the top of this file.
    let vector_stubs: &[(u8, u64)] = &[
        (0,  &__isr_stub_0  as *const _ as u64),
        (1,  &__isr_stub_1  as *const _ as u64),
        (2,  &__isr_stub_2  as *const _ as u64),
        (3,  &__isr_stub_3  as *const _ as u64),
        (4,  &__isr_stub_4  as *const _ as u64),
        (5,  &__isr_stub_5  as *const _ as u64),
        (6,  &__isr_stub_6  as *const _ as u64),
        (7,  &__isr_stub_7  as *const _ as u64),
        (8,  &__isr_stub_8  as *const _ as u64),
        (10, &__isr_stub_10 as *const _ as u64),
        (11, &__isr_stub_11 as *const _ as u64),
        (12, &__isr_stub_12 as *const _ as u64),
        (13, &__isr_stub_13 as *const _ as u64),
        (14, &__isr_stub_14 as *const _ as u64),
        (16, &__isr_stub_16 as *const _ as u64),
        (17, &__isr_stub_17 as *const _ as u64),
        (18, &__isr_stub_18 as *const _ as u64),
        (19, &__isr_stub_19 as *const _ as u64),
        (20, &__isr_stub_20 as *const _ as u64),
        (30, &__isr_stub_30 as *const _ as u64),
        (32, &__irq_stub_32 as *const _ as u64),
        (33, &__irq_stub_33 as *const _ as u64),
        (34, &__irq_stub_34 as *const _ as u64),
        (35, &__irq_stub_35 as *const _ as u64),
        (36, &__irq_stub_36 as *const _ as u64),
        (37, &__irq_stub_37 as *const _ as u64),
        (38, &__irq_stub_38 as *const _ as u64),
        (39, &__irq_stub_39 as *const _ as u64),
        (40, &__irq_stub_40 as *const _ as u64),
        (41, &__irq_stub_41 as *const _ as u64),
        (42, &__irq_stub_42 as *const _ as u64),
        (43, &__irq_stub_43 as *const _ as u64),
        (44, &__irq_stub_44 as *const _ as u64),
        (45, &__irq_stub_45 as *const _ as u64),
        (46, &__irq_stub_46 as *const _ as u64),
        (47, &__irq_stub_47 as *const _ as u64),
    ];
    unsafe { dbg(b'1'); }
    // Force the linker to keep the sentinel alive.
    let _ = core::ptr::read_volatile(&__isr_stub_num_stubs);

    unsafe { dbg(b'2'); }
    // Default all entries to the "no handler installed" state.
    let table = &mut *(&raw mut IDT);
    *table = IdtTable::new();
    unsafe { dbg(b'3'); }

    unsafe { dbg(b'4'); }
    // Install our handlers. 0x8E = present, DPL 0, 64-bit interrupt gate.
    for (vector, handler) in vector_stubs.iter().copied() {
        let entry = &mut table.entries[vector as usize];
        entry.set_handler(handler, SEL_KERNEL_CS, 0, 0x8E);
    }
    unsafe { dbg(b'5'); }

    // Install syscall handler at vector 0x80 (128)
    // DPL 3 permits int 0x80 from ring 3. The interrupt gate masks IRQs in the syscall.
    let syscall_handler = &syscall_stub_entry as *const u8 as u64;
    let syscall_entry = &mut table.entries[0x80];
    syscall_entry.set_handler(syscall_handler, SEL_KERNEL_CS, 0, 0xEE);

    unsafe { dbg(b'6'); }
    unsafe { dbg(b'7'); }
    // MARKER: 'X' right before lidt
    core::arch::asm!(
        "mov r10w, dx",
        "mov dx, 0x3F8",
        "mov al, 'X'",
        "out dx, al",
        "mov dx, r10w",
        out("r10") _,
        options(nostack, preserves_flags),
    );
    load_idt();
    // MARKER: 'Y' right after lidt (if we reach here, lidt succeeded)
    core::arch::asm!(
        "mov r10w, dx",
        "mov dx, 0x3F8",
        "mov al, 'Y'",
        "out dx, al",
        "mov dx, r10w",
        out("r10") _,
        options(nostack, preserves_flags),
    );

    // Initialise the legacy 8259 PIC so hardware IRQs (keyboard, timer, …)
    // are actually delivered to the CPU.  IRQ 0..7 map to IDT vectors 32..39,
    // IRQ 8..15 map to 40..47.  We remap them away from the exception range
    // (0..31) but keep every IRQ masked.  Boot-time handlers (timer,
    // keyboard) depend on the scheduler and device registry, which are not
    // ready yet; `start_interrupts` unmasks them once those are initialised.
    pic_init();
    // Leave IF=0: the caller enables interrupts after kernel init.
}

/// Load the IDT installed by the boot CPU without modifying it or the PIC.
///
/// # Safety
/// The boot CPU must have finished building the IDT and the local GDT must
/// already contain the kernel code selector.
pub unsafe fn load_idt() {
    let ptr = IdtPointer {
        limit: (size_of::<IdtTable>() - 1) as u16,
        base: (&raw const IDT) as u64,
    };
    lidt(&ptr as *const _ as u64);
}

/// Initialise the two 8259 PIC chips (master + slave).
///
/// Programs ICW1..ICW4 so IRQs map to IDT vectors 32..47, then masks all
/// IRQs.  Unmasking is deferred to [`start_interrupts`] because the timer
/// and keyboard handlers need the scheduler and device registry.
fn pic_init() {
    // ICW1: init, edge-triggered, ICW4 needed.
    crate::x86_64::outb(0x20, 0x11);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA0, 0x11);
    crate::x86_64::io_delay();

    // ICW2: vector offset — master 32, slave 40.
    crate::x86_64::outb(0x21, 0x20);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0x28);
    crate::x86_64::io_delay();

    // ICW3: master slave on IRQ2; slave cascade identity 2.
    crate::x86_64::outb(0x21, 0x04);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0x02);
    crate::x86_64::io_delay();

    // ICW4: 8086/88 mode.
    crate::x86_64::outb(0x21, 0x01);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0x01);
    crate::x86_64::io_delay();

    // OCW1: mask every IRQ (master 0xFF, slave 0xFF) during boot.
    crate::x86_64::outb(0x21, 0xFF);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0xFF);
    crate::x86_64::io_delay();
}

/// Enable boot-time hardware IRQs and maskable interrupts.
///
/// Unmasks IRQ0 (timer) and IRQ1 (keyboard) on the master PIC and executes
/// `sti`.  Must be called only after the scheduler and device registry are
/// initialised, because both handlers dereference them.
pub fn start_interrupts() {
    crate::x86_64::outb(0x43, 0x34);
    let count = (1_193_182 / crate::x86_64::timer::HZ) as u16;
    crate::x86_64::outb(0x40, count as u8);
    crate::x86_64::outb(0x40, (count >> 8) as u8);
    crate::x86_64::outb(0x21, 0xFC); // unmask IRQ0 + IRQ1
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0xFF); // slave remains masked
    crate::x86_64::io_delay();
    crate::x86_64::sti();
}

extern "C" {
    /// Assembly syscall entry stub defined in `idt_asm.S`.
    static syscall_stub_entry: u8;
}

//! Interrupt Descriptor Table for x86_64
//!
//! Each `IdtEntry` describes one of the 256 possible entries (0..=255).
//! In the boot path we install a single "spurious" handler at every vector
//! that:
//!   * prints the vector number on the VGA console (if available) so a
//!     fault is visible to the user;
//!   * halts the CPU (with interrupts disabled) so we never silently return
//!     from an unknown exception.
//!
//! The function is written in a single body and parameterised by the
//! exception number via an entry stub (see `isr_stubs` further down). Each
//! stub pushes the vector number, then jumps to `default_exception_handler`.

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
/// Must be called *after* the GDT is loaded and segment registers are
/// reloaded to the kernel selectors.
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
    for i in 0..256 {
        let entry = &mut *IDT.entries.get_unchecked_mut(i);
        *entry = IdtEntry::null();
    }
    unsafe { dbg(b'3'); }

    unsafe { dbg(b'4'); }
    // Install our handlers. 0x8E = present, DPL 0, 64-bit interrupt gate.
    for (vector, handler) in vector_stubs.iter().copied() {
        let entry = &mut *IDT.entries.get_unchecked_mut(vector as usize);
        entry.set_handler(handler, SEL_KERNEL_CS, 0, 0x8E);
    }
    unsafe { dbg(b'5'); }

    // Install syscall handler at vector 0x80 (128)
    // 0xEF = present, DPL 3, 64-bit trap gate.  DPL 3 is required because
    // `int 0x80` is issued from ring 3; 0x8F would set DPL 0 and cause #GP.
    let syscall_handler = &syscall_stub_entry as *const u8 as u64;
    let syscall_entry = &mut *IDT.entries.get_unchecked_mut(0x80);
    syscall_entry.set_handler(syscall_handler, SEL_KERNEL_CS, 0, 0xEF);

    unsafe { dbg(b'6'); }
    let ptr = IdtPointer {
        limit: ((size_of::<IdtEntry>() * 256) - 1) as u16,
        base: &IDT as *const _ as u64,
    };
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
    lidt(&ptr as *const _ as u64);
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
    // (0..31) and unmask IRQ0 (timer) and IRQ1 (keyboard).
    pic_init();

    // Enable maskable interrupts so the installed handlers can run.
    crate::x86_64::sti();
}

/// Initialise the two 8259 PIC chips (master + slave).
///
/// Programs ICW1..ICW4 so IRQs map to IDT vectors 32..47, then masks all
/// IRQs except IRQ0 (timer) and IRQ1 (keyboard).
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

    // OCW1: mask all, then unmask IRQ0 (timer) and IRQ1 (keyboard) on master.
    // Master mask: ~(1<<0 | 1<<1) = 0xFC; slave: mask all = 0xFF.
    crate::x86_64::outb(0x21, 0xFC);
    crate::x86_64::io_delay();
    crate::x86_64::outb(0xA1, 0xFF);
    crate::x86_64::io_delay();
}

/// Direct COM1 hex printout helper.
fn arch_log(s: &[u8]) {
    for &b in s {
        unsafe {
            // Preserve RDX: the exception handler receives `rip` in RDX and
            // must not overwrite it while emitting diagnostics.  R10 is a
            // scratch register used only inside the asm block.
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
    }
}

fn arch_log_hex(prefix: &[u8], val: u64) {
    arch_log(prefix);
    let hex = b"0123456789abcdef";
    let mut shift = 60;
    while (val >> shift) & 0xf == 0 && shift > 0 { shift -= 4; }
    loop {
        let nibble = ((val >> shift) & 0xf) as usize;
        arch_log(&[hex[nibble]]);
        if shift == 0 { break; }
        shift -= 4;
    }
}

/// Common exception handler body (defined in idt_asm.S).
///
/// This is defined in pure assembly (idt_asm.S) so we can use local labels
/// for the serial-print loop. It clears DR6/DR7, prints the exception
/// vector/error_code/rip in hex, and halts.
#[no_mangle]
pub unsafe extern "C" fn default_exception_handler(
    vector: u64, error_code: u64, rip: u64
) -> ! {
    arch_log(b"\n[FAULT] vector=");
    arch_log_dec(vector);
    arch_log(b" error=");
    arch_log_dec(error_code);
    arch_log_hex(b" rip=", rip);
    arch_log(b"\n");
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)); }
    }
}

/// Decimal print of a u64 (lowercased, no leading zeros).
fn arch_log_dec(mut v: u64) {
    if v == 0 {
        arch_log(b"0");
        return;
    }
    let mut buf = [0u8; 24];
    let mut len = 0;
    while v > 0 && len < buf.len() {
        buf[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut i = len;
    while i > 0 {
        i -= 1;
        arch_log(&[buf[i]]);
    }
}

/// Hex print of a u64 (no leading zeros except for one nibble if zero).
fn arch_log_hex_simple(mut v: u64) {
    let hex = b"0123456789abcdef";
    if v == 0 {
        arch_log(b"0");
        return;
    }
    let mut started = false;
    for shift in (0..16).rev().map(|i| i * 4) {
        let nibble = ((v >> shift) & 0xf) as usize;
        if started || nibble != 0 {
            arch_log(&[hex[nibble]]);
            started = true;
        }
    }
}

/// Type of the optional serial-output callback installed by the kernel's
/// console/serial driver.
type SerialOut = unsafe fn(&[u8]);

/// Global serial-output sink. Set by the console driver (or left as `None`).
static mut SERIAL_OUT: Option<SerialOut> = None;

/// Register a callback that receives bytes to emit on the serial port.
/// The kernel's serial driver calls this once during boot so exception
/// faults are visible to the user even when the VGA console is not yet
/// initialised (e.g. early page-fault before VGA map is set up).
pub fn set_serial_output(cb: SerialOut) {
    unsafe { SERIAL_OUT = Some(cb) };
}

fn emit_serial(buf: &[u8]) {
    // SAFETY: SERIAL_OUT is only ever written by `set_serial_output`,
    // which runs after the IDT is installed but before interrupts are
    // enabled, so we never race here.
    unsafe {
        if let Some(cb) = SERIAL_OUT {
            cb(buf);
        }
    }
}

// ============================================================================
// Syscall Handler (Minimal boot-time implementation)
// ============================================================================

/// Syscall number constants (must match init's syscall.rs)
const SYS_WRITE: usize = 1;
const SYS_READ: usize = 0;
const SYS_EXIT: usize = 6;
const SYS_GETPID: usize = 10;
const SYS_YIELD: usize = 11;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_STAT: usize = 4;
const SYS_BRK: usize = 5;
const SYS_FORK: usize = 7;
const SYS_EXEC: usize = 8;
const SYS_WAIT: usize = 9;
const SYS_DUP: usize = 12;
const SYS_CHDIR: usize = 14;
const SYS_LIST: usize = 15;
const SYS_PUTS: usize = 16;

/// Emit a string to serial port
fn emit_str(s: &[u8]) {
    emit_serial(s);
}

extern "C" {
    /// Provided by the kernel crate (`trap.rs`).  The architecture crate
    /// cannot depend on the kernel crate directly, so the symbol is declared
    /// externally and resolved when the kernel binary is linked.
    fn kernel_syscall_from_user(num: u64, a0: u64, a1: u64, a2: u64, frame_ptr: u64) -> i64;

    /// Kernel hardware-interrupt dispatcher.  Declared extern so the
    /// architecture crate does not need to depend on the kernel crate.
    fn kernel_interrupt_from_user(vector: u64);

    /// Assembly syscall entry stub defined in `idt_asm.S`.
    static syscall_stub_entry: u8;
}

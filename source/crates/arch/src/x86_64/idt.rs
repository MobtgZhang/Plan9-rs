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
            "mov dx, 0x3F8; mov al, {v}; out dx, al",
            v = in(reg_byte) b,
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
    // Use a trap gate (0x8F = present, DPL 3, 64-bit trap gate) so user mode can call it
    let syscall_handler = syscall_stub_entry as u64;
    let syscall_entry = &mut *IDT.entries.get_unchecked_mut(0x80);
    syscall_entry.set_handler(syscall_handler, SEL_KERNEL_CS, 0, 0x8F);

    unsafe { dbg(b'6'); }
    let ptr = IdtPointer {
        limit: ((size_of::<IdtEntry>() * 256) - 1) as u16,
        base: &IDT as *const _ as u64,
    };
    unsafe { dbg(b'7'); }
    // MARKER: 'X' right before lidt
    core::arch::asm!("mov dx, 0x3F8; mov al, 'X'; out dx, al", options(nostack, preserves_flags));
    lidt(&ptr as *const _ as u64);
    // MARKER: 'Y' right after lidt (if we reach here, lidt succeeded)
    core::arch::asm!("mov dx, 0x3F8; mov al, 'Y'; out dx, al", options(nostack, preserves_flags));
}

/// Direct COM1 hex printout helper.
fn arch_log(s: &[u8]) {
    for &b in s {
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8",
                "mov al, {v}",
                "out dx, al",
                v = in(reg_byte) b,
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
    _vector: u64, _error_code: u64, _rip: u64
) -> ! {
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

/// Handle a minimal set of syscalls during boot.
/// This is a fallback handler that works without the full kernel infrastructure.
fn handle_syscall(syscall_num: usize, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    match syscall_num {
        SYS_WRITE => {
            // write(fd, buf, count)
            let fd = arg0 as i64;
            let buf = arg1 as *const u8;
            let count = arg2 as usize;
            if fd == 1 || fd == 2 {
                // Write to serial console
                let slice = unsafe { core::slice::from_raw_parts(buf, count) };
                emit_str(slice);
                count as i64
            } else {
                -1 // Unsupported fd
            }
        }
        SYS_READ => {
            // read(fd, buf, count) - no input in boot mode, return EOF
            let _fd = arg0 as i64;
            let _buf = arg1 as *mut u8;
            let _count = arg2 as usize;
            0 // Return EOF (no input available)
        }
        SYS_EXIT => {
            // exit(code)
            let code = arg0 as i32;
            emit_str(b"\n[init] exiting with code ");
            emit_str(itoa(arg0 as u64));
            emit_str(b"\n[boot] halting\n");
            loop {
                unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)); }
            }
        }
        SYS_GETPID => {
            1 // Return pid 1 for init
        }
        SYS_YIELD => {
            0
        }
        SYS_PUTS => {
            // puts(buf) - write null-terminated string
            let buf = arg0 as *const u8;
            let mut len = 0usize;
            unsafe {
                while *buf.add(len) != 0 && len < 4096 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(buf, len);
                emit_str(slice);
            }
            len as i64
        }
        SYS_OPEN | SYS_CLOSE | SYS_STAT | SYS_BRK | SYS_FORK |
        SYS_EXEC | SYS_WAIT | SYS_DUP | SYS_CHDIR | SYS_LIST => {
            // These are not supported in boot mode
            emit_str(b"[syscall] syscall ");
            emit_str(itoa(syscall_num as u64));
            emit_str(b" not implemented\n");
            -1
        }
        _ => {
            emit_str(b"[syscall] unknown ");
            emit_str(itoa(syscall_num as u64));
            emit_str(b"\n");
            -1
        }
    }
}

/// Convert u64 to decimal string (simple implementation)
fn itoa(mut v: u64) -> &'static [u8] {
    static mut BUF: [u8; 32] = [0u8; 32];
    if v == 0 {
        return b"0";
    }
    let mut len = 0usize;
    while v > 0 && len < 31 {
        unsafe {
            BUF[30 - len] = b'0' + (v % 10) as u8;
        }
        v /= 10;
        len += 1;
    }
    unsafe {
        &BUF[31 - len..31]
    }
}

/// Syscall handler wrapper that matches the calling convention
unsafe fn syscall_handler_inner(num: usize, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    handle_syscall(num, arg0, arg1, arg2)
}

/// Syscall entry stub.
///
/// Reads the syscall number and up to three arguments from the user
/// registers (Linux x86_64 convention: rax=num, rdi/rsi/rdx=args),
/// calls `handle_syscall`, then returns to user mode via `iretq` with
/// the result in `rax`.
///
/// # Safety
/// Called from user mode via `int 0x80`.
#[no_mangle]
pub unsafe extern "C" fn syscall_stub_entry() {
    // Linux x86_64 syscall ABI:
    //   rax = syscall number, rdi/rsi/rdx = args 0..2.
    // r10/r8/r9 are args 3..4 in the syscall ABI but we don't need
    // them for the initial syscall set.
    let (num, arg0, arg1, arg2): (usize, u64, u64, u64);
    core::arch::asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov {num}, rax",
        "mov {arg0}, rdi",
        "mov {arg1}, rsi",
        "mov {arg2}, rdx",
        num  = out(reg) num,
        arg0 = out(reg) arg0,
        arg1 = out(reg) arg1,
        arg2 = out(reg) arg2,
        options(nostack, preserves_flags),
    );

    let ret = handle_syscall(num, arg0, arg1, arg2);

    // Return to user mode via iretq with rax = syscall result.
    core::arch::asm!(
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "mov rax, {ret}",
        "iretq",
        ret = in(reg) ret,
        options(nostack, preserves_flags),
    );
    core::hint::unreachable_unchecked();
}

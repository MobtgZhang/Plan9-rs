//! Minimal serial-port driver used during early boot.
//!
//! Just enough to push bytes out of COM1 (0x3F8) so that QEMU's `-serial
//! file:…` log captures anything we print before the VGA console is
//! available. We don't enable interrupts — that's done later by the full
//! UART device driver in `devuart.rs`.
//!
//! Safe to call before paging is enabled: every access is to a fixed
//! MMIO port, not a virtual address.

use core::sync::atomic::{AtomicBool, Ordering};

const COM1: u16 = 0x3F8;

/// `true` once `init()` has configured the port.
static READY: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags),
    );
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") val,
        options(nostack, preserves_flags),
    );
    val
}

/// Wait until the transmit buffer is empty by polling LSR bit 5.
unsafe fn wait_tx_ready() {
    for _ in 0..0x10000 {
        if inb(COM1 + 5) & 0x20 != 0 { return; }
    }
}

/// Initialise COM1 at 115200 8N1, no flow control.
pub fn init() {
    unsafe {
        // Simple outb directly to test serial is working
        // This writes 'A' to COM1 data port
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x41",
            "out dx, al",
            options(nostack, preserves_flags),
        );
    }
    unsafe {
        // Disable all interrupts.
        outb(COM1 + 1, 0x00);
        // Enable DLAB so we can set the baud-rate divisor.
        outb(COM1 + 3, 0x80);
        // Divisor = 1 -> 115200 baud with 1.8432 MHz crystal.
        outb(COM1 + 0, 0x01);
        outb(COM1 + 1, 0x00);
        // 8 bits, no parity, one stop bit.
        outb(COM1 + 3, 0x03);
        // Enable FIFO, clear buffers.
        outb(COM1 + 2, 0xC7);
        // Enable data-ready + tx-empty interrupts (for later).
        outb(COM1 + 4, 0x0B);
    }
    READY.store(true, Ordering::SeqCst);
}

/// Write a single byte to COM1.
pub fn putc(c: u8) {
    unsafe {
        wait_tx_ready();
        outb(COM1, c);
    }
}

/// Write a string to COM1.
pub fn puts(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            putc(b'\r');
            putc(b'\n');
        } else {
            putc(b);
        }
    }
}

/// Direct output of a `&[u8]` to COM1, bypassing the iterator infrastructure.
/// Useful during very early boot where the iterator state machine appears to
/// hang.
pub fn put_bytes(b: &[u8]) {
    let len = b.len();
    let ptr = b.as_ptr();
    let port: u16 = 0x3F8;
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "xor ecx, ecx",
            "cmp rcx, {len}",
            "je 9f",
            "2:",
            "mov al, byte ptr [rdi + rcx]",
            "out dx, al",
            "inc rcx",
            "cmp rcx, {len}",
            "jne 2b",
            "9:",
            len = in(reg) len as u64,
            in("rdi") ptr,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            options(preserves_flags),
        );
    }
}

/// Print a u64 in 16 lowercase hex digits.
pub fn put_hex_u64(v: u64) {
    // Emit one digit at a time directly, building the output via
    // repeated single-byte put_bytes calls. This avoids any
    // array-bound-check panics in early boot.
    let mut shift: u32 = 60;
    loop {
        let nibble = ((v >> shift) & 0xF) as u8;
        let ch: u8;
        if nibble < 10 {
            ch = 0x30 + nibble;
        } else {
            ch = 0x61 + nibble - 10;
        }
        let one = [ch; 1];
        put_bytes(&one);
        if shift == 0 { break; }
        shift -= 4;
    }
}

/// Print a u32 in 8 lowercase hex digits.
pub fn put_hex_u32(v: u32) {
    let mut shift: u32 = 28;
    loop {
        let nibble = ((v >> shift) & 0xF) as u8;
        let ch: u8;
        if nibble < 10 {
            ch = 0x30 + nibble;
        } else {
            ch = 0x61 + nibble - 10;
        }
        let one = [ch; 1];
        put_bytes(&one);
        if shift == 0 { break; }
        shift -= 4;
    }
}

/// Type alias matching what `arch::x86_64::idt::set_serial_output` expects.
type SerialOut = unsafe fn(&[u8]);

/// Adapter that lets the IDT exception handler emit messages via this
/// driver. Installed by `register_idt_output` below.
unsafe fn idt_output(buf: &[u8]) {
    for &b in buf {
        putc(b);
    }
}

/// Install the IDT serial-output sink. Call this after `init()` and after
/// the IDT is loaded.
pub fn register_idt_output() {
    crate::plan9_arch::x86_64::idt::set_serial_output(idt_output);
}
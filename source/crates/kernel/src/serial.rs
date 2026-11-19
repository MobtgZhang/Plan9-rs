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

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    crate::plan9_arch::hal::io::outb(port, val)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    crate::plan9_arch::hal::io::inb(port)
}

/// Wait until the transmit buffer is empty by polling LSR bit 5.
#[cfg(target_arch = "x86_64")]
unsafe fn wait_tx_ready() {
    for _ in 0..0x10000 {
        if inb(COM1 + 5) & 0x20 != 0 { return; }
    }
}
/// Initialise COM1 at 115200 8N1, no flow control.
#[cfg(target_arch = "x86_64")]
pub fn init() {
    crate::plan9_arch::hal::io::outb(COM1, b'A');
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

/// Non-x86_64: route through the architecture console (PL011, 16550 MMIO…).
#[cfg(not(target_arch = "x86_64"))]
pub fn init() {
    crate::plan9_arch::hal::console::init();
    READY.store(true, Ordering::SeqCst);
}

/// Non-x86_64 console byte output.
#[cfg(not(target_arch = "x86_64"))]
pub fn putc(c: u8) {
    crate::plan9_arch::hal::console::putc(c);
}

/// Write a single byte to COM1.
#[cfg(target_arch = "x86_64")]
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

/// Direct output of a `&[u8]` to COM1.
///
/// A plain per-byte loop avoids the inline-asm length operand being clobbered
/// by the `mov dx, 0x3F8` used for the port.  `putc` has a bounded TX-empty
/// wait, so early boot output cannot wedge.
pub fn put_bytes(b: &[u8]) {
    let len = b.len();
    let mut i = 0;
    while i < len {
        putc(b[i]);
        i += 1;
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

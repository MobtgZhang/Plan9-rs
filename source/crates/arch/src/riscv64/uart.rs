//! RISC-V early console — 16550A UART on the QEMU `virt` machine.
//!
//! QEMU's riscv64 virt machine places a byte-wide 16550A at physical
//! 0x1000_0000 with a 1-byte register stride.

/// Physical base of the 16550A on QEMU's virt machine.
pub const UART0_BASE: u64 = 0x1000_0000;

/// Register offsets (byte stride)
mod reg {
    pub const RBR: u64 = 0x00; // Receive buffer (read) / THR (write)
    pub const IER: u64 = 0x01; // Interrupt enable
    pub const FCR: u64 = 0x02; // FIFO control
    pub const LCR: u64 = 0x03; // Line control
    pub const LSR: u64 = 0x05; // Line status
}

/// Line status bits
mod lsr {
    pub const RX_READY: u8 = 1 << 0; // Data ready
    pub const TX_EMPTY: u8 = 1 << 5; // THR empty
}

#[inline(always)]
unsafe fn read(off: u64) -> u8 {
    ((UART0_BASE + off) as *const u8).read_volatile()
}

#[inline(always)]
unsafe fn write(off: u64, val: u8) {
    ((UART0_BASE + off) as *mut u8).write_volatile(val);
}

/// Configure the UART: 115200 8N1, FIFOs on, no interrupts. QEMU's
/// 16550A ignores divisor programming, but real hardware needs it; the
/// input clock is assumed to be 1.8432 MHz (divisor 1).
pub fn init() {
    unsafe {
        write(reg::IER, 0x00); // No interrupts
        write(reg::LCR, 0x03); // 8 data bits, 1 stop, no parity (DLAB=0)
        write(reg::FCR, 0x07); // Enable + clear FIFOs, 1-byte threshold
    }
}

/// Transmit one byte (blocking).
pub fn putc(b: u8) {
    unsafe {
        while read(reg::LSR) & lsr::TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
        write(reg::RBR, b);
    }
}

/// Transmit a slice of bytes.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// Receive one byte if available (non-blocking).
pub fn getc() -> Option<u8> {
    unsafe {
        if read(reg::LSR) & lsr::RX_READY != 0 {
            Some(read(reg::RBR))
        } else {
            None
        }
    }
}

/// Wait until the transmitter is empty.
pub fn flush() {
    unsafe {
        while read(reg::LSR) & lsr::TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
    }
}

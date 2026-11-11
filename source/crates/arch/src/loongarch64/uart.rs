//! LoongArch early console — 16550A UART on the QEMU `virt` machine.
//!
//! The LoongArch virt machine maps a byte-wide 16550A at physical
//! 0x1FE0_01E0 (8-bit registers, 1-byte stride). After `paging_init`
//! enables paged translation (CRMD.PG=1), physical addresses are no
//! longer directly addressable, so all MMIO goes through the uncached
//! direct-map window (DMW1: VA = 0x9000_0000_0000_0000 | PA). The boot
//! assembly (boot.S) installs both DMW windows before jumping into the
//! cached window, so this driver can always use the windowed address.

/// Uncached direct-map window base (DMW1, VSEG=9).
pub const MMIO_WINDOW: u64 = 0x9000_0000_0000_0000;

/// Physical base of the 16550A (QEMU loongarch64 virt).
pub const UART0_PHYS: u64 = 0x1FE0_01E0;

/// Virtual (windowed) base used for all register access.
pub const UART0_BASE: u64 = MMIO_WINDOW | UART0_PHYS;

/// Register offsets (byte stride)
mod reg {
    pub const RBR: u64 = 0x00; // Receive buffer (read) / THR (write)
    pub const IER: u64 = 0x01; // Interrupt enable
    pub const FCR: u64 = 0x02; // FIFO control
    pub const LCR: u64 = 0x03; // Line control
    pub const LSR: u64 = 0x05; // Line status
}

mod lsr {
    pub const RX_READY: u8 = 1 << 0;
    pub const TX_EMPTY: u8 = 1 << 5;
}

#[inline(always)]
unsafe fn read(off: u64) -> u8 {
    ((UART0_BASE + off) as *const u8).read_volatile()
}

#[inline(always)]
unsafe fn write(off: u64, val: u8) {
    ((UART0_BASE + off) as *mut u8).write_volatile(val);
}

/// Configure the UART: FIFOs on, 8N1, no interrupts. QEMU ignores the
/// divisor; the reference clock is 1.8432 MHz (divisor 1).
pub fn init() {
    unsafe {
        write(reg::IER, 0x00);
        write(reg::LCR, 0x03); // 8N1, DLAB=0
        write(reg::FCR, 0x07); // Enable + clear FIFOs
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

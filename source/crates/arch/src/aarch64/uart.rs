//! AArch64 early console — PL011 (ARM PrimeCell) UART driver.
//!
//! QEMU's `virt` machine places a PL011 at physical 0x0900_0000 with a
//! 32-bit register stride. The same layout is used by the ARM Versatile
//! Express boards, so this driver also covers most emulated ARM hardware.
//!
//! All low-level MMIO accesses for the whole kernel funnel through here
//! (or through `super::mmio`) so no assembly or raw pointer arithmetic is
//! needed outside the `plan9_arch` crate.

/// Physical base of the PL011 on QEMU's virt machine.
pub const UART0_BASE: u64 = 0x0900_0000;

/// PL011 register offsets (32-bit, byte addressable with stride 4)
mod reg {
    pub const DR: u64 = 0x000;      // Data register
    pub const RSR: u64 = 0x004;     // Receive status / error clear
    pub const FR: u64 = 0x018;      // Flag register
    pub const IBRD: u64 = 0x024;    // Integer baud rate divisor
    pub const FBRD: u64 = 0x028;    // Fractional baud rate divisor
    pub const LCR_H: u64 = 0x02C;   // Line control register
    pub const CR: u64 = 0x030;      // Control register
    pub const IFLS: u64 = 0x034;    // Interrupt FIFO level select
    pub const IMSC: u64 = 0x038;    // Interrupt mask set/clear
    pub const ICR: u64 = 0x044;     // Interrupt clear register
}

/// Flag register bits
mod fr {
    pub const RXFE: u32 = 1 << 4;   // Receive FIFO empty
    pub const TXFF: u32 = 1 << 5;   // Transmit FIFO full
    pub const BUSY: u32 = 1 << 3;   // UART busy
}

/// Configured baud rate. QEMU's model ignores the divisors, but real
/// hardware (and the QEMU "virt" with a serial-attached PL011 model that
/// honours timing) wants 115200 8N1 from a 24 MHz clock.
const CLK_HZ: u32 = 24_000_000;
const BAUD: u32 = 115_200;

#[inline(always)]
unsafe fn read(off: u64) -> u32 {
    let ptr = (UART0_BASE + off) as *const u32;
    ptr.read_volatile()
}

#[inline(always)]
unsafe fn write(off: u64, val: u32) {
    let ptr = (UART0_BASE + off) as *mut u32;
    ptr.write_volatile(val);
}

/// Configure the PL011 for 115200 8N1, FIFOs on, all interrupts masked.
pub fn init() {
    unsafe {
        // Disable the UART while reconfiguring.
        write(reg::CR, 0);
        // Mask all interrupts and clear pending ones.
        write(reg::IMSC, 0);
        write(reg::ICR, 0x7FF);
        // Divisors for 115200 from 24 MHz: IBRD=13, FBRD=1.
        //   div = CLK / (16 * BAUD) = 13.0209 → IBRD = 13, FBRD = round(0.0209 * 64) = 1
        let rem = (CLK_HZ % (16 * BAUD)) as u64;
        let denom = (16 * BAUD) as u64;
        write(reg::IBRD, (CLK_HZ / (16 * BAUD)) as u32);
        write(reg::FBRD, ((rem * 64 + denom / 2) / denom) as u32);
        // LCR_H: 8 data bits (0), FIFO enable (4), 1 stop bit, no parity.
        write(reg::LCR_H, (1 << 4) | (3 << 5));
        // CR: UART enable, TX enable, RX enable.
        write(reg::CR, (1 << 0) | (1 << 8) | (1 << 9));
    }
}

/// Transmit one byte (blocking until the TX FIFO has room).
pub fn putc(b: u8) {
    unsafe {
        while read(reg::FR) & fr::TXFF != 0 {
            core::hint::spin_loop();
        }
        write(reg::DR, b as u32);
    }
}

/// Transmit a slice of bytes.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        // CRLF translation like the x86 serial console.
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// Receive one byte if available (non-blocking).
pub fn getc() -> Option<u8> {
    unsafe {
        if read(reg::FR) & fr::RXFE != 0 {
            None
        } else {
            Some(read(reg::DR) as u8)
        }
    }
}

/// Block until the transmitter is completely idle.
pub fn flush() {
    unsafe {
        while read(reg::FR) & fr::BUSY != 0 {
            core::hint::spin_loop();
        }
    }
}

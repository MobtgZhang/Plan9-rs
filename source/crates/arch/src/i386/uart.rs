//! i386 early console — 16550A port-I/O UART at COM1.
#![allow(dead_code)]

const COM1: u16 = 0x3F8;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("outb {v}, {p}", v = in(reg) val, p = in(reg) port, options(nostack));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("inb {p}, {v}", v = out(reg) v, p = in(reg) port, options(nostack));
    v
}

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1 + 0, 12);
        outb(COM1 + 1, 0);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xC7);
        outb(COM1 + 4, 0x0B);
    }
}

pub fn putc(b: u8) {
    unsafe {
        for _ in 0..0x10000 {
            if inb(COM1 + 5) & 0x20 != 0 { break; }
        }
        outb(COM1, b);
    }
}

pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' { putc(b'\r'); }
        putc(b);
    }
}

pub fn getc() -> Option<u8> {
    unsafe {
        if inb(COM1 + 5) & 1 != 0 { Some(inb(COM1)) } else { None }
    }
}

pub fn flush() {}

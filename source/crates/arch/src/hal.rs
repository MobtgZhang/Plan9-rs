//! Architecture-neutral hardware facade.
//!
//! The kernel and libraries program the machine exclusively through
//! these modules; each re-exports the per-architecture implementation
//! chosen by the build target. No assembly or privileged instruction
//! may appear outside the `plan9-arch` crate.

// ============================================================================
// boot — early_init / paging_init dispatch
// ============================================================================

pub mod boot {
    /// Early architecture bring-up (console, timer, trait registry).
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::early_init;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::early_init;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::early_init;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::early_init;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::early_init;

    /// Paging bring-up (root tables, direct map, MMU enable).
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::paging_init;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::paging_init;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::paging_init;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::paging_init;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::paging_init;
}

// ============================================================================
// paging — page-table types and helpers
// ============================================================================

pub mod paging {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::paging::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::paging::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::paging::*;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::paging::*;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::paging::*;
}

// ============================================================================
// mmu — root-table switching, TLB maintenance, fault info
// ============================================================================

pub mod mmu {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::mmu::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::mmu::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::mmu::*;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::mmu::*;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::mmu::*;
}

// ============================================================================
// cpu — interrupt control, halt, CPU-id registers
// ============================================================================

pub mod cpu {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::{cli, hlt, interrupts_enabled, sti};
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::cpu::{
        cli, disable_interrupts, enable_interrupts, hlt, interrupts_enabled, sti,
    };
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::cpu::{
        cli, disable_interrupts, enable_interrupts, hlt, interrupts_enabled, sti,
    };
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::cpu::{
        cli, disable_interrupts, enable_interrupts, hlt, interrupts_enabled, sti,
    };
    #[cfg(target_arch = "x86")]
    pub use crate::i386::cpu::{
        cli, disable_interrupts, enable_interrupts, hlt, interrupts_enabled, sti,
    };

    /// Aliases matching the x86 naming used by kernel call sites.
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::{cli as disable_interrupts, sti as enable_interrupts};

    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::{cr0_read, cr2_read, cr3_read, cr4_read, write_tsc_aux};

    /// CR-register reads are x86-only; other architectures report 0.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cr0_read() -> u64 { 0 }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cr2_read() -> u64 { super::mmu::cr2_read() }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cr3_read() -> u64 { super::mmu::cr3_read().as_u64() }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cr4_read() -> u64 { 0 }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_tsc_aux(_v: u32) {}
}

// ============================================================================
// io — port I/O (x86 only; MMIO platforms must use device drivers)
// ============================================================================

pub mod io {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::{inb, inl, inw, io_delay, outb, outl, outw, wait};

    /// Port I/O does not exist on MMIO-only architectures; these stubs
    /// trap loudly so that accidental x86 device code on other targets
    /// is caught immediately.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn inb(_port: u16) -> u8 {
        panic!("io::inb called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn outb(_port: u16, _val: u8) {
        panic!("io::outb called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn inw(_port: u16) -> u16 {
        panic!("io::inw called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn outw(_port: u16, _val: u16) {
        panic!("io::outw called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn inl(_port: u16) -> u32 {
        panic!("io::inl called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn outl(_port: u16, _val: u32) {
        panic!("io::outl called on a non-port-I/O architecture")
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn io_delay() {}

    /// Short busy-wait (x86 `wait`); on other architectures a spin.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn wait() {
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// console — early UART console (the only pre-driver output path)
// ============================================================================

pub mod console {
    #[cfg(target_arch = "x86_64")]
    pub mod x86_console_impl {
        use crate::x86_64::{inb, outb};

        const COM1: u16 = 0x3F8;
        unsafe fn wait_tx() {
            for _ in 0..0x10000 {
                if inb(COM1 + 5) & 0x20 != 0 {
                    return;
                }
            }
        }
        pub fn init() {
            unsafe {
                outb(COM1 + 1, 0x00); // no interrupts
                outb(COM1 + 3, 0x80); // DLAB on
                outb(COM1 + 0, 12);   // 9600 baud divisor low
                outb(COM1 + 1, 0);    // divisor high
                outb(COM1 + 3, 0x03); // 8N1
                outb(COM1 + 2, 0xC7); // FIFO
                outb(COM1 + 4, 0x0B); // modem
            }
        }
        pub fn putc(b: u8) {
            unsafe {
                wait_tx();
                outb(COM1, b);
            }
        }
        pub fn write_bytes(bytes: &[u8]) {
            for &b in bytes {
                if b == b'\n' {
                    putc(b'\r');
                }
                putc(b);
            }
        }
        pub fn getc() -> Option<u8> {
            unsafe {
                if inb(COM1 + 5) & 1 != 0 {
                    Some(inb(COM1))
                } else {
                    None
                }
            }
        }
        pub fn flush() {}
    }

    #[cfg(target_arch = "x86_64")]
    pub use x86_console_impl::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::uart::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::uart::*;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::uart::*;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::uart::*;
}

// ============================================================================
// context — scheduler setjmp/longjmp context switching
// ============================================================================

pub mod context {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::context::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::context::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::context::*;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::context::*;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::context::*;
}

// ============================================================================
// switch_to_user — kernel → ring-3/user-mode entry
// ============================================================================

pub mod switch_to_user {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::switch_to_user::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::aarch64::switch_to_user::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::riscv64::switch_to_user::*;
    #[cfg(target_arch = "loongarch64")]
    pub use crate::loongarch64::switch_to_user::*;
    #[cfg(target_arch = "x86")]
    pub use crate::i386::switch_to_user::*;
}

// ============================================================================
// x86-only subsystems (gdt/idt/smp) — empty on other architectures
// ============================================================================

pub mod gdt {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::gdt::*;
}

pub mod idt {
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::idt::*;
}

pub mod smp {
    /// AP trampoline code blob (x86_64 INIT-SIPI bring-up).
    #[cfg(target_arch = "x86_64")]
    pub use crate::x86_64::smp::AP_TRAMPOLINE;
}

// ============================================================================
// Top-level convenience re-exports — the kernel previously reached these
// through `plan9_arch::x86_64::` directly.
// ============================================================================

pub use cpu::{cli, hlt, sti};
pub use io::{inb, inl, inw, outb, outl, outw, wait};
pub use cpu::{cr0_read, cr2_read, cr3_read, cr4_read, write_tsc_aux};

// ============================================================================
// Kernel-half cloning — per-process address spaces must include the
// kernel's own mappings (x86 clones PML4 256–511; others clone their
// identity blocks).
// ============================================================================

pub fn copy_kernel_half(dst_root: u64, src_root: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let dst = crate::x86_64::paging::phys_to_virt(
            plan9_common::types::PhysAddr::new(dst_root),
        );
        let src = crate::x86_64::paging::phys_to_virt(
            plan9_common::types::PhysAddr::new(src_root),
        );
        for i in 256..512usize {
            let e = unsafe { core::ptr::read((src.as_u64() as *const u64).add(i)) };
            if e != 0 {
                unsafe { core::ptr::write((dst.as_u64() as *mut u64).add(i), e) };
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    crate::aarch64::copy_kernel_half(dst_root, src_root);
    #[cfg(target_arch = "riscv64")]
    crate::riscv64::copy_kernel_half(dst_root, src_root);
    #[cfg(target_arch = "loongarch64")]
    crate::loongarch64::copy_kernel_half(dst_root, src_root);
    #[cfg(target_arch = "x86")]
    let _ = (dst_root, src_root);
}

// ============================================================================
// Frame-allocator registration — paging code needs frames for page
// tables; the kernel registers its allocator here once the heap is up.
// ============================================================================

#[cfg(not(target_arch = "x86_64"))]
pub fn register_frame_allocator(hook: fn() -> Option<u64>) {
    #[cfg(target_arch = "aarch64")]
    unsafe { crate::aarch64::register_frame_allocator(hook) };
    #[cfg(target_arch = "riscv64")]
    unsafe { crate::riscv64::register_frame_allocator(hook) };
    #[cfg(target_arch = "loongarch64")]
    unsafe { crate::loongarch64::register_frame_allocator(hook) };
    #[cfg(target_arch = "x86")]
    let _ = hook;
}

/// Set the trap-frame page consumed by the next user-mode switch.
#[cfg(not(target_arch = "x86_64"))]
pub fn set_switch_frame(frame_phys: u64) {
    #[cfg(target_arch = "aarch64")]
    crate::aarch64::set_switch_frame(frame_phys);
    #[cfg(target_arch = "riscv64")]
    crate::riscv64::set_switch_frame(frame_phys);
    #[cfg(target_arch = "loongarch64")]
    crate::loongarch64::set_switch_frame(frame_phys);
    #[cfg(target_arch = "x86")]
    let _ = frame_phys;
}

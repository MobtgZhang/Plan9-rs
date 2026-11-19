//! Plan 9 Kernel
//!
//! A Rust implementation of the Plan 9 operating system kernel.

#![no_std]
#![allow(dead_code)]

extern crate alloc;
extern crate plan9_common;
extern crate plan9_arch;
extern crate plan9_drivers;

// Kernel entry point (called by GRUB2/Multiboot2)
pub mod entry;
/// LoongArch64 direct-boot Multiboot2 synthesis (no firmware loader).
#[cfg(target_arch = "loongarch64")]
pub mod directboot;

// Process management
pub mod proc;
pub mod sched;

// Hardware
pub mod trap;
pub mod vm;
pub mod lapic;
pub mod user_regs;
pub mod console;
pub mod font;
pub mod serial;

// Process management
pub mod init_loader;

// System calls
pub mod syscall;

// Memory management
pub mod segment;
pub mod fault;
pub mod swap;
pub mod frame_alloc;
pub mod heap;

// Virtual filesystem
pub mod chan;
pub mod block;
pub mod vfs;
pub mod procfs;

// Root filesystem and boot archive
pub mod rootfs;
pub mod cpio;
pub mod upasswd;
pub mod keymap;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
pub mod vkey;

// Devices
pub mod cons;
pub mod dev;
pub mod devpipe;
pub mod devsd;
pub mod devfs;
pub mod storage_backend;
pub mod devuart;
pub mod devmouse;
pub mod devkb;
pub mod devdraw;
pub mod devaudio;
pub mod devmnt;
pub mod devtls;
pub mod devbridge;
pub mod devusb;
pub mod devsrv;
pub mod netfs;
pub mod netdrv;

// Graphics
pub mod vga;
pub mod vga_vesa;
pub mod vga_ega;
pub mod gpu;

// System
pub mod kmesg;
pub mod profiler;
pub mod syscall_trace;
pub mod debug;
pub mod debug_gating;
pub mod watchdog;
#[cfg(target_arch = "x86_64")]
pub mod acpi;
pub mod smp;
pub mod sema;
pub mod qlock;
pub mod timer;
pub mod rtc;
pub mod quota;

#[cfg(test)]
pub mod tests;

// Re-exports from sched module
pub use sched::{Scheduler, Schedq, ready,
    schedinit, yield_, sched_ticks,
    procsave, procrestore, resched, should_preempt,
    SCHED_QUANTUM, HZ, MAX_DELAY_SCHED};
pub use sched::schedule as sched_schedule;

// Re-exports from timer module
pub use timer::{increment_ticks, ticks_to_ms, ms_to_ticks,
    sleep, wakeup, tsleep, init_timer, global_timer,
    alarm_schedule, alarm_check, ProcAlarm, TimerWheel};
pub use timer::get_ticks as timer_get_ticks;

pub use plan9_common::sync::Spinlock;

// Memory constants
/// Common ELF load bias for init, exec and absolute-pointer relocations.
/// LoongArch uses the DMW-free canonical upper half; AArch64 uses L0[1]
/// to avoid the boot identity map in L0[0].
#[cfg(target_arch = "loongarch64")]
pub const USER_BASE: u64 = 0xFFFF_8000_4000_0000;
#[cfg(target_arch = "aarch64")]
pub const USER_BASE: u64 = 0x0000_0080_0000_0000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "loongarch64")))]
pub const USER_BASE: u64 = 0x0000_0000_4000_0000;
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;


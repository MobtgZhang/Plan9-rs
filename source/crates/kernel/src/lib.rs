//! Plan 9 Kernel
//!
//! A Rust implementation of the Plan 9 operating system kernel.

#![no_std]

extern crate alloc;
extern crate plan9_common;
extern crate plan9_arch;
extern crate plan9_drivers;

pub mod proc;
pub mod sched;
pub mod trap;
pub mod vm;
pub mod syscall;
pub mod segment;
pub mod fault;
pub mod cons;
pub mod dev;
pub mod vfs;
pub mod user_regs;
pub mod lapic;
pub mod procfs;
pub mod kmesg;
pub mod profiler;
pub mod syscall_trace;
pub mod debug;
pub mod watchdog;
pub mod acpi;
pub mod sema;
pub mod devpipe;
pub mod devsd;
pub mod devuart;
pub mod devmouse;
pub mod devkb;
pub mod devdraw;
pub mod devaudio;
pub mod devmnt;
pub mod devtls;
pub mod devbridge;
pub mod devusb;

pub use proc::{Proc, State, Segment, Pid, NSEG, NPRIQ, PRI_NORMAL, PRI_KPROC, proctable};
pub use sched::Scheduler;
pub use vm::{frame_allocator, alloc_frame, free_frame, alloc_frames, init_allocator};
pub use procfs::{ProcState, ProcQid, ProcCtl, ProcThread};
pub use kmesg::{KMESG_SIZE, init_kmesg, kmesg, kmesg_putc, kmesg_puts, KmesgDev};
pub use profiler::{init_kprof, kprof, kprof_sample, ProfDev, ProfSample, PROF_SAMPLES};
pub use syscall_trace::{init_syscall_trace, syscall_tracer, SyscallTraceDev, SyscallRecord};
pub use debug::{dump_regs, procdump, dump_stack, hexdump, kernel_panic, DebugDev};
pub use watchdog::{init_watchdog, watchdog_pet, watchdog_enable, watchdog_disable, WatchdogDev};
pub use acpi::{init_acpi, acpi, acpi_shutdown, acpi_reset, AcpiDev, AcpiPowerState};

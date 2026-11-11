//! Architecture-specific code
//!
//! Every architecture implements the same facade surface
//! (`plan9_arch::hal`) so that the kernel and libraries never touch
//! machine instructions or architecture-specific registers directly:
//! all low-level assembly lives inside this crate.

#![no_std]

extern crate plan9_common;

pub mod arch_trait;
pub mod hal;

#[cfg(target_arch = "x86")]
pub mod i386;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

/// Architecture-level early init and paging bring-up, selected by target.
pub use hal::boot::{early_init, paging_init};

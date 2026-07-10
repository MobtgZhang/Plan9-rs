//! Architecture-specific code

#![no_std]

extern crate plan9_common;

pub mod x86_64;
pub mod i386;
pub mod loongarch64;
pub mod riscv64;
pub mod aarch64;
pub mod arch_trait;

pub use x86_64::{early_init, paging_init};

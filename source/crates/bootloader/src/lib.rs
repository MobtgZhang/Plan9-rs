//! Bootloader Crate
//!
//! Provides UEFI boot environment support for loading and running the kernel.

#![no_std]

extern crate alloc;

pub mod uefi;

pub use uefi::{
    Bootloader, BootInfo, BootServices, SystemTable,
    LoadedKernel, FramebufferInfo, PixelFormat, MemoryDescriptor,
    MemoryType, Status, Handle, Guid,
};

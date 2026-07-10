//! Bootloader Crate
//!
//! Provides boot environment support for loading and running the kernel.
//! Supports both UEFI and GRUB2 (Multiboot2) boot environments.

#![no_std]

extern crate alloc;

pub mod uefi;
pub mod grub2;

pub use uefi::{
    Bootloader, BootServices, SystemTable,
    LoadedKernel, PixelFormat, MemoryType, Status, Handle,
};
pub use uefi::guid::Guid;
pub use uefi::BootInfo;

pub use grub2::{
    BootSource, Multiboot2Info, MemoryRegion, FramebufferConfig,
    parse_multiboot2, get_kernel_cmdline, get_memory_map, get_framebuffer_info,
};

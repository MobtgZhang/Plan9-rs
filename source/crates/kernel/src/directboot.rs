//! Multiboot2 blob synthesis for LoongArch64 direct QEMU boot.
//!
//! There is no LoongArch UEFI firmware for QEMU's `virt` machine, so the
//! kernel is booted with `-bios none -kernel 9kernel.elf` and the init
//! binaries are planted in RAM with `-device loader`.  QEMU hands the CPU
//! only `a0`/`a1` in an unknown (non-Multiboot2) state, so the kernel
//! synthesizes a real Multiboot2 information blob at a fixed physical
//! address that mirrors what a bootloader would have built, then lets
//! `kstart` run its normal bootinfo path with the blob's address.
//!
//! Layout (all tags padded to 8 bytes):
//!   * BASIC_MEMINFO (tag 4)  — mem_lower / mem_upper in KiB.
//!   * MEMMAP        (tag 6)  — one RAM entry covering all of RAM.
//!   * MODULE        (tag 3)  — the `init` ELF image.
//!   * MODULE        (tag 3)  — the `rootfs.cpio` archive (its name must
//!                              end in `rootfs.cpio` for the loader).
//!   * END           (tag 0)
//!
//! The blob and the modules all live inside the first 256 MiB because
//! `frame_alloc`'s fallback pool (used when the memory map yields no
//! usable region) starts at physical 0x100000, and module ranges are
//! reserved from that pool — anything outside it could be handed out as
//! a free frame and overwritten.

use core::mem::size_of;

/// Physical base of the synthesized Multiboot2 information blob.
pub const BLOB_BASE: u64 = 0x0300_0000;

/// Physical base of the init ELF (planted with `-device loader`).
pub const INIT_BASE: u64 = 0x0310_0000;

/// Physical base of the rootfs.cpio archive (planted with `-device loader`).
pub const ROOTFS_BASE: u64 = 0x0400_0000;

/// Total RAM QEMU is started with (`-m 512M`).
pub const RAM_SIZE: u64 = 512 * 1024 * 1024;

const TAG_END: u32 = 0;
const TAG_MODULE: u32 = 3;
const TAG_MEMINFO: u32 = 4;
const TAG_MEMMAP: u32 = 6;

/// One Multiboot2 memory-map entry, exactly as `parse_boot_info` walks
/// them: a 28-byte record with a leading size field, `addr`, `len`,
/// `type` and the trailing reserved word.
#[repr(C)]
struct MmapEntry {
    size: u32,
    addr: u64,
    len: u64,
    type_: u32,
    _reserved: u32,
}

const MMAP_ENTRY_SIZE: u32 = size_of::<MmapEntry>() as u32 - 4; // payload only, like GRUB
const MMAP_STRIDE: usize = size_of::<MmapEntry>(); // what the parser advances by
// The frame allocator's `is_available()` accepts only region_type 7
// (this kernel's "usable RAM" marker — see entry.rs MemoryRegion), so
// the RAM entry uses that type.
const MMAP_TYPE_RAM: u32 = 7;

#[inline]
fn write_u32(addr: u64, val: u32) {
    unsafe { (addr as *mut u32).write_volatile(val) };
}

#[inline]
fn write_u64(addr: u64, val: u64) {
    unsafe { (addr as *mut u64).write_volatile(val) };
}

/// Write one tag header; `size` includes the header.  Returns the offset
/// of the first payload byte.
#[inline]
fn put_tag_header(cur: u64, tag: u32, size: u32) -> u64 {
    write_u32(cur, tag);
    write_u32(cur + 4, size);
    cur + 8
}

/// Zero-pad to the next 8-byte boundary (the parser advances by
/// `(tag_size + 7) & !7`, so the padding bytes are never read).
fn align8(cur: u64) -> u64 {
    (cur + 7) & !7
}

/// Build the blob at `BLOB_BASE` and return the (magic, info) pair that
/// `kstart`'s common path expects.
///
/// # Safety
/// Must run before the frame allocator hands out frames; only ever
/// called once from `kstart` on the LoongArch64 direct-boot path.
pub unsafe fn synthesize() -> (u64, u64) {
    let base = BLOB_BASE;

    // ---- header (total_size patched in at the end) ----
    let mut cur = base + 8;

    // ---- BASIC_MEMINFO ----
    let payload = put_tag_header(cur, TAG_MEMINFO, 8 + 8);
    write_u32(payload, 0); // mem_lower (KiB below 1 MiB — irrelevant here)
    write_u32(payload + 4, (RAM_SIZE / 1024) as u32); // mem_upper
    cur = align8(cur + 16);

    // ---- MEMMAP: one RAM region covering all of RAM ----
    let entries = 1usize;
    let tag_size = (8 + entries * MMAP_STRIDE) as u64;
    let payload = put_tag_header(cur, TAG_MEMMAP, tag_size as u32);
    let entry = MmapEntry {
        size: MMAP_ENTRY_SIZE,
        addr: 0,
        len: RAM_SIZE,
        type_: MMAP_TYPE_RAM,
        _reserved: 0,
    };
    unsafe { (payload as *mut MmapEntry).write_volatile(entry) };
    cur = align8(cur + tag_size);

    // ---- MODULE: init ELF ----
    let name = b"init\0";
    let tag_size = (8 + 8 + name.len()) as u64;
    let payload = put_tag_header(cur, TAG_MODULE, tag_size as u32);
    write_u32(payload, INIT_BASE as u32);
    write_u32(payload + 4, 0); // mod_end filled in below (size unknown here)
    for (i, b) in name.iter().enumerate() {
        write_u8(payload + 8 + i as u64, *b);
    }
    cur = align8(cur + tag_size);

    // ---- MODULE: rootfs.cpio ----
    let name = b"rootfs.cpio\0";
    let tag_size = (8 + 8 + name.len()) as u64;
    let payload = put_tag_header(cur, TAG_MODULE, tag_size as u32);
    write_u32(payload, ROOTFS_BASE as u32);
    write_u32(payload + 4, 0); // mod_end filled in below
    for (i, b) in name.iter().enumerate() {
        write_u8(payload + 8 + i as u64, *b);
    }
    cur = align8(cur + tag_size);

    // ---- END tag ----
    let payload = put_tag_header(cur, TAG_END, 8);
    let _ = payload;
    cur = align8(cur + 8);

    // Patch total_size now that the layout is final, and fill in the
    // module end addresses by scanning for the trailing zero page (the
    // loader plants each module at its fixed base; RAM above it stays
    // zero, so the last non-zero page marks the module's end).
    write_u32(base, (cur - base) as u32);

    let init_end = probe_module_end(INIT_BASE, ROOTFS_BASE - INIT_BASE);
    let rootfs_end = probe_module_end(ROOTFS_BASE, ROOTFS_MAX_SIZE);
    // MODULE payload: mod_start@0, mod_end@4.
    let mut off = 8;
    while off < (cur - base) {
        let tag = read_u32(base + off);
        let size = read_u32(base + off + 4) as u64;
        if tag == TAG_MODULE {
            let start = read_u32(base + off + 8) as u64;
            write_u32(
                base + off + 8 + 4,
                if start == INIT_BASE { init_end } else { rootfs_end } as u32,
            );
        }
        if tag == TAG_END {
            break;
        }
        off += (size + 7) & !7;
    }

    (crate::entry::MB2_MAGIC, base)
}

#[inline]
fn write_u8(addr: u64, val: u8) {
    unsafe { (addr as *mut u8).write_volatile(val) };
}

#[inline]
fn read_u64(addr: u64) -> u64 {
    unsafe { (addr as *const u64).read_volatile() }
}

#[inline]
fn read_u32(addr: u64) -> u32 {
    unsafe { (addr as *const u32).read_volatile() }
}

/// Cap on how far past the rootfs base the end probe may scan.  The
/// archive is a few MiB; anything past this bound is treated as the
/// module's end (a modest over-reservation is harmless — the frame
/// allocator just keeps those frames reserved).
const ROOTFS_MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Find the exclusive end of the module planted at `base`: the first
/// page boundary above the last non-zero qword in `[base, base+max)`.
/// RAM past the module (written by `-device loader`, zero-filled
/// elsewhere) is all zero, so the last non-zero page marks the end.
/// If no non-zero qword is found, one page is claimed.
unsafe fn probe_module_end(base: u64, max: u64) -> u64 {
    let mut last = 0u64;
    let mut page = base;
    let end_limit = base + max;
    while page < end_limit {
        let mut q = page;
        while q < page + 4096 {
            if read_u64(q) != 0 {
                last = page + 4096;
                break;
            }
            q += 8;
        }
        page += 4096;
    }
    if last == 0 { base + 4096 } else { last }
}

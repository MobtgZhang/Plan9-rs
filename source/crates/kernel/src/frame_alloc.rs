//! Global frame allocator initialisation.
//!
//! The kernel uses a single static `FrameAllocator` initialised from the
//! Multiboot2 memory map. We keep the type itself in `vm.rs` (it has a lot
//! of existing logic); this module is responsible for:
//!
//!   * Walking the Multiboot2 memory map and picking the largest usable
//!     region to back the allocator.
//!   * Reserving frames that already hold the kernel image, the boot
//!     stack, GRUB-loaded modules, the page-table pool, etc. so they
//!     won't be handed out as free pages.
//!   * Exposing a simple `frame_alloc()` / `frame_alloc_zeroed()` API for
//!     the rest of the kernel (thin wrappers over `vm::alloc_frame*`).

extern crate alloc;

use alloc::vec::Vec;
use crate::plan9_arch::hal::paging::PAGESIZE;
use plan9_common::types::{PhysAddr, VirtAddr};
use plan9_common::sync::Spinlock;

use crate::entry::BootInfo;
use crate::serial;

/// Page-aligned reserved region that the allocator must skip.
#[derive(Clone, Copy, Debug)]
struct ReservedRange {
    start: u64,
    end:   u64,
}

static RESERVED: Spinlock<Vec<ReservedRange>> = Spinlock::new(Vec::new());

/// Initialise the global frame allocator from the Multiboot2 boot info.
///
/// # Safety
/// Must be called once, after paging is enabled but before any other code
/// tries to allocate a frame.
pub unsafe fn frame_init_from_bootinfo(boot: &BootInfo) {
    serial::put_bytes(b"[kernel] frame_init_from_bootinfo: entries=");
    serial::put_hex_u32(boot.memory_map.len() as u32);
    serial::put_bytes(b"\n");

    // Pick the largest available region as the allocator's pool.
    let mut best: Option<(u64, u64)> = None; // (base, size)
    
    // If we have regions from multiboot, use them
    if !boot.memory_map.is_empty() {
        for r in boot.memory_map.iter() {
            serial::put_bytes(b"[kernel] frame_init: region base=");
            serial::put_hex_u64(r.base);
            serial::put_bytes(b" len=");
            serial::put_hex_u64(r.length);
            serial::put_bytes(b" type=");
            serial::put_hex_u32(r.region_type);
            serial::put_bytes(b"\n");
            if r.is_available() {
                if best.map_or(true, |(_, sz)| r.length > sz) {
                    best = Some((r.base, r.length));
                    serial::put_bytes(b"[kernel] frame_init: new best region\n");
                }
            }
        }
    } else {
        // No multiboot regions - use default 256MB region
        serial::put_bytes(b"[kernel] frame_init: no MEMMAP, using default 256MB region\n");
        best = Some((0x100000, 256 * 1024 * 1024));
    }

    let (mut base, mut size) = match best {
        Some(b) => b,
        None => {
            serial::put_bytes(b"[kernel] frame_init: ERROR - no available memory regions!\n");
            return; // No usable RAM — boot into a degraded state.
        }
    };

    serial::put_bytes(b"[kernel] frame_init: best base=");
    serial::put_hex_u64(base);
    serial::put_bytes(b" size=");
    serial::put_hex_u64(size);
    serial::put_bytes(b"\n");

    // The boot heap is live kernel memory (its free-list blocks are
    // scattered across the whole reserved window).  A pool overlapping
    // it would have the allocator's own metadata — the struct including
    // the Spinlock plus the bitmap, both written at the pool base —
    // clobbered by heap blocks as soon as heap_init() runs, which
    // deadlocks the first alloc_frame() on x86_64 (heap at 16-48 MiB,
    // largest region starting at ~23.5 MiB).  Trim the pool so it starts
    // above the heap end; the allocator's metadata then lives in real
    // free RAM.
    let heap_start = crate::heap::BOOT_HEAP_START;
    let heap_end = crate::heap::BOOT_HEAP_END;
    {
        let end = base + size;
        if base < heap_end && end > heap_start {
            if end <= heap_end {
                // Region entirely inside the heap — unusable as a pool.
                base = 0;
                size = 0;
            } else {
                let trimmed = heap_end - base;
                base = heap_end;
                size -= trimmed;
            }
            serial::put_bytes(b"[kernel] frame_init: trimmed pool away from boot heap, base=");
            serial::put_hex_u64(base);
            serial::put_bytes(b" size=");
            serial::put_hex_u64(size);
            serial::put_bytes(b"\n");
        }
    }

    // Align the pool so the FrameAllocator's metadata lives at a page
    // boundary (it is constructed at the start of the region).
    let pool_base = align_up(base, PAGESIZE as u64);
    let pool_size = align_down(size, PAGESIZE as u64);
    serial::put_bytes(b"[kernel] frame_init: pool_base=");
    serial::put_hex_u64(pool_base);
    serial::put_bytes(b" pool_size=");
    serial::put_hex_u64(pool_size);
    serial::put_bytes(b"\n");

    if pool_size == 0 {
        serial::put_bytes(b"[kernel] frame_init: ERROR - pool_size is 0!\n");
        return;
    }

    serial::put_bytes(b"[kernel] frame_init: calling vm::init_allocator\n");
    crate::vm::init_allocator(PhysAddr::new(pool_base), pool_size as usize);
    serial::put_bytes(b"[kernel] frame_init: allocator initialized\n");

    // Reserve the kernel image + boot stack + page-table pool.
    reserve_kernel_image();

    // Reserve the boot heap region so the frame allocator never hands out
    // frames that the global bump allocator is using.
    reserve_range(crate::heap::BOOT_HEAP_START, crate::heap::BOOT_HEAP_END);

    // Reserve any GRUB-loaded modules so we never hand out their pages.
    for i in 0..boot.modules.count as usize {
        if let Some(m) = &boot.modules.entries[i] {
            serial::put_bytes(b"[kernel] frame_init: reserving module ");
            serial::put_hex_u64(m.start);
            serial::put_bytes(b" - ");
            serial::put_hex_u64(m.end);
            serial::put_bytes(b"\n");
            reserve_range(align_down(m.start, PAGESIZE as u64),
                          align_up  (m.end,   PAGESIZE as u64));
        }
    }

    // Now that RESERVED is populated, mark the corresponding bits in the
    // FrameAllocator's bitmap. We have to do this last so the allocator
    // is fully constructed.
    let reserved = RESERVED.lock().clone();
    drop(RESERVED.lock()); // re-acquire after clone
    serial::put_bytes(b"[kernel] frame_init: marking reserved frames\n");
    for r in reserved.iter() {
        mark_reserved(r.start, r.end);
    }
    serial::put_bytes(b"[kernel] frame_init: done\n");
}

/// Align `v` down to the previous multiple of `align`. `align` must be a power of two.
fn align_down(v: u64, align: u64) -> u64 { v & !(align - 1) }

/// Align `v` up to the next multiple of `align`. `align` must be a power of two.
fn align_up(v: u64, align: u64) -> u64 { (v + align - 1) & !(align - 1) }

extern "C" {
    static _kernel_start: u8;
    static _kernel_end:   u8;
    static _bootstack_bottom: u8;
    static _bootstack_top:    u8;
}

unsafe fn reserve_kernel_image() {
    let start = align_down(&_kernel_start as *const _ as u64, PAGESIZE as u64);
    let end   = align_up  (&_kernel_end   as *const _ as u64, PAGESIZE as u64);
    reserve_range(start, end);

    let stk_start = align_down(&_bootstack_bottom as *const _ as u64, PAGESIZE as u64);
    let stk_end   = align_up  (&_bootstack_top    as *const _ as u64, PAGESIZE as u64);
    reserve_range(stk_start, stk_end);

    // The boot heap is live kernel memory; frames inside it must never
    // be handed out.  (Ranges outside the pool are ignored by the
    // marker, so this is safe even if the pool was trimmed away.)
    reserve_range(crate::heap::BOOT_HEAP_START, crate::heap::BOOT_HEAP_END);
}

fn reserve_range(start: u64, end: u64) {
    let mut list = RESERVED.lock();
    list.push(ReservedRange { start, end });
}

/// Reserve a physical range `[start, end)` so the frame allocator never
/// hands it out (used by SMP bring-up for the trampoline page and the AP
/// stacks).
pub fn reserve_range_pub(start: u64, end: u64) {
    reserve_range(start, end);
}

/// Mark every frame in `[start, end)` as allocated in the frame allocator.
///
/// # Safety
/// `start`/`end` must come from a reserved range recorded by
/// `reserve_range` — i.e. they must lie inside the allocator's pool.
unsafe fn mark_reserved(start: u64, end: u64) {
    // Use the allocator's own method: hand-reinterpreting the struct with a
    // mirrored `Layout` broke under release builds because the compiler
    // reordered `FrameAllocator`'s fields (it has no `repr(C)`), so the
    // mirrored offsets were wrong and the marker corrupted the allocator.
    let alloc = crate::vm::frame_allocator();
    alloc.mark_range_reserved(start, end);
}

/// Allocate a single physical frame, skipping over reserved regions.
pub fn frame_alloc() -> Option<PhysAddr> {
    // The reserved bits are already set in the bitmap, so this just calls
    // the allocator and returns whatever it finds.
    crate::vm::alloc_frame()
}

/// Allocate a single physical frame and zero it.
pub fn frame_alloc_zeroed() -> Option<PhysAddr> {
    crate::vm::alloc_frame_zeroed()
}

/// Convert a physical address to a kernel-virtual address via the higher-half
/// direct mapping.
pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    crate::plan9_arch::hal::paging::phys_to_virt(paddr)
}
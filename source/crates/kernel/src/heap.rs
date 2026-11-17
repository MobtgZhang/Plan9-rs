//! Kernel heap allocator.
//!
//! First-fit free-list allocator over a pre-mapped 32 MiB boot region.
//! Free blocks are kept in a singly-linked list sorted by address; on
//! `dealloc` the block is re-inserted in sorted position and coalesced
//! with its neighbours, so repeated alloc/free churn (glyph caches, cpio
//! imports, process loading) reuses memory instead of leaking it.
//!
//! Every block — free or allocated — starts with a 16-byte header:
//!
//! ```text
//!   +--------------+--------------+--------------------------+
//!   | size (usize) | next (usize) | payload ...              |
//!   +--------------+--------------+--------------------------+
//! ```
//!
//! * `size` is the total block size including the header, always a
//!   multiple of `HDR` (16). Its bit 0 is the in-use flag.
//! * `next` is only meaningful for free blocks: the absolute address of
//!   the next free block (0 = end of list). The list is sorted by
//!   address, which makes coalescing on free a local operation.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::plan9_arch::hal::paging::PAGESIZE;
use plan9_common::types::VirtAddr;

/// Head of the free list (absolute virtual address, 0 = empty).
static HEAP_FREE: AtomicUsize = AtomicUsize::new(0);
/// Heap base (virtual), 0 until `heap_init` ran.
static HEAP_BASE: AtomicUsize = AtomicUsize::new(0);
/// One-past-the-end of the heap region.
static HEAP_END:  AtomicUsize = AtomicUsize::new(0);

/// Size of the block header (`size` + `next`), and the minimum block
/// granularity. 16-byte granularity keeps every payload 16-byte aligned.
const HDR: usize = 16;

/// Round `v` up to a multiple of `unit` (a power of two).
#[inline]
fn round_up(v: usize, unit: usize) -> usize { (v + unit - 1) & !(unit - 1) }

/// Allocation statistics (for `/proc` and diagnostics).
pub struct HeapStats {
    pub allocs: usize,
    pub frees: usize,
    /// Bytes currently handed out (payload only).
    pub live_bytes: usize,
    /// Total bytes of the heap region.
    pub total_bytes: usize,
}

static STAT_ALLOCS: AtomicUsize = AtomicUsize::new(0);
static STAT_FREES: AtomicUsize = AtomicUsize::new(0);
static STAT_LIVE: AtomicUsize = AtomicUsize::new(0);

/// Snapshot of allocator statistics.
pub fn stats() -> HeapStats {
    let base = HEAP_BASE.load(Ordering::Relaxed);
    let end = HEAP_END.load(Ordering::Relaxed);
    HeapStats {
        allocs: STAT_ALLOCS.load(Ordering::Relaxed),
        frees: STAT_FREES.load(Ordering::Relaxed),
        live_bytes: STAT_LIVE.load(Ordering::Relaxed),
        total_bytes: if base == 0 || end == 0 { 0 } else { end - base },
    }
}

/// Initialise the kernel heap. `start..end` is a virtual address range
/// (already mapped by the boot page tables) that the allocator can use.
///
/// # Safety
/// Must be called exactly once after paging is enabled. The region must
/// be at least one page, page-aligned, and not overlap the kernel image.
pub unsafe fn heap_init(start: VirtAddr, end: VirtAddr) {
    let heap_addr = start.as_u64() as usize;
    let heap_end  = end.as_u64()  as usize;
    crate::serial::put_bytes(b"[heap_init] start=");
    crate::serial::put_hex_u64(heap_addr as u64);
    crate::serial::put_bytes(b" end=");
    crate::serial::put_hex_u64(heap_end as u64);
    crate::serial::put_bytes(b"\n");
    // The whole region starts as one big free block; round the end down
    // so every block size stays a multiple of HDR.
    let size = (heap_end - heap_addr) & !(HDR - 1);
    let block = heap_addr as *mut usize;
    *block = size;        // size (free: bit 0 clear)
    *block.add(1) = 0;    // next (none)
    HEAP_BASE.store(heap_addr, Ordering::SeqCst);
    HEAP_END.store(heap_addr + size, Ordering::SeqCst);
    // Store the free-list head last so the allocator can detect
    // half-initialised state.
    HEAP_FREE.store(heap_addr, Ordering::SeqCst);
    crate::serial::put_bytes(b"[heap_init] DONE\n");
}

/// Static 64 KiB heap slab placed in .bss. Used as a bootstrap heap while
/// the frame allocator itself is being initialised.
pub const STATIC_HEAP_SIZE: usize = 0x10000;

/// Page-aligned wrapper so the bootstrap slab starts on a 4 KiB boundary.
/// `repr(align)` cannot be applied to a static directly.
#[repr(C, align(4096))]
pub struct StaticHeap {
    pub bytes: [u8; STATIC_HEAP_SIZE],
}

#[no_mangle]
pub static mut STATIC_HEAP: StaticHeap = StaticHeap {
    bytes: [0; STATIC_HEAP_SIZE],
};

/// Virtual/physical region reserved for the main boot heap. It lies above
/// the kernel image, inside the identity-mapped boot window, and is marked
/// reserved in the frame allocator before any frames are handed out.
///
/// On x86_64 QEMU RAM starts at physical 0, so 16 MiB is ordinary RAM.
/// On aarch64 virt the RAM base is 0x4000_0000 — the low 1 GiB is the
/// MMIO window and holds no usable memory — so the boot heap lives at
/// RAM+32 MiB. `frame_alloc` reserves this range either way.
#[cfg(target_arch = "aarch64")]
pub const BOOT_HEAP_START: u64 = 0x4200_0000; // RAM base + 32 MiB
#[cfg(not(target_arch = "aarch64"))]
pub const BOOT_HEAP_START: u64 = 0x0100_0000; // 16 MiB
pub const BOOT_HEAP_SIZE:  u64 = 0x0200_0000; // 32 MiB
pub const BOOT_HEAP_END:   u64 = BOOT_HEAP_START + BOOT_HEAP_SIZE;

#[inline]
unsafe fn read_word(addr: usize) -> usize {
    (addr as *mut usize).read_volatile()
}
#[inline]
unsafe fn write_word(addr: usize, v: usize) {
    (addr as *mut usize).write_volatile(v)
}
#[inline]
unsafe fn block_size(block: usize) -> usize {
    read_word(block)
}
#[inline]
unsafe fn block_next(block: usize) -> usize {
    read_word(block + 8)
}

/// The `GlobalAlloc` implementation. Safe to call once `heap_init()` has
/// run.
struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = HEAP_BASE.load(Ordering::SeqCst);
        let mut head = HEAP_FREE.load(Ordering::SeqCst);
        if base == 0 || head == 0 {
            return core::ptr::null_mut();
        }

        let align = layout.align().max(core::mem::size_of::<usize>());
        if align > PAGESIZE {
            return core::ptr::null_mut();
        }
        // Payload granularity: block sizes are multiples of HDR, so the
        // requested size is rounded up to keep every block 16-aligned.
        let size = round_up(layout.size(), HDR);

        static LOCK: plan9_common::sync::Spinlock<()> = plan9_common::sync::Spinlock::new(());
        let _guard = LOCK.lock();
        head = HEAP_FREE.load(Ordering::SeqCst);

        // First-fit scan over the address-sorted free list.
        let mut prev: usize = 0;
        let mut cur = head;
        while cur != 0 {
            let bsize = block_size(cur);
            let bnext = block_next(cur);

            // Payload starts right after the header, aligned up.
            let payload = round_up(cur + HDR, align);
            let hdr = payload - HDR;
            let front = hdr - cur; // 0 or >= HDR (see note below)
            let alloc_span = HDR + size;
            let alloc_end = hdr + alloc_span;

            // `front` is a multiple of HDR: `cur` is HDR-aligned, and for
            // `align` a power of two >= 8, align_up(cur + HDR, align) - HDR
            // is HDR-aligned too. So `front` is either 0 (header stays at
            // the block start) or at least HDR (the skipped region can
            // hold its own free-block header).
            let fits = if front == 0 {
                alloc_span <= bsize
            } else if front >= HDR {
                alloc_end <= cur + bsize
            } else {
                false // impossible per the alignment invariant, be safe
            };
            if fits {
                // Safe now: the allocation lies within this free block.
                let rem_tail = (cur + bsize) - alloc_end;
                let alloc_size;
                let list_next; // what replaces `cur` in the free list

                if front == 0 {
                    // Header at the block start.
                    if rem_tail >= HDR {
                        alloc_size = alloc_span;
                        list_next = hdr + alloc_span;
                        write_word(list_next, rem_tail);
                        write_word(list_next + 8, bnext);
                    } else {
                        // Donate the too-small tail to the allocation.
                        alloc_size = bsize;
                        list_next = bnext;
                    }
                    write_word(hdr, alloc_size | 1);
                    if prev == 0 {
                        HEAP_FREE.store(list_next, Ordering::SeqCst);
                    } else {
                        write_word(prev + 8, list_next);
                    }
                } else {
                    // The region before the aligned header stays free.
                    // Free list: ... -> cur(front) -> (tail) -> ...
                    let front_next;
                    if rem_tail >= HDR {
                        alloc_size = alloc_span;
                        let tail = hdr + alloc_span;
                        write_word(tail, rem_tail);
                        write_word(tail + 8, bnext);
                        front_next = tail;
                    } else {
                        // Donate the tail to the allocation.
                        alloc_size = (cur + bsize) - hdr;
                        front_next = bnext;
                    }
                    write_word(cur, front); // front region: free block
                    write_word(cur + 8, front_next);
                    write_word(hdr, alloc_size | 1);
                    if prev == 0 {
                        HEAP_FREE.store(cur, Ordering::SeqCst);
                    } else {
                        write_word(prev + 8, cur);
                    }
                }
                STAT_ALLOCS.fetch_add(1, Ordering::Relaxed);
                STAT_LIVE.fetch_add(size, Ordering::Relaxed);
                return payload as *mut u8;
            }

            prev = cur;
            cur = bnext;
        }
        // Out of memory.
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let base = HEAP_BASE.load(Ordering::SeqCst);
        let end = HEAP_END.load(Ordering::SeqCst);
        if base == 0 || ptr.is_null() {
            return;
        }
        let addr = ptr as usize;
        if addr < base + HDR || addr >= end {
            return;
        }

        static LOCK: plan9_common::sync::Spinlock<()> = plan9_common::sync::Spinlock::new(());
        let _guard = LOCK.lock();

        let hdr = addr - HDR;
        let size = read_word(hdr);
        if size & 1 == 0 {
            // Double free or foreign pointer — ignore.
            return;
        }
        let block = hdr; // reused as a free block at the same address
        let sz = size & !1;
        write_word(hdr, sz); // clear the in-use bit

        // Find the free blocks that bracket `block` in address order.
        let head = HEAP_FREE.load(Ordering::SeqCst);
        let mut prev: usize = 0;
        let mut after = head;
        while after != 0 && after < block {
            prev = after;
            after = block_next(after);
        }

        // Coalesce with `prev` (below) and `after` (above) when adjacent.
        let mut new_block = block;
        let mut new_size = sz;
        let mut new_next = after;

        if prev != 0 && prev + block_size(prev) == block {
            // Extend the previous free block over this one.
            new_block = prev;
            new_size = block_size(prev) + sz;
        }
        if after != 0 && new_block + new_size == after {
            // Absorb the following free block.
            new_size += block_size(after);
            new_next = block_next(after);
        }

        // Store the merged size and successor. This covers both the
        // fresh-node case (new_block == block) and the merged-into-prev
        // case: in both, the block's size may have grown by absorbing
        // the following block, and the old next pointer may point
        // inside the merged block.
        write_word(new_block, new_size);
        write_word(new_block + 8, new_next);
        if prev == 0 {
            HEAP_FREE.store(new_block, Ordering::SeqCst);
        } else if new_block != prev {
            write_word(prev + 8, new_block);
        }

        STAT_FREES.fetch_add(1, Ordering::Relaxed);
        STAT_LIVE.fetch_sub(sz - HDR, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: KernelHeap = KernelHeap;

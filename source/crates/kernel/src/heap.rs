//! Kernel heap allocator.
//!
//! A simple, locked, bump-allocator sufficient for the boot path. It
//! grows by carving out whole 4 KiB pages from the global frame
//! allocator. Once a page is committed, allocations within it are served
//! in bump-pointer fashion until the page fills; we then commit a new
//! page.
//!
//! This is intentionally crude — once the kernel is fully booted and
//! paging is wired up, a slab or free-list allocator can take over
//! without changing the `GlobalAlloc` implementation here.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::plan9_arch::x86_64::paging::PAGESIZE;
use plan9_common::types::VirtAddr;

/// Initial heap top. While this is 0 the allocator refuses to hand out
/// memory (use-before-init detection).
const HEAP_UNINIT: usize = 0;

/// Bump-pointer for the next allocation. Stored atomically because we
/// read it from interrupt context and across CPUs.
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(HEAP_UNINIT);
/// One-past-the-end of the heap region.
static HEAP_END:  AtomicUsize = AtomicUsize::new(HEAP_UNINIT);

/// Initialise the kernel heap. `start..end` is a virtual address range
/// (already mapped by the boot page tables) that the bump allocator can
/// use.
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
    // Set the top-of-heap first so the allocator can detect
    // half-initialised state, then the bump pointer last.
    HEAP_END.store(heap_end,  Ordering::SeqCst);
    HEAP_NEXT.store(heap_addr, Ordering::SeqCst);
    crate::serial::put_bytes(b"[heap_init] DONE\n");
}

/// Static 64 KiB heap slab placed in .bss. Used as a bootstrap heap while
/// the frame allocator itself is being initialised.
pub const STATIC_HEAP_SIZE: usize = 0x10000;

#[no_mangle]
pub static mut STATIC_HEAP: [u8; STATIC_HEAP_SIZE] = [0; STATIC_HEAP_SIZE];

/// Virtual/physical region reserved for the main boot heap. It lies above
/// the kernel image, inside the identity-mapped boot window, and is marked
/// reserved in the frame allocator before any frames are handed out.
pub const BOOT_HEAP_START: u64 = 0x0100_0000; // 16 MiB
pub const BOOT_HEAP_SIZE:  u64 = 0x0200_0000; // 32 MiB
pub const BOOT_HEAP_END:   u64 = BOOT_HEAP_START + BOOT_HEAP_SIZE;

/// Round `v` up to a multiple of `align`. `align` must be a power of two.
fn round_up(v: u64, align: u64) -> u64 { (v + align - 1) & !(align - 1) }

/// Round `v` down to a multiple of `align`. `align` must be a power of two.
fn round_down(v: u64, align: u64) -> u64 { v & !(align - 1) }

/// The actual `GlobalAlloc` implementation. Safe to call once
/// `heap_init()` has run.
struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Align the requested size to the layout's alignment. We can't
        // honour alignments beyond a page boundary with the simple bump
        // strategy below, so we reject those (no kernel code needs >4 KiB
        // alignment today; if that changes we have to fall back to a
        // proper slab).
        let align = layout.align().max(core::mem::size_of::<usize>());
        if align > PAGESIZE {
            return core::ptr::null_mut();
        }

        let size = round_up(layout.size() as u64, align as u64) as usize;

        // Serialise allocation against a spinlock so two cores can't
        // each carve out the same chunk.
        static LOCK: plan9_common::sync::Spinlock<()> = plan9_common::sync::Spinlock::new(());
        let _guard = LOCK.lock();

        let next = HEAP_NEXT.load(Ordering::SeqCst);
        let end  = HEAP_END.load(Ordering::SeqCst);
        if next == 0 || end == 0 {
            return core::ptr::null_mut();
        }

        // Bump pointer aligned to the request.
        let cur = round_up(next as u64, align as u64) as usize;
        if cur + size > end {
            return core::ptr::null_mut();
        }

        // Commit a new page if we crossed a page boundary inside an
        // unbacked region. For the boot heap the region is already
        // mapped by our 4 MiB identity window, so we only need to mark
        // it as used.
        HEAP_NEXT.store(cur + size, Ordering::SeqCst);
        cur as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: memory cannot be reclaimed until the region is
        // fully reset. This is intentional — deallocation would require
        // maintaining a free list, which this simple allocator does not
        // implement. Memory is leaked until a proper slab or free-list
        // allocator replaces this implementation during full kernel boot.
    }
}

#[global_allocator]
static ALLOC: KernelHeap = KernelHeap;
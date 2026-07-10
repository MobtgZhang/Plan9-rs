//! Memory operations for libsys
//!
//! This module implements the standard memory allocation functions using the
//! Plan 9 brk/sbrk system calls.

/// Alignment requirement (8 bytes for 64-bit)
const ALIGN: usize = 7;

/// Alignment mask
const ALIGN_MASK: usize = !ALIGN;

/// Minimum allocation size
///
/// Must be at least `size_of::<BlockHeader>()` plus alignment slack so a
/// released block can still be linked back into the free list. 32 bytes
/// comfortably covers a header plus `next` pointer on 64-bit and avoids
/// pathological fragmentation from tiny splits.
const MIN_SIZE: usize = 32;

/// Memory block header
/// 
/// Each allocated block has a header that stores the size.
/// Free blocks are linked together in a free list.
#[repr(C)]
struct BlockHeader {
    /// Size of the block (including header)
    size: usize,
    /// Magic number for validation
    magic: usize,
    /// Pointer to next free block (only valid when block is free)
    next: *mut BlockHeader,
}

impl BlockHeader {
    const MAGIC: usize = 0xDEADBEEF;

    /// Get pointer to the data area after this header
    fn data_ptr(&mut self) -> *mut u8 {
        unsafe {
            (self as *mut BlockHeader as *mut u8).add(core::mem::size_of::<BlockHeader>())
        }
    }

    /// Get header from data pointer
    unsafe fn from_data(data: *mut u8) -> *mut BlockHeader {
        data.sub(core::mem::size_of::<BlockHeader>()) as *mut BlockHeader
    }
}

/// Start of the heap (initialized on first malloc)
static mut HEAP_START: *mut u8 = core::ptr::null_mut();

/// Current break (end of allocated memory)
static mut CURRENT_BREAK: *mut u8 = core::ptr::null_mut();

/// Head of the free list
static mut FREE_LIST: *mut BlockHeader = core::ptr::null_mut();

/// Flag to track if heap is initialized
static mut HEAP_INIT: bool = false;

/// System call numbers (from lib.rs)
const SYS_BRK: u32 = 13;

// Make a syscall with 1 argument (see lib.rs for the full syscall ABI)
extern "C" {
    fn _syscall1(num: u32, arg1: u64) -> u64;
}

/// Initialize the heap
/// 
/// This should be called once at program start.
fn init_heap() {
    unsafe {
        if !HEAP_INIT {
            // Get current break as starting point using brk(0)
            let current = _syscall1(SYS_BRK, 0);
            let start = if current == 0 || current == !0u64 as u64 {
                core::ptr::null_mut()
            } else {
                current as *mut u8
            };
            
            if !start.is_null() {
                HEAP_START = start;
                CURRENT_BREAK = start;
                FREE_LIST = core::ptr::null_mut();
                HEAP_INIT = true;
            }
        }
    }
}

/// Call brk syscall
fn syscall_brk(addr: *mut u8) -> *mut u8 {
    let ret = unsafe { _syscall1(SYS_BRK, addr as u64) };
    if ret == 0 || ret == !0u64 as u64 {
        core::ptr::null_mut()
    } else {
        ret as *mut u8
    }
}

/// Round up to alignment boundary, ensuring at least MIN_SIZE bytes
fn round_up(size: usize) -> usize {
    let aligned = (size + ALIGN) & ALIGN_MASK;
    aligned.max(MIN_SIZE)
}

/// Allocate memory using sbrk
/// 
/// This implements a simple first-fit allocator.
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }

    let size = round_up(size);
    let total_size = size + core::mem::size_of::<BlockHeader>();

    init_heap();

    unsafe {
        // Search free list for a suitable block
        let mut prev: *mut BlockHeader = core::ptr::null_mut();
        let mut curr = FREE_LIST;

        while !curr.is_null() {
            let block = &mut *curr;
            if block.size >= total_size {
                // Found a block that's big enough
                
                // Only split if the leftover would still be a usable free
                // block (header + at least MIN_SIZE of usable space). This
                // avoids creating tiny unusable fragments in the free list.
                if block.size < total_size + core::mem::size_of::<BlockHeader>() + MIN_SIZE {
                    // Unlink from free list
                    if prev.is_null() {
                        FREE_LIST = block.next;
                    } else {
                        (&mut *prev).next = block.next;
                    }
                    
                    // Set magic and return data pointer
                    block.magic = BlockHeader::MAGIC;
                    return block.data_ptr();
                } else {
                    // Split the block
                    let remaining_size = block.size - total_size;
                    let new_block = curr.add(total_size);
                    (&mut *new_block).size = remaining_size;
                    (&mut *new_block).magic = BlockHeader::MAGIC;
                    (&mut *new_block).next = block.next;
                    
                    // Update original block size
                    block.size = total_size;
                    block.magic = BlockHeader::MAGIC;
                    
                    // Unlink original from free list
                    if prev.is_null() {
                        FREE_LIST = new_block;
                    } else {
                        (&mut *prev).next = new_block;
                    }
                    
                    return block.data_ptr();
                }
            }
            
            prev = curr;
            curr = block.next;
        }

        // No suitable free block found, allocate more memory
        let new_break = CURRENT_BREAK.add(total_size);

        // Extend break
        if syscall_brk(new_break).is_null() {
            return core::ptr::null_mut();
        }

        // The block header lives just before CURRENT_BREAK (which has
        // been advanced by total_size).
        let block_ptr = (new_break as usize - total_size) as *mut BlockHeader;
        let block = &mut *block_ptr;
        block.size = total_size;
        block.magic = BlockHeader::MAGIC;
        block.next = core::ptr::null_mut();

        // Update break and publish to the cached value used by `sbrk()`.
        CURRENT_BREAK = new_break;
        crate::set_sbrk_current(new_break);

        block.data_ptr()
    }
}

/// Free memory
/// 
/// In Plan 9's sbrk model, memory cannot be returned to the heap.
/// This implementation adds the block to the free list for reuse,
/// coalescing with any adjacent free blocks to reduce fragmentation.
pub fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let block = BlockHeader::from_data(ptr);
        let header = &*block;

        // Validate magic number
        if header.magic != BlockHeader::MAGIC {
            // Invalid block, ignore
            return;
        }

        // Coalesce with adjacent free blocks so we don't fragment the heap.
        // Walk the free list once and locate a physical neighbor on each
        // side (if any). We also remember `prev_after` so we can unlink
        // the merged-away after-block from the linked list.
        let block_addr = block as usize;
        let block_end = block_addr + header.size;

        let mut curr = FREE_LIST;
        let mut prev_before: *mut BlockHeader = core::ptr::null_mut();
        let mut to_merge_before: *mut BlockHeader = core::ptr::null_mut();
        let mut to_merge_after: *mut BlockHeader = core::ptr::null_mut();
        let mut prev_after: *mut BlockHeader = core::ptr::null_mut();

        while !curr.is_null() {
            let next_addr = curr as usize;
            let curr_size = (&*curr).size;
            let next_end = next_addr + curr_size;

            // The freed block's end abuts this free block's start -> this
            // block sits physically right after us.
            if next_addr == block_end {
                to_merge_after = curr;
                prev_after = prev_before;
            }
            // This free block's end abuts the freed block's start -> this
            // block sits physically right before us.
            if next_end == block_addr {
                to_merge_before = curr;
                // `prev_before` is whatever the predecessor at the time
                // we saw this node was. It'll be refreshed on the next
                // iteration only after we record it here, so the next
                // node's `prev_after` calculation still refers to *this*
                // node, which is exactly what we want when `to_merge_after`
                // happens to live directly after `to_merge_before`.
            }

            prev_before = curr;
            curr = (&*curr).next;
        }

        // The "before" neighbor (lower address) takes priority as the
        // base: we extend it forward to swallow the freed region and
        // (optionally) the "after" neighbor too.
        if !to_merge_before.is_null() {
            // Extend the before-block to cover the freed region and any
            // after-block; we unlink the after-block from the list
            // because its storage is now part of `to_merge_before`.
            let mut new_size = (&*to_merge_before).size + header.size;
            let remove_after: *mut BlockHeader = if !to_merge_after.is_null() {
                new_size += (&*to_merge_after).size;
                to_merge_after
            } else {
                core::ptr::null_mut()
            };
            (&mut *to_merge_before).size = new_size;

            // Unlink `remove_after` from the free list.
            if !remove_after.is_null() {
                let next_of_after = (&*remove_after).next;
                if prev_after.is_null() {
                    // `remove_after` was the head of the list.
                    FREE_LIST = next_of_after;
                } else {
                    (&mut *prev_after).next = next_of_after;
                }
            }

            // The merged block already lives in the free list (it's
            // `to_merge_before`), so nothing else to do.
            return;
        }

        if !to_merge_after.is_null() {
            // No before neighbor: extend the after-block backward to
            // cover the freed region. We unlink `to_merge_after` and
            // re-insert `block` in its place because the merged block
            // will live where `block` does.
            let after_size = (&*to_merge_after).size;
            let next_of_after = (&*to_merge_after).next;
            (&mut *block).size = header.size + after_size;
            (&mut *block).next = next_of_after;
            (&mut *block).magic = 0;

            // Unlink `to_merge_after` from the list.
            if prev_after.is_null() {
                FREE_LIST = block;
            } else {
                (&mut *prev_after).next = block;
            }
            return;
        }

        // No adjacent free blocks: insert the freed block at the head
        // of the free list.
        (&mut *block).next = FREE_LIST;
        (&mut *block).magic = 0;
        FREE_LIST = block;
    }
}

/// Reallocate memory
/// 
/// If ptr is null, behaves like malloc.
/// If size is 0, behaves like free and returns null.
///
/// If malloc fails, the original block at `ptr` is left untouched and a
/// null pointer is returned to the caller (the strict realloc(3)
/// contract). Only once the new block has been successfully allocated
/// and the old contents copied across is the original block released.
pub fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    if ptr.is_null() {
        return malloc(size);
    }

    if size == 0 {
        free(ptr);
        return core::ptr::null_mut();
    }

    unsafe {
        let old_block = BlockHeader::from_data(ptr);
        // `block.size` already accounts for the header; subtract it to get
        // the usable payload size available to the caller.
        let old_size = (&*old_block).size - core::mem::size_of::<BlockHeader>();

        // Cheap grow-in-place shortcut: the existing block is already
        // large enough for the requested size, so there is nothing to
        // copy or free.
        if size <= old_size {
            return ptr;
        }

        // Allocate new block. If this fails, return null *without*
        // touching `ptr` so the caller's data remains valid.
        let new_ptr = malloc(size);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }

        let copy_size = old_size.min(size);
        core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);

        // Free the old block only after the copy has succeeded; if free
        // itself somehow failed (the simple linked-list version always
        // succeeds today) we still hand the caller a valid, freshly
        // allocated buffer.
        free(ptr);

        new_ptr
    }
}

/// Allocate zero-initialized memory
pub fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    // Check for overflow
    let total = nmemb.checked_mul(size).unwrap_or(0);
    let ptr = malloc(total);
    if !ptr.is_null() {
        unsafe {
            core::ptr::write_bytes(ptr, 0, total);
        }
    }
    ptr
}

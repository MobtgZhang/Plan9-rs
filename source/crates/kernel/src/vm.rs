//! Virtual Memory Management
//!
//! Implements kernel virtual memory management including:
//! - Physical page frame allocator
//! - Virtual address space management
//! - Memory mapping operations
//! - Kernel heap allocator

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::plan9_arch::hal::paging::{
    self, PteFlags,
    PageTableIndices, PAGESIZE, PT_ENTRIES, PHYS_MEMORY_VIRT, KERNEL_VIRT_BASE,
};
use crate::plan9_common::error::{Error, Result};
// use crate::plan9_common::sync::Mutex;
use crate::plan9_common::types::{PhysAddr, VirtAddr};
use crate::serial;

// ============================================================================
// Physical Frame Allocator
// ============================================================================

/// Physical frame allocator using a bitmap
pub struct FrameAllocator {
    /// Base address of managed physical memory
    base: PhysAddr,
    /// Total number of frames
    total_frames: usize,
    /// Bitmap of allocated frames (atomic for safe concurrent access)
    bitmap: &'static mut [AtomicU64],
    /// Lock for thread safety
    lock: crate::plan9_common::sync::Spinlock<()>,
}

impl FrameAllocator {
    /// Create a new frame allocator for the given memory region
    pub fn new(base: PhysAddr, size: usize) -> &'static mut Self {
        let frame_size = PAGESIZE;
        let total_frames = size / frame_size;
        let bitmap_words = (total_frames + 63) / 64;

        serial::put_bytes(b"[FrameAllocator::new] STEP1: base=");
        serial::put_hex_u64(base.as_u64());
        serial::put_bytes(b" size=");
        serial::put_hex_u64(size as u64);
        serial::put_hex_u64(total_frames as u64);
        serial::put_bytes(b" frames bitmap_words=");
        serial::put_hex_u64(bitmap_words as u64);
        serial::put_bytes(b"\n");

        let allocator_size = core::mem::size_of::<Self>() + bitmap_words * 8;
        let allocator_base = base;

        serial::put_bytes(b"[FrameAllocator::new] STEP2: writing to ");
        serial::put_hex_u64(allocator_base.as_u64());
        serial::put_bytes(b"\n");

        // We need static mut for the allocator - this is safe because we're
        // initializing it once at boot
        unsafe {
            let alloc_ptr = allocator_base.as_u64() as *mut Self;
            serial::put_bytes(b"[FrameAllocator::new] STEP3: got ptr\n");

            // Create the bitmap as a separate slice of AtomicU64
            let bitmap_ptr = (allocator_base.as_u64() + core::mem::size_of::<Self>() as u64) as *mut AtomicU64;
            let bitmap_slice = core::slice::from_raw_parts_mut(bitmap_ptr, bitmap_words);

            // Use write instead of write_bytes to properly initialize the entire struct
            // including the Spinlock field
            core::ptr::write(alloc_ptr, Self {
                base,
                total_frames,
                bitmap: bitmap_slice,
                lock: crate::plan9_common::sync::Spinlock::new(()),
            });
            serial::put_bytes(b"[FrameAllocator::new] STEP4: write done\n");

            let alloc = &mut *alloc_ptr;
            serial::put_bytes(b"[FrameAllocator::new] STEP5: dereferenced\n");

            // Initialize all bitmap words to 0 (all frames free initially)
            for word in alloc.bitmap.iter() {
                word.store(0, Ordering::Relaxed);
            }

            // Reserve the allocator's own memory (self-referencing fix)
            // The allocator metadata occupies the first `allocator_size` bytes.
            // Mark these frames as used so they will never be allocated.
            let reserved_frames = (allocator_size + PAGESIZE - 1) / PAGESIZE;
            for i in 0..reserved_frames {
                let word_idx = i / 64;
                let bit = i % 64;
                if word_idx < bitmap_words {
                    alloc.bitmap[word_idx].fetch_or(1u64 << bit, Ordering::Relaxed);
                }
            }

            serial::put_bytes(b"[FrameAllocator::new] STEP6: bitmap filled, reserved_frames=");
            serial::put_hex_u64(reserved_frames as u64);
            serial::put_bytes(b"\n");

            serial::put_bytes(b"[FrameAllocator::new] alloc_ptr=");
            serial::put_hex_u64(alloc_ptr as u64);
            serial::put_bytes(b"\n");

            alloc
        }
    }

    /// Mark every frame in `[start, end)` as allocated (reserved).
    ///
    /// Used at init to record frames that hold live data (kernel image,
    /// boot heap, loader modules, ...).  Frames outside the managed pool
    /// are ignored.
    pub fn mark_range_reserved(&mut self, start: u64, end: u64) {
        let frame_size = PAGESIZE as u64;
        let base_u64 = self.base.as_u64();
        let total = self.total_frames;
        // Skip everything below the pool start; align to a frame boundary.
        let mut cur = if start < base_u64 { base_u64 } else { start };
        cur &= !(frame_size - 1);
        while cur < end {
            let frame_idx = ((cur - base_u64) / frame_size) as usize;
            if frame_idx >= total {
                break;
            }
            self.bitmap[frame_idx / 64]
                .fetch_or(1u64 << (frame_idx % 64), core::sync::atomic::Ordering::Relaxed);
            cur += frame_size;
        }
    }

    /// Allocate a single physical frame
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        let _guard = self.lock.lock();

        for word_idx in 0..self.bitmap.len() {
            let old_val = self.bitmap[word_idx].load(Ordering::Acquire);
            if old_val == u64::MAX {
                continue;
            }
            let free_bit = old_val.trailing_ones() as usize;
            let new_val = old_val | (1u64 << free_bit);

            // Use compare_exchange to atomically mark the bit
            match self.bitmap[word_idx].compare_exchange(
                old_val,
                new_val,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let frame_idx = word_idx * 64 + free_bit;
                    if frame_idx < self.total_frames {
                        return Some(PhysAddr::new(
                            self.base.as_u64() + (frame_idx * PAGESIZE) as u64,
                        ));
                    }
                }
                Err(_) => {
                    // CAS failed, another thread modified this word, retry
                    continue;
                }
            }
        }
        None
    }

    /// Allocate a contiguous range of frames
    pub fn alloc_frames(&mut self, count: usize) -> Option<PhysAddr> {
        if count == 0 {
            return Some(self.base);
        }

        let _guard = self.lock.lock();

        for word_idx in 0..self.bitmap.len() {
            // Snapshot the starting word atomically.
            let start_word = self.bitmap[word_idx].load(Ordering::Acquire);
            let mut current_word = start_word;

            for bit in 0..64 {
                if current_word & 1 == 0 {
                    // This bit is free, check if we have enough consecutive bits
                    let frame_idx = word_idx * 64 + bit;

                    // Check if we can allocate 'count' frames starting here
                    let mut can_alloc = true;
                    let mut remaining = count;

                    for check_word in word_idx..self.bitmap.len() {
                        let check_bit = if check_word == word_idx { bit } else { 0 };

                        while remaining > 0 && check_bit < 64 {
                            let word = if check_word == word_idx {
                                start_word
                            } else {
                                self.bitmap[check_word].load(Ordering::Acquire)
                            };

                            let available_in_word = if check_word == word_idx {
                                (64 - check_bit) as usize
                            } else {
                                64
                            };

                            let needed = remaining.min(available_in_word);
                            let mut check_word_val = word >> check_bit;

                            for _i in 0..needed {
                                if check_word_val & 1 != 0 {
                                    can_alloc = false;
                                    break;
                                }
                                check_word_val >>= 1;
                                remaining -= 1;
                            }

                            if !can_alloc || remaining == 0 {
                                break;
                            }
                        }

                        if !can_alloc {
                            break;
                        }
                    }

                    if can_alloc && remaining == 0 {
                        // Allocate the frames using atomic CAS for each word
                        let mut rem = count;
                        let mut w = word_idx;
                        let mut b = bit;

                        while rem > 0 {
                            if w >= self.bitmap.len() {
                                // Should not happen given the check above,
                                // but bail out safely.
                                return None;
                            }
                            let target_bit = b;
                            // CAS-loop: set the bit in word w atomically
                            let mut current = self.bitmap[w].load(Ordering::Acquire);
                            loop {
                                let new_val = current | (1u64 << target_bit);
                                match self.bitmap[w].compare_exchange(
                                    current,
                                    new_val,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => break,
                                    Err(actual) => current = actual,
                                }
                            }

                            b += 1;
                            rem -= 1;

                            if b >= 64 {
                                w += 1;
                                b = 0;
                            }
                        }

                        return Some(PhysAddr::new(
                            self.base.as_u64() + (frame_idx * PAGESIZE) as u64
                        ));
                    }
                }
                current_word >>= 1;
            }
        }
        None
    }

    /// Free a physical frame
    pub fn free_frame(&mut self, addr: PhysAddr) -> Result<()> {
        let _guard = self.lock.lock();

        let offset = (addr.as_u64() - self.base.as_u64()) as usize;
        if offset % PAGESIZE != 0 {
            return Err(Error::Einval);
        }

        let frame_idx = offset / PAGESIZE;
        if frame_idx >= self.total_frames {
            return Err(Error::Einval);
        }

        let word_idx = frame_idx / 64;
        let bit = frame_idx % 64;

        // Atomically clear the bit (CAS-loop to handle concurrent modifications)
        loop {
            let current = self.bitmap[word_idx].load(Ordering::Acquire);
            if current & (1u64 << bit) == 0 {
                return Err(Error::Eperm); // Not allocated
            }
            let new_val = current & !(1u64 << bit);
            match self.bitmap[word_idx].compare_exchange(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Get total number of frames
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Get number of free frames
    pub fn free_frames(&self) -> usize {
        let _guard = self.lock.lock();
        let mut used = 0;
        for word in self.bitmap.iter() {
            let val = word.load(Ordering::Acquire);
            used += val.count_ones() as usize;
        }
        self.total_frames - used
    }
}

// ============================================================================
// Virtual Memory Manager
// ============================================================================

/// Virtual memory manager for kernel address space
pub struct VmManager {
    /// Physical frame allocator
    frame_alloc: &'static mut FrameAllocator,
    /// Kernel page table (temporary, will be replaced by actual PML4)
    pml4_virt: VirtAddr,
}

impl VmManager {
    /// Create a new VM manager
    pub fn new(frame_alloc: &'static mut FrameAllocator) -> Self {
        Self {
            frame_alloc,
            pml4_virt: VirtAddr::null(),
        }
    }

    /// Initialize with an existing page table
    pub fn with_page_table(mut self, pml4: PhysAddr) -> Self {
        self.pml4_virt = VirtAddr::new(KERNEL_VIRT_BASE | pml4.as_u64());
        self
    }

    /// Map a physical frame to a virtual address
    pub fn map_frame(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PteFlags,
    ) -> Result<()> {
        debug_assert!(phys.is_aligned(), "Physical address must be page-aligned");

        // Walk the page table, creating entries as needed
        let indices = PageTableIndices::from_virt(virt);

        // For simplicity, we assume the page table structure already exists
        // In a full implementation, this would walk and create entries

        let pml4_entry_ptr = self.pml4_virt.as_u64()
            + (indices.pml4 * 8) as u64;
        let pml4_entry = unsafe { &mut *(pml4_entry_ptr as *mut u64) };

        if *pml4_entry == 0 {
            // Allocate PDPT
            let pdpt_phys = self.frame_alloc.alloc_frame()
                .ok_or(Error::Enomem)?;
            let pdpt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pdpt_phys.as_u64());

            // Clear the new table
            unsafe {
                core::ptr::write_bytes(pdpt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pml4_entry = pdpt_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Read PDPT entry
        let pdpt_phys = PhysAddr::new(*pml4_entry & 0x000_FFFF_FFFF_F000);
        let pdpt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pdpt_phys.as_u64());
        let pdpt_entry_ptr = pdpt_virt.as_u64() + (indices.pdpt * 8) as u64;
        let pdpt_entry = unsafe { &mut *(pdpt_entry_ptr as *mut u64) };

        if *pdpt_entry == 0 {
            // Allocate PD
            let pd_phys = self.frame_alloc.alloc_frame()
                .ok_or(Error::Enomem)?;
            let pd_virt = VirtAddr::new(KERNEL_VIRT_BASE | pd_phys.as_u64());

            unsafe {
                core::ptr::write_bytes(pd_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pdpt_entry = pd_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Read PD entry
        let pd_phys = PhysAddr::new(*pdpt_entry & 0x000_FFFF_FFFF_F000);
        let pd_virt = VirtAddr::new(KERNEL_VIRT_BASE | pd_phys.as_u64());
        let pd_entry_ptr = pd_virt.as_u64() + (indices.pd * 8) as u64;
        let pd_entry = unsafe { &mut *(pd_entry_ptr as *mut u64) };

        if *pd_entry == 0 {
            // Allocate PT
            let pt_phys = self.frame_alloc.alloc_frame()
                .ok_or(Error::Enomem)?;
            let pt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pt_phys.as_u64());

            unsafe {
                core::ptr::write_bytes(pt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pd_entry = pt_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Set the final PT entry
        let pt_phys = PhysAddr::new(*pd_entry & 0x000_FFFF_FFFF_F000);
        let pt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pt_phys.as_u64());
        let pt_entry_ptr = pt_virt.as_u64() + (indices.pt * 8) as u64;

        // Set the final PT entry. Ensure PRESENT is set; for user mappings,
        // also force the USER bit so the page is accessible from CPL3.
        let mut entry_flags = flags;
        if !entry_flags.is_present() {
            entry_flags = entry_flags.with_present();
        }
        if !virt.is_kernel() {
            entry_flags = entry_flags.with_user();
        }
        unsafe {
            core::ptr::write(pt_entry_ptr as *mut u64, phys.as_u64() | entry_flags.bits());
            // (store ordering is provided by the TLB invalidate below)
        }
        invalidate_tlb(virt);

        Ok(())
    }

    /// Unmap a virtual address
    pub fn unmap(&mut self, virt: VirtAddr) -> Result<()> {
        let indices = PageTableIndices::from_virt(virt);

        // Walk to PT entry and clear it
        let pml4_entry = self.read_pml4_entry(indices.pml4)?;
        if pml4_entry == 0 { return Err(Error::Enoent); }

        let pdpt_phys = PhysAddr::new(pml4_entry & 0x000_FFFF_FFFF_F000);
        let pdpt_entry = self.read_entry(pdpt_phys, indices.pdpt)?;
        if pdpt_entry == 0 { return Err(Error::Enoent); }

        let pd_phys = PhysAddr::new(pdpt_entry & 0x000_FFFF_FFFF_F000);
        let pd_entry = self.read_entry(pd_phys, indices.pd)?;
        if pd_entry == 0 { return Err(Error::Enoent); }

        // Check if it's a large page
        if pd_entry & (1 << 7) != 0 {
            return Err(Error::Einval); // Can't unmap large pages this way
        }

        let pt_phys = PhysAddr::new(pd_entry & 0x000_FFFF_FFFF_F000);
        let pt_entry_ptr = VirtAddr::new(KERNEL_VIRT_BASE | pt_phys.as_u64())
            .as_u64() + (indices.pt * 8) as u64;

        let pt_entry = unsafe { core::ptr::read(pt_entry_ptr as *const u64) };
        if pt_entry == 0 {
            return Err(Error::Enoent);
        }

        // Clear the entry
        unsafe {
            core::ptr::write(pt_entry_ptr as *mut u64, 0);
            // (store ordering is provided by the TLB invalidate below)
        }
        invalidate_tlb(virt);

        Ok(())
    }

    /// Get the physical address for a virtual address
    pub fn virt_to_phys(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let pml4_phys = if self.pml4_virt.as_u64() >= KERNEL_VIRT_BASE {
            PhysAddr::new(self.pml4_virt.as_u64() - KERNEL_VIRT_BASE)
        } else {
            PhysAddr::new(self.pml4_virt.as_u64())
        };
        let entry = paging::walk_page_table_entry(pml4_phys, virt)?;

        if entry.is_large() {
            // For large pages, the offset is only 21 bits
            let phys_base = entry.addr();
            let offset = virt.as_u64() & ((1 << 21) - 1);
            Some(PhysAddr::new(phys_base.as_u64() | offset))
        } else {
            let phys_base = entry.addr();
            let offset = virt.as_u64() & 0xFFF;
            Some(PhysAddr::new(phys_base.as_u64() | offset))
        }
    }

    /// Read a PML4 entry
    fn read_pml4_entry(&self, index: usize) -> Result<u64> {
        if self.pml4_virt.is_null() {
            return Err(Error::Enodev);
        }
        let ptr = self.pml4_virt.as_u64() + (index * 8) as u64;
        Ok(unsafe { core::ptr::read(ptr as *const u64) })
    }

    /// Read a page table entry
    fn read_entry(&self, table: PhysAddr, index: usize) -> Result<u64> {
        let virt = VirtAddr::new(KERNEL_VIRT_BASE | table.as_u64());
        let ptr = virt.as_u64() + (index * 8) as u64;
        Ok(unsafe { core::ptr::read(ptr as *const u64) })
    }

    /// Allocate and map a new frame
    pub fn alloc_map(&mut self, virt: VirtAddr, flags: PteFlags) -> Result<PhysAddr> {
        let phys = self.frame_alloc.alloc_frame().ok_or(Error::Enomem)?;
        // Ensure at least PRESENT is set so the frame is actually addressable
        // after mapping; map_frame will additionally set USER for user mappings.
        let map_flags = if flags.is_present() { flags } else { flags.with_present() };
        self.map_frame(virt, phys, map_flags)?;
        Ok(phys)
    }
}

// ============================================================================
// Kernel Heap Allocator
// ============================================================================

/// Free block for the kernel heap
struct FreeBlock {
    /// Block size (includes header)
    size: usize,
    /// Next free block
    next: Option<*mut FreeBlock>,
}

/// Simple kernel heap using a bump allocator with free lists
pub struct KernelHeap {
    /// Current end of allocated heap
    end: u64,
    /// Current allocation position
    current: u64,
    /// Heap size limit
    limit: u64,
    /// Lock
    lock: crate::plan9_common::sync::Spinlock<()>,
    /// Free list for deallocated blocks
    free_list: Option<*mut FreeBlock>,
}

impl KernelHeap {
    /// Create a new kernel heap
    pub fn new(start: u64, size: usize) -> Self {
        Self {
            end: start + size as u64,
            current: start,
            limit: start + size as u64,
            lock: crate::plan9_common::sync::Spinlock::new(()),
            free_list: None,
        }
    }

    /// Allocate memory from the kernel heap
    /// Uses best-fit strategy from the free list, falls back to bump allocation
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<u64> {
        let aligned_size = (size + 7) & !7; // 8-byte alignment
        let align_mask = if align > 8 { !(align - 1) } else { !7 };

        // First, try to find a suitable block in the free list
        if let Some(ptr) = self.alloc_from_free_list(aligned_size, align_mask) {
            return Some(ptr);
        }

        // Fall back to bump allocation
        let aligned_ptr = (self.current as usize & align_mask) as u64;
        if aligned_ptr + aligned_size as u64 > self.end {
            return None;
        }

        self.current = aligned_ptr + aligned_size as u64;
        Some(aligned_ptr)
    }

    /// Try to allocate from the free list using best-fit strategy
    fn alloc_from_free_list(&mut self, size: usize, _align_mask: usize) -> Option<u64> {
        // Get the free list pointer
        let mut current = self.free_list;
        let mut prev: Option<*mut FreeBlock> = None;
        let mut best_fit: Option<*mut FreeBlock> = None;
        let mut best_prev: Option<*mut FreeBlock> = None;
        let mut best_size = usize::MAX;

        while let Some(block_ptr) = current {
            unsafe {
                let block = &*block_ptr;
                if block.size >= size && block.size < best_size {
                    best_size = block.size;
                    best_fit = Some(block_ptr);
                    best_prev = prev;
                }
                prev = Some(block_ptr);
                current = block.next;
            }
        }

        if let Some(block_ptr) = best_fit {
            // Update free list to remove the allocated block
            if let Some(bp) = best_prev {
                unsafe {
                    (&mut *bp).next = (&*block_ptr).next;
                }
            } else {
                self.free_list = unsafe { (&*block_ptr).next };
            }

            // If block is much larger than needed, split it
            let remaining = unsafe { (&*block_ptr).size - size };
            if remaining >= core::mem::size_of::<FreeBlock>() + 8 {
                let new_block_ptr = unsafe { (block_ptr as *mut u64).add(size) as *mut FreeBlock };
                unsafe {
                    (&mut *new_block_ptr).size = remaining;
                    (&mut *new_block_ptr).next = self.free_list;
                }
                self.free_list = Some(new_block_ptr);
            }

            // Return the block (skip header)
            Some(unsafe { (block_ptr as *mut u64).add(core::mem::size_of::<FreeBlock>()) as u64 })
        } else {
            None
        }
    }

    /// Deallocate memory back to the heap
    /// Uses simple coalescing for adjacent free blocks
    pub fn dealloc(&mut self, ptr: u64, size: usize) {
        if ptr == 0 {
            return;
        }

        let aligned_size = (size + 7) & !7;

        // Create a new free block
        let block_ptr = unsafe { (ptr as *mut u64).sub(core::mem::size_of::<FreeBlock>()) as *mut FreeBlock };

        unsafe {
            (&mut *block_ptr).size = aligned_size;
            (&mut *block_ptr).next = self.free_list;
            self.free_list = Some(block_ptr);

            // Coalesce adjacent free blocks
            self.coalesce();
        }
    }

    /// Coalesce adjacent free blocks
    /// Collects all blocks, sorts by address, then merges adjacent blocks
    fn coalesce(&mut self) {
        if self.free_list.is_none() {
            return;
        }

        // Collect all blocks and sort by address
        let mut blocks: Vec<(*mut FreeBlock, usize)> = Vec::new();
        let mut current = self.free_list;
        while let Some(ptr) = current {
            unsafe {
                blocks.push((ptr, (&*ptr).size));
                current = (&*ptr).next;
            }
        }

        if blocks.is_empty() {
            return;
        }

        // Sort by address
        blocks.sort_by_key(|k| k.0 as usize);

        // Merge adjacent blocks
        let mut i = 0;
        while i < blocks.len() {
            let (mut ptr, mut size) = blocks[i];
            let mut j = i + 1;

            while j < blocks.len() {
                let (next_ptr, next_size) = blocks[j];
                let block_end = (ptr as usize + size) as *mut FreeBlock;

                if block_end == next_ptr {
                    // Merge next into current
                    size += next_size;
                    j += 1;
                } else {
                    break;
                }
            }

            unsafe {
                (&mut *ptr).size = size;
                if j < blocks.len() {
                    (&mut *ptr).next = Some(blocks[j].0);
                } else {
                    (&mut *ptr).next = None;
                }
            }

            if i == 0 {
                self.free_list = Some(ptr);
            }
            i = j;
        }
    }

    /// Get current heap usage
    pub fn used(&self) -> usize {
        (self.current - (self.end - self.limit)) as usize
    }

    /// Get remaining heap space (sum of free list blocks only)
    pub fn available(&self) -> usize {
        // Only sum the free list blocks - bump allocator space is already "used"
        let mut free_size = 0usize;
        let mut current = self.free_list;
        while let Some(block_ptr) = current {
            unsafe {
                free_size += (&*block_ptr).size;
                current = (&*block_ptr).next;
            }
        }
        free_size
    }

    /// Expand heap (can only grow, never shrinks)
    pub fn expand(&mut self, additional: usize) {
        self.end += additional as u64;
    }
}

// ============================================================================
// Slab Allocator
// ============================================================================

/// Slab cache for objects of a specific size
/// 
/// A slab allocator pre-allocates memory and divides it into equal-sized
/// objects, reducing allocation overhead and memory fragmentation.
pub struct SlabCache {
    /// Name of this cache (for debugging)
    name: &'static str,
    /// Size of each object in this cache
    object_size: usize,
    /// Number of objects per slab (pages)
    objects_per_slab: usize,
    /// List of free objects
    free_list: Option<*mut u8>,
    /// Number of free objects available
    free_count: usize,
    /// Total objects in this cache
    total_objects: usize,
}

impl SlabCache {
    /// Create a new slab cache
    pub fn new(name: &'static str, object_size: usize) -> Self {
        // Align object size to at least 8 bytes
        let object_size = if object_size < 8 { 8 } else { (object_size + 7) & !7 };

        // Calculate objects per slab (each slab is one page)
        // For objects larger than a page, we can only fit 1 per slab
        let objects_per_slab = if object_size > 4096 {
            1
        } else {
            (4096 / object_size).max(1)
        };

        Self {
            name,
            object_size,
            objects_per_slab,
            free_list: None,
            free_count: 0,
            total_objects: 0,
        }
    }
    
    /// Allocate an object from this cache
    pub fn alloc(&mut self) -> Option<*mut u8> {
        // Try to get from free list first
        if let Some(ptr) = self.free_list.take() {
            self.free_count -= 1;
            
            // Read the next pointer from the object
            unsafe {
                let next = core::ptr::read(ptr as *const *mut u8);
                self.free_list = Some(next);
            }
            return Some(ptr);
        }
        
        // Need to allocate a new slab
        self.allocate_slab()?;
        
        // Should have free objects now, recurse
        self.alloc()
    }
    
    /// Allocate a new slab page and add its objects to the free list
    fn allocate_slab(&mut self) -> Option<()> {
        // Allocate a physical frame
        let frame = crate::vm::alloc_frame()?;

        // Convert to virtual address
        let slab_base = crate::vm::phys_to_virt(frame);
        let ptr = slab_base.as_mut_ptr::<u8>();

        // Chain all objects in the slab
        for i in 0..self.objects_per_slab {
            let current = unsafe { ptr.add(i * self.object_size) };
            let next = if i < self.objects_per_slab - 1 {
                unsafe { ptr.add((i + 1) * self.object_size) }
            } else {
                // Last object points to old free list
                self.free_list.unwrap_or(core::ptr::null_mut())
            };

            unsafe {
                core::ptr::write(current as *mut *mut u8, next);
            }
        }

        // Update free list to first object
        self.free_list = Some(ptr);
        self.free_count += self.objects_per_slab;
        self.total_objects += self.objects_per_slab;

        Some(())
    }
    
    /// Free an object back to this cache
    pub fn free(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        
        // Chain the object to the free list
        unsafe {
            core::ptr::write(ptr as *mut *mut u8, self.free_list.unwrap_or(core::ptr::null_mut()));
        }
        self.free_list = Some(ptr);
        self.free_count += 1;
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> SlabStats {
        SlabStats {
            name: self.name,
            object_size: self.object_size,
            free_count: self.free_count,
            total_objects: self.total_objects,
        }
    }
}

/// Statistics for a slab cache
pub struct SlabStats {
    pub name: &'static str,
    pub object_size: usize,
    pub free_count: usize,
    pub total_objects: usize,
}

/// Global slab caches for common kernel objects
pub struct SlabCaches {
    /// Cache for small objects (16 bytes)
    pub cache_16: SlabCache,
    /// Cache for small objects (32 bytes)
    pub cache_32: SlabCache,
    /// Cache for small objects (64 bytes)
    pub cache_64: SlabCache,
    /// Cache for small objects (128 bytes)
    pub cache_128: SlabCache,
    /// Cache for small objects (256 bytes)
    pub cache_256: SlabCache,
    /// Cache for small objects (512 bytes)
    pub cache_512: SlabCache,
    /// Cache for medium objects (1024 bytes)
    pub cache_1024: SlabCache,
    /// Cache for medium objects (2048 bytes)
    pub cache_2048: SlabCache,
    /// Cache for larger objects (4096 bytes)
    pub cache_4096: SlabCache,
}

impl SlabCaches {
    /// Create all slab caches
    pub fn new() -> Self {
        Self {
            cache_16: SlabCache::new("kmem-16", 16),
            cache_32: SlabCache::new("kmem-32", 32),
            cache_64: SlabCache::new("kmem-64", 64),
            cache_128: SlabCache::new("kmem-128", 128),
            cache_256: SlabCache::new("kmem-256", 256),
            cache_512: SlabCache::new("kmem-512", 512),
            cache_1024: SlabCache::new("kmem-1024", 1024),
            cache_2048: SlabCache::new("kmem-2048", 2048),
            cache_4096: SlabCache::new("kmem-4096", 4096),
        }
    }

    /// Allocate from the appropriate cache based on size
    pub fn alloc(&mut self, size: usize) -> Option<*mut u8> {
        if size <= 16 {
            self.cache_16.alloc()
        } else if size <= 32 {
            self.cache_32.alloc()
        } else if size <= 64 {
            self.cache_64.alloc()
        } else if size <= 128 {
            self.cache_128.alloc()
        } else if size <= 256 {
            self.cache_256.alloc()
        } else if size <= 512 {
            self.cache_512.alloc()
        } else if size <= 1024 {
            self.cache_1024.alloc()
        } else if size <= 2048 {
            self.cache_2048.alloc()
        } else if size <= 4096 {
            self.cache_4096.alloc()
        } else {
            None // Too large for slab
        }
    }

    /// Free to the appropriate cache based on size
    pub fn free(&mut self, ptr: *mut u8, size: usize) {
        if ptr.is_null() {
            return;
        }

        if size <= 16 {
            self.cache_16.free(ptr);
        } else if size <= 32 {
            self.cache_32.free(ptr);
        } else if size <= 64 {
            self.cache_64.free(ptr);
        } else if size <= 128 {
            self.cache_128.free(ptr);
        } else if size <= 256 {
            self.cache_256.free(ptr);
        } else if size <= 512 {
            self.cache_512.free(ptr);
        } else if size <= 1024 {
            self.cache_1024.free(ptr);
        } else if size <= 2048 {
            self.cache_2048.free(ptr);
        } else if size <= 4096 {
            self.cache_4096.free(ptr);
        }
        // If size > 4096, caller should use a different allocator
    }

    /// Get statistics for all caches
    pub fn stats(&self) -> [SlabStats; 9] {
        [
            self.cache_16.stats(),
            self.cache_32.stats(),
            self.cache_64.stats(),
            self.cache_128.stats(),
            self.cache_256.stats(),
            self.cache_512.stats(),
            self.cache_1024.stats(),
            self.cache_2048.stats(),
            self.cache_4096.stats(),
        ]
    }
}

impl Default for SlabCaches {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Virtual Memory Area
// ============================================================================

/// Virtual Memory Area descriptor
#[derive(Debug, Clone, Copy)]
pub struct Vma {
    /// Start virtual address
    pub start: VirtAddr,
    /// End virtual address
    pub end: VirtAddr,
    /// Flags (read, write, exec, user)
    pub flags: VmaFlags,
    /// Name (for debugging)
    pub name: &'static str,
}

impl Vma {
    /// Create a new VMA
    pub fn new(start: VirtAddr, end: VirtAddr, flags: VmaFlags, name: &'static str) -> Self {
        Self { start, end, flags, name }
    }

    /// Get size of this VMA
    pub fn size(&self) -> usize {
        (self.end.as_u64() - self.start.as_u64()) as usize
    }

    /// Check if this VMA contains an address
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }
}

/// VMA flags
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaFlags(u32);

impl VmaFlags {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const USER: Self = Self(1 << 3);
    pub const GROWS_DOWN: Self = Self(1 << 4);
    pub const SHARED: Self = Self(1 << 5);
    pub const PRIVATE: Self = Self(1 << 6);

    pub fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    pub fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    pub fn without(self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }
}

// ============================================================================
// Address Space
// ============================================================================

/// Process address space
pub struct AddressSpace {
    /// Pointer to the PML4 table (physical address)
    pml4: PhysAddr,
    /// Virtual memory areas (dynamically grown under a mutex)
    vmas: crate::plan9_common::sync::Mutex<Vec<Vma>>,
    /// Memory regions
    memory_regions: crate::plan9_common::sync::Mutex<Vec<Vma>>,
}

impl AddressSpace {
    /// Create a new empty address space
    pub fn new() -> Self {
        Self {
            pml4: PhysAddr::null(),
            vmas: crate::plan9_common::sync::Mutex::new(Vec::new()),
            memory_regions: crate::plan9_common::sync::Mutex::new(Vec::new()),
        }
    }

    /// Initialize address space
    pub fn init(&mut self, pml4_phys: PhysAddr) {
        self.pml4 = pml4_phys;
    }

    /// Get PML4 physical address
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4
    }

    /// Add a VMA
    pub fn add_vma(&self, vma: Vma) -> Result<()> {
        let mut vmas = self.vmas.lock();

        // Check for overlap with existing VMAs
        for existing in vmas.iter() {
            if vma.start.as_u64() < existing.end.as_u64()
                && vma.end.as_u64() > existing.start.as_u64()
            {
                return Err(Error::Ebusy);
            }
        }

        vmas.push(vma);
        Ok(())
    }

    /// Find VMA containing an address
    pub fn find_vma(&self, addr: VirtAddr) -> Option<Vma> {
        let vmas = self.vmas.lock();
        vmas.iter().find(|v| v.contains(addr)).copied()
    }

    /// Map a region
    pub fn mmap(
        &self,
        addr: Option<VirtAddr>,
        size: usize,
        flags: VmaFlags,
        _fd: Option<i32>,
        _offset: usize,
    ) -> Result<VirtAddr> {
        let start = if let Some(a) = addr {
            a
        } else {
            // Find a free region in user space
            const USER_REGION_BASE: u64 = 0x4000_0000;
            const USER_REGION_END: u64 = 0x0000_7FFF_FFFF_FFFF;
            let mut current = USER_REGION_BASE;
            let vmas = self.vmas.lock();
            // Sort vmas by start address so we can scan for gaps
            let mut sorted: Vec<Vma> = vmas.iter().copied().collect();
            sorted.sort_by_key(|v| v.start.as_u64());
            for vma in sorted.iter() {
                if current + size as u64 <= vma.start.as_u64() {
                    break;
                }
                if vma.end.as_u64() > current {
                    current = vma.end.as_u64();
                }
            }
            if current + size as u64 > USER_REGION_END {
                return Err(Error::Enomem);
            }
            VirtAddr::new(current)
        };

        let vma = Vma::new(start, VirtAddr::new(start.as_u64() + size as u64), flags, "anon");
        self.add_vma(vma)?;

        Ok(start)
    }

    /// Unmap a region (supports partial unmaps, splitting VMAs as needed)
    pub fn munmap(&self, addr: VirtAddr, size: usize) -> Result<()> {
        let mut vmas = self.vmas.lock();
        let target_end = addr.as_u64() + size as u64;
        let mut new_vmas: Vec<Vma> = Vec::with_capacity(vmas.len());
        let mut modified = false;

        for vma in vmas.iter() {
            let vma_start = vma.start.as_u64();
            let vma_end = vma.end.as_u64();
            if vma_end <= addr.as_u64() || vma_start >= target_end {
                // No overlap - keep as-is
                new_vmas.push(*vma);
            } else {
                modified = true;
                // Partial overlap - keep the unaffected portions
                if vma_start < addr.as_u64() {
                    new_vmas.push(Vma::new(
                        vma.start,
                        addr,
                        vma.flags,
                        vma.name,
                    ));
                }
                if vma_end > target_end {
                    new_vmas.push(Vma::new(
                        VirtAddr::new(target_end),
                        vma.end,
                        vma.flags,
                        vma.name,
                    ));
                }
            }
        }

        if !modified {
            return Err(Error::Enoent);
        }

        *vmas = new_vmas;
        Ok(())
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Convert physical address to kernel virtual address
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(PHYS_MEMORY_VIRT | phys.as_u64())
}

/// Convert kernel virtual address to physical address
#[inline]
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    if virt.is_kernel() && virt.as_u64() >= PHYS_MEMORY_VIRT {
        Some(PhysAddr::new(virt.as_u64() - PHYS_MEMORY_VIRT))
    } else {
        None
    }
}

/// Read a value from memory (volatile)
pub fn read_volatile<T>(ptr: *const T) -> T {
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Write a value to memory (volatile)
pub fn write_volatile<T>(ptr: *mut T, val: T) {
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ============================================================================
// User Page Table Management
// ============================================================================

/// User page table manager for creating and managing user address spaces
pub struct UserPageTable {
    /// PML4 physical address
    pml4_phys: PhysAddr,
    /// Reference to the frame allocator
    frame_alloc: &'static mut FrameAllocator,
}

impl UserPageTable {
    /// Create a new user page table
    ///
    /// This allocates a new PML4 table and sets up the required identity
    /// mappings for kernel access (so the kernel can still access its memory).
    pub fn new(frame_alloc: &'static mut FrameAllocator) -> Option<Self> {
        // Allocate a frame for the PML4 table
        let pml4_phys = frame_alloc.alloc_frame()?;

        // Get kernel virtual address to access the PML4
        let pml4_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pml4_phys.as_u64());

        // Clear the PML4 (all entries to 0)
        unsafe {
            core::ptr::write_bytes(pml4_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
        }

        // In a full implementation, we would:
        // 1. Copy kernel mappings from the boot page table
        // 2. Set up identity mapping for kernel access
        // For now, just return the empty table

        Some(Self { pml4_phys, frame_alloc })
    }

    /// Get the PML4 physical address
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// Map a user virtual address to a physical frame
    ///
    /// This walks the page table hierarchy and creates the necessary
    /// intermediate page tables, then maps the virtual address to the
    /// given physical frame with the specified flags.
    pub fn map(&mut self, virt: VirtAddr, phys: PhysAddr, flags: PteFlags) -> Result<()> {
        // User addresses must be in the lower half
        if virt.as_u64() >= KERNEL_VIRT_BASE {
            return Err(Error::Einval);
        }

        let indices = PageTableIndices::from_virt(virt);

        // Get kernel virtual address for PML4
        let pml4_virt = VirtAddr::new(PHYS_MEMORY_VIRT | self.pml4_phys.as_u64());

        // Read PML4 entry
        let pml4_entry_ptr = pml4_virt.as_u64() + (indices.pml4 * 8) as u64;
        let pml4_entry = unsafe { &mut *(pml4_entry_ptr as *mut u64) };

        // Allocate PDPT if needed
        if *pml4_entry == 0 {
            let pdpt_phys = self.frame_alloc.alloc_frame().ok_or(Error::Enomem)?;
            let pdpt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pdpt_phys.as_u64());

            unsafe {
                core::ptr::write_bytes(pdpt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pml4_entry = pdpt_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Read PDPT entry
        let pdpt_phys = PhysAddr::new(*pml4_entry & 0x000_FFFF_FFFF_F000);
        let pdpt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pdpt_phys.as_u64());
        let pdpt_entry_ptr = pdpt_virt.as_u64() + (indices.pdpt * 8) as u64;
        let pdpt_entry = unsafe { &mut *(pdpt_entry_ptr as *mut u64) };

        // Allocate PD if needed
        if *pdpt_entry == 0 {
            let pd_phys = self.frame_alloc.alloc_frame().ok_or(Error::Enomem)?;
            let pd_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pd_phys.as_u64());

            unsafe {
                core::ptr::write_bytes(pd_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pdpt_entry = pd_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Read PD entry
        let pd_phys = PhysAddr::new(*pdpt_entry & 0x000_FFFF_FFFF_F000);
        let pd_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pd_phys.as_u64());
        let pd_entry_ptr = pd_virt.as_u64() + (indices.pd * 8) as u64;
        let pd_entry = unsafe { &mut *(pd_entry_ptr as *mut u64) };

        // Allocate PT if needed
        if *pd_entry == 0 {
            let pt_phys = self.frame_alloc.alloc_frame().ok_or(Error::Enomem)?;
            let pt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pt_phys.as_u64());

            unsafe {
                core::ptr::write_bytes(pt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
            }

            *pd_entry = pt_phys.as_u64() | PteFlags::PAGE_TABLE.bits();
        }

        // Read PT entry
        let pt_phys = PhysAddr::new(*pd_entry & 0x000_FFFF_FFFF_F000);
        let pt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pt_phys.as_u64());
        let pt_entry_ptr = pt_virt.as_u64() + (indices.pt * 8) as u64;

        // Set the final PTE
        let user_flags = flags | PteFlags::USER;
        unsafe {
            core::ptr::write(pt_entry_ptr as *mut u64, phys.as_u64() | user_flags.bits());
            // Memory barrier to ensure the PTE write is committed before
            // the TLB flush (the arch crate provides the right barrier).
            crate::plan9_arch::hal::mmu::flush_tlb();
        }

        // Invalidate TLB for this address
        invalidate_tlb(virt);

        Ok(())
    }

    /// Unmap a user virtual address
    pub fn unmap(&mut self, virt: VirtAddr) -> Result<()> {
        if virt.as_u64() >= KERNEL_VIRT_BASE {
            return Err(Error::Einval);
        }

        let indices = PageTableIndices::from_virt(virt);
        let pml4_virt = VirtAddr::new(PHYS_MEMORY_VIRT | self.pml4_phys.as_u64());

        // Walk down to find the PTE
        let pml4_entry_ptr = pml4_virt.as_u64() + (indices.pml4 * 8) as u64;
        let pml4_entry = unsafe { &mut *(pml4_entry_ptr as *mut u64) };

        if *pml4_entry == 0 {
            return Err(Error::Enoent);
        }

        let pdpt_phys = PhysAddr::new(*pml4_entry & 0x000_FFFF_FFFF_F000);
        let pdpt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pdpt_phys.as_u64());
        let pdpt_entry_ptr = pdpt_virt.as_u64() + (indices.pdpt * 8) as u64;
        let pdpt_entry = unsafe { &mut *(pdpt_entry_ptr as *mut u64) };

        if *pdpt_entry == 0 {
            return Err(Error::Enoent);
        }

        let pd_phys = PhysAddr::new(*pdpt_entry & 0x000_FFFF_FFFF_F000);
        let pd_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pd_phys.as_u64());
        let pd_entry_ptr = pd_virt.as_u64() + (indices.pd * 8) as u64;
        let pd_entry = unsafe { &mut *(pd_entry_ptr as *mut u64) };

        if *pd_entry == 0 {
            return Err(Error::Enoent);
        }

        let pt_phys = PhysAddr::new(*pd_entry & 0x000_FFFF_FFFF_F000);
        let pt_virt = VirtAddr::new(PHYS_MEMORY_VIRT | pt_phys.as_u64());
        let pt_entry_ptr = pt_virt.as_u64() + (indices.pt * 8) as u64;
        let pt_entry = unsafe { &mut *(pt_entry_ptr as *mut u64) };

        if *pt_entry == 0 {
            return Err(Error::Enoent);
        }

        // Clear the PTE
        unsafe {
            core::ptr::write(pt_entry_ptr as *mut u64, 0);
        }

        // Invalidate TLB
        invalidate_tlb(virt);

        Ok(())
    }

    /// Free all page tables associated with this user address space
    pub fn destroy(&mut self) {
        // Walk through all PML4 entries and free the page tables
        let pml4_virt = VirtAddr::new(PHYS_MEMORY_VIRT | self.pml4_phys.as_u64());

        for i in 0..PT_ENTRIES {
            let entry_ptr = pml4_virt.as_u64() + (i * 8) as u64;
            let entry = unsafe { core::ptr::read(entry_ptr as *const u64) };

            if entry != 0 {
                // This is a PDPT, walk through and free it
                let pdpt_phys = PhysAddr::new(entry & 0x000_FFFF_FFFF_F000);

                // We don't free nested tables in this simplified implementation
                // A full implementation would recursively free all tables

                // Free the PDPT frame
                let _ = self.frame_alloc.free_frame(pdpt_phys);
            }
        }

        // Free the PML4 frame
        let _ = self.frame_alloc.free_frame(self.pml4_phys);
    }
}

/// Phys-map windows served by the kernel's own page table (see
/// `ensure_kernel_page_table`): each is a PML4 slot backed by a PDPT of
/// 1 GiB huge pages, so `window | phys` translates directly to `phys`
/// for any address below 512 GiB.
const PHYS_MAP_9000: u64 = 0xFFFF_9000_0000_0000; // MMIO window (UC)
const PHYS_MAP_8800: u64 = 0xFFFF_8800_0000_0000; // phys_to_virt window (UC)
const PHYS_MAP_LIMIT: u64 = 512 << 30;            // PDPT covers 512 GiB

/// Physical address of the kernel-owned PML4, installed on the first
/// `map_phys_range` call.  0 until then.
static KERNEL_PML4: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// PML4 slot indices for the phys-map windows (bits 47:39 of the VA).
const PML4_IDX_8800: usize = 272; // 0xFFFF_8800_0000_0000 >> 39 & 0x1FF
const PML4_IDX_9000: usize = 288; // 0xFFFF_9000_0000_0000 >> 39 & 0x1FF

/// Build a kernel-owned PML4 and switch to it.
///
/// The firmware (OVMF) hands us a page table whose pages are mapped
/// READ-ONLY, so we cannot install MMIO mappings by appending entries to
/// it — the write faults with a write-protection violation (QEMU: #PF
/// e=3, CR2 inside the firmware page-table page).  Instead we create our
/// own PML4:
///
///   * PML4[0]   -> own PDPT, PDPT[0] = 1 GiB identity huge page (RW, WB),
///                  covering everything the kernel itself runs in.
///   * PML4[272] -> own PDPT of 1 GiB huge pages (RW, WB) serving the
///                  0xFFFF_8800 phys_to_virt window (normal RAM access).
///   * PML4[288] -> own PDPT of 1 GiB huge pages (RW, PCD=UC) serving
///                  the 0xFFFF_9000 MMIO window.
///   * every other non-zero PML4 entry is copied verbatim from the
///     firmware table (e.g. the GOP framebuffer window at PML4[511]),
///     which we use but never modify.
///
/// The firmware's entries are only *read* (through the low 1 GiB identity
/// mapping, still live until we switch CR3), so the read-only protection
/// does not matter.
unsafe fn ensure_kernel_page_table() -> u64 {
    use core::sync::atomic::Ordering;

    let cached = KERNEL_PML4.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }

    let pml4 = match alloc_frame_zeroed() {
        Some(p) => p.as_u64(),
        None => return 0,
    };
    let pdpt_low = match alloc_frame_zeroed() {
        Some(p) => p.as_u64(),
        None => return 0,
    };
    let pdpt_ram = match alloc_frame_zeroed() {
        Some(p) => p.as_u64(),
        None => return 0,
    };
    let pdpt_mmio = match alloc_frame_zeroed() {
        Some(p) => p.as_u64(),
        None => return 0,
    };

    // PML4[0]: full 512 GiB identity map (huge pages, RW, WB) so that
    // direct physical writes (alloc_frame_zeroed zeroing, module access,
    // ...) work for any frame the allocator may hand out.
    core::ptr::write_volatile(pml4 as *mut u64, pdpt_low | 0x3u64);
    for i in 0..512usize {
        core::ptr::write_volatile(
            (pdpt_low as *mut u64).add(i),
            ((i as u64) << 30) | 0x83u64, // 1 GiB huge page, P | RW | PS, WB
        );
    }

    // PDPT for the phys_to_virt window: entry i maps [i*1GiB, (i+1)*1GiB)
    // as a WB huge page — 0x83 = P | RW | PS with PWT/PCD clear (WB).
    for i in 0..512usize {
        core::ptr::write_volatile(
            (pdpt_ram as *mut u64).add(i),
            ((i as u64) << 30) | 0x83u64,
        );
    }
    core::ptr::write_volatile((pml4 as *mut u64).add(PML4_IDX_8800), pdpt_ram | 0x3u64);

    // PDPT for the MMIO window: same layout but with PCD (uncacheable)
    // set — 0x93 = P | RW | PS | PCD.
    for i in 0..512usize {
        core::ptr::write_volatile(
            (pdpt_mmio as *mut u64).add(i),
            ((i as u64) << 30) | 0x93u64,
        );
    }
    core::ptr::write_volatile((pml4 as *mut u64).add(PML4_IDX_9000), pdpt_mmio | 0x3u64);

    // Copy the firmware's remaining PML4 entries (GOP framebuffer window,
    // any firmware-reserved higher mappings).  Reading the firmware PML4
    // is fine: it is identity-mapped in the low 1 GiB and we only read.
    let old_cr3 = crate::plan9_arch::hal::mmu::cr3_read().as_u64() & 0x000F_FFFF_FFFF_F000;
    for i in 0..512usize {
        if i == 0 || i == PML4_IDX_8800 || i == PML4_IDX_9000 {
            continue;
        }
        let v = core::ptr::read_volatile((old_cr3 as *const u64).add(i));
        if v != 0 {
            core::ptr::write_volatile((pml4 as *mut u64).add(i), v);
        }
    }

    serial::put_bytes(b"[vm] kernel page table installed, pml4=");
    serial::put_hex_u64(pml4);
    serial::put_bytes(b" (was ");
    serial::put_hex_u64(old_cr3);
    serial::put_bytes(b")\n");

    KERNEL_PML4.store(pml4, Ordering::Release);
    // Switch CR3 (also flushes the whole TLB).
    crate::plan9_arch::hal::mmu::cr3_write(PhysAddr::new(pml4));
    pml4
}

/// Map a physical address range into kernel virtual memory.
///
/// With the kernel-owned page table (see `ensure_kernel_page_table`) the
/// phys-map windows are direct 1 GiB huge-page translations, so this is a
/// pure address computation for any physical address below 512 GiB.
/// Returns the kernel virtual address of `phys`, or null on failure.
///
/// # Safety
/// Must be called after the frame allocator is initialised.  The mapping
/// is uncacheable (PCD), which is what MMIO and framebuffers want.
pub unsafe fn map_phys_range(phys: u64, size: u64) -> *mut u8 {
    use crate::plan9_arch::hal::paging::PAGE_SHIFT;

    serial::put_bytes(b"[map_phys_range] phys=");
    serial::put_hex_u64(phys);
    serial::put_bytes(b" size=");
    serial::put_hex_u64(size);
    serial::put_bytes(b"\n");

    let page_size: u64 = 1u64 << PAGE_SHIFT;
    let phys_aligned = phys & !(page_size - 1);
    let end = (phys + size + page_size - 1) & !(page_size - 1);

    if phys_aligned >= PHYS_MAP_LIMIT || end > PHYS_MAP_LIMIT {
        serial::put_bytes(b"[map_phys_range] FAILED: phys outside 512GiB window\n");
        return core::ptr::null_mut();
    }

    if ensure_kernel_page_table() == 0 {
        serial::put_bytes(b"[map_phys_range] FAILED: page table alloc\n");
        return core::ptr::null_mut();
    }

    let base_virt = PHYS_MAP_9000 + phys_aligned;
    let result_virt = base_virt + (phys - phys_aligned);
    serial::put_bytes(b"[map_phys_range] DONE, virt=");
    serial::put_hex_u64(result_virt);
    serial::put_bytes(b"\n");
    result_virt as *mut u8
}

/// Invalidate TLB entry for a specific virtual address
fn invalidate_tlb(virt: VirtAddr) {
    crate::plan9_arch::hal::mmu::invlpg(virt);
}

// ============================================================================
// Global Frame Allocator
// ============================================================================

use core::sync::atomic::AtomicPtr;
use crate::plan9_common::types::PhysAddr as CommonPhysAddr;

static FRAME_ALLOCATOR_INSTANCE: AtomicPtr<FrameAllocator> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global frame allocator
/// Called during kernel initialization
pub fn init_allocator(base: CommonPhysAddr, size: usize) {
    serial::put_bytes(b"[vm::init_allocator] STEP1: calling FrameAllocator::new\n");
    // FrameAllocator::new() writes to the managed memory region at `base`
    // and returns a reference pointing to that memory.
    // We take its address to store in the global.
    let alloc = FrameAllocator::new(base, size);
    serial::put_bytes(b"[vm::init_allocator] STEP2: FrameAllocator::new returned\n");
    let alloc_ptr = alloc as *const FrameAllocator as *mut FrameAllocator;
    serial::put_bytes(b"[vm::init_allocator] STEP3: storing ptr\n");
    FRAME_ALLOCATOR_INSTANCE.store(alloc_ptr, Ordering::SeqCst);
    serial::put_bytes(b"[vm::init_allocator] STEP4: ptr stored\n");
}

/// Get mutable reference to global frame allocator
pub fn frame_allocator() -> &'static mut FrameAllocator {
    unsafe { &mut *FRAME_ALLOCATOR_INSTANCE.load(Ordering::SeqCst) }
}

/// Allocate a physical frame
pub fn alloc_frame() -> Option<PhysAddr> {
    frame_allocator().alloc_frame()
}

/// Allocate a physical frame. Alias used by the new `frame_alloc` module.
#[inline(always)]
pub fn frame_alloc_one() -> Option<PhysAddr> {
    alloc_frame()
}

/// Allocate a physical frame and zero it.
pub fn alloc_frame_zeroed() -> Option<PhysAddr> {
    let paddr = alloc_frame()?;

    unsafe {
        // The boot kernel runs in the low identity mapping, so physical
        // frames inside the mapped window can be addressed directly.
        core::ptr::write_bytes(paddr.as_u64() as *mut u8, 0, PAGESIZE);
    }

    Some(paddr)
}

/// Allocate multiple physical frames
pub fn alloc_frames(count: usize) -> Option<PhysAddr> {
    frame_allocator().alloc_frames(count)
}

/// Free a physical frame
pub fn free_frame(addr: PhysAddr) -> Result<()> {
    frame_allocator().free_frame(addr)
}

/// Get total number of frames
pub fn total_frames() -> usize {
    frame_allocator().total_frames()
}

/// Get number of free frames
pub fn free_frames() -> usize {
    frame_allocator().free_frames()
}

/// Create a new user page table for a process
///
/// This allocates a new PML4 table and sets up the necessary
/// kernel identity mappings so the kernel can still access memory.
pub fn create_user_page_table() -> Option<PhysAddr> {
    let table = UserPageTable::new(frame_allocator())?;
    Some(table.pml4_phys())
}

/// Switch to user page table
///
/// This loads the new CR3 value to switch address spaces.
/// Note: This should only be called from kernel context.
pub fn switch_to_user_page_table(pml4_phys: PhysAddr) {
    use crate::plan9_arch::hal::mmu::cr3_write;
    cr3_write(pml4_phys);
}

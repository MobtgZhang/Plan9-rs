//! Virtual Memory Management
//!
//! Implements kernel virtual memory management including:
//! - Physical page frame allocator
//! - Virtual address space management
//! - Memory mapping operations
//! - Kernel heap allocator

use alloc::vec::Vec;
use crate::plan9_arch::x86_64::paging::{
    self, PteFlags, PageTableEntry, PageTable,
    PageTableIndices, PAGESIZE, PT_ENTRIES, PHYS_MEMORY_VIRT, KERNEL_VIRT_BASE,
    KERNEL_IMAGE_VIRT, LARGE_PAGE_SIZE, kernel_layout,
};
use crate::plan9_common::error::{Error, Result};
use crate::plan9_common::sync::Mutex;
use crate::plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// Physical Frame Allocator
// ============================================================================

/// Physical frame allocator using a bitmap
pub struct FrameAllocator {
    /// Base address of managed physical memory
    base: PhysAddr,
    /// Total number of frames
    total_frames: usize,
    /// Bitmap of allocated frames
    bitmap: &'static mut [u64],
    /// Lock for thread safety
    lock: crate::plan9_common::sync::Spinlock,
}

impl FrameAllocator {
    /// Create a new frame allocator for the given memory region
    pub fn new(base: PhysAddr, size: usize) -> &'static mut Self {
        let frame_size = PAGESIZE;
        let total_frames = size / frame_size;
        let bitmap_words = (total_frames + 63) / 64;

        // Allocate space for the allocator itself (in the managed region)
        let allocator_size = core::mem::size_of::<Self>() + bitmap_words * 8;
        let allocator_base = base;

        // We need static mut for the allocator - this is safe because we're
        // initializing it once at boot
        unsafe {
            let alloc = &mut *(allocator_base.as_u64() as *mut Self);
            core::ptr::write_bytes(alloc, 0, 1);
            alloc.base = base;
            alloc.total_frames = total_frames;

            let bitmap_ptr = (allocator_base.as_u64() + core::mem::size_of::<Self>()) as *mut u64;
            alloc.bitmap = core::slice::from_raw_parts_mut(bitmap_ptr, bitmap_words);
            alloc.bitmap[..bitmap_words].fill(0); // All frames free initially

            alloc
        }
    }

    /// Allocate a single physical frame
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        let _guard = self.lock.lock();

        for (word_idx, &word) in self.bitmap.iter().enumerate() {
            if word != u64::MAX {
                // Find first free bit
                let free_bit = word.trailing_ones() as usize;
                let frame_idx = word_idx * 64 + free_bit;

                if frame_idx < self.total_frames {
                    // Mark as allocated
                    self.bitmap[word_idx] |= 1 << free_bit;
                    return Some(PhysAddr::new(self.base.as_u64() + (frame_idx * PAGESIZE) as u64));
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
            let mut current_word = self.bitmap[word_idx];

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
                                current_word
                            } else {
                                self.bitmap[check_word]
                            };

                            let available_in_word = if check_word == word_idx {
                                (64 - check_bit) as usize
                            } else {
                                64
                            };

                            let needed = remaining.min(available_in_word);
                            let mut check_word_val = word >> check_bit;

                            for i in 0..needed {
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
                        // Allocate the frames
                        let mut rem = count;
                        let mut w = word_idx;
                        let mut b = bit;

                        while rem > 0 {
                            self.bitmap[w] |= 1 << b;
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

        if self.bitmap[word_idx] & (1 << bit) == 0 {
            return Err(Error::Eperm); // Not allocated
        }

        self.bitmap[word_idx] &= !(1 << bit);
        Ok(())
    }

    /// Get total number of frames
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Get number of free frames
    pub fn free_frames(&self) -> usize {
        let _guard = self.lock.lock();
        let mut used = 0;
        for &word in self.bitmap.iter() {
            used += word.count_ones() as usize;
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
        debug_assert!(virt.is_kernel(), "Only kernel mapping supported");
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

        unsafe {
            core::ptr::write(pt_entry_ptr as *mut u64, phys.as_u64() | flags.bits());
        }

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
        unsafe { core::ptr::write(pt_entry_ptr as *mut u64, 0) };

        Ok(())
    }

    /// Get the physical address for a virtual address
    pub fn virt_to_phys(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let entry = paging::walk_page_table_entry(
            PhysAddr::new(self.pml4_virt.as_u64() - KERNEL_VIRT_BASE),
            virt
        )?;

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
        self.map_frame(virt, phys, flags)?;
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
    lock: crate::plan9_common::sync::Spinlock,
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
            lock: crate::plan9_common::sync::Spinlock::new(),
            free_list: None,
        }
    }

    /// Allocate memory from the kernel heap
    /// Uses best-fit strategy from the free list, falls back to bump allocation
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<u64> {
        let _guard = self.lock.lock();

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
        let mut prev: Option<*mut FreeBlock> = None;
        let mut best_fit: Option<*mut FreeBlock> = None;
        let mut best_prev: Option<*mut FreeBlock> = None;
        let mut best_size = usize::MAX;

        let mut current = self.free_list;

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
            unsafe {
                // Remove from free list
                let block = &*block_ptr;
                if let Some(bp) = best_prev {
                    (&mut *bp).next = block.next;
                } else {
                    self.free_list = block.next;
                }

                // If block is much larger than needed, split it
                let remaining = block.size - size;
                if remaining >= core::mem::size_of::<FreeBlock>() + 8 {
                    let new_block_ptr = (block_ptr as *mut u8).add(size) as *mut FreeBlock;
                    (&mut *new_block_ptr).size = remaining;
                    (&mut *new_block_ptr).next = self.free_list;
                    self.free_list = Some(new_block_ptr);
                }

                // Return the block (skip header)
                let data_ptr = (block_ptr as *mut u8).add(core::mem::size_of::<FreeBlock>()) as u64;
                return Some(data_ptr);
            }
        }

        None
    }

    /// Deallocate memory back to the heap
    /// Uses simple coalescing for adjacent free blocks
    pub fn dealloc(&mut self, ptr: u64, size: usize) {
        if ptr == 0 {
            return;
        }

        let _guard = self.lock.lock();

        let aligned_size = (size + 7) & !7;

        // Create a new free block
        let block_ptr = (ptr as *mut u8).sub(core::mem::size_of::<FreeBlock>()) as *mut FreeBlock;

        unsafe {
            (&mut *block_ptr).size = aligned_size;
            (&mut *block_ptr).next = self.free_list;
            self.free_list = Some(block_ptr);

            // Coalesce adjacent free blocks
            self.coalesce();
        }
    }

    /// Coalesce adjacent free blocks
    fn coalesce(&mut self) {
        let mut current = match self.free_list {
            Some(c) => c,
            None => return,
        };

        loop {
            unsafe {
                let next = match (&*current).next {
                    Some(n) => n,
                    None => break,
                };

                // Check if current and next are adjacent
                let current_end = (current as *mut u8).add((&*current).size) as *mut FreeBlock;
                if current_end == next {
                    // Merge the blocks
                    (&mut *current).size += (&*next).size;
                    (&mut *current).next = (&*next).next;
                } else {
                    current = next;
                }
            }
        }
    }

    /// Get current heap usage
    pub fn used(&self) -> usize {
        (self.current - (self.end - self.limit)) as usize
    }

    /// Get remaining heap space
    pub fn available(&self) -> usize {
        // Sum up all free blocks plus bump allocator space
        let mut free_size = 0usize;
        let mut current = self.free_list;
        while let Some(block_ptr) = current {
            unsafe {
                free_size += (&*block_ptr).size;
                current = (&*block_ptr).next;
            }
        }
        free_size + (self.end - self.current) as usize
    }

    /// Expand heap (can only grow, never shrinks)
    pub fn expand(&mut self, additional: usize) {
        self.end += additional as u64;
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
    /// Virtual memory areas
    vmas: [Option<Vma>; 16],
    /// Number of VMAs
    vma_count: usize,
    /// Memory regions
    memory_regions: crate::plan9_common::sync::Mutex<Vec<Vma>>,
}

impl AddressSpace {
    /// Create a new empty address space
    pub fn new() -> Self {
        Self {
            pml4: PhysAddr::null(),
            vmas: [const { None }; 16],
            vma_count: 0,
            memory_regions: crate::plan9_common::sync::Spinlock::new(Vec::new()),
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
    pub fn add_vma(&mut self, vma: Vma) -> Result<()> {
        if self.vma_count >= 16 {
            return Err(Error::Enomem);
        }

        // Check for overlap
        for i in 0..self.vma_count {
            if let Some(existing) = &self.vmas[i] {
                if vma.start.as_u64() < existing.end.as_u64()
                    && vma.end.as_u64() > existing.start.as_u64()
                {
                    return Err(Error::Ebusy); // Overlap
                }
            }
        }

        self.vmas[self.vma_count] = Some(vma);
        self.vma_count += 1;
        Ok(())
    }

    /// Find VMA containing an address
    pub fn find_vma(&self, addr: VirtAddr) -> Option<&Vma> {
        for i in 0..self.vma_count {
            if let Some(vma) = &self.vmas[i] {
                if vma.contains(addr) {
                    return Some(vma);
                }
            }
        }
        None
    }

    /// Map a region
    pub fn mmap(
        &mut self,
        addr: Option<VirtAddr>,
        size: usize,
        flags: VmaFlags,
        _fd: Option<i32>,
        _offset: usize,
    ) -> Result<VirtAddr> {
        let start = addr.unwrap_or_else(|| {
            // Anonymous mapping - find a free region
            // For simplicity, return kernel space address
            VirtAddr::new(kernel_layout::heap_start())
        });

        let vma = Vma::new(start, VirtAddr::new(start.as_u64() + size as u64), flags, "anon");
        self.add_vma(vma)?;

        Ok(start)
    }

    /// Unmap a region
    pub fn munmap(&mut self, addr: VirtAddr, size: usize) -> Result<()> {
        for i in 0..self.vma_count {
            if let Some(vma) = &self.vmas[i] {
                if vma.start == addr && vma.size() == size {
                    self.vmas[i] = None;
                    return Ok(());
                }
            }
        }
        Err(Error::Enoent)
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
// Global Frame Allocator
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};
use crate::plan9_common::types::PhysAddr as CommonPhysAddr;

static FRAME_ALLOCATOR_INSTANCE: AtomicPtr<FrameAllocator> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global frame allocator
/// Called during kernel initialization
pub fn init_allocator(base: CommonPhysAddr, size: usize) {
    let alloc = FrameAllocator::new(base, size);
    let ptr = alloc as *mut FrameAllocator;
    FRAME_ALLOCATOR_INSTANCE.store(ptr, Ordering::SeqCst);
}

/// Get mutable reference to global frame allocator
pub fn frame_allocator() -> &'static mut FrameAllocator {
    unsafe { &mut *FRAME_ALLOCATOR_INSTANCE.load(Ordering::SeqCst) }
}

/// Allocate a physical frame
pub fn alloc_frame() -> Option<PhysAddr> {
    frame_allocator().alloc_frame()
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

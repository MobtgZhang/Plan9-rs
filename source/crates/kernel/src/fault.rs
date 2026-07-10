//! Page fault handling
//!
//! This module implements the page fault handler for demand paging,
//! copy-on-write (COW), and stack expansion.

use alloc::vec::Vec;
use crate::proc::{curproc, Proc, State, SegType};
use crate::plan9_arch::x86_64::paging::{ PAGESIZE, USER_VIRT_END, PteFlags, PT_ENTRIES };
use crate::plan9_arch::x86_64::mmu::{cr2_read, invlpg, PageFaultError};
use crate::plan9_common::types::PhysAddr;

const PAGE_SIZE: u64 = PAGESIZE as u64;
const PAGE_FRAME_MASK: u64 = 0x000_FFFF_FFFF_F000;
const COW_PTE_BIT: u64 = 1 << 9;

// ============================================================================
// Page Fault Handler
// ============================================================================

/// Handle a page fault
/// 
/// This is called from the trap handler when a #PF (page fault) exception occurs.
/// The fault address is read from CR2, and the error code tells us what kind
/// of fault occurred.
pub fn page_fault_handler(frame: &crate::trap::ExceptionFrame) {
    let fault_addr = cr2_read();
    let error = PageFaultError::new(frame.error_code);
    
    // Get current process
    let proc_ptr = match curproc() {
        Some(p) => core::ptr::addr_of!(*p) as *mut Proc,
        None => {
            // No current process - kernel page fault
            panic!(
                "Kernel page fault at {:#018x}, error={:#x} (write={}, user={})",
                fault_addr,
                frame.error_code,
                error.write(),
                error.user()
            );
        }
    };

    // Check if fault was in user mode
    if !error.user() {
        // Supervisor mode fault - this is serious
        panic!(
            "Supervisor page fault at {:#018x}, error={:#x}",
            fault_addr,
            frame.error_code
        );
    }

    // Validate fault address
    if fault_addr >= USER_VIRT_END {
        // Invalid user address
        unsafe { kill_process(&mut *proc_ptr, "invalid address"); }
        return;
    }

    // Handle the fault
    let result = handle_page_fault(unsafe { &mut *proc_ptr }, fault_addr, error);
    
    match result {
        Ok(_) => {
            // Successfully handled, update the page table
            let vaddr = crate::plan9_common::types::VirtAddr::new(fault_addr);
            invlpg(vaddr);
        }
        Err(e) => {
            // Failed to handle - send signal
            unsafe { kill_process(&mut *proc_ptr, e.as_str()); }
        }
    }
}

/// Page fault error types
#[derive(Debug)]
pub enum FaultError {
    /// Address not in any segment
    NoSegment,
    /// Permission denied
    PermissionDenied,
    /// Out of memory
    OutOfMemory,
    /// Invalid address
    InvalidAddress,
    /// Stack expansion failed
    StackFault,
}

impl FaultError {
    pub fn as_str(&self) -> &'static str {
        match self {
            FaultError::NoSegment => "address not in a known segment",
            FaultError::PermissionDenied => "protection fault",
            FaultError::OutOfMemory => "out of memory",
            FaultError::InvalidAddress => "address not in a known segment",
            FaultError::StackFault => "stack guard page",
        }
    }
}

/// Handle a page fault for a process
fn handle_page_fault(proc: &mut Proc, addr: u64, error: PageFaultError) -> Result<(), FaultError> {
    // Find the segment that contains this address (mutable for mapping)
    // Use raw pointer to avoid borrow conflicts
    let _seg_ptr: *mut ProcSegment = core::ptr::null_mut();
    let seg_idx = proc.seg.iter().position(|opt_seg| {
        if let Some(seg) = opt_seg {
            addr >= seg.base && addr < seg.top
        } else {
            false
        }
    }).ok_or(FaultError::NoSegment)?;
    
    // Get pointer to the segment
    let seg_ptr_raw = match proc.seg.get_mut(seg_idx) {
        Some(Some(seg)) => core::ptr::addr_of_mut!(*seg),
        _ => return Err(FaultError::NoSegment),
    };

    // Now use the segment with immutable reference to proc
    let seg = unsafe { &mut *seg_ptr_raw };

    // Check write permission for write faults
    if error.write() && !seg.perm().write() {
        return Err(FaultError::PermissionDenied);
    }

    // Calculate page index within segment
    let offset = addr - seg.base;
    let page_idx = offset / PAGE_SIZE as u64;

    // Check if the page exists in the segment's page table
    let pte = seg.get_pte(page_idx as usize);

    if pte == 0 {
        // Page doesn't exist - need to allocate
        // Extract needed data before mutable borrow ends
        let segtype = seg.segtype;
        let is_cow = seg.is_cow();

        if is_cow || segtype == crate::proc::SegType::Bss {
            // COW or BSS - allocate a new page
            // Re-acquire mutable reference for the call
            let seg_ptr = match proc.seg.get_mut(seg_idx) {
                Some(Some(s)) => core::ptr::addr_of_mut!(*s),
                _ => return Err(FaultError::NoSegment),
            };
            handle_cow_or_zero_page(proc, unsafe { &mut *seg_ptr }, addr, page_idx as usize)
        } else if segtype == crate::proc::SegType::Stack {
            // Stack - expand the stack
            let seg_ptr = match proc.seg.get_mut(seg_idx) {
                Some(Some(s)) => core::ptr::addr_of_mut!(*s),
                _ => return Err(FaultError::NoSegment),
            };
            handle_stack_expansion(proc, unsafe { &mut *seg_ptr }, addr)
        } else {
            // Text or data segment - should have been mapped
            Err(FaultError::NoSegment)
        }
    } else if (pte & PteFlags::PRESENT.bits()) != 0 {
        if error.write() && (pte & PteFlags::WRITABLE.bits()) == 0 {
            let seg_ptr = match proc.seg.get_mut(seg_idx) {
                Some(Some(s)) => core::ptr::addr_of_mut!(*s),
                _ => return Err(FaultError::NoSegment),
            };
            handle_cow_or_zero_page(proc, unsafe { &mut *seg_ptr }, addr, page_idx as usize)
        } else {
            Ok(())
        }
    } else {
        // Page was paged out - need to page in
        handle_swap_in_page(seg, page_idx as usize)
    }
}

/// Find the segment containing a given address (mutable version)
fn find_segment_mut(proc: &mut Proc, addr: u64) -> Option<&mut ProcSegment> {
    for opt_seg in &mut proc.seg {
        if let Some(seg) = opt_seg {
            if addr >= seg.base && addr < seg.top {
                return Some(seg);
            }
        }
    }
    None
}

/// Handle COW (Copy-on-Write) or zero page allocation
fn handle_cow_or_zero_page(
    _proc: &Proc,
    seg: &mut ProcSegment,
    addr: u64,
    page_idx: usize,
) -> Result<(), FaultError> {
    // Get current PTE to check if page exists
    let pte = seg.get_pte(page_idx);
    
    // If page doesn't exist at all, allocate a zero page
    if pte == 0 {
        let frame = match alloc_user_frame() {
            Some(f) => f,
            None => return Err(FaultError::OutOfMemory),
        };
        let frame_idx = (frame.addr / PAGE_SIZE) as usize;
        page_ref::init(frame_idx);
        seg.map_page(addr, frame, false);
        return Ok(());
    }
    
    let is_cow_pte = (pte & COW_PTE_BIT) != 0;
    if !is_cow_pte {
        let frame_addr = pte & PAGE_FRAME_MASK;
        seg.map_page(addr, PhysFrame::new(frame_addr), true);
        return Ok(());
    }
    
    let src_frame_addr = pte & PAGE_FRAME_MASK;
    let src_frame_idx = (src_frame_addr / PAGE_SIZE) as usize;
    if !page_ref::is_shared(src_frame_idx) {
        seg.map_page(addr, PhysFrame::new(src_frame_addr), true);
        return Ok(());
    }
    
    // Allocate a new frame for copy
    let new_frame = match alloc_user_frame() {
        Some(f) => f,
        None => return Err(FaultError::OutOfMemory),
    };
    
    copy_page_content(src_frame_addr, new_frame.addr)?;
    page_ref::decref(src_frame_idx);
    page_ref::init((new_frame.addr / PAGE_SIZE) as usize);
    
    // Map the new frame with write permission
    seg.map_page(addr, new_frame, true);
    
    Ok(())
}

/// Copy page content from source to destination frame
/// 
/// This is a critical operation for COW page handling.
/// Copies PAGE_SIZE bytes from source physical address to destination.
fn copy_page_content(src: u64, dst: u64) -> Result<(), FaultError> {
    use crate::plan9_arch::x86_64::paging::{phys_to_virt, PAGESIZE};
    
    let src_virt = phys_to_virt(crate::plan9_common::types::PhysAddr::new(src));
    let dst_virt = phys_to_virt(crate::plan9_common::types::PhysAddr::new(dst));
    
    // Copy using volatile operations to prevent optimization
    unsafe {
        let src_ptr = src_virt.as_ptr::<u64>();
        let dst_ptr = dst_virt.as_mut_ptr::<u64>();
        let count = PAGESIZE / 8;
        
        for i in 0..count {
            core::ptr::write_volatile(
                dst_ptr.add(i),
                core::ptr::read_volatile(src_ptr.add(i))
            );
        }
    }
    
    Ok(())
}

/// Page reference counting system
/// 
/// This is essential for COW page handling. Each physical frame
/// tracks how many virtual mappings reference it.
pub mod page_ref {
    use alloc::vec::Vec;
    use crate::plan9_common::sync::Spinlock;
    
    /// Reference counts for physical frames, grown on demand.
    static REF_COUNTS: Spinlock<Vec<u32>> = Spinlock::new(Vec::new());
    
    fn ensure_size(counts: &mut Vec<u32>, frame_idx: usize) {
        if frame_idx >= counts.len() {
            counts.resize(frame_idx + 1, 0);
        }
    }
    
    /// Increment reference count for a frame
    pub fn incref(frame_idx: usize) {
        let mut counts = REF_COUNTS.lock();
        ensure_size(&mut counts, frame_idx);
        counts[frame_idx] = counts[frame_idx].saturating_add(1);
    }
    
    /// Decrement reference count for a frame
    /// Returns the new reference count
    pub fn decref(frame_idx: usize) -> u32 {
        let mut counts = REF_COUNTS.lock();
        if frame_idx >= counts.len() {
            return 0;
        }
        counts[frame_idx] = counts[frame_idx].saturating_sub(1);
        counts[frame_idx]
    }
    
    /// Get current reference count
    pub fn get_refcount(frame_idx: usize) -> u32 {
        let counts = REF_COUNTS.lock();
        if frame_idx < counts.len() {
            counts[frame_idx]
        } else {
            0
        }
    }
    
    /// Check if a frame is shared (refcount > 1)
    pub fn is_shared(frame_idx: usize) -> bool {
        get_refcount(frame_idx) > 1
    }
    
    /// Initialize reference count for a new frame
    pub fn init(frame_idx: usize) {
        let mut counts = REF_COUNTS.lock();
        ensure_size(&mut counts, frame_idx);
        counts[frame_idx] = 1;
    }
}

/// COW page handling during fork
/// 
/// When a process forks, all its pages are marked as COW.
/// This function sets up COW mappings for the child process.
/// 
/// For each writable page in the parent's segments:
/// 1. Find the corresponding child segment
/// 2. Copy the PTE (page table entry) to child's page table
/// 3. Mark both pages as COW (read-only)
/// 4. Increment reference count on the physical frame
pub fn setup_cow_for_fork(child: &mut Proc, parent: &Proc) -> Result<(), FaultError> {
    // Walk through all segments in parent
    for (i, parent_seg) in parent.seg.iter().enumerate() {
        if let Some(seg) = parent_seg {
            // Skip read-only segments (text segment)
            if !seg.can_write() {
                continue;
            }

            // Find corresponding child segment
            let child_seg = match child.seg.get_mut(i) {
                Some(Some(cs)) => cs,
                _ => continue,
            };

            // Walk through all pages in this segment
            let page_count = seg.page_count();
            // Collect PTEs first to avoid borrow conflict
            let ptes: Vec<u64> = (0..page_count).map(|i| seg.get_pte(i)).collect();
            for page_idx in 0..page_count {
                let pte = ptes[page_idx as usize];

                // Skip if page not present
                if (pte & PteFlags::PRESENT.bits()) == 0 {
                    continue;
                }

                let frame_addr = pte & PAGE_FRAME_MASK;

                // Create a COW PTE: present, user, read-only, and marked with bit 9.
                let flags = PteFlags::new((pte & 0xFFF) & !PteFlags::WRITABLE.bits())
                    | PteFlags::PRESENT
                    | PteFlags::USER;
                let cow_pte = frame_addr | flags.bits() | COW_PTE_BIT;

                // Set the COW PTE in child's page table (also COW)
                child_seg.set_pte(page_idx, cow_pte);

                // Increment reference count on the physical frame
                let frame_idx = (frame_addr / PAGE_SIZE) as usize;
                if page_ref::get_refcount(frame_idx) == 0 {
                    page_ref::init(frame_idx);
                }
                page_ref::incref(frame_idx);
            }
        }
    }

    Ok(())
}

/// Handle a write fault on a COW page
/// 
/// This is called when a process tries to write to a COW page.
/// It creates a private copy of the page for this process.
pub fn handle_cow_write(
    proc: &mut Proc,
    addr: u64,
) -> Result<(), FaultError> {
    // Find the segment containing this address
    let seg = match find_segment_mut(proc, addr) {
        Some(s) => s,
        None => return Err(FaultError::NoSegment),
    };
    
    // Calculate page index
    let offset = addr - seg.base;
    let page_idx = (offset / PAGE_SIZE as u64) as usize;
    
    // Get current PTE
    let pte = seg.get_pte(page_idx);
    if pte == 0 {
        return Err(FaultError::NoSegment);
    }
    
    // Get frame address
    let frame_addr = pte & PAGE_FRAME_MASK;
    let frame_idx = (frame_addr / PAGE_SIZE) as usize;
    
    if (pte & COW_PTE_BIT) == 0 {
        seg.map_page(addr, PhysFrame::new(frame_addr), true);
        return Ok(());
    }
    
    // Check if page is shared
    if page_ref::is_shared(frame_idx) {
        // Allocate new frame
        let new_frame = match alloc_user_frame() {
            Some(f) => f,
            None => return Err(FaultError::OutOfMemory),
        };
        
        // Copy content
        copy_page_content(frame_addr, new_frame.addr)?;
        
        // Decrement old frame refcount
        page_ref::decref(frame_idx);
        page_ref::init((new_frame.addr / PAGE_SIZE) as usize);
        
        // Update PTE with new frame (writable, not COW)
        seg.map_page(addr, new_frame, true);
    } else {
        // Page is private - just make it writable and clear COW
        seg.map_page(addr, PhysFrame::new(frame_addr), true);
    }
    
    Ok(())
}

/// Handle stack expansion
fn handle_stack_expansion(
    _proc: &Proc,
    seg: &mut ProcSegment,
    addr: u64,
) -> Result<(), FaultError> {
    // Stack grows downward
    let page_addr = addr & !(PAGE_SIZE - 1);
    let page_end = page_addr.saturating_add(PAGE_SIZE);

    // Check if we're expanding into the guard page
    let guard_size = PAGE_SIZE * 4; // 4 pages of guard
    let lower_limit = seg.top.saturating_sub(seg.size() as u64).saturating_sub(guard_size);
    if page_addr < lower_limit {
        return Err(FaultError::StackFault);
    }

    // Allocate a new frame for the stack
    let frame = match alloc_user_frame() {
        Some(f) => f,
        None => return Err(FaultError::OutOfMemory),
    };
    page_ref::init((frame.addr / PAGE_SIZE) as usize);

    // Map the frame and expand the segment limit if this fault extends it.
    seg.map_page(page_addr, frame, true);
    if page_end > seg.top {
        seg.top = page_end;
    }

    Ok(())
}

/// Handle swapping a page back in from disk
///
/// This function is called when a page fault occurs for a page that has
/// been swapped out. The page's PTE should contain the swap offset
/// in its high bits.
fn handle_swap_in(
    seg: &mut ProcSegment,
    _addr: u64,
    page_idx: usize,
) -> Result<(), FaultError> {
    // Get the swap offset from the PTE
    // In Plan 9, the swap offset is stored in the PTE when the page is swapped out
    let pte = seg.get_pte(page_idx);
    let swap_offset = (pte >> 12) & 0x7FFF_FFFF; // Bits 12-40 hold swap offset
    
    if swap_offset == 0 {
        // No swap offset - shouldn't happen if called correctly
        // Just allocate a new page
        let frame = match alloc_user_frame() {
            Some(f) => f,
            None => return Err(FaultError::OutOfMemory),
        };
        seg.set_pte(page_idx, frame.addr);
        return Ok(());
    }
    
    // Allocate a physical frame for the incoming page
    let frame = match alloc_user_frame() {
        Some(f) => f,
        None => {
            // No memory - try to free some by kicking the pager
            crate::swap::kick_pager();
            // Retry allocation
            match alloc_user_frame() {
                Some(f) => f,
                None => return Err(FaultError::OutOfMemory),
            }
        }
    };
    
    // Read the page from swap
    // Convert swap offset to byte offset
    let swap_byte_offset = (swap_offset as usize) * 4096;
    
    // Perform the actual swap I/O
    if let Err(_) = crate::swap::read_page_from_swap(frame.addr, swap_byte_offset) {
        // I/O error - release the frame and return error
        free_user_frame(frame);
        return Err(FaultError::OutOfMemory);
    }
    
    // Update the PTE with the new frame address
    // The page is now present, not in swap
    let flags = if seg.is_cow() {
        // COW page - read-only initially
        crate::plan9_arch::x86_64::paging::PteFlags::PRESENT.bits()
            | crate::plan9_arch::x86_64::paging::PteFlags::USER.bits()
    } else {
        // Regular page - use segment's permissions
        seg.perm().to_flags().bits()
    };
    seg.set_pte(page_idx, frame.addr | flags);
    
    // Free the swap slot
    crate::swap::free_swap(swap_byte_offset as usize);
    
    // Update statistics
    crate::swap::swap_manager().stats();
    
    Ok(())
}

/// Handle swap-in when we already have the page_idx
fn handle_swap_in_page(seg: &mut ProcSegment, page_idx: usize) -> Result<(), FaultError> {
    // Redirect to the full function
    handle_swap_in(seg, 0, page_idx)
}

// ============================================================================
// Segment Extension (for page fault handling)
// ============================================================================

use crate::proc::ProcSegment;
use crate::proc::SegType as ProcSegType;
// use crate::segment::ProcSegmentPerm;

/// Extension trait for ProcSegment to support page fault handling
impl ProcSegment {
    /// Check if segment uses copy-on-write
    pub fn is_cow(&self) -> bool {
        // COW is typically used for data and BSS segments
        matches!(self.segtype, ProcSegType::Data | ProcSegType::Bss)
    }

    /// Check if segment is readable
    pub fn can_read(&self) -> bool {
        // For now, all segments are readable
        true
    }

    /// Check if segment is writable
    pub fn can_write(&self) -> bool {
        matches!(
            self.segtype,
            SegType::Data | SegType::Bss | SegType::Stack | SegType::Physical
        )
    }

    /// Check if segment is executable
    pub fn can_exec(&self) -> bool {
        matches!(self.segtype, SegType::Text)
    }

    /// Map a page into this segment
    ///
    /// Updates both the segment's page_table and the process's actual page table.
    pub fn map_page(&mut self, addr: u64, frame: PhysFrame, writable: bool) {
        
        use crate::plan9_arch::x86_64::paging::{
            phys_to_virt, PageTableIndices, PteFlags, PAGESIZE,
//             KERNEL_VIRT_BASE, PT_ENTRIES,
        };
        use crate::proc::curproc;

        // Calculate page index within segment
        let offset = addr - self.base;
        let page_idx = (offset / PAGESIZE as u64) as usize;

        // Build the PTE value
        let mut flags = PteFlags::PRESENT | PteFlags::USER;
        if writable {
            flags = PteFlags::new(flags.bits() | PteFlags::WRITABLE.bits());
        }

        // Update segment's page table
        self.set_pte(page_idx, frame.addr | flags.bits());

        // Walk the process's page table and create entries
        if let Some(proc) = curproc() {
            let pml4_phys = proc.mmupdb;
            let indices = PageTableIndices::from_virt(
                crate::plan9_common::types::VirtAddr::new(addr)
            );

            // Get PML4 virtual address
            let pml4_virt = phys_to_virt(pml4_phys);

            // PML4 entry
            let pml4_entry_ptr = (pml4_virt.as_u64() + indices.pml4 as u64 * 8) as *mut u64;
            if unsafe { *pml4_entry_ptr } == 0 {
                // Allocate PDPT
                if let Some(pdpt_frame) = crate::vm::alloc_frame() {
                    let pdpt_virt = phys_to_virt(pdpt_frame);
                    unsafe {
                        core::ptr::write_bytes(pdpt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
                        *pml4_entry_ptr = pdpt_frame.as_u64() | PteFlags::PRESENT.bits() | PteFlags::WRITABLE.bits();
                    }
                } else {
                    return;
                }
            }

            // PDPT entry
            let pdpt_phys = PhysAddr::new(unsafe { *pml4_entry_ptr } & 0x000_FFFF_FFFF_F000);
            let pdpt_virt = phys_to_virt(pdpt_phys);
            let pdpt_entry_ptr = (pdpt_virt.as_u64() + indices.pdpt as u64 * 8) as *mut u64;
            if unsafe { *pdpt_entry_ptr } == 0 {
                if let Some(pd_frame) = crate::vm::alloc_frame() {
                    let pd_virt = phys_to_virt(pd_frame);
                    unsafe {
                        core::ptr::write_bytes(pd_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
                        *pdpt_entry_ptr = pd_frame.as_u64() | PteFlags::PRESENT.bits() | PteFlags::WRITABLE.bits();
                    }
                } else {
                    return;
                }
            }

            // PD entry
            let pd_phys = PhysAddr::new(unsafe { *pdpt_entry_ptr } & 0x000_FFFF_FFFF_F000);
            let pd_virt = phys_to_virt(pd_phys);
            let pd_entry_ptr = (pd_virt.as_u64() + indices.pd as u64 * 8) as *mut u64;
            if unsafe { *pd_entry_ptr } == 0 {
                if let Some(pt_frame) = crate::vm::alloc_frame() {
                    let pt_virt = phys_to_virt(pt_frame);
                    unsafe {
                        core::ptr::write_bytes(pt_virt.as_mut_ptr::<u64>(), 0, PT_ENTRIES);
                        *pd_entry_ptr = pt_frame.as_u64() | PteFlags::PRESENT.bits() | PteFlags::WRITABLE.bits();
                    }
                } else {
                    return;
                }
            }

            // PT entry - finally set the mapping
            let pt_phys = PhysAddr::new(unsafe { *pd_entry_ptr } & 0x000_FFFF_FFFF_F000);
            let pt_virt = phys_to_virt(pt_phys);
            let pt_entry_ptr = (pt_virt.as_u64() + indices.pt as u64 * 8) as *mut u64;
            unsafe {
                *pt_entry_ptr = frame.addr | flags.bits();
            }

            // Flush TLB for this address
            use crate::plan9_arch::x86_64::mmu::invlpg;
            invlpg(crate::plan9_common::types::VirtAddr::new(addr));
        }
    }
}

/// Physical frame identifier
#[derive(Debug, Clone, Copy)]
pub struct PhysFrame {
    pub addr: u64,
    pub refcount: u32,
}

impl PhysFrame {
    pub fn new(addr: u64) -> Self {
        Self { addr, refcount: 1 }
    }

    pub fn inc_ref(&mut self) {
        self.refcount += 1;
    }

    pub fn dec_ref(&mut self) {
        self.refcount = self.refcount.saturating_sub(1);
    }
}

// ============================================================================
// Frame Allocation
// ============================================================================

/// Allocate a user frame
///
/// Allocates a physical frame from the global allocator and zeros it.
fn alloc_user_frame() -> Option<PhysFrame> {
    use crate::vm::frame_allocator;
    use crate::plan9_arch::x86_64::paging::phys_to_virt;
    use crate::plan9_arch::x86_64::paging::PAGESIZE;

    let allocator = frame_allocator();
    let phys = allocator.alloc_frame()?;

    // Zero the frame to avoid leaking data
    let virt = phys_to_virt(phys);
    unsafe {
        core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, PAGESIZE);
    }

    Some(PhysFrame { addr: phys.as_u64(), refcount: 1 })
}

/// Free a user frame
fn free_user_frame(frame: PhysFrame) {
    use crate::vm::frame_allocator;
    use crate::plan9_common::types::PhysAddr;
    

    // Reference counting would be implemented here:
    // In a full implementation, frames would have a reference count
    // and only be freed when count reaches zero
    
    // For now, just free the frame directly
    let _ = frame;
    let _ = frame_allocator().free_frame(PhysAddr::new(frame.addr));
}

// ============================================================================
// Signal Sending
// ============================================================================

/// Kill a process with a signal
fn kill_process(proc: &mut Proc, _msg: &str) {
    // Send SIGSEGV to the process
    // This would:
    // 1. Set up the note with the error message
    // 2. If the process has a signal handler, jump to it
    // 3. Otherwise, terminate the process
    
    // Mark for termination
    proc.state = State::Moribund;
    
    // Log for debugging. The kmesg call is cheap and helpful so we keep it
    // in both debug and release builds; the call site is preserved as a
    // single point that can later be moved behind a runtime toggle.
    crate::kmesg::kmesg_puts(b"Process killed\n");
}

// ============================================================================
// Permission Structure
// ============================================================================

/// Segment permissions
#[derive(Debug, Clone, Copy)]
pub struct SegmentPerm {
    read: bool,
    write: bool,
    exec: bool,
}

impl SegmentPerm {
    pub fn new(read: bool, write: bool, exec: bool) -> Self {
        Self { read, write, exec }
    }

    pub fn read(&self) -> bool {
        self.read
    }

    pub fn write(&self) -> bool {
        self.write
    }

    pub fn exec(&self) -> bool {
        self.exec
    }

    pub fn to_flags(&self) -> PteFlags {
        let mut flags = PteFlags::PRESENT;
        if self.read {
            flags = flags | PteFlags::USER;
        }
        if self.write {
            flags = flags | PteFlags::WRITABLE;
        }
        if !self.exec {
            flags = flags | PteFlags::NX;
        }
        flags
    }
}

impl ProcSegment {
    /// Get segment permissions
    pub fn perm(&self) -> SegmentPerm {
        SegmentPerm::new(self.can_read(), self.can_write(), self.can_exec())
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Signal number for segmentation fault
pub const SIGSEGV: i32 = 11;

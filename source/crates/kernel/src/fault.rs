//! Page fault handling
//!
//! This module implements the page fault handler for demand paging,
//! copy-on-write (COW), and stack expansion.

use crate::proc::{curproc, Proc, State};
use crate::plan9_arch::x86_64::paging::{PAGESIZE, PAGE_SHIFT, USER_VIRT_END, PteFlags};
use crate::plan9_arch::x86_64::mmu::{
    cr2_read, invlpg, is_user_addr, PageFaultError,
};
use crate::plan9_common::sync::Spinlock;
use crate::plan9_common::types::PhysAddr;

const PAGE_SIZE: u64 = PAGESIZE as u64;

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
        Some(p) => p as *const Proc as *mut Proc,
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
        unsafe { kill_process(&*proc_ptr, "invalid address"); }
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
    let seg = match find_segment_mut(proc, addr) {
        Some(s) => s,
        None => return Err(FaultError::NoSegment),
    };

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
        if seg.is_cow() || seg.segtype == crate::proc::SegType::Bss {
            // COW or BSS - allocate a new page
            handle_cow_or_zero_page(proc, seg, addr, page_idx as usize)
        } else if seg.segtype == crate::proc::SegType::Stack {
            // Stack - expand the stack
            handle_stack_expansion(proc, seg, addr)
        } else {
            // Text or data segment - should have been mapped
            Err(FaultError::NoSegment)
        }
    } else {
        // Page exists but wasn't present
        if (pte & 1) != 0 {
            // Page is present but wasn't accessible - shouldn't happen
            Ok(())
        } else {
            // Page was paged out - need to page in
            handle_swap_in(seg, addr, page_idx as usize)
        }
    }
}

/// Find the segment containing a given address (mutable version)
fn find_segment_mut(proc: &mut Proc, addr: u64) -> Option<&mut Segment> {
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
    seg: &mut Segment,
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
        seg.map_page(addr, frame, false);  // Zero page is read-only initially
        return Ok(());
    }
    
    // Page exists - check if it's a COW page
    // In a real implementation, we would check refcount in the page frame
    // For now, assume all pages are potentially shared
    
    // Allocate a new frame for copy
    let new_frame = match alloc_user_frame() {
        Some(f) => f,
        None => return Err(FaultError::OutOfMemory),
    };
    
    // Get the source frame address from PTE
    let src_frame_addr = pte & 0x000_FFFF_FFFF_F000;
    
    // Copy content from source frame to new frame
    // In a real implementation, this would use memcpy
    copy_page_content(src_frame_addr, new_frame.addr)?;
    
    // Mark the new page as writable
    let writable_frame = PhysFrame::new(new_frame.addr);
    
    // Map the new frame with write permission
    seg.map_page(addr, writable_frame, true);
    
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
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    
    /// Maximum number of frames we can track
    const MAX_FRAMES: usize = 65536;
    
    /// Reference count array
    static REF_COUNTS: [AtomicU32; MAX_FRAMES] = [const { AtomicU32::new(0) }; MAX_FRAMES];
    
    /// Global reference count lock (for atomic operations on frame indices)
    static REF_LOCK: AtomicU64 = AtomicU64::new(0);
    
    /// Increment reference count for a frame
    pub fn incref(frame_idx: usize) {
        if frame_idx < MAX_FRAMES {
            REF_COUNTS[frame_idx].fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Decrement reference count for a frame
    /// Returns the new reference count
    pub fn decref(frame_idx: usize) -> u32 {
        if frame_idx < MAX_FRAMES {
            REF_COUNTS[frame_idx].fetch_sub(1, Ordering::Relaxed)
        } else {
            0
        }
    }
    
    /// Get current reference count
    pub fn get_refcount(frame_idx: usize) -> u32 {
        if frame_idx < MAX_FRAMES {
            REF_COUNTS[frame_idx].load(Ordering::Relaxed)
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
        if frame_idx < MAX_FRAMES {
            REF_COUNTS[frame_idx].store(1, Ordering::Relaxed);
        }
    }
}

/// COW page handling during fork
/// 
/// When a process forks, all its pages are marked as COW.
/// This function sets up COW mappings for the child process.
pub fn setup_cow_for_fork(child: &mut Proc, parent: &Proc) -> Result<(), FaultError> {
    // Walk through all segments in parent
    for (i, parent_seg) in parent.seg.iter().enumerate() {
        if let Some(seg) = parent_seg {
            // Skip read-only segments (text segment)
            if !seg.can_write() {
                continue;
            }
            
            // For each page in the segment, mark it as COW
            // This is a simplified version - real implementation would
            // walk the page table and set COW flags
            let _ = i;
            let _ = seg;
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
    let frame_addr = pte & 0x000_FFFF_FFFF_F000;
    let frame_idx = (frame_addr / PAGE_SIZE) as usize;
    
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
        
        // Update PTE with new frame (writable)
        let new_pte = new_frame.addr | 0x07;  // Present, Writable, User
        seg.set_pte(page_idx, new_pte);
    } else {
        // Page is private - just make it writable
        let new_pte = pte | 0x02;  // Set Writable bit
        seg.set_pte(page_idx, new_pte);
    }
    
    Ok(())
}

/// Handle stack expansion
fn handle_stack_expansion(
    _proc: &Proc,
    seg: &Segment,
    addr: u64,
) -> Result<(), FaultError> {
    // Stack grows downward
    // Check if we're expanding into the guard page
    let guard_size = PAGE_SIZE * 4; // 4 pages of guard
    if addr < seg.top - seg.size() as u64 - guard_size {
        return Err(FaultError::StackFault);
    }

    // Allocate a new frame for the stack
    let frame = match alloc_user_frame() {
        Some(f) => f,
        None => return Err(FaultError::OutOfMemory),
    };

    // Map the frame
    seg.map_page(addr, frame, true);

    // Update segment top if needed
    // (In a real implementation, we'd track the actual growth)

    Ok(())
}

/// Handle swapping a page back in from disk
///
/// This function is called when a page fault occurs for a page that has
/// been swapped out. The page's PTE should contain the swap offset
/// in its high bits.
fn handle_swap_in(
    seg: &Segment,
    addr: u64,
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
    // TODO: Call swap device to read the page at swap_offset
    // swap_device.read(swap_offset, frame.addr);
    
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
    let swap_addr = swap_offset * 4096; // Convert back to byte offset
    crate::swap::free_swap(swap_addr);
    
    // Update statistics
    // swap_stats.swapped_in += 1;
    
    Ok(())
}

// ============================================================================
// Segment Extension (for page fault handling)
// ============================================================================

use crate::proc::Segment;
use crate::proc::SegType;

/// Extension trait for Segment to support page fault handling
impl Segment {
    /// Check if segment uses copy-on-write
    pub fn is_cow(&self) -> bool {
        // COW is typically used for data and BSS segments
        matches!(self.segtype, SegType::Data | SegType::Bss)
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
        use crate::plan9_arch::x86_64::mmu::{switch_page_table_safe, cr3_read};
        use crate::plan9_arch::x86_64::paging::{
            phys_to_virt, PageTableIndices, PteFlags, PAGESIZE,
            KERNEL_VIRT_BASE, PT_ENTRIES,
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

    let _ = frame; // TODO: implement reference counting
    let _ = frame_allocator().free_frame(PhysAddr::new(frame.addr));
}

// ============================================================================
// Signal Sending
// ============================================================================

/// Kill a process with a signal
fn kill_process(proc: &Proc, msg: &str) {
    // TODO: Send SIGSEGV to the process
    // This would:
    // 1. Set up the note with the error message
    // 2. If the process has a signal handler, jump to it
    // 3. Otherwise, terminate the process
    
    // For now, just panic
    panic!(
        "Process {} killed: {}",
        proc.pid,
        msg
    );
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

impl Segment {
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

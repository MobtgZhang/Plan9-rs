//! Segment Management
//!
//! Implements memory segment management including:
//! - Segment types (text, data, bss, stack)
//! - Page table management for segments
//! - Fault handling for demand paging
//! - COW (Copy-on-Write) support

use alloc::boxed::Box;
use crate::plan9_common::sync::{ Mutex };
// ============================================================================
// Constants
// ============================================================================

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Large page size (2MB)
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Page mask
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Maximum address space size
pub const MAX_VADDR: u64 = 0x0000_7FFF_FFFF_FFFF; // 47-bit user space

/// Kernel space base
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;

/// User space base
pub const USER_BASE: u64 = 0x0000_0000_4000_00;

/// Link-time image range used by the non-PIE user ELFs.  Absolute pointers
/// found in .got / .data.rel.ro must lie in this range to be relocated.
pub const USER_IMAGE_BASE: u64 = 0x0000_0000_0020_0000;
pub const USER_IMAGE_LIMIT: u64 = 0x0000_0000_0030_0000;

/// Stack base (high address, grows down)
pub const USER_STACK_TOP: u64 = MAX_VADDR;
pub const USER_STACK_BASE: u64 = MAX_VADDR - (8 * 1024 * 1024);

// ============================================================================
// Segment Types
// ============================================================================

/// Segment type constants
pub mod segtype {
    pub const NONE: u8 = 0;
    pub const TEXT: u8 = 1;
    pub const DATA: u8 = 2;
    pub const BSS: u8 = 3;
    pub const STACK: u8 = 4;
    pub const SHARED: u8 = 5;
    pub const PHYSICAL: u8 = 6;
    pub const MAPPED: u8 = 7;
}

/// Segment flags
#[derive(Debug, Clone, Copy)]
pub struct SegFlags(u32);

impl SegFlags {
    pub const R: u32 = 0x01;     // Read
    pub const W: u32 = 0x02;     // Write
    pub const X: u32 = 0x04;     // Execute
    pub const C: u32 = 0x08;     // Copy-on-write
    pub const A: u32 = 0x10;     // Accessed
    pub const D: u32 = 0x20;     // Dirty
    pub const U: u32 = 0x40;     // User accessible
    pub const G: u32 = 0x80;     // Global

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }

    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    pub fn bits(&self) -> u32 {
        self.0
    }
}

// Re-export ProcSegment for backward compatibility
pub use crate::proc::ProcSegment;

// ============================================================================
// Page Table Entry
// ============================================================================

/// Page table entry (x86_64)
#[derive(Debug, Clone, Copy)]
pub struct Pte {
    /// Raw value
    pub val: u64,
}

impl Pte {
    /// Create new PTE
    pub fn new(addr: u64, flags: PteFlags) -> Self {
        Self { val: addr | flags.bits() }
    }

    /// Get physical address from PTE
    pub fn addr(&self) -> u64 {
        self.val & 0x000_FFFF_FFFF_F000
    }

    /// Check if present
    pub fn present(&self) -> bool {
        (self.val & 1) != 0
    }

    /// Check if writable
    pub fn writable(&self) -> bool {
        (self.val & 2) != 0
    }

    /// Check if user accessible
    pub fn user(&self) -> bool {
        (self.val & 4) != 0
    }

    /// Check if accessed
    pub fn accessed(&self) -> bool {
        (self.val & 0x20) != 0
    }

    /// Check if dirty
    pub fn dirty(&self) -> bool {
        (self.val & 0x40) != 0
    }

    /// Check if it's a large page (2MB)
    pub fn large(&self) -> bool {
        (self.val & 0x80) != 0
    }

    /// Check if no-execute
    pub fn nx(&self) -> bool {
        (self.val & 0x8000_0000_0000_0000) != 0
    }

    /// Clear the entry
    pub fn clear(&mut self) {
        self.val = 0;
    }
}

/// Page table entry flags
#[derive(Debug, Clone, Copy)]
pub struct PteFlags(u64);

impl PteFlags {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Writable bit
    pub const WRITABLE: u64 = 1 << 1;
    /// User accessible bit
    pub const USER: u64 = 1 << 2;
    /// Write-through bit
    pub const PWT: u64 = 1 << 3;
    /// Cache disable bit
    pub const PCD: u64 = 1 << 4;
    /// Accessed bit
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty bit
    pub const DIRTY: u64 = 1 << 6;
    /// Page size (large page)
    pub const LARGE: u64 = 1 << 7;
    /// Global bit
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute bit
    pub const NX: u64 = 1 << 63;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u64) -> Self {
        self.0 |= flag;
        self
    }

    pub fn bits(&self) -> u64 {
        self.0
    }
}

// ============================================================================
// Memory Segment
// ============================================================================

/// Memory segment descriptor
#[derive(Debug)]
pub struct Segment {
    /// Segment type
    pub segtype: u8,
    /// Base virtual address
    pub base: u64,
    /// Top address (exclusive)
    pub top: u64,
    /// File start offset (for text segment)
    pub fstart: u64,
    /// File length
    pub flen: u64,
    /// Memory length (may differ from flen for BSS)
    pub mlen: u64,
    /// Permission flags
    pub flags: SegFlags,
    /// Reference count
    refcount: Mutex<u32>,
    /// Image file (for text segment)
    image: Option<*const u8>,
}

impl Segment {
    /// Create a new segment
    pub fn new(segtype: u8, base: u64, size: u64, flags: SegFlags) -> Self {
        Self {
            segtype,
            base,
            top: base + size,
            fstart: 0,
            flen: size,
            mlen: size,
            flags,
            refcount: Mutex::new(1),
            image: None,
        }
    }

    /// Create text segment
    pub fn text(base: u64, size: u64) -> Self {
        Self::new(segtype::TEXT, base, size, 
            SegFlags::new().with(SegFlags::R).with(SegFlags::X))
    }

    /// Create data segment
    pub fn data(base: u64, size: u64) -> Self {
        Self::new(segtype::DATA, base, size,
            SegFlags::new().with(SegFlags::R).with(SegFlags::W))
    }

    /// Create BSS segment (uninitialized data)
    pub fn bss(base: u64, size: u64) -> Self {
        Self::new(segtype::BSS, base, size,
            SegFlags::new().with(SegFlags::R).with(SegFlags::W))
    }

    /// Create stack segment
    pub fn stack(base: u64, size: u64) -> Self {
        Self::new(segtype::STACK, base, size,
            SegFlags::new().with(SegFlags::R).with(SegFlags::W).with(SegFlags::G))
    }

    /// Get segment size
    pub fn size(&self) -> u64 {
        self.top - self.base
    }

    /// Check if address is in segment
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.top
    }

    /// Increment reference count
    pub fn incref(&self) {
        *self.refcount.lock() += 1;
    }

    /// Decrement reference count
    pub fn decref(&self) -> u32 {
        let mut count = self.refcount.lock();
        *count = count.saturating_sub(1);
        *count
    }

    /// Get reference count
    pub fn refcount(&self) -> u32 {
        *self.refcount.lock()
    }
}

// ============================================================================
// Fault Handling
// ============================================================================

/// Fault type
#[derive(Debug, Clone, Copy)]
pub enum FaultType {
    /// Read fault
    Read,
    /// Write fault
    Write,
    /// Execute fault
    Execute,
}

/// Page fault result
#[derive(Debug)]
pub enum FaultResult {
    /// Fault was handled successfully
    Ok,
    /// Fault was a page fault, page was allocated
    PageAllocated,
    /// Fault indicates an error
    Error,
    /// Fault indicatesseg should be killed
    Killed,
}

/// Global fault handler function type
type FaultHandler = fn(u64, FaultType) -> FaultResult;

/// Global fault handler
static FAULT_HANDLER: Mutex<Option<FaultHandler>> = Mutex::new(None);

/// Register a fault handler
pub fn set_fault_handler(handler: FaultHandler) {
    *FAULT_HANDLER.lock() = Some(handler);
}

/// Handle a page fault
pub fn fault(addr: u64, write: bool) -> FaultResult {
    // Get current process's fault handler
    let handler = FAULT_HANDLER.lock();
    
    if let Some(h) = *handler {
        let ftype = if write { FaultType::Write } else { FaultType::Read };
        h(addr, ftype)
    } else {
        // Default: return error
        FaultResult::Error
    }
}

// ============================================================================
// Segment Table
// ============================================================================

/// Maximum segments per process
pub const NSEG: usize = 10;

/// Segment table for a process
#[derive(Debug)]
pub struct SegmentTable {
    /// Array of segments
    segments: [Option<Box<Segment>>; NSEG],
}

impl SegmentTable {
    /// Create empty segment table
    pub fn new() -> Self {
        Self {
            segments: [const { None }; NSEG],
        }
    }

    /// Add a segment
    pub fn add(&mut self, seg: Box<Segment>) -> Option<usize> {
        for (i, slot) in self.segments.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(seg);
                return Some(i);
            }
        }
        None
    }

    /// Get segment by index
    pub fn get(&self, i: usize) -> Option<&Segment> {
        if i < NSEG {
            self.segments[i].as_deref()
        } else {
            None
        }
    }

    /// Get mutable segment by index
    pub fn get_mut(&mut self, i: usize) -> Option<&mut Segment> {
        if i < NSEG {
            self.segments[i].as_deref_mut()
        } else {
            None
        }
    }

    /// Remove segment by index
    pub fn remove(&mut self, i: usize) -> Option<Box<Segment>> {
        if i < NSEG {
            self.segments[i].take()
        } else {
            None
        }
    }

    /// Find segment containing address
    pub fn find(&self, addr: u64) -> Option<&Segment> {
        for seg in &self.segments {
            if let Some(s) = seg.as_deref() {
                if s.contains(addr) {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Find free slot
    pub fn find_free(&self) -> Option<usize> {
        for (i, slot) in self.segments.iter().enumerate() {
            if slot.is_none() {
                return Some(i);
            }
        }
        None
    }
}

// ============================================================================
// COW (Copy-on-Write)
// ============================================================================

/// COW page reference
pub struct CowPage {
    /// Physical address
    pub phys: u64,
    /// Reference count
    pub refcount: Mutex<u32>,
}

impl CowPage {
    /// Create new COW page
    pub fn new(phys: u64) -> Self {
        Self {
            phys,
            refcount: Mutex::new(2), // Initial: parent + child
        }
    }

    /// Copy the page (allocate new physical page)
    pub fn copy(&self) -> u64 {
        match crate::vm::alloc_frame() {
            Some(frame) => frame.as_u64(),
            None => 0,
        }
    }

    /// Increment reference
    pub fn incref(&self) {
        *self.refcount.lock() += 1;
    }

    /// Decrement reference, return true if should be freed
    pub fn decref(&self) -> bool {
        let mut count = self.refcount.lock();
        *count = count.saturating_sub(1);
        *count == 0
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if address is in user space
pub fn is_user_addr(addr: u64) -> bool {
    addr < KERNEL_BASE
}

/// Check if address is in kernel space
pub fn is_kernel_addr(addr: u64) -> bool {
    addr >= KERNEL_BASE
}

/// Align address down to page boundary
pub fn page_align_down(addr: u64) -> u64 {
    addr & PAGE_MASK
}

/// Align address up to page boundary
pub fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & PAGE_MASK
}

/// Get page number from address
pub fn page_num(addr: u64) -> u64 {
    addr >> 12
}

/// Get offset within page
pub fn page_offset(addr: u64) -> u64 {
    addr & !PAGE_MASK
}

/// Convert virtual page number to index in page table level
pub fn pte_index(vpn: u64, level: usize) -> usize {
    (vpn >> (9 * level)) as usize & 0x1FF
}

// ============================================================================
// TLB Management
// ============================================================================

/// Flush TLB for a range of addresses
pub fn tlb_flush_range(_start: u64, _count: u64) {
    // In a real implementation, this would use INVLPG or flush entire TLB
    // For now, we rely on the architecture-level implementation
    #[cfg(target_arch = "x86_64")]
    {
        // Use the architecture module
        crate::plan9_arch::hal::mmu::flush_tlb();
    }
}

/// Increment reference count for a page
pub fn inc_ref(_page: u64) {
    // In a real implementation, this would update page reference counts
}

/// Get page reference count
pub fn page_ref(_page: u64) -> u32 {
    // In a real implementation, this would return the actual reference count
    1
}

// ============================================================================
// Segment Permissions
// ============================================================================

/// Segment permissions structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcSegmentPerm {
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Execute permission
    pub exec: bool,
    /// User mode permission
    pub user: bool,
}

impl ProcSegmentPerm {
    /// Create permissions from flags
    pub fn from_flags(flags: u32) -> Self {
        Self {
            read: (flags & 0x01) != 0,
            write: (flags & 0x02) != 0,
            exec: (flags & 0x04) != 0,
            user: (flags & 0x40) != 0,
        }
    }

    /// Convert to flags
    pub fn to_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.read { flags |= 0x01; }
        if self.write { flags |= 0x02; }
        if self.exec { flags |= 0x04; }
        if self.user { flags |= 0x40; }
        flags
    }
}

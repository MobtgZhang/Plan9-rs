//! Paging support for x86_64
//!
//! Implements the full 4-level page table structure for x86_64 architecture.
//! Supports 4KB pages, 2MB large pages, and 1GB huge pages.

extern crate plan9_common;

use plan9_common::error::{Error, Result};
use plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// Constants
// ============================================================================

/// Page size (4KB)
pub const PAGESIZE: usize = 4096;

/// Page shift (12 bits for 4KB pages)
pub const PAGE_SHIFT: u32 = 12;

/// Large page size (2MB)
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Large page shift (21 bits for 2MB pages)
pub const LARGE_PAGE_SHIFT: u32 = 21;

/// Huge page size (1GB)
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024;

/// Huge page shift (30 bits for 1GB pages)
pub const HUGE_PAGE_SHIFT: u32 = 30;

/// Number of entries in a page table
pub const PT_ENTRIES: usize = 512;

/// Address space size (48-bit virtual addresses)
pub const ADDR_SPACE_BITS: u32 = 48;

/// Virtual address mask (lower 48 bits)
pub const VADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Page table level indices
pub const PML4_INDEX_SHIFT: u32 = 39;
pub const PDPT_INDEX_SHIFT: u32 = 30;
pub const PD_INDEX_SHIFT: u32 = 21;
pub const PT_INDEX_SHIFT: u32 = 12;

/// Memory region boundaries
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_VIRT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const USER_VIRT_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_VIRT_END: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Kernel image virtual base
pub const KERNEL_IMAGE_VIRT: u64 = 0xFFFF_8000_0010_0000;

/// Physical memory virtual base (direct mapping)
pub const PHYS_MEMORY_VIRT: u64 = 0xFFFF_8800_0000_0000;

// ============================================================================
// Page Table Entry Flags
// ============================================================================

/// Page table entry flags
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PteFlags(u64);

impl PteFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const PWT: Self = Self(1 << 3);        // Write-through
    pub const PCD: Self = Self(1 << 4);         // Cache disable
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const PAT: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const NX: Self = Self(1 << 63);         // No-execute

    pub const fn new(bits: u64) -> Self { Self(bits) }
    pub fn bits(self) -> u64 { self.0 }

    pub fn with_present(self) -> Self { Self(self.0 | Self::PRESENT.0) }
    pub fn with_writable(self) -> Self { Self(self.0 | Self::WRITABLE.0) }
    pub fn with_user(self) -> Self { Self(self.0 | Self::USER.0) }
    pub fn with_no_exec(self) -> Self { Self(self.0 | Self::NX.0) }
    pub fn with_global(self) -> Self { Self(self.0 | Self::GLOBAL.0) }
    pub fn withaccessed(self) -> Self { Self(self.0 | Self::ACCESSED.0) }
    pub fn with_dirty(self) -> Self { Self(self.0 | Self::DIRTY.0) }

    pub fn is_present(self) -> bool { (self.0 & Self::PRESENT.0) != 0 }
    pub fn is_writable(self) -> bool { (self.0 & Self::WRITABLE.0) != 0 }
    pub fn is_user(self) -> bool { (self.0 & Self::USER.0) != 0 }
    pub fn is_no_exec(self) -> bool { (self.0 & Self::NX.0) != 0 }
    pub fn is_accessed(self) -> bool { (self.0 & Self::ACCESSED.0) != 0 }
    pub fn is_dirty(self) -> bool { (self.0 & Self::DIRTY.0) != 0 }
}

/// Common flag combinations
impl PteFlags {
    /// Kernel page: present, writable, global, no user access
    pub const KERNEL_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::GLOBAL.0);
    /// Kernel page: present, read-only, global, no user access
    pub const KERNEL_RO: Self = Self(Self::PRESENT.0 | Self::GLOBAL.0);
    /// User page: present, writable, user accessible
    pub const USER_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::USER.0);
    /// User page: present, read-only, user accessible
    pub const USER_RO: Self = Self(Self::PRESENT.0 | Self::USER.0);
    /// 4KB page table entry
    pub const PAGE_TABLE: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0);
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for PteFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ============================================================================
// Page Table Entry
// ============================================================================

/// Page table entry structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create a new PTE pointing to a physical address
    pub fn new(addr: PhysAddr, flags: PteFlags) -> Self {
        debug_assert!(addr.as_u64() & 0xFFF == 0, "PTE address must be page-aligned");
        Self(addr.as_u64() | flags.bits())
    }

    /// Get the physical address from this entry
    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000_FFFF_FFFF_F000)
    }

    /// Get the flags from this entry
    pub fn flags(&self) -> PteFlags {
        PteFlags::new(self.0 & !(0x000_FFFF_FFFF_F000))
    }

    /// Check if this entry is present
    pub fn is_present(&self) -> bool {
        self.flags().is_present()
    }

    /// Check if this entry maps to a large page
    pub fn is_large(&self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    /// Clear this entry
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ============================================================================
// Page Table
// ============================================================================

/// A page table (512 entries, one page)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageTable {
    entries: [PageTableEntry; PT_ENTRIES],
}

impl PageTable {
    /// Create a new empty page table
    pub fn new() -> Self {
        // Initialize all entries to zero using array literal
        Self { entries: [PageTableEntry(0); PT_ENTRIES] }
    }

    /// Get entry at index
    pub fn entry(&self, index: usize) -> PageTableEntry {
        debug_assert!(index < PT_ENTRIES);
        self.entries[index]
    }

    /// Get mutable entry at index
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        debug_assert!(index < PT_ENTRIES);
        &mut self.entries[index]
    }

    /// Set entry at index
    pub fn set_entry(&mut self, index: usize, entry: PageTableEntry) {
        debug_assert!(index < PT_ENTRIES);
        self.entries[index] = entry;
    }

    /// Clear entry at index
    pub fn clear_entry(&mut self, index: usize) {
        debug_assert!(index < PT_ENTRIES);
        self.entries[index].clear();
    }

    /// Get iterator over entries
    pub fn entries(&self) -> &[PageTableEntry; PT_ENTRIES] {
        &self.entries
    }

    /// Check if a specific entry is present
    pub fn is_index_present(&self, index: usize) -> bool {
        self.entry(index).is_present()
    }

    /// Count present entries
    pub fn count_present(&self) -> usize {
        self.entries.iter().filter(|e| e.is_present()).count()
    }
}

// ============================================================================
// Virtual Address Translation
// ============================================================================

/// Extract page table indices from a virtual address
#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableIndices {
    pub pml4: usize,
    pub pdpt: usize,
    pub pd: usize,
    pub pt: usize,
    pub offset: u64,
}

impl PageTableIndices {
    /// Extract indices from a virtual address
    pub fn from_virt(virt: VirtAddr) -> Self {
        let addr = virt.as_u64();
        Self {
            pml4: ((addr >> PML4_INDEX_SHIFT) & 0x1FF) as usize,
            pdpt: ((addr >> PDPT_INDEX_SHIFT) & 0x1FF) as usize,
            pd: ((addr >> PD_INDEX_SHIFT) & 0x1FF) as usize,
            pt: ((addr >> PT_INDEX_SHIFT) & 0x1FF) as usize,
            offset: addr & 0xFFF,
        }
    }

    /// Extract indices from a virtual address for large page (2MB)
    pub fn from_virt_large(virt: VirtAddr) -> Self {
        let addr = virt.as_u64();
        Self {
            pml4: ((addr >> PML4_INDEX_SHIFT) & 0x1FF) as usize,
            pdpt: ((addr >> PDPT_INDEX_SHIFT) & 0x1FF) as usize,
            pd: ((addr >> PD_INDEX_SHIFT) & 0x1FF) as usize,
            pt: 0,
            offset: addr & 0x1F_FFFF,
        }
    }

    /// Get the page frame number for 4KB pages
    pub fn page_frame_number(&self) -> u64 {
        let mut pfn = (self.pml4 as u64) << (PML4_INDEX_SHIFT - 12);
        pfn |= (self.pdpt as u64) << (PDPT_INDEX_SHIFT - 12);
        pfn |= (self.pd as u64) << (PD_INDEX_SHIFT - 12);
        pfn |= (self.pt as u64);
        pfn
    }

    /// Check if this is a kernel address
    pub fn is_kernel(&self) -> bool {
        self.pml4 >= 256
    }
}

// ============================================================================
// Virtual Address Operations (x86_64 specific extensions)
// ============================================================================

/// x86_64-specific virtual address operations
pub mod virt_addr {
    use super::*;

    /// Create a virtual address from raw value with canonical check
    pub fn new_checked(addr: u64) -> Option<VirtAddr> {
        let masked = addr & VADDR_MASK;
        if masked != addr {
            None
        } else {
            Some(VirtAddr::new(masked))
        }
    }

    /// Check if address is properly canonical
    pub fn is_canonical(addr: VirtAddr) -> bool {
        let val = addr.as_u64();
        let sign_bit = (val >> 47) & 1;
        let high_bits = val >> 48;
        if sign_bit == 0 {
            high_bits == 0
        } else {
            high_bits == 0x1FF
        }
    }

    /// Check if this is a kernel address
    pub fn is_kernel(addr: VirtAddr) -> bool {
        addr.as_u64() >= KERNEL_VIRT_BASE
    }

    /// Align down to page boundary
    pub fn page_align_down(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }

    /// Align up to page boundary
    pub fn page_align_up(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }

    /// Get the offset within a page
    pub fn page_offset(addr: VirtAddr) -> u64 {
        addr.as_u64() & 0xFFF
    }
}

// ============================================================================
// Physical Address Operations (x86_64 specific extensions)
// ============================================================================

/// x86_64-specific physical address operations
pub mod phys_addr {
    use super::*;

    /// Create from page number
    pub fn from_page(pn: PageNum) -> PhysAddr {
        PhysAddr::new(pn.as_u64() << PAGE_SHIFT)
    }

    /// Convert to page number
    pub fn to_page(addr: PhysAddr) -> PageNum {
        PageNum::new(addr.as_u64() >> PAGE_SHIFT)
    }

    /// Align down to page boundary
    pub fn page_align_down(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }

    /// Align up to page boundary
    pub fn page_align_up(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }

    /// Check if address is page-aligned
    pub fn is_aligned(addr: PhysAddr) -> bool {
        addr.as_u64() % PAGESIZE as u64 == 0
    }
}

// ============================================================================
// Page Operations
// ============================================================================

/// Represents a page number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageNum(u64);

impl PageNum {
    pub const fn new(num: u64) -> Self { Self(num) }
    pub fn from_virt(virt: VirtAddr) -> Self {
        Self(virt.as_u64() >> PAGE_SHIFT)
    }
    pub fn as_u64(self) -> u64 { self.0 }
    pub fn as_virt(self) -> VirtAddr {
        VirtAddr::new(self.0 << PAGE_SHIFT)
    }
}

/// Represents a large page number (2MB)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LargePageNum(u64);

impl LargePageNum {
    pub const fn new(num: u64) -> Self { Self(num) }
    pub fn from_virt(virt: VirtAddr) -> Self {
        Self(virt.as_u64() >> LARGE_PAGE_SHIFT)
    }
    pub fn as_u64(self) -> u64 { self.0 }
    pub fn as_virt(self) -> VirtAddr {
        VirtAddr::new(self.0 << LARGE_PAGE_SHIFT)
    }
}

/// Number of pages for a given size
pub fn pages_for_size(size: usize) -> usize {
    (size + PAGESIZE - 1) / PAGESIZE
}

// ============================================================================
// Memory Mapping
// ============================================================================

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub virt_start: VirtAddr,
    pub virt_end: VirtAddr,
    pub phys_start: PhysAddr,
    pub flags: PteFlags,
}

impl MemoryRegion {
    /// Create a new memory region
    pub fn new(virt: VirtAddr, phys: PhysAddr, size: usize, flags: PteFlags) -> Self {
        Self {
            virt_start: virt,
            virt_end: VirtAddr::new(virt.as_u64() + size as u64),
            phys_start: phys,
            flags,
        }
    }

    /// Get the size of this region
    pub fn size(&self) -> usize {
        (self.virt_end.as_u64() - self.virt_start.as_u64()) as usize
    }
}

// ============================================================================
// Address Space
// ============================================================================

/// x86_64 address space structure
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    pub pml4_phys: PhysAddr,
}

impl AddressSpace {
    /// Create a new address space (empty page table)
    pub fn new() -> Self {
        Self { pml4_phys: PhysAddr::null() }
    }

    /// Check if address space is valid
    pub fn is_valid(&self) -> bool {
        !self.pml4_phys.is_null()
    }
}

// ============================================================================
// Page Table Operations (for bootloader/kernel use)
// ============================================================================

/// Walk page table and get entry at given virtual address
/// Returns the entry and its level (4=PML4, 3=PDPT, 2=PD, 1=PT, 0=not found)
pub fn walk_page_table_entry(pml4: PhysAddr, virt: VirtAddr) -> Option<PageTableEntry> {
    let indices = PageTableIndices::from_virt(virt);

    // Read PML4 entry
    let pml4_virt = VirtAddr::new(KERNEL_VIRT_BASE | pml4.as_u64());
    let pml4_entry = read_page_table_entry(pml4_virt, indices.pml4)?;

    if !pml4_entry.is_present() {
        return None;
    }

    // Read PDPT entry
    let pdpt_phys = pml4_entry.addr();
    let pdpt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pdpt_phys.as_u64());
    let pdpt_entry = read_page_table_entry(pdpt_virt, indices.pdpt)?;

    if !pdpt_entry.is_present() {
        return None;
    }

    // Read PD entry
    let pd_phys = pdpt_entry.addr();
    let pd_virt = VirtAddr::new(KERNEL_VIRT_BASE | pd_phys.as_u64());
    let pd_entry = read_page_table_entry(pd_virt, indices.pd)?;

    if !pd_entry.is_present() {
        return None;
    }

    // Check for large page
    if pd_entry.is_large() {
        return Some(pd_entry);
    }

    // Read PT entry
    let pt_phys = pd_entry.addr();
    let pt_virt = VirtAddr::new(KERNEL_VIRT_BASE | pt_phys.as_u64());
    read_page_table_entry(pt_virt, indices.pt)
}

/// Read a page table entry from a virtual address
fn read_page_table_entry(table_virt: VirtAddr, index: usize) -> Option<PageTableEntry> {
    if index >= PT_ENTRIES {
        return None;
    }
    let entry_ptr = (table_virt.as_u64() + (index as u64) * 8) as *const u64;
    // Safety: In practice this requires the memory to be mapped
    let value = unsafe { *entry_ptr };
    Some(PageTableEntry(value))
}

/// Calculate identity mapped virtual address for a physical address
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(PHYS_MEMORY_VIRT | phys.as_u64())
}

/// Calculate physical address from kernel virtual address
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    if virt_addr::is_kernel(virt) && virt.as_u64() >= PHYS_MEMORY_VIRT {
        Some(PhysAddr::new(virt.as_u64() - PHYS_MEMORY_VIRT))
    } else {
        None
    }
}

// ============================================================================
// Higher Half Kernel Mapping
// ============================================================================

/// Kernel virtual memory layout
pub mod kernel_layout {
    use super::*;

    /// Kernel text section (read-only, executable)
    pub fn text_virt() -> u64 { KERNEL_IMAGE_VIRT }
    /// Kernel rodata section (read-only)
    pub fn rodata_virt() -> u64 { KERNEL_IMAGE_VIRT + 0x100000 }
    /// Kernel data/bss section (read-write)
    pub fn data_virt() -> u64 { KERNEL_IMAGE_VIRT + 0x200000 }
    /// Kernel initial stack (down-growing)
    pub fn stack_virt() -> u64 { KERNEL_VIRT_END - 0x3FFF_FFFF - 1 }
    /// Kernel heap start
    pub fn heap_start() -> u64 { KERNEL_IMAGE_VIRT + 0x400000 }
    /// Kernel heap end (grows upward)
    pub const HEAP_INITIAL_SIZE: usize = 16 * 1024 * 1024; // 16MB initial

    /// User space base
    pub const USER_BASE: u64 = USER_VIRT_BASE;
    /// User space end
    pub const USER_END: u64 = USER_VIRT_END;
    /// User stack base
    pub const USER_STACK_TOP: u64 = USER_VIRT_END - 0xFFF;
}

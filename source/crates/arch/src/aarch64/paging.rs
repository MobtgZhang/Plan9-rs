//! AArch64 paging — 4-level page tables with a 4 KiB granule.
//!
//! Mirrors the x86_64 `paging` module's API surface so that the kernel's
//! virtual-memory code (`vm.rs`, `proc.rs`, `syscall.rs`, …) can be written
//! against a single architecture-neutral interface
//! (`plan9_arch::hal::paging`).
//!
//! ARMv8 translation table (granule 4K, 48-bit VA):
//!
//!   L0 index  = VA[47:39]   (512 entries)
//!   L1 index  = VA[38:30]
//!   L2 index  = VA[29:21]
//!   L3 index  = VA[20:12]
//!   PA offset = VA[11:0]
//!
//! Descriptor formats:
//!   * L0–L2 ("table"):  bit0 VALID, bit1 TABLE, attrs in [14:2] ignored.
//!   * L3 ("page"):      bit0 VALID, bits[5:2] = AF/SH/ATTR index,
//!                       bits[7:6] AP, bit11 nG, bit54 PXN, OA in [47:12].

extern crate plan9_common;

use plan9_common::error::Error;
use plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// Constants — kept identical in shape to the x86_64 module
// ============================================================================

/// Page size (4 KiB granule)
pub const PAGESIZE: usize = 4096;

/// Page shift (12 bits for 4 KiB pages)
pub const PAGE_SHIFT: u32 = 12;

/// Large page size (2 MiB — L2 block entry)
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Large page shift
pub const LARGE_PAGE_SHIFT: u32 = 21;

/// Huge page size (1 GiB — L1 block entry)
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024;

/// Huge page shift
pub const HUGE_PAGE_SHIFT: u32 = 30;

/// Number of entries in a page table
pub const PT_ENTRIES: usize = 512;

/// Address space size (48-bit VA with 4K granule)
pub const ADDR_SPACE_BITS: u32 = 48;

/// Virtual address mask (lower 48 bits)
pub const VADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Page table level indices
pub const PML4_INDEX_SHIFT: u32 = 39; // L0 (top) level
pub const PDPT_INDEX_SHIFT: u32 = 30; // L1
pub const PD_INDEX_SHIFT: u32 = 21;   // L2
pub const PT_INDEX_SHIFT: u32 = 12;   // L3

/// Virtual memory layout. The kernel's generic code assumes a high-half
/// kernel window; on AArch64 we place the physical-memory direct map in
/// the TTBR1 region at 0xFFFF_FF80_0000_0000 (2 GiB window) and keep the
/// kernel image identity-mapped in the TTBR0 region during early boot.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_VIRT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const USER_VIRT_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_VIRT_END: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Kernel image virtual base (identity-mapped RAM base on AArch64).
pub const KERNEL_IMAGE_VIRT: u64 = 0x0000_4000_0000_0000;

/// Physical memory virtual base (TTBR1 direct-map window).
///
/// `phys_to_virt` adds this to a physical address; the window is created
/// by `paging_init()` as a recursive 4-level table in TTBR1.
pub const PHYS_MEMORY_VIRT: u64 = 0xFFFF_FF80_0000_0000;

// ============================================================================
// Page Table Entry Flags — architecture-neutral names, AArch64 bits
// ============================================================================

/// Page table entry flags.
///
/// The constant names match the x86_64 module; the bit values are real
/// AArch64 descriptor bits so entries can be written straight into tables.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PteFlags(u64);

impl PteFlags {
    /// VALID — descriptor is valid (x86 "present").
    pub const PRESENT: Self = Self(1 << 0);

    /// TABLE — descriptor type bit (bit 1). Set for L0–L2 table
    /// descriptors and L3 page descriptors; clear for block descriptors.
    pub const PS: Self = Self(1 << 1);
    pub const TABLE: Self = Self(1 << 1);

    /// Access flag — must be set on block/page descriptors.
    pub const AF: Self = Self(1 << 10);
    pub const ACCESSED: Self = Self(1 << 10);

    /// Shareability: inner-shareable (SH = 0b11, bits 9:8).
    pub const SH_INNER: Self = Self(0b11 << 8);

    /// AP[1] — accessible at EL0 (bit 6).
    pub const USER: Self = Self(1 << 6);

    /// AP[2] — read-only (bit 7). VMSAv8-64 has no AP[0]; "writable"
    /// means this bit is clear.
    pub const READONLY: Self = Self(1 << 7);

    /// Pseudo-flag: writable is the absence of READONLY.
    pub const WRITABLE: Self = Self(0);

    /// UXN — unprivileged execute never (bit 54).
    pub const NX: Self = Self(1 << 54);
    /// PXN — privileged execute never (bit 53).
    pub const PXN: Self = Self(1 << 53);

    /// Software dirty marker (reserved software bits 58:55).
    pub const DIRTY: Self = Self(1 << 55);
    /// Software copy-on-write marker.
    pub const COW: Self = Self(1 << 56);

    /// Software-managed "global" marker (nG=0 is the default).
    pub const GLOBAL: Self = Self(0);

    /// Cache-disable pseudo-flags are expressed through AttrIndx/MAIR.
    pub const PCD: Self = Self(0);
    pub const PWT: Self = Self(0);

    pub const fn new(bits: u64) -> Self { Self(bits) }
    pub const fn bits(self) -> u64 { self.0 }
    pub fn from_pte(pte: u64) -> Self { Self(pte) }

    pub fn with_present(self) -> Self { Self(self.0 | Self::PRESENT.0) }
    pub fn with_writable(self) -> Self { Self(self.0 & !Self::READONLY.0) }
    pub fn with_user(self) -> Self { Self(self.0 | Self::USER.0) }
    pub fn with_no_exec(self) -> Self { Self(self.0 | Self::NX.0) }
    pub fn with_global(self) -> Self { Self(self.0 | Self::GLOBAL.0) }
    pub fn withaccessed(self) -> Self { Self(self.0 | Self::ACCESSED.0) }
    pub fn with_dirty(self) -> Self { Self(self.0 | Self::DIRTY.0) }

    pub fn is_present(self) -> bool { (self.0 & Self::PRESENT.0) != 0 }
    pub fn is_writable(self) -> bool { (self.0 & Self::READONLY.0) == 0 }
    pub fn is_user(self) -> bool { (self.0 & Self::USER.0) != 0 }
    pub fn is_no_exec(self) -> bool { (self.0 & Self::NX.0) != 0 }
    pub fn is_accessed(self) -> bool { (self.0 & Self::ACCESSED.0) != 0 }
    pub fn is_dirty(self) -> bool { (self.0 & Self::DIRTY.0) != 0 }
    pub fn is_cow(self) -> bool { (self.0 & Self::COW.0) != 0 }

    /// Block descriptor: bit 1 (TABLE) is clear.
    pub fn is_large_page(self) -> bool { (self.0 & Self::PS.0) == 0 }
    pub fn is_huge_page(self) -> bool { (self.0 & Self::PS.0) == 0 }
}

/// Attribute index in MAIR (bits 4:2 of a descriptor).
const ATTR_IDX_SHIFT: u64 = 2;
/// Inner-shareable (bits 9:8).
const SH_INNER_BITS: u64 = 0b11 << 8;

impl PteFlags {
    /// MAIR index 0 = Normal cacheable (write-back, inner shareable).
    pub const fn attr_mem(self) -> Self { Self(self.0 | (0 << ATTR_IDX_SHIFT) | SH_INNER_BITS) }
    /// MAIR index 1 = Device-nGnRnE.
    pub const fn attr_dev(self) -> Self { Self(self.0 | (1 << ATTR_IDX_SHIFT) | SH_INNER_BITS) }
}

/// Common flag combinations (kernel pages run at EL1, user at EL0).
impl PteFlags {
    /// Kernel page: valid, cached, AF set, EL1 read/write.
    pub const KERNEL_RW: Self =
        Self(Self::PRESENT.0 | Self::AF.0 | Self::SH_INNER.0);
    /// Kernel page: valid, cached, AF set, EL1 read-only.
    pub const KERNEL_RO: Self =
        Self(Self::PRESENT.0 | Self::AF.0 | Self::READONLY.0 | Self::SH_INNER.0);
    /// User page: valid, cached, AF set, EL0 read/write.
    pub const USER_RW: Self =
        Self(Self::PRESENT.0 | Self::AF.0 | Self::USER.0 | Self::SH_INNER.0);
    /// User page: valid, cached, AF set, EL0 read-only.
    pub const USER_RO: Self =
        Self(Self::PRESENT.0 | Self::AF.0 | Self::USER.0 | Self::READONLY.0 | Self::SH_INNER.0);
    /// Page-table descriptor (L0–L2): valid + table marker.
    pub const PAGE_TABLE: Self = Self(Self::PRESENT.0 | Self::PS.0);
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for PteFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

// ============================================================================
// Page Table Entry
// ============================================================================

/// One 64-bit descriptor.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    pub fn new(addr: PhysAddr, flags: PteFlags) -> Self {
        // Output address occupies bits [47:12].
        Self((addr.as_u64() & 0x0000_FFFF_FFFF_F000) | flags.bits())
    }

    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x0000_FFFF_FFFF_F000)
    }

    pub fn flags(&self) -> PteFlags { PteFlags::new(self.0 & !0x0000_FFFF_FFFF_F000) }

    pub fn is_present(&self) -> bool { self.0 & PteFlags::PRESENT.0 != 0 }

    /// Block entry at L1/L2 (ARM) — used by huge-page code.
    pub fn is_large(&self) -> bool { self.0 & PteFlags::PS.0 == 0 }

    pub fn clear(&mut self) { self.0 = 0; }
}

/// A 512-entry page table (one 4 KiB page).
#[derive(Debug)]
#[repr(C)]
pub struct PageTable {
    pub entries: [PageTableEntry; PT_ENTRIES],
}

impl PageTable {
    pub fn new() -> Self {
        Self { entries: [PageTableEntry(0); PT_ENTRIES] }
    }

    pub fn entry(&self, index: usize) -> PageTableEntry { self.entries[index] }
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry { &mut self.entries[index] }
    pub fn set_entry(&mut self, index: usize, entry: PageTableEntry) { self.entries[index] = entry; }
    pub fn clear_entry(&mut self, index: usize) { self.entries[index] = PageTableEntry(0); }
    pub fn entries(&self) -> &[PageTableEntry; PT_ENTRIES] { &self.entries }
    pub fn is_index_present(&self, index: usize) -> bool { self.entries[index].is_present() }

    pub fn count_present(&self) -> usize {
        self.entries.iter().filter(|e| e.is_present()).count()
    }
}

// ============================================================================
// Virtual address decomposition
// ============================================================================

/// Decomposition of a virtual address into page-table indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableIndices {
    pub pml4: usize, // L0
    pub pdpt: usize, // L1
    pub pd: usize,   // L2
    pub pt: usize,   // L3
    pub offset: u64,
}

impl PageTableIndices {
    pub fn from_virt(virt: VirtAddr) -> Self {
        let v = virt.as_u64();
        Self {
            pml4: ((v >> PML4_INDEX_SHIFT) & 0x1FF) as usize,
            pdpt: ((v >> PDPT_INDEX_SHIFT) & 0x1FF) as usize,
            pd: ((v >> PD_INDEX_SHIFT) & 0x1FF) as usize,
            pt: ((v >> PT_INDEX_SHIFT) & 0x1FF) as usize,
            offset: v & 0xFFF,
        }
    }

    /// Same decomposition (large/huge variants kept for API parity; on
    /// AArch64 block entries are detected by descriptor type, not by a
    /// separate index computation).
    pub fn from_virt_large(virt: VirtAddr) -> Self { Self::from_virt(virt) }
    pub fn from_virt_huge(virt: VirtAddr) -> Self { Self::from_virt(virt) }

    pub fn page_frame_number(&self) -> u64 {
        let v = (self.pml4 as u64) << PML4_INDEX_SHIFT
            | (self.pdpt as u64) << PDPT_INDEX_SHIFT
            | (self.pd as u64) << PD_INDEX_SHIFT
            | (self.pt as u64) << PT_INDEX_SHIFT;
        v >> PAGE_SHIFT
    }

    pub fn is_kernel(&self) -> bool { self.pml4 >= 256 }
}

// ============================================================================
// Address helpers — API parity with the x86_64 module
// ============================================================================

/// AArch64-specific virtual address operations (API parity with x86_64).
pub mod virt_addr {
    use super::*;

    /// Create a virtual address from a raw value. AArch64 imposes no
    /// canonicality constraint, so any value is acceptable.
    pub fn new_checked(addr: u64) -> Option<VirtAddr> {
        Some(VirtAddr::new(addr))
    }

    /// AArch64 has no canonicality constraint.
    pub fn is_canonical(_addr: VirtAddr) -> bool { true }

    pub fn is_kernel(addr: VirtAddr) -> bool { addr.as_u64() >= KERNEL_VIRT_BASE }

    pub fn page_align_down(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn page_align_up(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn offset(addr: VirtAddr) -> u64 { addr.as_u64() & 0xFFF }
}

/// AArch64-specific physical address operations.
pub mod phys_addr {
    use super::*;

    pub fn from_page(pn: PageNum) -> PhysAddr {
        PhysAddr::new(pn.as_u64() << PAGE_SHIFT)
    }

    pub fn to_page(addr: PhysAddr) -> PageNum {
        PageNum::new(addr.as_u64() >> PAGE_SHIFT)
    }

    pub fn page_align_down(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn page_align_up(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn is_aligned(addr: PhysAddr) -> bool {
        addr.as_u64() % PAGESIZE as u64 == 0
    }
}

/// A 4 KiB page number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageNum(u64);

impl PageNum {
    pub const fn new(num: u64) -> Self { Self(num) }
    pub fn from_virt(virt: VirtAddr) -> Self { Self(virt.as_u64() >> PAGE_SHIFT) }
    pub fn as_u64(self) -> u64 { self.0 }
    pub fn as_virt(self) -> VirtAddr { VirtAddr::new(self.0 << PAGE_SHIFT) }
}

/// A 2 MiB large-page number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargePageNum(u64);

impl LargePageNum {
    pub const fn new(num: u64) -> Self { Self(num) }
    pub fn from_virt(virt: VirtAddr) -> Self { Self(virt.as_u64() >> LARGE_PAGE_SHIFT) }
    pub fn as_u64(self) -> u64 { self.0 }
    pub fn as_virt(self) -> VirtAddr { VirtAddr::new(self.0 << LARGE_PAGE_SHIFT) }
}

pub fn pages_for_size(size: usize) -> usize {
    (size + PAGESIZE - 1) / PAGESIZE
}

/// A contiguous memory region mapped with a single flag set.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub virt: VirtAddr,
    pub phys: PhysAddr,
    pub size: usize,
    pub flags: PteFlags,
}

impl MemoryRegion {
    pub fn new(virt: VirtAddr, phys: PhysAddr, size: usize, flags: PteFlags) -> Self {
        Self { virt, phys, size, flags }
    }
    pub fn size(&self) -> usize { self.size }
}

/// Placeholder address-space handle kept for API parity.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddressSpace {
    pub root_phys: u64,
}

impl AddressSpace {
    pub fn new() -> Self { Self { root_phys: 0 } }
    pub fn is_valid(&self) -> bool { self.root_phys != 0 }
}

// ============================================================================
// Page-table walking
// ============================================================================

/// Walk a 4-level table from `root` (physical address of the L0 table)
/// for `virt`, returning the final L3 descriptor if all levels are
/// present. Physical addresses are translated through the direct map.
pub fn walk_page_table_entry(root: PhysAddr, virt: VirtAddr) -> Option<PageTableEntry> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root.as_u64();
    for level_index in [idx.pml4, idx.pdpt, idx.pd, idx.pt] {
        if table_phys == 0 {
            return None;
        }
        let table = unsafe { &*(super::paging_phys_to_virt(table_phys) as *const PageTable) };
        let entry = table.entry(level_index);
        if !entry.is_present() {
            return None;
        }
        // If this is a table descriptor (bit1 set) descend; otherwise it
        // is a block entry (only possible at L1/L2).
        if entry.0 & (1 << 1) != 0 || level_index == idx.pt {
            table_phys = entry.addr().as_u64();
        } else {
            return Some(entry);
        }
    }
    Some(unsafe { &*(super::paging_phys_to_virt(table_phys) as *const PageTable) }
        .entry(idx.pt))
}

// ============================================================================
// Direct-map helpers
// ============================================================================

/// Physical → virtual translation through the TTBR1 direct map window.
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(PHYS_MEMORY_VIRT + phys.as_u64())
}

/// Map one 4 KiB page into a user address space rooted at `root_phys`.
///
/// Allocates lower-level tables on demand from the kernel's frame
/// allocator. Returns `Err(Enomem)` when a table cannot be allocated.
pub fn map_page(
    root_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PteFlags,
) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root_phys.as_u64();
    for (level, level_index) in [idx.pml4, idx.pdpt, idx.pd, idx.pt]
        .into_iter()
        .enumerate()
    {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[level_index];
        if !entry.is_present() {
            if level == 3 {
                // Final level: write the page descriptor.
                *entry = PageTableEntry::new(phys, flags.withaccessed());
                super::mmu::invlpg(virt);
                return Ok(());
            }
            // Allocate a zeroed lower-level table.
            let new_table = match super::alloc_zeroed_frame() {
                Some(p) => p,
                None => return Err(Error::Enomem),
            };
            *entry = PageTableEntry::new(
                PhysAddr::new(new_table),
                PteFlags::PAGE_TABLE.attr_mem(),
            );
        }
        table_phys = entry.addr().as_u64();
    }
    Ok(())
}

/// Unmap one 4 KiB page (leaves intermediate levels allocated).
pub fn unmap_page(root_phys: PhysAddr, virt: VirtAddr) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root_phys.as_u64();
    for (level, level_index) in [idx.pml4, idx.pdpt, idx.pd, idx.pt]
        .into_iter()
        .enumerate()
    {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[level_index];
        if !entry.is_present() {
            return Err(Error::Enoent);
        }
        if level == 3 {
            entry.clear();
            super::mmu::invlpg(virt);
            return Ok(());
        }
        table_phys = entry.addr().as_u64();
    }
    Err(Error::Enoent)
}

/// Map a 2 MiB (`level_bits == 21`) or 1 GiB (`level_bits == 30`) block
/// entry at the appropriate level, allocating intermediate tables.
pub fn map_huge_page(
    root_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PteFlags,
    level_bits: u32,
) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    // Descend to the level *above* the block entry: for 1 GiB blocks only
    // through L0, for 2 MiB blocks through L0 and L1.
    let (depth, level_index) = if level_bits >= HUGE_PAGE_SHIFT {
        (1usize, idx.pdpt)
    } else {
        (2usize, idx.pd)
    };
    let path: [usize; 2] = [idx.pml4, idx.pdpt];

    let mut table_phys = root_phys.as_u64();
    for i in 0..depth {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[path[i]];
        if !entry.is_present() {
            let new_table = match super::alloc_zeroed_frame() {
                Some(p) => p,
                None => return Err(Error::Enomem),
            };
            *entry = PageTableEntry::new(
                PhysAddr::new(new_table),
                PteFlags::PAGE_TABLE.attr_mem(),
            );
        }
        table_phys = entry.addr().as_u64();
    }
    let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
    // Block descriptor: VALID + AF + attributes, *without* the TABLE bit.
    let block_flags = PteFlags::new(flags.bits() & !PteFlags::PS.0).withaccessed();
    table.entries[level_index] = PageTableEntry::new(phys, block_flags);
    super::mmu::invlpg(virt);
    Ok(())
}

/// Unmap a 2 MiB / 1 GiB block entry.
pub fn unmap_huge_page(root_phys: PhysAddr, virt: VirtAddr) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root_phys.as_u64();
    let path: [usize; 2] = [idx.pml4, idx.pdpt];
    // Walk to the L1 table.
    for (i, level_index) in path.into_iter().enumerate().take(2) {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[level_index];
        if !entry.is_present() {
            return Err(Error::Enoent);
        }
        if i == 1 {
            // L1 entry itself: if it is a block (1 GiB), clear it.
            entry.clear();
            super::mmu::invlpg(virt);
            return Ok(());
        }
        table_phys = entry.addr().as_u64();
    }
    // Otherwise try clearing the L2 block entry.
    let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
    let entry = &mut table.entries[idx.pd];
    if !entry.is_present() {
        return Err(Error::Enoent);
    }
    entry.clear();
    super::mmu::invlpg(virt);
    Ok(())
}

fn idx_l1(virt: VirtAddr) -> usize { ((virt.as_u64() >> PDPT_INDEX_SHIFT) & 0x1FF) as usize }
fn idx_l2(virt: VirtAddr) -> usize { ((virt.as_u64() >> PD_INDEX_SHIFT) & 0x1FF) as usize }

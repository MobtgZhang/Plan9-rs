//! LoongArch64 paging — software-managed 4-level page tables for the
//! page-mapped (TLB) address space, plus the direct-mapped windows.
//!
//! Mirrors the x86_64 `paging` module's API surface so the kernel's
//! virtual-memory code compiles against `plan9_arch::hal::paging`.
//!
//! # Address-space layout
//!
//! LoongArch64 has a 48-bit VA. Direct-mapped windows (CSR.DMWn) give
//! the kernel a zero-page-table mapping of all of physical memory; the
//! page-mapped half is reserved for user processes:
//!
//!   * 0x0000_0000_0000_0000 .. 0x7FFF_FFFF_FFFF  — user, page-mapped
//!   * 0x8000_0000_0000_0000 ..                    — DMW0 cached window
//!     (kernel image + direct map: VA = PA | window base)
//!   * 0x9000_0000_0000_0000 ..                    — DMW1 uncached window
//!     (MMIO)
//!
//! # Page-table model
//!
//! 4 levels × 512 entries × 8-byte descriptors (PTE index VA[20:12],
//! PMD VA[29:21], PUD VA[38:30], PGD VA[47:39]). The hardware walker
//! (CSR.PGDL/PGDH + TLB refill) uses a 16-byte upper-level entry format;
//! this bring-up model is walked in software by the trap path and kept
//! 8-bytes-per-entry for API parity with the x86_64 module. The PTE
//! descriptor bits are the real LoongArch bits:
//!
//!   V(0) MAT[3:2] PLV[5:4] W(6) P(7) D(8), PA in [47:12]

extern crate plan9_common;

use plan9_common::error::Error;
use plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// Constants
// ============================================================================

pub const PAGESIZE: usize = 4096;
pub const PAGE_SHIFT: u32 = 12;

/// 2 MiB large page.
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
pub const LARGE_PAGE_SHIFT: u32 = 21;

/// 1 GiB huge page.
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024;
pub const HUGE_PAGE_SHIFT: u32 = 30;

pub const PT_ENTRIES: usize = 512;
pub const ADDR_SPACE_BITS: u32 = 48;
pub const VADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Level shifts (named after the x86 levels; "PML4" is the LoongArch PGD).
pub const PML4_INDEX_SHIFT: u32 = 39;
pub const PDPT_INDEX_SHIFT: u32 = 30;
pub const PD_INDEX_SHIFT: u32 = 21;
pub const PT_INDEX_SHIFT: u32 = 12;

/// Page-mapped user half ends here; everything above is DMW windows.
pub const KERNEL_VIRT_BASE: u64 = 0x8000_0000_0000_0000;
pub const KERNEL_VIRT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const USER_VIRT_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_VIRT_END: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Kernel image virtual base — the cached DMW0 window at the 2 MiB RAM
/// base used by the LoongArch virt machine.
pub const RAM_PHYS_BASE: u64 = 0x0000_0000_0020_0000;
pub const KERNEL_IMAGE_VIRT: u64 = KERNEL_VIRT_BASE | RAM_PHYS_BASE;

/// Physical memory virtual base (cached DMW0 direct-map window):
/// `phys_to_virt` adds this to a physical address.
pub const PHYS_MEMORY_VIRT: u64 = 0x8000_0000_0000_0000;

/// Uncached MMIO direct-map window (DMW1).
pub const MMIO_VIRT: u64 = 0x9000_0000_0000_0000;

// ============================================================================
// Page Table Entry Flags — neutral names, LoongArch descriptor bits
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PteFlags(u64);

impl PteFlags {
    /// V | P — descriptor valid and page present.
    pub const PRESENT: Self = Self((1 << 0) | (1 << 7));

    /// W — write permitted.
    pub const WRITABLE: Self = Self(1 << 6);

    /// PLV3 — accessible at privilege level 3 (user).
    pub const USER: Self = Self(0b11 << 4);

    /// No-op: LoongArch has no hardware accessed bit (kept for API parity).
    pub const ACCESSED: Self = Self(0);

    /// D — dirty.
    pub const DIRTY: Self = Self(1 << 8);

    /// No-op: no global bit in the PTE (ASIDs handled separately).
    pub const GLOBAL: Self = Self(0);

    /// No-op: LoongArch PTEs carry no execute-disable bit.
    pub const NX: Self = Self(0);

    /// Software copy-on-write marker (LoongArch reserved PTE bit 9).
    pub const COW: Self = Self(1 << 9);

    /// Pseudo-flag for API parity: a page is read-only when W is clear.
    pub const READONLY: Self = Self(0);

    /// No-ops kept for API parity with the x86 module.
    pub const PWT: Self = Self(0);
    pub const PCD: Self = Self(0);
    /// Block-entry marker (no block entries in the software model).
    pub const PS: Self = Self(0);

    pub const fn new(bits: u64) -> Self { Self(bits) }
    pub const fn bits(self) -> u64 { self.0 }
    pub fn from_pte(pte: u64) -> Self { Self(pte) }

    pub fn with_present(self) -> Self { Self(self.0 | Self::PRESENT.0) }
    pub fn with_writable(self) -> Self { Self(self.0 | Self::WRITABLE.0) }
    pub fn with_user(self) -> Self { Self(self.0 | Self::USER.0) }
    pub fn with_no_exec(self) -> Self { Self(self.0 | Self::NX.0) }
    pub fn with_global(self) -> Self { Self(self.0 | Self::GLOBAL.0) }
    pub fn withaccessed(self) -> Self { Self(self.0 | Self::ACCESSED.0) }
    pub fn with_dirty(self) -> Self { Self(self.0 | Self::DIRTY.0) }

    pub fn is_present(self) -> bool { (self.0 & Self::PRESENT.0) == Self::PRESENT.0 }
    pub fn is_writable(self) -> bool { (self.0 & Self::WRITABLE.0) != 0 }
    pub fn is_user(self) -> bool { (self.0 & Self::USER.0) == Self::USER.0 }
    pub fn is_no_exec(self) -> bool { false }
    pub fn is_accessed(self) -> bool { false }
    pub fn is_dirty(self) -> bool { (self.0 & Self::DIRTY.0) != 0 }
    pub fn is_cow(self) -> bool { (self.0 & Self::COW.0) != 0 }
    pub fn is_large_page(self) -> bool { false }
    pub fn is_huge_page(self) -> bool { false }
}

/// MAT (memory access type) — bits [3:2]: 0 = strongly-uncached,
/// 1 = coherent-cached.
impl PteFlags {
    pub const fn attr_mem(self) -> Self { Self(self.0 | (1 << 2)) }
    pub const fn attr_dev(self) -> Self { Self(self.0 & !(0b11 << 2)) }
}

/// Common flag combinations.
impl PteFlags {
    pub const KERNEL_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0).attr_mem();
    pub const KERNEL_RO: Self = Self(Self::PRESENT.0).attr_mem();
    pub const USER_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::USER.0).attr_mem();
    pub const USER_RO: Self = Self(Self::PRESENT.0 | Self::USER.0).attr_mem();
    /// Page-table descriptor: V only.
    pub const PAGE_TABLE: Self = Self(1 << 0);
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for PteFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

// ============================================================================
// Page Table Entry / Page Table
// ============================================================================

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    pub fn new(addr: PhysAddr, flags: PteFlags) -> Self {
        Self((addr.as_u64() & 0x0000_FFFF_FFFF_F000) | flags.bits())
    }

    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x0000_FFFF_FFFF_F000)
    }

    pub fn flags(&self) -> PteFlags { PteFlags::new(self.0 & 0x1FF) }

    pub fn is_present(&self) -> bool { self.0 & PteFlags::PRESENT.0 == PteFlags::PRESENT.0 }

    pub fn is_large(&self) -> bool { false }

    pub fn clear(&mut self) { self.0 = 0; }
}

#[derive(Debug)]
#[repr(C)]
pub struct PageTable {
    pub entries: [PageTableEntry; PT_ENTRIES],
}

impl PageTable {
    pub fn new() -> Self { Self { entries: [PageTableEntry(0); PT_ENTRIES] } }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableIndices {
    pub pml4: usize, // PGD (VA[47:39])
    pub pdpt: usize, // PUD (VA[38:30])
    pub pd: usize,   // PMD (VA[29:21])
    pub pt: usize,   // PTE (VA[20:12])
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

    pub fn from_virt_large(virt: VirtAddr) -> Self { Self::from_virt(virt) }
    pub fn from_virt_huge(virt: VirtAddr) -> Self { Self::from_virt(virt) }

    pub fn page_frame_number(&self) -> u64 {
        let v = (self.pml4 as u64) << PML4_INDEX_SHIFT
            | (self.pdpt as u64) << PDPT_INDEX_SHIFT
            | (self.pd as u64) << PD_INDEX_SHIFT
            | (self.pt as u64) << PT_INDEX_SHIFT;
        v >> PAGE_SHIFT
    }

    pub fn is_kernel(&self) -> bool { (self.pml4 & 0x100) != 0 }
}

// ============================================================================
// Address helpers
// ============================================================================

pub mod virt_addr {
    use super::*;

    pub fn new_checked(addr: u64) -> Option<VirtAddr> {
        Some(VirtAddr::new(addr & VADDR_MASK))
    }

    pub fn is_canonical(addr: VirtAddr) -> bool { addr.as_u64() <= USER_VIRT_END || addr.as_u64() >= KERNEL_VIRT_BASE }

    pub fn is_kernel(addr: VirtAddr) -> bool { addr.as_u64() >= KERNEL_VIRT_BASE }

    pub fn page_align_down(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn page_align_up(addr: VirtAddr) -> VirtAddr {
        VirtAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }

    pub fn offset(addr: VirtAddr) -> u64 { addr.as_u64() & 0xFFF }
}

pub mod phys_addr {
    use super::*;

    pub fn from_page(pn: PageNum) -> PhysAddr { PhysAddr::new(pn.as_u64() << PAGE_SHIFT) }
    pub fn to_page(addr: PhysAddr) -> PageNum { PageNum::new(addr.as_u64() >> PAGE_SHIFT) }
    pub fn page_align_down(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new((addr.as_u64() / PAGESIZE as u64) * PAGESIZE as u64)
    }
    pub fn page_align_up(addr: PhysAddr) -> PhysAddr {
        PhysAddr::new(((addr.as_u64() + PAGESIZE as u64 - 1) / PAGESIZE as u64) * PAGESIZE as u64)
    }
    pub fn is_aligned(addr: PhysAddr) -> bool { addr.as_u64() % PAGESIZE as u64 == 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageNum(u64);

impl PageNum {
    pub const fn new(num: u64) -> Self { Self(num) }
    pub fn from_virt(virt: VirtAddr) -> Self { Self(virt.as_u64() >> PAGE_SHIFT) }
    pub fn as_u64(self) -> u64 { self.0 }
    pub fn as_virt(self) -> VirtAddr { VirtAddr::new(self.0 << PAGE_SHIFT) }
}

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

#[derive(Debug, Clone, Copy, Default)]
pub struct AddressSpace {
    pub root_phys: u64,
}

impl AddressSpace {
    pub fn new() -> Self { Self { root_phys: 0 } }
    pub fn is_valid(&self) -> bool { self.root_phys != 0 }
}

// ============================================================================
// Walking / mapping (4 levels)
// ============================================================================

/// Walk the table rooted at `root` (physical) for `virt`, returning the
/// final PTE-level descriptor when all levels are present.
pub fn walk_page_table_entry(root: PhysAddr, virt: VirtAddr) -> Option<PageTableEntry> {
    let idx = PageTableIndices::from_virt(virt);
    let levels = [idx.pml4, idx.pdpt, idx.pd, idx.pt];
    let mut table_phys = root.as_u64();
    for (i, &level_index) in levels.iter().enumerate() {
        if table_phys == 0 {
            return None;
        }
        let table = unsafe { &*(super::paging_phys_to_virt(table_phys) as *const PageTable) };
        let entry = table.entry(level_index);
        if !entry.is_present() {
            return None;
        }
        if i == levels.len() - 1 {
            return Some(entry);
        }
        table_phys = entry.addr().as_u64();
    }
    None
}

// ============================================================================
// Direct map
// ============================================================================

/// Physical → virtual translation through the cached DMW0 window.
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(PHYS_MEMORY_VIRT | phys.as_u64())
}

/// Physical → uncached MMIO window (DMW1).
#[inline]
pub fn phys_to_mmio(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(MMIO_VIRT | phys.as_u64())
}

/// Map one 4 KiB page into the page-mapped address space rooted at
/// `root_phys`, allocating lower-level tables on demand.
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
                *entry = PageTableEntry::new(phys, flags.with_present());
                super::mmu::invlpg(virt);
                return Ok(());
            }
            let new_table = match super::alloc_zeroed_frame() {
                Some(p) => p,
                None => return Err(Error::Enomem),
            };
            *entry = PageTableEntry::new(PhysAddr::new(new_table), PteFlags::PAGE_TABLE);
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

/// Map a 2 MiB or 1 GiB block entry (modeled as a PTE-level entry in the
/// software walk; hardware block pages use the TLB PS field instead).
pub fn map_huge_page(
    root_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PteFlags,
    level_bits: u32,
) -> Result<(), Error> {
    let _ = level_bits;
    map_page(root_phys, virt, phys, flags)
}

/// Unmap a large/huge entry (same as the 4 KiB path in the software model).
pub fn unmap_huge_page(root_phys: PhysAddr, virt: VirtAddr) -> Result<(), Error> {
    unmap_page(root_phys, virt)
}

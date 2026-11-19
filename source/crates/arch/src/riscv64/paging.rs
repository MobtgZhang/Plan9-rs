//! RISC-V paging — Sv39 three-level page tables.
//!
//! Mirrors the x86_64 `paging` module's API surface so the kernel's
//! virtual-memory code compiles against `plan9_arch::hal::paging`.
//!
//! Sv39 translation (4 KiB base pages):
//!   * PGD index = VA[38:30]  (512 entries, 512 GiB each)
//!   * PMD index = VA[29:21]  (2 MiB)
//!   * PTE index = VA[20:12]  (4 KiB)
//!
//! Descriptor bits: V(0) R(1) W(2) X(3) U(4) G(5) A(6) D(7), PPN[53:10].
//!
//! Flag semantics note: the API surface is OR-only (x86 style), so
//! `PRESENT` bundles R+X+A+D — every present page is readable and
//! executable (RISC-V has no W^X enforcement, and x86 call sites pass
//! `PRESENT|WRITABLE` for data and `PRESENT` for text). `WRITABLE`
//! bundles W+R (W-without-R is a reserved encoding in RISC-V).

extern crate plan9_common;

use plan9_common::error::Error;
use plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// Constants
// ============================================================================

pub const PAGESIZE: usize = 4096;
pub const PAGE_SHIFT: u32 = 12;

/// 2 MiB mega-page (PMD block entry).
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
pub const LARGE_PAGE_SHIFT: u32 = 21;

/// 1 GiB giga-page (PGD block entry).
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024;
pub const HUGE_PAGE_SHIFT: u32 = 30;

pub const PT_ENTRIES: usize = 512;
pub const ADDR_SPACE_BITS: u32 = 39;
pub const VADDR_MASK: u64 = 0x0000_3FFF_FFFF_FFFF;

/// Level shifts — named after the x86 levels; "PML4" is the Sv39 PGD.
pub const PML4_INDEX_SHIFT: u32 = 30; // VPN2
pub const PDPT_INDEX_SHIFT: u32 = 21; // VPN1
pub const PD_INDEX_SHIFT: u32 = 12;   // VPN0
pub const PT_INDEX_SHIFT: u32 = 12;   // (no 4th level on Sv39)

/// Virtual layout. Sv39's high half starts at 0xFFFF_FFC0_0000_0000
/// (bits [63:39] all set); we put the direct map there like Linux does.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFC0_0000_0000;
pub const KERNEL_VIRT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const USER_VIRT_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_VIRT_END: u64 = 0x0000_3FFF_FFFF_FFFF;

/// Kernel image virtual base (identity — the kernel is linked at
/// 0x8100_0000, the address OpenSBI hands control to).
pub const KERNEL_IMAGE_VIRT: u64 = 0x0000_0000_8100_0000;

/// Physical memory virtual base (direct-map window).
pub const PHYS_MEMORY_VIRT: u64 = 0xFFFF_FFC0_0000_0000;

// ============================================================================
// Page Table Entry Flags — neutral names, Sv39 bits
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PteFlags(u64);

impl PteFlags {
    /// Valid + Read + eXecute + Accessed + Dirty.
    ///
    /// Bundled so OR-composition from x86-style call sites produces a
    /// legal Sv39 descriptor (W-without-R is reserved; RISC-V also
    /// faults on !A/!D access for paging, so both are pre-set).
    pub const PRESENT: Self = Self((1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 7));

    /// Write + Read (W-without-R is reserved in RISC-V).
    pub const WRITABLE: Self = Self((1 << 2) | (1 << 1));

    /// User (U).
    pub const USER: Self = Self(1 << 4);

    /// Accessed (A) — already part of PRESENT.
    pub const ACCESSED: Self = Self(1 << 6);

    /// Dirty (D) — already part of PRESENT.
    pub const DIRTY: Self = Self(1 << 7);

    /// Global (G) — not used in the ASID-less bring-up model.
    pub const GLOBAL: Self = Self(1 << 5);

    /// Block entry marker at PMD/PGD level (same value as W — only
    /// meaningful when checking block descriptors via `is_large_page`).
    pub const PS: Self = Self(1 << 2);

    /// No-exec pseudo-flag (X is always set by PRESENT; no-op here).
    pub const NX: Self = Self(0);

    /// Software copy-on-write marker (Sv39 reserved bits 8–9).
    pub const COW: Self = Self(1 << 9);

    /// Pseudo-flag for API parity: Sv39 has no read-only bit, so a page is
    /// read-only when WRITABLE is clear.
    pub const READONLY: Self = Self(0);

    /// Cache-disable pseudo-flag (RISC-V PTEs have no cache bits).
    pub const PWT: Self = Self(0);
    pub const PCD: Self = Self(0);

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

    pub fn is_present(self) -> bool { (self.0 & (1 << 0)) != 0 }
    pub fn is_writable(self) -> bool { (self.0 & (1 << 2)) != 0 }
    pub fn is_user(self) -> bool { (self.0 & (1 << 4)) != 0 }
    pub fn is_no_exec(self) -> bool { (self.0 & (1 << 3)) == 0 }
    pub fn is_accessed(self) -> bool { (self.0 & (1 << 6)) != 0 }
    pub fn is_dirty(self) -> bool { (self.0 & (1 << 7)) != 0 }
    pub fn is_cow(self) -> bool { (self.0 & Self::COW.0) != 0 }
    pub fn is_large_page(self) -> bool { false }
    pub fn is_huge_page(self) -> bool { false }
}

/// Common flag combinations.
impl PteFlags {
    pub const KERNEL_RW: Self =
        Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::GLOBAL.0);
    pub const KERNEL_RO: Self =
        Self(Self::PRESENT.0 | Self::GLOBAL.0);
    pub const USER_RW: Self =
        Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::USER.0);
    pub const USER_RO: Self =
        Self(Self::PRESENT.0 | Self::USER.0);
    /// Page-table descriptor (V only — lower levels have no R/W/X).
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
        // PPN occupies bits [53:10] (PA[55:12] shifted left by 2... —
        // for Sv39, PTE.PPN = PA >> 12 << 10).
        let ppn = (addr.as_u64() >> 12) << 10;
        Self(ppn | (flags.bits() & 0x3FF))
    }

    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new((self.0 >> 10) << 12)
    }

    pub fn flags(&self) -> PteFlags { PteFlags::new(self.0 & 0x3FF) }

    pub fn is_present(&self) -> bool { self.0 & 1 != 0 }

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
    pub pml4: usize, // Sv39 PGD (VPN2)
    pub pdpt: usize, // PMD (VPN1)
    pub pd: usize,   // PTE (VPN0)
    pub pt: usize,   // unused (always 0)
    pub offset: u64,
}

impl PageTableIndices {
    pub fn from_virt(virt: VirtAddr) -> Self {
        let v = virt.as_u64();
        Self {
            pml4: ((v >> PML4_INDEX_SHIFT) & 0x1FF) as usize,
            pdpt: ((v >> PDPT_INDEX_SHIFT) & 0x1FF) as usize,
            pd: ((v >> PD_INDEX_SHIFT) & 0x1FF) as usize,
            pt: 0,
            offset: v & 0xFFF,
        }
    }

    pub fn from_virt_large(virt: VirtAddr) -> Self { Self::from_virt(virt) }
    pub fn from_virt_huge(virt: VirtAddr) -> Self { Self::from_virt(virt) }

    pub fn page_frame_number(&self) -> u64 {
        ((self.pml4 as u64) << 21)
            | ((self.pdpt as u64) << 12)
            | (self.pd as u64)
    }

    pub fn is_kernel(&self) -> bool { self.pml4 >= 256 }
}

// ============================================================================
// Address helpers
// ============================================================================

pub mod virt_addr {
    use super::*;

    pub fn new_checked(addr: u64) -> Option<VirtAddr> {
        // Sv39 requires bits [63:39] all equal (sign extension).
        let sign = (addr >> 38) & 1;
        let top = addr >> 39;
        if (sign == 0 && top == 0) || (sign == 1 && top == 0x1FF_FFFF) {
            Some(VirtAddr::new(addr))
        } else {
            None
        }
    }

    pub fn is_canonical(addr: VirtAddr) -> bool { new_checked(addr.as_u64()).is_some() }

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
// Walking / mapping (3 levels)
// ============================================================================

/// Walk the table rooted at `root` (physical) for `virt`, returning the
/// final (PTE-level) descriptor when all levels are present.
pub fn walk_page_table_entry(root: PhysAddr, virt: VirtAddr) -> Option<PageTableEntry> {
    let idx = PageTableIndices::from_virt(virt);
    let levels = [idx.pml4, idx.pdpt, idx.pd];
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

#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(PHYS_MEMORY_VIRT + phys.as_u64())
}

/// Map one 4 KiB page into the address space rooted at `root_phys`.
pub fn map_page(
    root_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PteFlags,
) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root_phys.as_u64();
    for (level, level_index) in [idx.pml4, idx.pdpt, idx.pd]
        .into_iter()
        .enumerate()
    {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[level_index];
        if !entry.is_present() {
            if level == 2 {
                *entry = PageTableEntry::new(phys, flags.withaccessed());
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

/// Unmap one 4 KiB page.
pub fn unmap_page(root_phys: PhysAddr, virt: VirtAddr) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let mut table_phys = root_phys.as_u64();
    for (level, level_index) in [idx.pml4, idx.pdpt, idx.pd]
        .into_iter()
        .enumerate()
    {
        let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
        let entry = &mut table.entries[level_index];
        if !entry.is_present() {
            return Err(Error::Enoent);
        }
        if level == 2 {
            entry.clear();
            super::mmu::invlpg(virt);
            return Ok(());
        }
        table_phys = entry.addr().as_u64();
    }
    Err(Error::Enoent)
}

/// Map a 2 MiB or 1 GiB block entry.
pub fn map_huge_page(
    root_phys: PhysAddr,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PteFlags,
    level_bits: u32,
) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    // 1 GiB block → single PGD entry; 2 MiB block → descend one level.
    let (depth, level_index) = if level_bits >= HUGE_PAGE_SHIFT {
        (0usize, idx.pml4)
    } else {
        (1usize, idx.pdpt)
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
            *entry = PageTableEntry::new(PhysAddr::new(new_table), PteFlags::PAGE_TABLE);
        }
        table_phys = entry.addr().as_u64();
    }
    let table = unsafe { &mut *(super::paging_phys_to_virt(table_phys) as *mut PageTable) };
    table.entries[level_index] = PageTableEntry::new(phys, flags.withaccessed());
    super::mmu::invlpg(virt);
    Ok(())
}

/// Unmap a 2 MiB / 1 GiB block entry.
///
/// RISC-V distinguishes leaf (block) descriptors from table pointers by
/// the R/W/X bits (all zero = pointer, any set = leaf).
pub fn unmap_huge_page(root_phys: PhysAddr, virt: VirtAddr) -> Result<(), Error> {
    let idx = PageTableIndices::from_virt(virt);
    let pgd = unsafe {
        &mut *((super::paging_phys_to_virt(root_phys.as_u64())) as *mut PageTable)
    };
    let pgd_entry = pgd.entries[idx.pml4];
    if !pgd_entry.is_present() {
        return Err(Error::Enoent);
    }
    // Leaf (R/W/X set) → 1 GiB block; clear it. Pointer → descend.
    if pgd_entry.0 & 0b1110 != 0 {
        pgd.entries[idx.pml4].clear();
        super::mmu::invlpg(virt);
        return Ok(());
    }
    let pmd = unsafe { &mut *(super::paging_phys_to_virt(pgd_entry.addr().as_u64()) as *mut PageTable) };
    if pmd.entries[idx.pdpt].is_present() {
        pmd.entries[idx.pdpt].clear();
        super::mmu::invlpg(virt);
        return Ok(());
    }
    Err(Error::Enoent)
}

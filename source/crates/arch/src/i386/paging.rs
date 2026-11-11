//! i386 paging — 2-level page tables (4 KiB pages, PAE off).
#![allow(dead_code)]

extern crate plan9_common;

use plan9_common::types::{PhysAddr, VirtAddr};

pub const PAGESIZE: usize = 4096;
pub const PAGE_SHIFT: u32 = 12;
pub const LARGE_PAGE_SIZE: usize = 4 * 1024 * 1024;
pub const LARGE_PAGE_SHIFT: u32 = 22;
pub const PT_ENTRIES: usize = 1024;
pub const ADDR_SPACE_BITS: u32 = 32;
pub const VADDR_MASK: u64 = 0xFFFF_FFFF;

pub const KERNEL_VIRT_BASE: u64 = 0x8000_0000;
pub const KERNEL_VIRT_END: u64 = 0xFFFF_FFFF;
pub const USER_VIRT_BASE: u64 = 0;
pub const USER_VIRT_END: u64 = 0x7FFF_FFFF;
pub const KERNEL_IMAGE_VIRT: u64 = 0x8000_0000;
/// i386 has no direct map; the stub reports the identity window.
pub const PHYS_MEMORY_VIRT: u64 = 0x0000_0000;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PteFlags(pub u32);

impl PteFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const NX: Self = Self(0);
    pub const PS: Self = Self(1 << 7);
    pub const PWT: Self = Self(1 << 3);
    pub const PCD: Self = Self(1 << 4);

    pub const fn new(bits: u32) -> Self { Self(bits) }
    pub fn bits(self) -> u32 { self.0 }
    pub fn with_present(self) -> Self { Self(self.0 | Self::PRESENT.0) }
    pub fn with_writable(self) -> Self { Self(self.0 | Self::WRITABLE.0) }
    pub fn with_user(self) -> Self { Self(self.0 | Self::USER.0) }
    pub fn with_no_exec(self) -> Self { self }
    pub fn with_global(self) -> Self { Self(self.0 | Self::GLOBAL.0) }
    pub fn withaccessed(self) -> Self { Self(self.0 | Self::ACCESSED.0) }
    pub fn with_dirty(self) -> Self { Self(self.0 | Self::DIRTY.0) }
    pub fn is_present(self) -> bool { (self.0 & Self::PRESENT.0) != 0 }
    pub fn is_writable(self) -> bool { (self.0 & Self::WRITABLE.0) != 0 }
    pub fn is_user(self) -> bool { (self.0 & Self::USER.0) != 0 }
    pub fn is_no_exec(self) -> bool { false }
    pub fn is_accessed(self) -> bool { (self.0 & Self::ACCESSED.0) != 0 }
    pub fn is_dirty(self) -> bool { (self.0 & Self::DIRTY.0) != 0 }
    pub fn is_large_page(self) -> bool { (self.0 & Self::PS.0) != 0 }
    pub fn is_huge_page(self) -> bool { (self.0 & Self::PS.0) != 0 }

    pub const KERNEL_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0);
    pub const KERNEL_RO: Self = Self(Self::PRESENT.0);
    pub const USER_RW: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0 | Self::USER.0);
    pub const USER_RO: Self = Self(Self::PRESENT.0 | Self::USER.0);
    pub const PAGE_TABLE: Self = Self(Self::PRESENT.0 | Self::WRITABLE.0);
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}
impl core::ops::BitOrAssign for PteFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageTableEntry(pub u32);

impl PageTableEntry {
    pub fn new(addr: PhysAddr, flags: PteFlags) -> Self {
        Self((addr.as_u64() as u32 & 0xFFFF_F000) | flags.bits())
    }
    pub fn addr(&self) -> PhysAddr { PhysAddr::new((self.0 & 0xFFFF_F000) as u64) }
    pub fn flags(&self) -> PteFlags { PteFlags(self.0 & 0xFFF) }
    pub fn is_present(&self) -> bool { self.0 & 1 != 0 }
    pub fn is_large(&self) -> bool { self.0 & (1 << 7) != 0 }
    pub fn clear(&mut self) { self.0 = 0; }
}

#[derive(Debug)]
#[repr(C)]
pub struct PageTable {
    pub entries: [PageTableEntry; PT_ENTRIES],
}

impl PageTable {
    pub fn new() -> Self { Self { entries: [PageTableEntry(0); PT_ENTRIES] } }
    pub fn entry(&self, i: usize) -> PageTableEntry { self.entries[i] }
    pub fn entry_mut(&mut self, i: usize) -> &mut PageTableEntry { &mut self.entries[i] }
    pub fn set_entry(&mut self, i: usize, e: PageTableEntry) { self.entries[i] = e; }
    pub fn clear_entry(&mut self, i: usize) { self.entries[i] = PageTableEntry(0); }
    pub fn entries(&self) -> &[PageTableEntry; PT_ENTRIES] { &self.entries }
    pub fn is_index_present(&self, i: usize) -> bool { self.entries[i].is_present() }
    pub fn count_present(&self) -> usize { self.entries.iter().filter(|e| e.is_present()).count() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableIndices {
    pub pml4: usize, // unused on i386 (always 0)
    pub pdpt: usize, // page directory index (VA[31:22])
    pub pd: usize,   // page table index (VA[21:12])
    pub pt: usize,   // same as pd on 2-level
    pub offset: u64,
}

impl PageTableIndices {
    pub fn from_virt(virt: VirtAddr) -> Self {
        let v = virt.as_u64() as u32;
        Self {
            pml4: 0,
            pdpt: ((v >> 22) & 0x3FF) as usize,
            pd: ((v >> 12) & 0x3FF) as usize,
            pt: ((v >> 12) & 0x3FF) as usize,
            offset: (v & 0xFFF) as u64,
        }
    }
    pub fn from_virt_large(virt: VirtAddr) -> Self { Self::from_virt(virt) }
    pub fn from_virt_huge(virt: VirtAddr) -> Self { Self::from_virt(virt) }
    pub fn page_frame_number(&self) -> u64 { (self.pd as u64) << 22 >> 12 }
    pub fn is_kernel(&self) -> bool { self.pdpt >= 512 }
}

pub mod virt_addr {
    use super::*;
    pub fn new_checked(addr: u64) -> Option<VirtAddr> { Some(VirtAddr::new(addr as u32 as u64)) }
    pub fn is_canonical(_addr: VirtAddr) -> bool { true }
    pub fn is_kernel(addr: VirtAddr) -> bool { addr.as_u64() >= KERNEL_VIRT_BASE }
    pub fn page_align_down(addr: VirtAddr) -> VirtAddr { VirtAddr::new(addr.as_u64() & !0xFFF) }
    pub fn page_align_up(addr: VirtAddr) -> VirtAddr { VirtAddr::new((addr.as_u64() + 0xFFF) & !0xFFF) }
    pub fn offset(addr: VirtAddr) -> u64 { addr.as_u64() & 0xFFF }
}

pub mod phys_addr {
    use super::*;
    pub fn from_page(pn: PageNum) -> PhysAddr { PhysAddr::new(pn.0 << PAGE_SHIFT) }
    pub fn to_page(addr: PhysAddr) -> PageNum { PageNum((addr.as_u64() >> PAGE_SHIFT) as u32) }
    pub fn page_align_down(addr: PhysAddr) -> PhysAddr { PhysAddr::new(addr.as_u64() & !0xFFF) }
    pub fn page_align_up(addr: PhysAddr) -> PhysAddr { PhysAddr::new((addr.as_u64() + 0xFFF) & !0xFFF) }
    pub fn is_aligned(addr: PhysAddr) -> bool { addr.as_u64() & 0xFFF == 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageNum(pub u32);

impl PageNum {
    pub const fn new(n: u32) -> Self { Self(n) }
    pub fn from_virt(v: VirtAddr) -> Self { Self(((v.as_u64() >> PAGE_SHIFT) as u32) & 0xFFFFF) }
    pub fn as_u64(self) -> u64 { self.0 as u64 }
    pub fn as_virt(self) -> VirtAddr { VirtAddr::new((self.0 as u64) << PAGE_SHIFT) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargePageNum(pub u32);

impl LargePageNum {
    pub const fn new(n: u32) -> Self { Self(n) }
    pub fn from_virt(v: VirtAddr) -> Self { Self(((v.as_u64() >> LARGE_PAGE_SHIFT) as u32) & 0xFFF) }
    pub fn as_u64(self) -> u64 { self.0 as u64 }
    pub fn as_virt(self) -> VirtAddr { VirtAddr::new((self.0 as u64) << LARGE_PAGE_SHIFT) }
}

pub fn pages_for_size(size: usize) -> usize { (size + PAGESIZE - 1) / PAGESIZE }

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
pub struct AddressSpace { pub root_phys: u64 }

impl AddressSpace {
    pub fn new() -> Self { Self { root_phys: 0 } }
    pub fn is_valid(&self) -> bool { self.root_phys != 0 }
}

pub fn walk_page_table_entry(_root: PhysAddr, _virt: VirtAddr) -> Option<PageTableEntry> {
    None // not implemented on the i386 stub
}

#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr { VirtAddr::new(phys.as_u64()) }

pub fn map_page(_root: PhysAddr, _v: VirtAddr, _p: PhysAddr, _f: PteFlags) -> Result<(), plan9_common::error::Error> {
    Err(plan9_common::error::Error::Enodev)
}

pub fn unmap_page(_root: PhysAddr, _v: VirtAddr) -> Result<(), plan9_common::error::Error> {
    Err(plan9_common::error::Error::Enodev)
}

pub fn map_huge_page(_root: PhysAddr, _v: VirtAddr, _p: PhysAddr, _f: PteFlags, _l: u32) -> Result<(), plan9_common::error::Error> {
    Err(plan9_common::error::Error::Enodev)
}

pub fn unmap_huge_page(_root: PhysAddr, _v: VirtAddr) -> Result<(), plan9_common::error::Error> {
    Err(plan9_common::error::Error::Enodev)
}

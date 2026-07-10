//! MMU and page table switching for x86_64
//!
//! This module provides functions for manipulating the Memory Management Unit,
//! including page table switching and TLB operations.

extern crate plan9_common;

use plan9_common::types::{PhysAddr, VirtAddr};

// ============================================================================
// CR3 Register Operations
// ============================================================================

/// Switch to a new page table
/// 
/// This function loads a new page directory physical address into CR3.
/// Note: This automatically flushes the TLB for non-global pages.
#[inline(always)]
pub fn switch_page_table(pdb_phys: PhysAddr) {
    unsafe {
        core::arch::asm!(
            "mov rax, rdi",
            "mov cr3, rax",
            // Optionally flush TLB completely
            // "mov rax, cr3",
            // "mov cr3, rax",
            in("rdi") pdb_phys.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

/// Get the current CR3 value (page directory base)
#[inline(always)]
pub fn get_page_directory() -> PhysAddr {
    let pdb: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, cr3",
            out("rax") pdb,
            options(nostack, preserves_flags)
        );
    }
    PhysAddr::new(pdb)
}

// ============================================================================
// CR2 Register Operations
// ============================================================================

/// Read CR2 to get the faulting address from a page fault
#[inline(always)]
pub fn read_cr2() -> u64 {
    let cr2: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, cr2",
            out("rax") cr2,
            options(nostack, preserves_flags)
        );
    }
    cr2
}

/// Alias for read_cr2
pub fn cr2_read() -> u64 {
    read_cr2()
}

// ============================================================================
// CR3 Read/Write
// ============================================================================

/// Read CR3
#[inline(always)]
pub fn cr3_read() -> PhysAddr {
    let cr3: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, cr3",
            out("rax") cr3,
            options(nostack, preserves_flags)
        );
    }
    PhysAddr::new(cr3)
}

/// Write to CR3
#[inline(always)]
pub fn cr3_write(pdb: PhysAddr) {
    unsafe {
        core::arch::asm!(
            "mov rax, rdi",
            "mov cr3, rax",
            in("rdi") pdb.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// TLB Operations
// ============================================================================

/// Invalidate (flush) a single page's TLB entry
#[inline(always)]
pub fn invlpg(addr: VirtAddr) {
    unsafe {
        core::arch::asm!(
            "invlpg [rdi]",
            in("rdi") addr.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

/// Invalidate the entire TLB (flush all entries)
/// This is slower than invlpg but simpler
pub fn flush_tlb() {
    // Writing to CR3 automatically flushes the TLB
    let cr3 = cr3_read();
    cr3_write(cr3);
}

/// Invalidate TLB for a specific address range
pub fn flush_tlb_range(start: VirtAddr, count: usize) {
    // Use invlpg for each page
    let page_size = 4096;
    for i in 0..count {
        let addr = VirtAddr::new(start.as_u64() + (i * page_size) as u64);
        invlpg(addr);
    }
}

// ============================================================================
// Page Table Access
// ============================================================================

/// Read a page table entry at a given virtual address
/// 
/// This is used internally for walking page tables
pub fn read_pte(table_virt: VirtAddr, index: usize) -> Option<u64> {
    if index >= 512 {
        return None;
    }
    let entry_ptr = (table_virt.as_u64() + (index as u64) * 8) as *const u64;
    Some(unsafe { *entry_ptr })
}

/// Write a page table entry
pub fn write_pte(table_virt: VirtAddr, index: usize, entry: u64) {
    if index >= 512 {
        return;
    }
    let entry_ptr = (table_virt.as_u64() + (index as u64) * 8) as *mut u64;
    unsafe { *entry_ptr = entry; }
}

// ============================================================================
// Paging Flags
// ============================================================================

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
    /// Page write-through
    pub const PWT: u64 = 1 << 3;
    /// Page cache disable
    pub const PCD: u64 = 1 << 4;
    /// Accessed flag
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty flag
    pub const DIRTY: u64 = 1 << 6;
    /// Page attribute table
    pub const PAT: u64 = 1 << 7;
    /// Global page (not flushed on CR3 switch)
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute bit
    pub const NX: u64 = 1 << 63;

    /// Kernel code: present, writable, global
    pub const KERNEL_RW: u64 = Self::PRESENT | Self::WRITABLE | Self::GLOBAL;
    /// Kernel code: present, read-only, global
    pub const KERNEL_RO: u64 = Self::PRESENT | Self::GLOBAL;
    /// User code: present, writable, user accessible
    pub const USER_RW: u64 = Self::PRESENT | Self::WRITABLE | Self::USER;
    /// User code: present, read-only, user accessible
    pub const USER_RO: u64 = Self::PRESENT | Self::USER;
    /// Page table entry (for paging structures)
    pub const PAGE_TABLE: u64 = Self::PRESENT | Self::WRITABLE;

    /// Create new flags from raw bits
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub fn bits(&self) -> u64 {
        self.0
    }

    /// Check if present
    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    /// Check if writable
    pub fn is_writable(&self) -> bool {
        (self.0 & Self::WRITABLE) != 0
    }

    /// Check if user accessible
    pub fn is_user(&self) -> bool {
        (self.0 & Self::USER) != 0
    }

    /// Check if global
    pub fn is_global(&self) -> bool {
        (self.0 & Self::GLOBAL) != 0
    }

    /// Check if no-execute
    pub fn is_nx(&self) -> bool {
        (self.0 & Self::NX) != 0
    }

    /// Get physical address from PTE
    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000_FFFF_FFFF_F000)
    }
}

// ============================================================================
// Page Fault Error Code
// ============================================================================

/// Page fault error code bits
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    /// Raw error code
    pub raw: u64,
}

impl PageFaultError {
    /// Create from raw error code
    pub fn new(raw: u64) -> Self {
        Self { raw }
    }

    /// Page was present (0) or not present (1)
    pub fn present(&self) -> bool {
        (self.raw & 1) == 0
    }

    /// Write access (1) or read access (0)
    pub fn write(&self) -> bool {
        (self.raw & 2) != 0
    }

    /// User mode access (1) or supervisor mode (0)
    pub fn user(&self) -> bool {
        (self.raw & 4) != 0
    }

    /// Reserved bit violation (1)
    pub fn reserved(&self) -> bool {
        (self.raw & 8) != 0
    }

    /// Instruction fetch (1)
    pub fn instruction_fetch(&self) -> bool {
        (self.raw & 16) != 0
    }

    /// Fault was caused by a protection key violation
    pub fn protection_key(&self) -> bool {
        (self.raw & 32) != 0
    }

    /// Shadow stack access
    pub fn shadow_stack(&self) -> bool {
        (self.raw & 0x40) != 0
    }
}

// ============================================================================
// Address Validation
// ============================================================================

/// Check if an address is a valid user address
pub fn is_user_addr(addr: u64) -> bool {
    addr < super::paging::USER_VIRT_END
}

/// Check if an address is a valid kernel address
pub fn is_kernel_addr(addr: u64) -> bool {
    addr >= super::paging::KERNEL_VIRT_BASE
}

/// Check if an address is in the user range
pub fn is_in_user_range(addr: u64) -> bool {
    addr < super::paging::USER_VIRT_END
}

/// Check if an address is in the kernel range
pub fn is_in_kernel_range(addr: u64) -> bool {
    addr >= super::paging::KERNEL_VIRT_BASE
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the page table index for a given virtual address at a given level
pub fn pte_index(virt: u64, level: usize) -> usize {
    const SHIFTS: [u32; 4] = [39, 30, 21, 12];
    if level < 4 {
        ((virt >> SHIFTS[level]) & 0x1FF) as usize
    } else {
        0
    }
}

/// Get the page offset for a 4KB page
pub fn page_offset(virt: u64) -> u64 {
    virt & 0xFFF
}

/// Get the page frame number from a PTE
pub fn pfn(pte: u64) -> u64 {
    pte & 0x000_FFFF_FFFF_F000
}

// ============================================================================
// Page Table Switch Lock
// ============================================================================

use plan9_common::sync::Spinlock;

/// Lock for page table switching
/// Prevents concurrent page table modifications
static PAGE_TABLE_LOCK: Spinlock<()> = Spinlock::new(());

/// Switch to a new page table with lock protection
///
/// This function loads a new page directory physical address into CR3
/// while holding a lock to prevent concurrent modifications.
///
/// # Safety
/// - The caller must ensure the new page table is valid
/// - Interrupts should be disabled or the lock should not be held during I/O
#[inline(always)]
pub fn switch_page_table_safe(pdb_phys: PhysAddr) {
    let _guard = PAGE_TABLE_LOCK.lock();

    unsafe {
        core::arch::asm!(
            "mov rax, rdi",
            "mov cr3, rax",
            // Full TLB flush for safety
            "mov rax, cr3",
            "mov cr3, rax",
            in("rdi") pdb_phys.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

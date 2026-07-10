//! Early paging setup for x86_64.
//!
//! At boot GRUB leaves us with paging disabled. The kernel itself lives in
//! low memory (linker base = 0x200000), so before enabling paging we build
//! a minimal 4-level page table that:
//!
//!   1. Identity-maps the low 8 MiB so GRUB's loaded modules, the
//!      Multiboot2 information structure, the kernel image (.text/.data),
//!      the entire BSS (including the kernel stack and the static page-
//!      table pool), and the early-heap region remain accessible.
//!   2. Mirror-maps the same 8 MiB at 0xFFFF_8000_0000_0000 so the kernel
//!      can later switch to the canonical address without another CR3
//!      reload.
//!
//! After `early_paging_init()` returns, paging is enabled and the CPU is
//! running with the new PML4. The kernel keeps running in low memory for
//! the duration of the boot path.
//!
//! Page-table memory comes from a small static page-table pool in `.bss`,
//! so we don't depend on the heap here.

use core::arch::asm;

/// Page size constant.
pub const PAGE_SIZE: u64 = 4096;

/// Page-table entry flag bits (subset).
pub const PTE_PRESENT:    u64 = 1 << 0;
pub const PTE_WRITABLE:   u64 = 1 << 1;
pub const PTE_USER:       u64 = 1 << 2;
pub const PTE_ACCESSED:   u64 = 1 << 5;
pub const PTE_DIRTY:      u64 = 1 << 6;
pub const PTE_PS:         u64 = 1 << 7;  /* page-size: 2 MiB huge */
pub const PTE_GLOBAL:     u64 = 1 << 8;
pub const PTE_NX:         u64 = 1 << 63;

/// Bottom-of-RAM kernel image start (from kernel-x86_64.ld).
pub const KERNEL_PHYS_BASE: u64 = 0x200_000;

/// Total mapped region. The kernel BSS extends to roughly 0x480000, and we
/// want our static page-table pool, the kernel stack, and any heap
/// variables in BSS to remain addressable, so we identity-map the first
/// 12 MiB. (12 MiB = 6 huge pages.)
///
/// Additionally, we need a PDPT for PML4[256] that covers the
/// 0x80000000 region (GOP framebuffer physical address range). We
/// allocate that from the identity-mapped area (at 0xC00000, which is
/// safe — the kernel image ends well before that).
pub const MAPPED_BYTES: u64 = 64 * 1024 * 1024;

/// A 4 KiB-aligned page-table page.
#[repr(C, align(4096))]
pub struct PageTablePage(pub [u64; 512]);

/// Static page-table pool. Sized for our minimal boot map:
///   * 1 PML4 page covering all 512 GiB regions
///   * 1 PDPT page covering all 1 GiB slots within the low region
///   * 1 PD page covering 2 MiB × 512 = 1 GiB (pd_low: first 12 MiB identity)
///   * 1 PD page for the higher-half mirror (pd_high: same as pd_low)
///   * 1 PD page for PML4[256] covering 0x80000000 (GOP framebuffer region)
///   * NOTE: We use separate PDs for the identity mirror and GOP so they
///     don't interfere with each other. The pd_gop page lives in the
///     identity-mapped region at ~0xC00000.
#[repr(C, align(4096))]
struct BootPageTablePool {
    pml4:        PageTablePage,
    pdpt:        PageTablePage,
    pdpt_gop:    PageTablePage,  // PDPT for the GOP region (PML4[256])
    pd_low:      PageTablePage,
    pd_high:     PageTablePage,
    pd_gop:      PageTablePage,
}

// PT_POOL lives in the .pagetable_pool section so the linker can place it
// at a 2 MiB-aligned address (the boot-time identity map uses 2 MiB huge
// pages, so the pool must be reachable via identity-mapped virtual
// addresses).
#[link_section = ".pagetable_pool"]
static mut PT_POOL: BootPageTablePool = BootPageTablePool {
    pml4:        PageTablePage([0; 512]),
    pdpt:        PageTablePage([0; 512]),
    pdpt_gop:    PageTablePage([0; 512]),
    pd_low:      PageTablePage([0; 512]),
    pd_high:     PageTablePage([0; 512]),
    pd_gop:      PageTablePage([0; 512]),
};

/// Returns the physical address of the early-boot PML4 page.
pub fn pml4_pool_ptr() -> u64 {
    let pool = &raw mut PT_POOL;
    pool as u64
}

/// Build the early page tables and enable paging.
///
/// After this function returns, code is still executing at the linker
/// base (`KERNEL_PHYS_BASE`) but the CPU is now using our PML4.
///
/// # Safety
/// Caller must ensure this is invoked at most once.
pub unsafe fn early_paging_init() {
    let pool = &mut *(&raw mut PT_POOL);

    // Diagnostic: print 'A' so we know we entered.
    asm!("mov dx, 0x3F8; mov al, 'A'; out dx, al", options(nostack, preserves_flags));
    // 1. Zero everything so any "not present" PTE is genuinely zero.
    for p in pool.pml4.0.iter_mut()     { *p = 0; }
    for p in pool.pdpt.0.iter_mut()     { *p = 0; }
    for p in pool.pdpt_gop.0.iter_mut() { *p = 0; }
    for p in pool.pd_low.0.iter_mut()   { *p = 0; }
    for p in pool.pd_high.0.iter_mut()  { *p = 0; }
    asm!("mov dx, 0x3F8; mov al, 'B'; out dx, al", options(nostack, preserves_flags));

    // 2. Point both PML4 slots at the same PDPT.
    //
    //    PML4[0]   -> low-half identity
    //    PML4[508] -> kernel high-half mirror (-2 GiB canonical region)
    //
    //    PML4[511] -> pdpt_gop. The GOP virtual address
    //    0xffff800080000000 uses PML4[511] (canonical upper half),
    //    not PML4[256]. Within pdpt_gop, pdpt_gop[2] -> pd_gop,
    //    which maps the GOP framebuffer at physical 0x80000000 via 2 MiB huge pages.
    //
    // CRITICAL: PML4[256] maps the range 0xFFFF_8000_0000_0000..0xFFFF_807F_FFFF_FFFF,
    // which is NOT where 0xffff800080000000 falls. The canonical upper-half address
    // range starts at PML4[511].
    let pdpt_phys     = pool.pdpt.0.as_ptr() as u64;
    let pdpt_gop_phys = pool.pdpt_gop.0.as_ptr() as u64;
    let pd_low_phys   = pool.pd_low.0.as_ptr() as u64;
    let pd_high_phys  = pool.pd_high.0.as_ptr() as u64;

    pool.pml4.0[0]     = pdpt_phys     | PTE_PRESENT | PTE_WRITABLE;
    pool.pml4.0[508]   = pdpt_phys     | PTE_PRESENT | PTE_WRITABLE;
    asm!("mov dx, 0x3F8; mov al, 'C'; out dx, al", options(nostack, preserves_flags));

    // PML4[511] -> pdpt_gop. This covers the full canonical upper-half
    // address range 0xFFFF_8000_0000_0000 to 0xFFFF_FFFF_FFFF_FFFF.
    let pd_gop_phys = pool.pd_gop.0.as_ptr() as u64;
    pool.pml4.0[511]   = pdpt_gop_phys | PTE_PRESENT | PTE_WRITABLE;
    asm!("mov dx, 0x3F8; mov al, 'D'; out dx, al", options(nostack, preserves_flags));

    // 3. PDPT slot 0 -> pd_low, slot 0 from the high mirror -> pd_high.
    //    (Both PML4 entries share this PDPT.)
    pool.pdpt.0[0] = pd_low_phys  | PTE_PRESENT | PTE_WRITABLE;
    pool.pdpt.0[1] = pd_high_phys | PTE_PRESENT | PTE_WRITABLE;
    asm!("mov dx, 0x3F8; mov al, 'E'; out dx, al", options(nostack, preserves_flags));

    // GOP framebuffer physical base — must match entry.rs.
    const GOP_BASE: u64 = 0x8000_0000u64;

    // 3b. PDPT for GOP: pdpt_gop[256] -> 1 GiB huge page.
    //     The GOP virtual address 0xFFFF_8080_0000_0000 uses:
    //       - PML4[511] (bits 47:39 = 511)
    //       - PDPT[256] (bits 38:30 = 256)
    //       - Offset in 1 GiB page (bits 29:0)
    //     A 1 GiB huge page in PDPT[256] maps
    //     VA 0xFFFF_8080_0000_0000..0xFFFF_80FF_FFFF_FFFF
    //     directly to physical 0x8000_0000..0xBFFF_FFFF (1 GiB).
    //     This covers the entire 192 MiB GOP framebuffer (0x80000000).
    pool.pdpt_gop.0[256] = GOP_BASE | PTE_PRESENT | PTE_WRITABLE | PTE_PS | PTE_GLOBAL;
    asm!("mov dx, 0x3F8; mov al, 'd'; out dx, al", options(nostack, preserves_flags));

    // 4. Identity-map the first MAPPED_BYTES with 2 MiB huge pages.
    //    MAPPED_BYTES must be a multiple of 2 MiB.
    let n_huge = (MAPPED_BYTES / (2u64 * 1024 * 1024)) as usize;
    asm!("mov dx, 0x3F8; mov al, '4'; out dx, al", options(nostack, preserves_flags));
    for i in 0..n_huge {
        pool.pd_low.0[i] = (i as u64) * 2u64 * 1024 * 1024
            | PTE_PRESENT | PTE_WRITABLE | PTE_PS | PTE_GLOBAL;
    }
    asm!("mov dx, 0x3F8; mov al, 'F'; out dx, al", options(nostack, preserves_flags));

    // 5. Same mapping for the high-half mirror.
    asm!("mov dx, 0x3F8; mov al, '5'; out dx, al", options(nostack, preserves_flags));
    for i in 0..n_huge {
        pool.pd_high.0[i] = (i as u64) * 2u64 * 1024 * 1024
            | PTE_PRESENT | PTE_WRITABLE | PTE_PS | PTE_GLOBAL;
        if i == 0 {
            asm!("mov dx, 0x3F8; mov al, 'a'; out dx, al", options(nostack, preserves_flags));
        }
        if i == 1 {
            asm!("mov dx, 0x3F8; mov al, 'b'; out dx, al", options(nostack, preserves_flags));
        }
        if i == 2 {
            asm!("mov dx, 0x3F8; mov al, 'c'; out dx, al", options(nostack, preserves_flags));
        }
    }
    asm!("mov dx, 0x3F8; mov al, 'G'; out dx, al", options(nostack, preserves_flags));

    // 6. Map the GOP framebuffer at physical 0x80000000.
    //    COVERED BY pdpt_gop[256] 1 GiB huge page.
    //    The pd_gop table is no longer used but we fill it for completeness.
    // Last diagnostic marker before we load CR3.
    asm!(
        "mov dx, 0x3F8",
        "mov al, 'H'",
        "out dx, al",
        "mov al, 'I'",
        "out dx, al",
        options(nostack, preserves_flags),
    );

    // 7. Load the new PML4 into CR3 and turn paging on. We do this in a
    //    single inline asm! block so the compiler can't reorder it past
    //    the diagnostic marker above.
    let pml4_phys = pool.pml4.0.as_ptr() as u64;
    let cr0_set: u64 = 0x8001_0000;
    let cr0_clr: u64 = 0x6000;
    asm!(
        "mov cr3, {pml4}",
        "mov rax, cr0",
        "or  rax, {set_mask}",
        "mov rcx, {clr_mask}",
        "not rcx",
        "and rax, rcx",
        "mov cr0, rax",
        // After CR0.PG is set, the CPU walks our new page tables for
        // the very next instruction. If we hit a #PF or #GP here we
        // have no IDT installed yet, so the failure shows up as a
        // hang rather than a serial message. Mark 'J' once we're
        // safely executing with the new tables.
        "mov dx, 0x3F8",
        "mov al, 'J'",
        "out dx, al",
        pml4     = in(reg) pml4_phys,
        set_mask = in(reg) cr0_set,
        clr_mask = in(reg) cr0_clr,
        out("rax") _,
        out("rcx") _,
        options(nostack, preserves_flags),
    );
}

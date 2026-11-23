//! RISC-V architecture root — `Arch` trait implementation and kernel
//! bring-up entry points.
//!
//! Hardware model (matches QEMU's `riscv64` virt machine with OpenSBI):
//!   * 16550A UART at 0x1000_0000          → `uart`
//!   * CLINT/ACLINT time + SBI set_timer   → `timer`
//!   * sstatus.SIE interrupt control       → `cpu`
//!   * Sv39 three-level page tables        → `paging`
//!   * satp + sfence.vma                   → `mmu`
//!
//! Boot contract: OpenSBI (default `-bios`) loads the kernel ELF at
//! 0x8020_0000 and enters S-mode with `a0 = hartid`, `a1 = device tree
//! pointer`. The kernel entry assembly saves both, sets `tp = hartid`,
//! and calls [`early_init`] then [`paging_init`].

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::AtomicU64;

use crate::arch_trait::{Arch, ContextArch, InterruptControl, TimerArch};

pub mod context;
pub mod cpu;
pub mod mmu;
pub mod paging;
pub mod regs;
pub mod switch_to_user;
pub mod timer;
pub mod uart;

// ============================================================================
// Architecture-neutral facade re-exports (used by `plan9_arch::hal`)
// ============================================================================

pub use cpu::{disable_interrupts, enable_interrupts, hlt, interrupts_enabled};
pub use timer::{current_tick, init_timer as init_generic_timer};

/// Physical → virtual through the direct map (reachable as
/// `super::paging_phys_to_virt` from the paging submodule).
pub use mmu::paging_phys_to_virt;

/// Physical RAM base on the reference (QEMU virt) platform. OpenSBI
/// reserves the first 2 MiB; the uefiboot loader sits at 0x8030_0000 and
/// the kernel is linked at 0x8100_0000 (16 MiB above the RAM base, clear
/// of the loader image and its low allocations).
pub const RAM_PHYS_BASE: u64 = 0x8000_0000;
pub const KERNEL_PHYS_BASE: u64 = 0x8100_0000;

/// GiB of RAM identity-mapped at boot (supervisor only).
pub const IDENTITY_GIB: u64 = 4;

// ============================================================================
// Frame-allocator hook (kernel registers its allocator at boot)
// ============================================================================

type AllocHook = fn() -> Option<u64>;

static mut FRAME_ALLOC_HOOK: Option<AllocHook> = None;

/// Register the kernel frame allocator used for page-table allocation.
///
/// # Safety
/// Must be called once, after the allocator is functional.
pub unsafe fn register_frame_allocator(hook: AllocHook) {
    FRAME_ALLOC_HOOK = Some(hook);
}

/// Allocate one zeroed 4 KiB frame for a page table (hook dispatch).
pub fn alloc_zeroed_frame() -> Option<u64> {
    let hook = unsafe { &*core::ptr::addr_of!(FRAME_ALLOC_HOOK) };
    let f = (*hook)?;
    let frame = f()?;
    let va = mmu::paging_phys_to_virt(frame);
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, paging::PAGESIZE) };
    Some(frame)
}

// ============================================================================
// Root-table storage (static, 4 KiB-aligned, before any allocator)
// ============================================================================

#[repr(C, align(4096))]
struct RootTable {
    entries: [u64; 512],
}

/// Boot root (satp) — supervisor identity blocks + the user VA space.
static mut BOOT_ROOT: RootTable = RootTable { entries: [0; 512] };

/// Direct-map L1 tables (Sv39: PGD entries point at PMD tables; for a
/// flat 1 GiB-block direct map each region needs one PMD table).
static mut DIRECT_PMD: RootTable = RootTable { entries: [0; 512] };

// ============================================================================
// Arch trait implementation
// ============================================================================

pub struct RiscV64Arch;

impl InterruptControl for RiscV64Arch {
    unsafe fn disable_interrupts(&self) { cpu::disable_interrupts() }
    unsafe fn enable_interrupts(&self) { cpu::enable_interrupts() }
    fn are_enabled(&self) -> bool { cpu::interrupts_enabled() }
}

impl TimerArch for RiscV64Arch {
    fn init_timer(&self) { timer::init_timer() }
    fn current_tick(&self) -> u64 { timer::current_tick() }
}

impl ContextArch for RiscV64Arch {
    unsafe fn switch_to_user(&self, pml4_phys: u64) -> ! {
        let frame = NEXT_FRAME.load(core::sync::atomic::Ordering::Relaxed);
        switch_to_user::switch_to_user_trampoline(pml4_phys, frame)
    }
}

impl Arch for RiscV64Arch {
    fn name(&self) -> &'static str { "riscv64" }
    fn cpu_id(&self) -> usize { cpu::hart_id() }
}

static NEXT_FRAME: AtomicU64 = AtomicU64::new(0);

/// Install the RISC-V `Arch` implementation into the trait registry.
pub fn install_arch() {
    unsafe { crate::arch_trait::set_arch(0, Box::new(RiscV64Arch)) };
}

/// Set the trap-frame page consumed by the next `switch_to_user`.
pub fn set_switch_frame(frame_phys: u64) {
    NEXT_FRAME.store(frame_phys, core::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// Kernel bring-up
// ============================================================================

/// Early initialization — runs with the MMU off, straight after boot.S.
pub fn early_init() {
    uart::init();
    install_arch();
    timer::init_timer();
}

/// Full paging bring-up for RISC-V (the `paging_init` facade):
///
///  1. Build the boot root (satp): supervisor-only identity blocks for
///     the kernel image region + the direct-map window.
///  2. Switch satp on and flush the TLB.
///
/// Early page tables come from static storage (no allocator yet).
pub fn paging_init() {
    // ---- Direct-map window (high half) --------------------------------
    // VA = PHYS_MEMORY_VIRT + phys. Each 1 GiB region needs its own PMD
    // table of 2 MiB block entries; 4 regions share one static PMD table
    // only if they have the same PGD index — they don't, so use one PMD
    // table per region by packing 2 MiB blocks for the first 1 GiB and
    // PGD-level 1 GiB blocks are NOT possible below PMD (Sv39 PGD block
    // entries are legal: R/W/X leaf at PGD level is a 1 GiB page).
    unsafe {
        let root = &raw mut BOOT_ROOT;
        // Identity blocks: 1 GiB leaf entries at the PGD level.
        // Sv39 leaf PTE = (PA >> 12) << 10 | flags. For a valid 1 GiB
        // leaf, PTE bits [27:10] (PPN[17:0]) must be zero, i.e. the PA
        // must be 1 GiB aligned — true for RAM_PHYS_BASE + i << 30.
        for i in 0..(IDENTITY_GIB as u64) {
            let va = RAM_PHYS_BASE + (i << 30);
            let vi = paging::PageTableIndices::from_virt(
                plan9_common::types::VirtAddr::new(va),
            );
            let flags = paging::PteFlags::new(
                paging::PteFlags::PRESENT.bits() | paging::PteFlags::WRITABLE.bits(),
            );
            let pa = RAM_PHYS_BASE + (i << 30);
            (*root).entries[vi.pml4] =
                ((pa >> 12) << 10) | (flags.bits() & 0x3FF);
        }
        // Direct-map blocks: PHYS_MEMORY_VIRT + i GiB → PA i GiB.
        for i in 0..(IDENTITY_GIB as u64) {
            let va = paging::PHYS_MEMORY_VIRT + (i << 30);
            let vi = paging::PageTableIndices::from_virt(
                plan9_common::types::VirtAddr::new(va),
            );
            let flags = paging::PteFlags::new(
                paging::PteFlags::PRESENT.bits() | paging::PteFlags::WRITABLE.bits(),
            );
            let pa = i << 30;
            (*root).entries[vi.pml4] =
                ((pa >> 12) << 10) | (flags.bits() & 0x3FF);
        }
        // Low 1 GiB: firmware/MMIO devices. QEMU virt places the 16550A
        // UART at 0x1000_0000, inside PGD index 0. Map it with 2 MiB
        // PMD blocks (a PGD-level 1 GiB block would require the physical
        // base to be 1 GiB-aligned). This keeps the console reachable
        // after satp is switched on.
        let pmd = &raw mut DIRECT_PMD;
        // Non-leaf descriptors on RISC-V must have only V set (R/W/X=0);
        // A/D/U are reserved for leaf entries.
        (*root).entries[0] =
            (((pmd as *mut RootTable as u64) >> 12) << 10) | 1;
        for i in 0..(paging::PT_ENTRIES as u64) {
            let pa = i << paging::LARGE_PAGE_SHIFT;
            let flags = paging::PteFlags::new(
                paging::PteFlags::PRESENT.bits() | paging::PteFlags::WRITABLE.bits(),
            );
            (*pmd).entries[i as usize] =
                ((pa >> 12) << 10) | (flags.bits() & 0x3FF);
        }
    }

    // Switch the MMU on (satp + sfence.vma) with a barrier.
    cpu::fence_rw();
    let satp = mmu::satp_for(&raw mut BOOT_ROOT as *mut RootTable as u64);
    unsafe {
        core::arch::asm!(
            "csrw satp, {satp}",
            "fence.i",               // sync instruction stream after MMU on
            "sfence.vma zero, zero",
            satp = in(reg) satp,
            options(nostack)
        );
    }
    cpu::fence_rw();
    uart::flush();
}

// ============================================================================
// Kernel-half cloning (the RISC-V analogue of x86 PML4 256–511 copy)
// ============================================================================

/// Copy the supervisor identity entries (PGD indices for the kernel RAM
/// region — Sv39 indices 2..=5 for 4 GiB at 0x8000_0000) from `src_root`
/// into `dst_root`, so the kernel keeps executing after a root switch.
///
/// The kernel's generic code additionally copies PGD entries 256–511
/// (the high half — Sv39's direct-map window), mirroring x86_64.
pub fn copy_kernel_half(dst_root: u64, src_root: u64) {
    let dst = mmu::paging_phys_to_virt(dst_root) as *mut u64;
    let src = mmu::paging_phys_to_virt(src_root) as *const u64;
    // The user root must carry every kernel mapping so supervisor code
    // keeps working while a user root table is installed in satp:
    //   * PGD index 0        — low-GiB device blocks (16550A UART at
    //                          0x1000_0000, PCIe ECAM at 0x3000_0000)
    //   * PGD indices 2..=5  — RAM identity blocks
    //   * PGD indices 256..  — the high-half direct-map window
    // The boot root never holds user mappings, so cloning every non-zero
    // entry covers all of the above and stays correct if more kernel
    // windows are added.
    for i in 0..paging::PT_ENTRIES {
        let e = unsafe { core::ptr::read(src.add(i)) };
        if e != 0 {
            unsafe { core::ptr::write(dst.add(i), e) };
        }
    }
}

pub unsafe fn map_boot_mmio(start: u64, end: u64) -> bool {
    use plan9_common::types::{PhysAddr, VirtAddr};

    let root = &raw mut BOOT_ROOT as u64;
    if start < (4u64 << 30) || start >= end || end > (1u64 << 38)
        || start % paging::PAGESIZE as u64 != 0 || end % paging::PAGESIZE as u64 != 0
        || mmu::cr3_read().as_u64() != root
    {
        return false;
    }
    let flags = paging::PteFlags::new((1 << 0) | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 7));
    for physical in (start..end).step_by(paging::PAGESIZE) {
        if paging::map_page(PhysAddr::new(root), VirtAddr::new(paging_phys_to_virt(physical)),
            PhysAddr::new(physical), flags).is_err()
        {
            return false;
        }
    }
    mmu::flush_tlb();
    true
}

//! AArch64 architecture root — `Arch` trait implementation and kernel
//! bring-up entry points.
//!
//! Hardware model (matches QEMU's `virt` machine, the reference platform):
//!   * PL011 UART at 0x0900_0000            → `uart`
//!   * ARMv8 generic timer                  → `timer`
//!   * DAIF interrupt control               → `cpu`
//!   * 4-level page tables, 4 KiB granule   → `paging`
//!   * TTBR0/TTBR1 + TLBI                   → `mmu`
//!
//! Boot contract: the kernel entry assembly (`boot.S` in the kernel
//! crate) runs with the MMU off at the kernel's link address (RAM base
//! 0x4000_0000 on the virt machine), installs the EL1 vector table
//! (`VBAR_EL1`), and calls [`early_init`] then [`paging_init`].

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch_trait::{Arch, ContextArch, InterruptControl, TimerArch};

pub mod cpu;
pub mod context;
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

/// Physical RAM base on the reference (QEMU virt) platform.
pub const RAM_PHYS_BASE: u64 = 0x4000_0000;

/// GiB of RAM identity-mapped at boot (supervisor only).
pub const IDENTITY_GIB: u64 = 4;

// ============================================================================
// Frame-allocator hook
// ============================================================================
//
// The paging code needs to hand out zeroed 4 KiB frames for lower-level
// page tables. To avoid a dependency from `plan9-arch` back into the
// kernel, the kernel registers an allocator callback here during
// `paging_init()` (the same inversion-of-control used by the kernel's
// panic handler).

type AllocHook = fn() -> Option<u64>;

static mut FRAME_ALLOC_HOOK: Option<AllocHook> = None;

/// Register the kernel frame allocator used for page-table allocation.
///
/// # Safety
/// Must be called once, after the allocator is functional, before any
/// `map_page` call can happen.
pub unsafe fn register_frame_allocator(hook: AllocHook) {
    FRAME_ALLOC_HOOK = Some(hook);
}

/// Allocate one zeroed 4 KiB frame for a page table (hook dispatch).
pub fn alloc_zeroed_frame() -> Option<u64> {
    let hook = unsafe { &*core::ptr::addr_of!(FRAME_ALLOC_HOOK) };
    let hook = (*hook)?;
    let frame = hook()?;
    // Zero the frame through the direct map.
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

/// TTBR0_EL1 boot root — identity maps of RAM (supervisor only) that the
/// kernel image runs on until per-process address spaces exist.
static mut BOOT_ROOT: RootTable = RootTable { entries: [0; 512] };

/// TTBR1_EL1 root — kernel direct-map window at `PHYS_MEMORY_VIRT`.
static mut TTBR1_ROOT: RootTable = RootTable { entries: [0; 512] };

/// User root table pending installation (set before `switch_to_user`).
static NEXT_FRAME: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Arch trait implementation
// ============================================================================

pub struct AArch64Arch;

impl InterruptControl for AArch64Arch {
    unsafe fn disable_interrupts(&self) { cpu::disable_interrupts() }
    unsafe fn enable_interrupts(&self) { cpu::enable_interrupts() }
    fn are_enabled(&self) -> bool { cpu::interrupts_enabled() }
}

impl TimerArch for AArch64Arch {
    fn init_timer(&self) { timer::init_timer() }
    fn current_tick(&self) -> u64 { timer::current_tick() }
}

impl ContextArch for AArch64Arch {
    unsafe fn switch_to_user(&self, pml4_phys: u64) -> ! {
        let frame = NEXT_FRAME.load(Ordering::Relaxed);
        switch_to_user::switch_to_user_trampoline(pml4_phys, frame)
    }
}

impl Arch for AArch64Arch {
    fn name(&self) -> &'static str { "aarch64" }
    fn cpu_id(&self) -> usize { 0 }
}

/// Install the AArch64 `Arch` implementation into the trait registry.
pub fn install_arch() {
    unsafe { crate::arch_trait::set_arch(0, Box::new(AArch64Arch)) };
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

/// Set the trap-frame page consumed by the next [`switch_to_user`].
pub fn set_switch_frame(frame_phys: u64) {
    NEXT_FRAME.store(frame_phys, Ordering::Relaxed);
}

/// Program the EL1 system registers (MAIR/TCR) without enabling the MMU.
fn program_mmu_config() {
    // Enable FP/SIMD at EL0 and EL1.  Release builds may vectorize bulk
    // page-table writes with `ldr q`/`stp q`, which otherwise traps as an
    // Undefined Instruction while CPACR_EL1.FPEN is zero.
    write_sysreg!("CPACR_EL1", 0b11 << 20);

    // MAIR: index 0 = Normal WB, index 1 = Device-nGnRnE.
    let mair: u64 = 0xFF | (0x00u64 << 8);
    write_sysreg!("MAIR_EL1", mair);

    // TCR_EL1 fields:
    //   T0SZ (bits 5:0)    = 16  → 48-bit lower VA range
    //   IRGN0 (bits 9:8)   = 01  → write-back
    //   ORGN0 (bits 11:10) = 01  → write-back
    //   SH0 (bits 13:12)   = 11  → inner shareable
    //   TG0 (bits 15:14)   = 00  → 4 KiB granule
    //   IPS (bits 34:32)   = 010 → 40-bit PA (1 TiB)
    //   T1SZ (bits 39:32)  = 16  → 48-bit upper VA range (8-bit field;
    //        overlaps IPS [34:32] which we leave 0 → 4 GiB PA, enough
    //        for QEMU virt default RAM layouts)
    //   TG1 (bits 31:30)   = 10  → 4 KiB granule (TG1 encoding differs!)
    //   SH1 (bits 29:28)   = 11  → inner shareable
    //   ORGN1 (bits 27:26) = 01  → write-back
    //   IRGN1 (bits 25:24) = 01  → write-back
    let t0_half: u64 = 16              // T0SZ
        | (0b01 << 8)                  // IRGN0
        | (0b01 << 10)                 // ORGN0
        | (0b11 << 12)                 // SH0
        | (0b00 << 14);                // TG0 = 4K
    let t1_half: u64 = (16 << 32)      // T1SZ
        | (0b01 << 24)                 // IRGN1
        | (0b01 << 26)                 // ORGN1
        | (0b11 << 28)                 // SH1
        | (0b00 << 30);                // TG1 = 4K
    write_sysreg!("TCR_EL1", t0_half | t1_half);
}

/// Write the TTBR roots and enable the MMU.
fn enable_mmu() {
    unsafe {
        core::arch::asm!(
            // TTBR0 = boot root (identity), TTBR1 = direct map root.
            "msr ttbr0_el1, {t0}",
            "msr ttbr1_el1, {t1}",
            // Enable MMU + caches in SCTLR_EL1 (M|C|I).
            "mrs x9, sctlr_el1",
            "orr x9, x9, #(1 << 0)",   // M  — MMU enable
            "orr x9, x9, #(1 << 2)",   // C  — D-cache
            "orr x9, x9, #(1 << 12)",  // I  — I-cache
            "msr sctlr_el1, x9",
            "isb",
            t0 = in(reg) (&raw mut BOOT_ROOT as *mut RootTable as u64),
            t1 = in(reg) (&raw mut TTBR1_ROOT as *mut RootTable as u64),
            options(nostack)
        );
    }
}

/// Full paging bring-up for AArch64 (the `paging_init` facade):
///
///  1. Program MAIR/TCR.
///  2. Build the TTBR1 direct-map window (1 GiB block entries).
///  3. Build the boot TTBR0 root (supervisor-only identity blocks).
///  4. Enable the MMU and caches.
///
/// Early page tables come from a static pool (like the x86_64 kernel's
/// `.pagetable_pool`) because the frame allocator does not exist yet;
/// later tables come from the kernel-registered hook.
pub fn paging_init() {
    program_mmu_config();

    // ---- Static L1 tables (before any allocator exists) ---------------
    #[repr(C, align(4096))]
    struct L1Table([u64; 512]);
    static mut L1_DIRECT: L1Table = L1Table([0; 512]);
    static mut L1_IDENTITY: L1Table = L1Table([0; 512]);

    // ---- TTBR1: direct map window ------------------------------------
    // PHYS_MEMORY_VIRT + phys, one 1 GiB block per entry.
    unsafe {
        let root = &raw mut TTBR1_ROOT;
        let l1 = &raw mut L1_DIRECT;
        let l1_phys = (l1 as *mut L1Table as u64) & 0x0000_FFFF_FFFF_F000;
        let l0_ptr = l1 as *mut L1Table; // root table itself is static
        let idx = paging::PageTableIndices::from_virt(plan9_common::types::VirtAddr::new(
            paging::PHYS_MEMORY_VIRT,
        ));
        (*root).entries[idx.pml4] =
            l1_phys | paging::PteFlags::PAGE_TABLE.attr_mem().bits();

        for i in 0..IDENTITY_GIB {
            let va = paging::PHYS_MEMORY_VIRT + (i << 30);
            let vi = paging::PageTableIndices::from_virt(plan9_common::types::VirtAddr::new(va));
            let block_flags = paging::PteFlags::KERNEL_RW.attr_mem();
            (*l0_ptr).0[vi.pdpt] = (i << 30) | block_flags.bits();
        }
    }

    // ---- TTBR0: supervisor-only identity blocks ----------------------
    unsafe {
        let root = &raw mut BOOT_ROOT;
        let l1 = &raw mut L1_IDENTITY;
        let l1_phys = (l1 as *mut L1Table as u64) & 0x0000_FFFF_FFFF_F000;
        let idx = paging::PageTableIndices::from_virt(plan9_common::types::VirtAddr::new(0));
        (*root).entries[idx.pml4] =
            l1_phys | paging::PteFlags::PAGE_TABLE.attr_mem().bits();

        // Low 1 GiB: firmware and MMIO devices (PL011 at 0x0900_0000,
        // GIC at 0x0800_0000). Map it as Device-nGnRnE so the UART remains
        // accessible after the MMU is enabled.
        (*l1).0[0] = paging::PteFlags::KERNEL_RW.attr_dev().bits();

        for i in 0..IDENTITY_GIB {
            let vi = paging::PageTableIndices::from_virt(plan9_common::types::VirtAddr::new(
                RAM_PHYS_BASE + (i << 30),
            ));
            // Supervisor-only: AP = 0b01 (EL1 read/write), AF set.
            // Do *not* set PXN here: the kernel itself executes from this
            // identity mapping after the MMU is enabled.
            let flags = paging::PteFlags::new(
                paging::PteFlags::PRESENT.bits()
                    | paging::PteFlags::WRITABLE.bits()
                    | paging::PteFlags::ACCESSED.bits(),
            )
            .attr_mem();
            (*l1).0[vi.pdpt] = ((RAM_PHYS_BASE >> 30) + i) << 30 | flags.bits();
        }
    }

    // Flush any stale entries and switch the MMU on.
    cpu::dsb_sy();
    enable_mmu();
    cpu::isb();
}

// ============================================================================
// Kernel-half cloning (the AArch64 analogue of x86 PML4 256–511 copy)
// ============================================================================

/// Copy the kernel identity entries (L0 indices 0..=7 — the supervisor
/// blocks built by [`paging_init`]) from `src_root` into `dst_root`.
/// Per-process address spaces must include them so the kernel keeps
/// executing after a root-table switch, mirroring the x86_64 kernel's
/// clone of PML4 entries 256–511.
pub fn copy_kernel_half(dst_root: u64, src_root: u64) {
    let dst = mmu::paging_phys_to_virt(dst_root) as *mut u64;
    let src = mmu::paging_phys_to_virt(src_root) as *const u64;
    // The boot root stores the L0[0] pointer to the identity L1 table;
    // copy L0 indices 0..(IDENTITY_GIB) — each covers one 1 GiB region.
    for i in 0..(IDENTITY_GIB as usize) {
        let e = unsafe { core::ptr::read(src.add(i)) };
        if e != 0 {
            unsafe { core::ptr::write(dst.add(i), e) };
        }
    }
}

// ============================================================================
// Sysreg helpers (crate-root macros)
// ============================================================================

pub(crate) use crate::write_sysreg;

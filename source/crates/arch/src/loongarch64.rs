//! LoongArch64 architecture root — `Arch` trait implementation and
//! kernel bring-up entry points.
//!
//! Hardware model (matches QEMU's `loongarch64` virt machine):
//!   * 16550A UART at 0x1FE0_01E0 (uncached DMW1 window) → `uart`
//!   * Constant timer, 100 MHz, via `rdtime.d`/CSR.TCFG  → `timer`
//!   * CRMD.IE interrupt control                          → `cpu`
//!   * DMW direct-mapped windows + page-mapped user space → `paging`
//!   * PGDL/PGDH + INVTLB                                 → `mmu`
//!
//! Boot contract: the kernel entry assembly (boot.S) installs DMW0
//! (cached, VSEG 8) and DMW1 (uncached, VSEG 9), enables paged
//! translation (CRMD.PG = 1), and jumps into the cached window where
//! the kernel image resides — i.e. by the time Rust code runs, the
//! machine is already executing at `KERNEL_IMAGE_VIRT` with the direct
//! map and MMIO windows live. `paging_init` finishes the configuration
//! (user root, exception config, TLB flush).

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

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

pub use cpu::{cli, disable_interrupts, enable_interrupts, hlt, interrupts_enabled, sti};
pub use timer::{current_tick, init_timer as init_generic_timer};

/// Physical → virtual through the DMW0 direct map (reachable as
/// `super::paging_phys_to_virt` from the paging submodule).
pub use mmu::paging_phys_to_virt;

/// Physical RAM base on the reference (QEMU virt) platform.
pub const RAM_PHYS_BASE: u64 = 0x0000_0000_0020_0000;

/// GiB of RAM covered by the DMW0 direct map.
pub const DIRECT_MAP_GIB: u64 = 1;

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

/// Boot user root table (PGDL target). All entries are zero, so every
/// page-mapped (TLB) access faults until the kernel sets up real user
/// address spaces — exactly like the x86_64 bring-up.
static mut BOOT_ROOT: RootTable = RootTable { entries: [0; 512] };

/// Trap-frame page pending installation (set before `switch_to_user`).
static NEXT_FRAME: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Arch trait implementation
// ============================================================================

pub struct LoongArch64Arch;

impl InterruptControl for LoongArch64Arch {
    unsafe fn disable_interrupts(&self) { cpu::disable_interrupts() }
    unsafe fn enable_interrupts(&self) { cpu::enable_interrupts() }
    fn are_enabled(&self) -> bool { cpu::interrupts_enabled() }
}

impl TimerArch for LoongArch64Arch {
    fn init_timer(&self) { timer::init_timer() }
    fn current_tick(&self) -> u64 { timer::current_tick() }
}

impl ContextArch for LoongArch64Arch {
    unsafe fn switch_to_user(&self, pml4_phys: u64) -> ! {
        let frame = NEXT_FRAME.load(Ordering::Relaxed);
        switch_to_user::switch_to_user_trampoline(pml4_phys, frame)
    }
}

impl Arch for LoongArch64Arch {
    fn name(&self) -> &'static str { "loongarch64" }
    fn cpu_id(&self) -> usize { cpu::hart_id() }
}

/// Install the LoongArch64 `Arch` implementation into the trait registry.
pub fn install_arch() {
    unsafe { crate::arch_trait::set_arch(0, Box::new(LoongArch64Arch)) };
}

/// Set the trap-frame page consumed by the next `switch_to_user`.
pub fn set_switch_frame(frame_phys: u64) {
    NEXT_FRAME.store(frame_phys, Ordering::Relaxed);
}

// ============================================================================
// Kernel bring-up
// ============================================================================

/// Early initialization — runs in the cached DMW0 window, straight
/// after boot.S switched on paged translation.
pub fn early_init() {
    uart::init();
    install_arch();
    timer::init_timer();
}

/// Full paging bring-up for LoongArch64 (the `paging_init` facade):
///
///  1. Re-install the DMW direct-map windows (idempotent — boot.S may
///     have already done it; on firmware-boot paths it may not have).
///  2. Point CSR.PGDL at the boot user root (all-zero — page-mapped
///     accesses fault until real user spaces exist).
///  3. Enable the timer interrupt line in ECFG.LIE.
///  4. Flush the TLB.
pub fn paging_init() {
    mmu::install_direct_windows();

    // User root: the static boot table (zeroed).
    let boot_root_phys = (&raw mut BOOT_ROOT as *mut RootTable as u64) & 0x0000_FFFF_FFFF_F000;
    mmu::cr3_write(plan9_common::types::PhysAddr::new(boot_root_phys));

    // Exception configuration: timer interrupt line on (LIE bit 11),
    // FP usable (FPE bit 5 — the kernel's font/console code contains
    // float math), everything else left as-is.
    let ecfg = cpu::csr_read::<{ cpu::csr::ECFG }>();
    let ecfg = (ecfg & !(0x7FFFu64)) | (1 << 11) | (1 << 5);
    cpu::csr_write::<{ cpu::csr::ECFG }>(ecfg);

    // Flush the TLB now that the root is live.
    mmu::flush_tlb();
    cpu::dbar();
    uart::flush();
}

// ============================================================================
// Kernel-half cloning
// ============================================================================

/// On LoongArch the kernel's mappings live in the DMW direct-map
/// windows, which are *global* — they apply to every address space and
/// every privilege level enabled by the window's PLV bits — so a
/// per-process root table needs no kernel half cloned into it (the
/// LoongArch analogue of the x86_64 PML4 256–511 copy is the empty set).
///
/// The function is kept for API parity; `dst_root` and `src_root` are
/// unused by design.
pub fn copy_kernel_half(_dst_root: u64, _src_root: u64) {
    // No-op: DMW windows are global to all address spaces.
}

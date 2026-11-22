//! LoongArch64 CPU control: CSR access helpers, interrupt (CRMD.IE)
//! management, halt (`idle`), barriers, and CPUCFG reads.
//!
//! All privileged instructions for the whole kernel live here so that no
//! `core::arch::asm!` blocks are needed outside the `plan9_arch` crate.
//!
//! CSR instruction forms (LoongArch Vol. 2):
//!   * `csrrd   rd, num`        — read CSR `num` into `rd`
//!   * `csrwr   rd, num`        — write `rd` into CSR `num`, old value → `rd`
//!   * `csrxchg rd, num, mask`  — masked read-modify-write, old value → `rd`

/// CSR numbers (LoongArch Reference Manual Vol. 2 / Linux loongarchregs.h).
pub mod csr {
    pub const CRMD: u64 = 0x0; // current mode info (PLV, IE, DA, PG)
    pub const PRMD: u64 = 0x1; // pre-exception mode info
    pub const EUEN: u64 = 0x2; // extension unit enable (FPU)
    pub const ECFG: u64 = 0x4; // exception config (LIE mask)
    pub const ESTAT: u64 = 0x5; // exception status
    pub const ERA: u64 = 0x6; // exception return address
    pub const BADV: u64 = 0x7; // faulting virtual address
    pub const EENTRY: u64 = 0xC; // exception entry point
    pub const TLBIDX: u64 = 0x10; // TLB index / page size
    pub const TLBEHI: u64 = 0x11; // TLB entry-high (VPPN tag)
    pub const TLBELO0: u64 = 0x12; // TLB entry-lo 0 (even page)
    pub const TLBELO1: u64 = 0x13; // TLB entry-lo 1 (odd page)
    pub const ASID: u64 = 0x18; // ASID
    pub const PGDL: u64 = 0x19; // low-half page global directory base
    pub const PGDH: u64 = 0x1A; // high-half page global directory base
    pub const STLBPS: u64 = 0x1E; // software TLB page size
    pub const CPUID: u64 = 0x20; // CPU identifier
    pub const PRCFG1: u64 = 0x21; // privileged config 1
    pub const KS0: u64 = 0x30; // saved-data register 0 (trap scratch)
    pub const TLBRENTRY: u64 = 0x88; // TLB refill exception entry
    pub const TLBRBADV: u64 = 0x89; // TLB refill bad virtual address
    pub const TLBRERA: u64 = 0x8A; // TLB refill exception return address
    pub const TCFG: u64 = 0x41; // timer configuration
    pub const TVAL: u64 = 0x42; // timer value (countdown)
    pub const CNTC: u64 = 0x43; // constant counter compensation
    pub const TICLR: u64 = 0x44; // timer interrupt clear
    pub const DMW0: u64 = 0x180; // direct-mapped window 0
    pub const DMW1: u64 = 0x181; // direct-mapped window 1
    pub const DMW2: u64 = 0x182; // direct-mapped window 2
    pub const DMW3: u64 = 0x183; // direct-mapped window 3
}

// ============================================================================
// CSR access primitives
// ============================================================================

/// Read CSR `num`.
#[inline(always)]
pub fn csr_read<const N: u64>() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "csrrd {v}, {n}",
            v = out(reg) v,
            n = const N,
            options()
        );
    }
    v
}

/// Write CSR `num`; returns the previous value (csrwr's return-in-rd
/// semantics map naturally onto `inout`).
#[inline(always)]
pub fn csr_write<const N: u64>(val: u64) -> u64 {
    let mut v = val;
    unsafe {
        core::arch::asm!(
            "csrwr {v}, {n}",
            v = inout(reg) v,
            n = const N,
            options()
        );
    }
    v
}

/// Masked read-modify-write of CSR `num`; returns the previous value.
/// The mask travels in a register (CSRXCHG rd, rj, num form).
#[inline(always)]
pub fn csr_xchg<const N: u64, const MASK: u64>(val: u64) -> u64 {
    let mut v = val;
    let mask = MASK;
    unsafe {
        core::arch::asm!(
            "csrxchg {v}, {mask}, {n}",
            v = inout(reg) v,
            mask = in(reg) mask,
            n = const N,
            options()
        );
    }
    v
}

// ============================================================================
// Interrupt control (CRMD.IE, bit 2)
// ============================================================================

/// CRMD.IE bit position.
const CRMD_IE: u64 = 1 << 2;
/// CRMD.DA (direct address mode) bit position.
pub const CRMD_DA: u64 = 1 << 3;
/// CRMD.PG (paged translation enable) bit position.
pub const CRMD_PG: u64 = 1 << 4;

#[inline(always)]
pub unsafe fn disable_interrupts() {
    csr_xchg::<{ csr::CRMD }, { CRMD_IE }>(0);
}

#[inline(always)]
pub unsafe fn enable_interrupts() {
    csr_xchg::<{ csr::CRMD }, { CRMD_IE }>(CRMD_IE);
}

/// Aliases matching the x86 naming used by kernel call sites.
#[inline(always)]
pub fn cli() {
    // Safe wrapper: the operation itself is atomic.
    unsafe { disable_interrupts() }
}

#[inline(always)]
pub fn sti() {
    unsafe { enable_interrupts() }
}

#[inline(always)]
pub fn interrupts_enabled() -> bool {
    (csr_read::<{ csr::CRMD }>() & CRMD_IE) != 0
}

/// Read the full CRMD (PLV, IE, DA, PG fields).
#[inline(always)]
pub fn crmd_read() -> u64 {
    csr_read::<{ csr::CRMD }>()
}

/// Write the full CRMD.
#[inline(always)]
pub unsafe fn crmd_write(val: u64) {
    csr_write::<{ csr::CRMD }>(val);
}

// ============================================================================
// Halt / wait
// ============================================================================

#[inline(always)]
pub fn hlt() {
    unsafe { core::arch::asm!("idle 0", options(nostack)) }
}

/// Loop forever halting; used for the panic path.
#[inline(never)]
pub fn hlt_loop() -> ! {
    loop {
        hlt();
    }
}

// ============================================================================
// Barriers
// ============================================================================

/// Data barrier.
#[inline(always)]
pub fn dbar() {
    unsafe { core::arch::asm!("dbar 0", options(nostack)) };
}

/// Instruction barrier (needed after writing code pages).
#[inline(always)]
pub fn ibar() {
    unsafe { core::arch::asm!("ibar 0", options(nostack)) };
}

// ============================================================================
// CPU identification
// ============================================================================

/// Read the CPU (core) identifier (CSR.CPUID).
#[inline(always)]
pub fn hart_id() -> usize {
    (csr_read::<{ csr::CPUID }>() & 0x3FF) as usize
}

/// Read the timer frequency from CPUCFG 0x4/0x5:
/// freq = CPUCFG4.CC_FREQ * CPUCFG5.CC_MUL / CPUCFG5.CC_DIV.
pub fn timer_frequency() -> u64 {
    let base: u64;
    unsafe {
        core::arch::asm!(
            "cpucfg {o}, {n}",
            o = out(reg) base,
            n = in(reg) 0x4u64,
            options()
        );
    }
    let cfg5: u64;
    unsafe {
        core::arch::asm!(
            "cpucfg {o}, {n}",
            o = out(reg) cfg5,
            n = in(reg) 0x5u64,
            options()
        );
    }
    let mul = (cfg5 >> 0) & 0xFFFF;
    let div = (cfg5 >> 16) & 0xFFFF;
    if base == 0 || mul == 0 || div == 0 {
        // QEMU virt: constant 100 MHz timer.
        return 100_000_000;
    }
    u64::from(base as u32) * mul / div
}

//! x86_64 Architecture Support
//!
//! Provides low-level CPU operations, control register access, and other
//! architecture-specific functionality for x86_64.

use core::arch::asm;

// ============================================================================
// CPUID Operations
// ============================================================================

/// Call CPUID with given function number
/// Returns (eax, ebx, ecx, edx)
#[inline(always)]
pub fn cpuid(eax_in: u32) -> (u32, u32, u32, u32) {
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    let mut eax_tmp: u32 = eax_in;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {1:e}, ebx",
            "mov {2:e}, ecx",
            "mov {3:e}, edx",
            "mov {0:e}, eax",
            "pop rbx",
            out(reg) eax_tmp,
            out(reg) ebx_out,
            out(reg) ecx_out,
            out(reg) edx_out,
        );
    }
    (eax_tmp, ebx_out, ecx_out, edx_out)
}

/// Extended CPUID call with sub-function
#[inline(always)]
pub fn cpuid_ext(eax_in: u32, ecx_in: u32) -> (u32, u32, u32, u32) {
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    let mut eax_tmp: u32 = eax_in;
    let mut ecx_tmp: u32 = ecx_in;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {1:e}, ebx",
            "mov {2:e}, ecx",
            "mov {3:e}, edx",
            "mov {0:e}, eax",
            "pop rbx",
            inout(reg) eax_tmp,
            out(reg) ebx_out,
            inout(reg) ecx_tmp,
            out(reg) edx_out,
        );
    }
    (eax_tmp, ebx_out, ecx_tmp, edx_out)
}

// ============================================================================
// Control Registers
// ============================================================================

/// Read CR0
#[inline(always)]
pub fn cr0_read() -> u64 {
    let cr0: u64;
    unsafe { asm!("mov {0:x}, cr0", out(reg) cr0, options(nostack)); }
    cr0
}

/// Write CR0
#[inline(always)]
pub fn cr0_write(val: u64) {
    unsafe { asm!("mov cr0, {0:x}", in(reg) val, options(nostack)); }
}

/// Read CR2 (page fault linear address)
#[inline(always)]
pub fn cr2_read() -> u64 {
    let cr2: u64;
    unsafe { asm!("mov {0:x}, cr2", out(reg) cr2, options(nostack)); }
    cr2
}

/// Read CR3
#[inline(always)]
pub fn cr3_read() -> u64 {
    let cr3: u64;
    unsafe { asm!("mov {0:x}, cr3", out(reg) cr3, options(nostack)); }
    cr3
}

/// Write CR3
#[inline(always)]
pub fn cr3_write(val: u64) {
    unsafe { asm!("mov cr3, {0:x}", in(reg) val, options(nostack)); }
}

/// Read CR4
#[inline(always)]
pub fn cr4_read() -> u64 {
    let cr4: u64;
    unsafe { asm!("mov {0:x}, cr4", out(reg) cr4, options(nostack)); }
    cr4
}

/// Write CR4
#[inline(always)]
pub fn cr4_write(val: u64) {
    unsafe { asm!("mov cr4, {0:x}", in(reg) val, options(nostack)); }
}

/// Read CR8
#[inline(always)]
pub fn cr8_read() -> u64 {
    let cr8: u64;
    unsafe { asm!("mov {0:x}, cr8", out(reg) cr8, options(nostack)); }
    cr8
}

/// Write CR8
#[inline(always)]
pub fn cr8_write(val: u64) {
    unsafe { asm!("mov cr8, {0:x}", in(reg) val, options(nostack)); }
}

// ============================================================================
// Model Specific Registers
// ============================================================================

/// Read MSR
#[inline(always)]
pub fn msr_read(msr: u32) -> u64 {
    let val: u64;
    let mut eax_val: u32 = 0;
    let mut edx_val: u32 = 0;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") eax_val,
            out("edx") edx_val,
            options(nostack),
        );
    }
    ((edx_val as u64) << 32) | (eax_val as u64)
}

/// Write MSR
#[inline(always)]
pub fn msr_write(msr: u32, val: u64) {
    let eax_val = val as u32;
    let edx_val = (val >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") eax_val,
            in("edx") edx_val,
            options(nostack),
        );
    }
}

// ============================================================================
// EFLAGS/RFLAGS
// ============================================================================

/// Read RFLAGS
#[inline(always)]
pub fn rflags_read() -> u64 {
    let rflags: u64;
    unsafe { asm!("pushfq; pop {0:x}", out(reg) rflags, options(nostack)); }
    rflags
}

/// Write RFLAGS
#[inline(always)]
pub fn rflags_write(val: u64) {
    unsafe { asm!("push {0:x}; popfq", in(reg) val, options(nostack, preserves_flags)); }
}

/// Check if interrupt flag is set
#[inline(always)]
pub fn interrupts_enabled() -> bool {
    (rflags_read() & (1 << 9)) != 0
}

/// Enable interrupts
#[inline(always)]
pub fn sti() {
    unsafe { asm!("sti", options(nostack)); }
}

/// Disable interrupts
#[inline(always)]
pub fn cli() {
    unsafe { asm!("cli", options(nostack)); }
}

// ============================================================================
// CPU Instructions
// ============================================================================

/// Halt CPU
#[inline(always)]
pub fn hlt() {
    unsafe { asm!("hlt", options(nostack)); }
}

/// Wait for interrupt
#[inline(always)]
pub fn wait() {
    unsafe { asm!("wait", options(nostack)); }
}

/// Invalidate TLB entry
#[inline(always)]
pub fn invlpg(addr: u64) {
    unsafe { asm!("invlpg {0}", in(reg) addr, options(nostack)); }
}

/// Flush entire TLB
#[inline(always)]
pub fn flush_tlb() {
    let cr3_val = cr3_read();
    cr3_write(cr3_val);
}

// ============================================================================
// Task Register
// ============================================================================

/// Read task register
#[inline(always)]
pub fn sdt_read() -> u16 {
    let val: u16;
    unsafe { asm!("str {0:x}", out(reg) val, options(nostack)); }
    val
}

/// Write task register
#[inline(always)]
pub fn ltr(selector: u16) {
    unsafe { asm!("ltr {0:x}", in(reg) selector, options(nostack)); }
}

// ============================================================================
// GS Base
// ============================================================================

/// Read GS base
#[inline(always)]
pub fn rdgsbase() -> u64 {
    let val: u64;
    unsafe { asm!("rdgsbase {0:x}", out(reg) val, options(nostack)); }
    val
}

/// Write GS base
#[inline(always)]
pub fn wrgsbase(val: u64) {
    unsafe { asm!("wrgsbase {0:x}", in(reg) val, options(nostack)); }
}

// ============================================================================
// I/O Port Access (stub implementations for no_std)
// ============================================================================

/// Read byte from I/O port
#[inline(always)]
pub fn inb(_port: u16) -> u8 {
    0
}

/// Write byte to I/O port
#[inline(always)]
pub fn outb(_port: u16, _val: u8) {
}

/// Read word from I/O port
#[inline(always)]
pub fn inw(_port: u16) -> u16 {
    0
}

/// Write word to I/O port
#[inline(always)]
pub fn outw(_port: u16, _val: u16) {
}

/// Read dword from I/O port
#[inline(always)]
pub fn inl(_port: u16) -> u32 {
    0
}

/// Write dword to I/O port
#[inline(always)]
pub fn outl(_port: u16, _val: u32) {
}

/// I/O delay
#[inline(always)]
pub fn io_wait() {
}

// ============================================================================
// PCI Configuration
// ============================================================================

pub const PCI_CONFIG_ADDR_PORT: u16 = 0xCF8;
pub const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;

#[inline(always)]
pub fn pci_config_addr_port() -> u16 { PCI_CONFIG_ADDR_PORT }
#[inline(always)]
pub fn pci_config_data_port() -> u16 { PCI_CONFIG_DATA_PORT }

// ============================================================================
// CPU Information
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Unknown([u8; 12]),
}

impl CpuVendor {
    pub fn detect() -> Self {
        let (_, ebx, ecx, edx) = cpuid(0);
        let vendor: [u8; 12] = [
            (ebx >> 0) as u8, (ebx >> 8) as u8, (ebx >> 16) as u8, (ebx >> 24) as u8,
            (edx >> 0) as u8, (edx >> 8) as u8, (edx >> 16) as u8, (edx >> 24) as u8,
            (ecx >> 0) as u8, (ecx >> 8) as u8, (ecx >> 16) as u8, (ecx >> 24) as u8,
        ];

        if &vendor == b"GenuineIntel" {
            Self::Intel
        } else if &vendor == b"AuthenticAMD" {
            Self::Amd
        } else {
            Self::Unknown(vendor)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub vendor: CpuVendor,
    pub has_pae: bool,
    pub has_pge: bool,
    pub has_nx: bool,
    pub has_smep: bool,
    pub has_smap: bool,
    pub has_fsgsbase: bool,
    pub has_xsave: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_avx512f: bool,
}

impl CpuFeatures {
    pub fn detect() -> Self {
        let vendor = CpuVendor::detect();
        
        // Get CPUID function 1
        let (_, _, ecx1, edx1) = cpuid(1);
        
        // Get CPUID function 7, subfunction 0
        let (_, ebx7, ecx7, _) = cpuid_ext(7, 0);
        
        let has_avx2 = (ecx7 & (1 << 5)) != 0;
        let has_avx512f = (ebx7 & (1 << 16)) != 0;
        
        Self {
            vendor,
            has_pae: (edx1 & (1 << 6)) != 0,
            has_pge: (edx1 & (1 << 13)) != 0,
            has_nx: (edx1 & (1 << 20)) != 0,
            has_smep: (ebx7 & (1 << 7)) != 0,
            has_smap: (ebx7 & (1 << 20)) != 0,
            has_fsgsbase: (ebx7 & (1 << 16)) != 0,
            has_xsave: (ecx1 & (1 << 26)) != 0,
            has_avx: (ecx1 & (1 << 28)) != 0,
            has_avx2,
            has_avx512f,
        }
    }
}

/// Get CPU vendor string
pub fn cpu_vendor() -> CpuVendor {
    CpuVendor::detect()
}

/// Get CPU features
pub fn cpu_features() -> CpuFeatures {
    CpuFeatures::detect()
}

/// Check if running on a 64-bit processor
pub fn is_64bit() -> bool {
    let (_, _, _, edx) = cpuid(0x80000001);
    (edx & (1 << 29)) != 0
}

/// Get number of CPU cores
pub fn num_cores() -> usize {
    let (eax, _, _, _) = cpuid(1);
    ((eax >> 16) & 0xFF) as usize
}

/// Get number of logical processors
pub fn num_logical() -> usize {
    let (eax, _, _, _) = cpuid(1);
    ((eax >> 16) & 0xFF) as usize
}

// ============================================================================
// LAPIC
// ============================================================================

pub const LAPIC_BASE_MSR: u32 = 0x1B;

/// Read LAPIC base address
#[inline(always)]
pub fn lapic_base() -> u64 {
    msr_read(LAPIC_BASE_MSR) & 0xFFFFFFFFFFFFF000
}

/// Enable/disable LAPIC
#[inline(always)]
pub fn set_lapic_base(base: u64, enable: bool) {
    let val = if enable { base | 0x800 } else { base & !0x800 };
    msr_write(LAPIC_BASE_MSR, val);
}

// Submodules
pub mod context;
pub mod paging;
pub mod mmu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod regs;

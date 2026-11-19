//! x86_64 Architecture Support
//!
//! Provides low-level CPU operations, control register access, and other
//! architecture-specific functionality for x86_64.

#[cfg(target_arch = "x86_64")]
mod x86_64_asm {
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
                inout(reg) eax_tmp,
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
        unsafe { asm!("mov {0}, cr0", out(reg) cr0, options(nostack)); }
        cr0
    }

    /// Write CR0
    #[inline(always)]
    pub fn cr0_write(val: u64) {
        unsafe { asm!("mov cr0, {0}", in(reg) val, options(nostack)); }
    }

    /// Read CR2 (page fault linear address)
    #[inline(always)]
    pub fn cr2_read() -> u64 {
        let cr2: u64;
        unsafe { asm!("mov {0}, cr2", out(reg) cr2, options(nostack)); }
        cr2
    }

    /// Read CR3
    #[inline(always)]
    pub fn cr3_read() -> u64 {
        let cr3: u64;
        unsafe { asm!("mov {0}, cr3", out(reg) cr3, options(nostack)); }
        cr3
    }

    /// Write CR3
    #[inline(always)]
    pub fn cr3_write(val: u64) {
        unsafe { asm!("mov cr3, {0}", in(reg) val, options(nostack)); }
    }

    /// Read CR4
    #[inline(always)]
    pub fn cr4_read() -> u64 {
        let cr4: u64;
        unsafe { asm!("mov {0}, cr4", out(reg) cr4, options(nostack)); }
        cr4
    }

    /// Write CR4
    #[inline(always)]
    pub fn cr4_write(val: u64) {
        unsafe { asm!("mov cr4, {0}", in(reg) val, options(nostack)); }
    }

    /// Read CR8
    #[inline(always)]
    pub fn cr8_read() -> u64 {
        let cr8: u64;
        unsafe { asm!("mov {0}, cr8", out(reg) cr8, options(nostack)); }
        cr8
    }

    /// Write CR8
    #[inline(always)]
    pub fn cr8_write(val: u64) {
        unsafe { asm!("mov cr8, {0}", in(reg) val, options(nostack)); }
    }

    /// Read the per-CPU id stored in `IA32_TSC_AUX` (MSR 0xC0000103).
    ///
    /// The kernel sets this MSR once during per-CPU bring-up. Returns
    /// 0 before SMP init has run.
    #[inline(always)]
    pub fn read_tsc_aux() -> u32 {
        let mut eax: u32 = 0;
        let mut _edx: u32 = 0;
        unsafe {
            asm!(
                "rdtscp",
                out("eax") eax,
                out("edx") _edx,
                out("ecx") _,
                options(nostack, preserves_flags),
            );
        }
        eax
    }

    /// Write `IA32_TSC_AUX` (MSR 0xC0000103).
    ///
    /// Used during SMP bring-up to associate each CPU with a stable id.
    #[inline(always)]
    pub fn write_tsc_aux(val: u32) {
        let eax = val;
        let _edx: u32 = 0;
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") 0xC0000103u32,
                in("eax") eax,
                in("edx") _edx,
                options(nostack),
            );
        }
    }

    // ============================================================================
    // Model Specific Registers
    // ============================================================================

    /// Read MSR
    #[inline(always)]
    pub fn msr_read(msr: u32) -> u64 {
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
        unsafe { asm!("pushfq; pop {0}", out(reg) rflags, options(nostack)); }
        rflags
    }

    /// Write RFLAGS
    #[inline(always)]
    pub fn rflags_write(val: u64) {
        unsafe { asm!("push {0}; popfq", in(reg) val, options(nostack, preserves_flags)); }
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

    /// Load the Global Descriptor Table.
    ///
    /// The `gdt_ptr` argument is the physical/linear address of a
    /// `GdtPointer` (limit:u16, base:u64, packed) exactly as the GDTR
    /// register expects it.
    #[inline(always)]
    pub fn lgdt(gdt_ptr: u64) {
        unsafe {
            asm!(
                "lgdt [{0}]",
                in(reg) gdt_ptr,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Load the Interrupt Descriptor Table.
    ///
    /// `idt_ptr` is the address of an `IdtPointer` (limit:u16, base:u64).
    #[inline(always)]
    pub fn lidt(idt_ptr: u64) {
        unsafe {
            asm!(
                "lidt [{0}]",
                in(reg) idt_ptr,
                options(nostack, preserves_flags),
            );
        }
    }

    // ============================================================================
    // GS Base
    // ============================================================================

    /// Read GS base
    #[inline(always)]
    pub fn rdgsbase() -> u64 {
        let val: u64;
        unsafe { asm!("rdgsbase {0}", out(reg) val, options(nostack)); }
        val
    }

    /// Write GS base
    #[inline(always)]
    pub fn wrgsbase(val: u64) {
        unsafe { asm!("wrgsbase {0}", in(reg) val, options(nostack)); }
    }

    // ============================================================================
    // I/O Port Access (stub implementations for no_std)
    // ============================================================================

    /// Read byte from I/O port
    #[inline(always)]
    pub fn inb(port: u16) -> u8 {
        let val: u8;
        // SAFETY: caller-supplied port I/O.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") val,
                options(nostack, preserves_flags),
            );
        }
        val
    }

    /// Write byte to I/O port
    #[inline(always)]
    pub fn outb(port: u16, val: u8) {
        // SAFETY: caller-supplied port I/O.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Read word from I/O port
    #[inline(always)]
    pub fn inw(port: u16) -> u16 {
        let val: u16;
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                in("dx") port,
                out("ax") val,
                options(nostack, preserves_flags),
            );
        }
        val
    }

    /// Write word to I/O port
    #[inline(always)]
    pub fn outw(port: u16, val: u16) {
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") val,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Read dword from I/O port
    #[inline(always)]
    pub fn inl(port: u16) -> u32 {
        let val: u32;
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                in("dx") port,
                out("eax") val,
                options(nostack, preserves_flags),
            );
        }
        val
    }

    /// Write dword to I/O port
    #[inline(always)]
    pub fn outl(port: u16, val: u32) {
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") val,
                options(nostack, preserves_flags),
            );
        }
    }

    /// I/O delay — a few `outb` to port 0x80 gives the chipset time to
    /// settle between back-to-back PIC register accesses.
    #[inline(always)]
    pub fn io_delay() {
        unsafe {
            for _ in 0..4 {
                // Port 0x80 is a classic POST/diagnostic port; writing to it
                // is harmless and slow enough to act as a short delay.
                asm!("out dx, al", in("dx") 0x80u16, in("al") 0u8, options(nostack, preserves_flags));
            }
        }
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
}

#[cfg(target_arch = "x86_64")]
pub use x86_64_asm::*;

// ============================================================================
// Kernel Initialization Functions
// ============================================================================

/// Early initialization - called before memory management is set up.
/// Sets up the GDT, builds an initial 4-level page table, enables paging,
/// installs the IDT, and leaves the CPU running with interrupts still
/// disabled (the caller decides when to `sti`).
///
/// # Safety
/// Must be called exactly once, very early in `_start`-equivalent code,
/// while executing at the kernel's link address.
#[cfg(target_arch = "x86_64")]
pub fn early_init() {
    // For now, every entry path is GRUB Multiboot2 in long mode. We
    // keep the BootMode enum so a future BIOS/handover path can
    // override this default without changing the kernel entry.
    bootstrap::early_init_for(bootstrap::BootMode::GrubLongMode);
    smp::install_cpu_id_provider();
}

/// Backwards-compatible alias for the assembly entry that used to call
/// `early_gdt_init()` directly. New code should call `early_init()`.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn early_gdt_init() {
    unsafe { gdt::gdt_init(); }
}

/// Backwards-compatible alias used by older init code.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn early_paging_init() {
    unsafe { paging_init::early_paging_init(); }
}

/// Initialize the Interrupt Descriptor Table.
#[cfg(target_arch = "x86_64")]
pub fn idt_init() {
    unsafe { idt::idt_init(); }
}

// Submodules
#[cfg(target_arch = "x86_64")]
pub mod context;
#[cfg(target_arch = "x86_64")]
pub mod paging;
#[cfg(target_arch = "x86_64")]
pub mod paging_init;
#[cfg(target_arch = "x86_64")]
pub mod mmu;
#[cfg(target_arch = "x86_64")]
pub mod gdt;
#[cfg(target_arch = "x86_64")]
pub mod idt;
#[cfg(target_arch = "x86_64")]
pub mod interrupts;
#[cfg(target_arch = "x86_64")]
pub mod regs;
#[cfg(target_arch = "x86_64")]
pub mod smp;
#[cfg(target_arch = "x86_64")]
pub mod bootstrap;
#[cfg(target_arch = "x86_64")]
pub mod switch_to_user;
#[cfg(target_arch = "x86_64")]
pub mod timer;

//! Global Descriptor Table for x86_64
//!
//! Provides the GDT layout, the `lgdt` loader, and segment selector
//! constants used by the kernel.
//!
//! Layout
//! ------
//! Index | Selector | Type                | Notes
//! ------|----------|---------------------|-------------------------------
//! 0     | 0x00     | null descriptor     | mandatory
//! 1     | 0x08     | kernel CS (64-bit)  | flat, DPL 0, long mode
//! 2     | 0x10     | kernel DS (rw)      | flat, DPL 0
//! 3     | 0x18     | user DS (rw, low)   | used by Ring-3 stack/data
//! 4     | 0x20     | user CS (64-bit)    | ring-3 code
//! 5     | 0x28     | user DS (rw)        | ring-3 data (alias of #3)
//! 6     | 0x30     | TSS descriptor      | populated by tss module later
//!
//! For the boot path we only need #0–#3; user-CS (#4) is loaded by
//! `switch_to_user` so that `iretq` returns to ring 3. The TSS slot is
//! reserved but left zero for now — we have no TSS-driven task switching
//! in this revision.

use core::mem::size_of;

use crate::x86_64::x86_64_asm::{lgdt, ltr};

/// 8-byte GDT entry.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags_limit: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            flags_limit: 0,
            base_high: 0,
        }
    }

    /// 64-bit kernel code segment. Long-mode + readable + executable, DPL 0.
    pub const fn kernel_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            // access = present(1) | ring0(00) | S(1) | exec(1) | rw/c(0) = 0x9A
            access: 0x9A,
            // flags = limit_hi=0xF | G=1 | L=1 | D/B=0.
            // 0xAF = 0b1010_1111: G=1, L=1, D/B=0, limit_hi=0xF.
            flags_limit: 0xAF,
            base_high: 0,
        }
    }

    /// 64-bit kernel data segment. Writable, DPL 0.
    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            // access = present(1) | ring0(00) | S(1) | exec(0) | rw(1) = 0x92
            access: 0x92,
            // flags = limit_hi=0xF | G=1 | D/B=1 => full 4 GiB flat segment.
            flags_limit: 0xCF,
            base_high: 0,
        }
    }

    /// 64-bit user data segment. Writable, DPL 3, flat.
    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            // access = present(1) | ring3(11) | S(1) | exec(0) | rw(1) = 0xF2
            access: 0xF2,
            // flags = limit_hi=0xF | G=1 | D/B=1 => full 4 GiB flat segment.
            flags_limit: 0xCF,
            base_high: 0,
        }
    }

    /// 64-bit user code segment. Readable/executable, DPL 3, long mode.
    pub const fn user_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            // access = present(1) | ring3(11) | S(1) | exec(1) | rw(0) = 0xFA
            access: 0xFA,
            // flags = limit_hi=0xF | G=1 | L=1 | D/B=0 => 0xAF.
            flags_limit: 0xAF,
            base_high: 0,
        }
    }
}

/// Full GDT table. Keep it 8-byte aligned.
#[repr(C, align(16))]
pub struct GdtTable {
    // Index 6..7 together form the 16-byte 64-bit TSS descriptor.
    pub entries: [GdtEntry; 8],
}

impl GdtTable {
    pub const fn new() -> Self {
        Self {
            entries: [
                GdtEntry::null(),
                GdtEntry::kernel_code(),
                GdtEntry::kernel_data(),
                GdtEntry::user_data(),   // index 3
                GdtEntry::user_code(),   // index 4
                GdtEntry::user_data(),   // index 5 (alias)
                GdtEntry::null(),         // index 6: TSS descriptor low half
                GdtEntry::null(),         // index 7: TSS descriptor high half
            ],
        }
    }
}

/// Pointer passed to `lgdt`. Must be packed to the GDTR layout.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtPointer {
    /// Limit (size - 1) in bytes.
    pub limit: u16,
    /// Linear address of the GDT.
    pub base: u64,
}

// Segment selectors (index << 3, plus RPL 0/3). Keep as constants so both
// the Rust side and `boot.S` can reference the same numbers.
pub const SEL_NULL:        u16 = 0x00;
pub const SEL_KERNEL_CS:   u16 = 0x08;
pub const SEL_KERNEL_DS:   u16 = 0x10;
pub const SEL_USER_DS:     u16 = 0x18;
pub const SEL_USER_CS:     u16 = 0x20;
pub const SEL_USER_DS_ALT: u16 = 0x28;
pub const SEL_TSS:         u16 = 0x30;

/// Globally-installed GDT. Statically allocated in `.bss` and populated on
/// first use, then never written again.
static mut GDT: GdtTable = GdtTable::new();

/// Load the kernel GDT into the CPU.
///
/// # Safety
/// Must be called from a context where the old selectors are still valid
/// (i.e. before the function returns to user code that uses different
/// selectors). After this function returns, segment registers CS/DS/ES/SS
/// still point at the OLD descriptors; the caller is responsible for
/// reloading them with `reload_segments()` before any data access.
pub unsafe fn gdt_init() {
    let gdt_ptr = GdtPointer {
        limit: (size_of::<GdtTable>() - 1) as u16,
        base: &raw const GDT as u64,
    };
    lgdt(&gdt_ptr as *const _ as u64);
}

/// Reload CS / SS / DS / ES / FS / GS to point at the kernel segments.
///
/// Uses a far-return trick (push new CS; push new RIP; retfq) to switch CS
/// to the kernel code segment, then rewrites the data segment registers
/// with the kernel data segment selector.
///
/// The actual implementation lives in `reload_segments.S`, which is compiled
/// by the arch crate's `build.rs` (it's not in the kernel crate so we can't
/// rely on the kernel's build script to assemble it).
///
/// # Safety
/// Caller must ensure the new selectors are valid (i.e. `gdt_init` has
/// already been called).
pub unsafe fn reload_segments() {
    extern "C" {
        fn reload_segments_trampoline();
    }
    reload_segments_trampoline();
}

// ============================================================================
// TSS (Task State Segment)
// ============================================================================

/// 64-bit TSS layout (104 bytes), matching Intel's documented structure.
/// The packed representation is important: `ltr` reads the raw bytes.
#[repr(C, packed)]
struct Tss {
    reserved1: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved2: u64,
    ist: [u64; 7],
    reserved3: u64,
    reserved4: u16,
    iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            reserved1: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: 0,
        }
    }
}

/// Static TSS. Lives in the kernel image's low (identity-mapped) region.
static mut TSS: Tss = Tss::new();

/// Kernel stack used by interrupts that enter from ring 3. The CPU loads
/// RSP0 from the TSS whenever it switches from user mode to kernel mode.
const INTERRUPT_STACK_SIZE: usize = 16384;
static mut INTERRUPT_STACK: [u8; INTERRUPT_STACK_SIZE] = [0; INTERRUPT_STACK_SIZE];

pub fn interrupt_stack_range() -> core::ops::Range<usize> {
    let base = &raw const INTERRUPT_STACK as usize;
    base..base + INTERRUPT_STACK_SIZE
}

/// Write the 16-byte TSS descriptor at GDT slots 6 and 7.
unsafe fn set_tss_descriptor(base: u64) {
    // TSS limit = 103 (0x67); descriptor bytes are:
    //   limit[15:0], base[15:0], base[23:16], access (0x89 = present,
    //   DPL 0, type 1001b = available 64-bit TSS), limit[19:16], base[31:24]
    //   base[63:32], reserved.
    let limit = 0x0067u16;
    GDT.entries[6] = GdtEntry {
        limit_low: limit,
        base_low: base as u16,
        base_mid: ((base >> 16) & 0xFF) as u8,
        access: 0x89,
        flags_limit: 0,
        base_high: ((base >> 24) & 0xFF) as u8,
    };
    GDT.entries[7] = GdtEntry {
        limit_low: (base >> 32) as u16,
        base_low: ((base >> 48) & 0xFFFF) as u16,
        base_mid: 0,
        access: 0,
        flags_limit: 0,
        base_high: 0,
    };
}

/// Install a real TSS and load it with `ltr`.
///
/// Must be called after `gdt_init()` (so the GDT is active) and before
/// entering ring 3. Without a TSS, the first `int 0x80` from user mode
/// causes an invalid-TSS fault because the CPU cannot switch stacks.
pub unsafe fn tss_init() {
    let stack_top = (&raw mut INTERRUPT_STACK) as u64 + INTERRUPT_STACK_SIZE as u64 - 16;
    TSS.rsp0 = stack_top;
    TSS.rsp1 = stack_top;
    TSS.rsp2 = stack_top;

    let base = &raw mut TSS as u64;
    set_tss_descriptor(base);
    ltr(SEL_TSS);
}

/// Public re-exports so the rest of the kernel can refer to GDT symbols
/// without going through `crate::x86_64::gdt`.
pub use GdtEntry as Entry;
pub use GdtTable as Table;
pub use GdtPointer as Pointer;

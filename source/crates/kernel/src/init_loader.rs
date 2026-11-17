//! init-process loader.
//!
//! Loads the user-mode `init` program from a Multiboot2 module tag and
//! sets up a fresh address space for it:
//!
//!   * A new PML4 page.
//!   * An empty low half (populated by the init ELF's segments).
//!   * A kernel-half mirror identical to the boot PML4 so the kernel can
//!     service page faults and system calls from init.
//!   * A user stack at `0x7FFF_FFFF_F000`.
//!
//! On success the function returns the virtual entry address, the user
//! stack pointer, and the new PML4 physical address so the caller can
//! invoke `switch_to_user`.

extern crate alloc;

use alloc::vec::Vec;

use crate::entry::BootInfo;
use crate::plan9_arch::hal::paging::PAGESIZE;
use plan9_common::types::{PhysAddr, VirtAddr};
use crate::plan9_common::sync::Spinlock;

use crate::frame_alloc;

/// Segment metadata collected while mapping the init ELF: a
/// `crate::proc::SegType` discriminant, base and top virtual addresses.
/// The boot path applies this to proc0 so `/proc/N/mem` and `status`
/// report the real segment layout.
pub type UserSegInfo = (u8, u64, u64);

static USER_SEGS: Spinlock<Vec<UserSegInfo>> = Spinlock::new(Vec::new());

/// Drain the collected segment metadata (called once by the boot path).
pub fn take_user_segments() -> Vec<UserSegInfo> {
    let mut guard = USER_SEGS.lock();
    core::mem::take(&mut *guard)
}

fn record_user_seg(tag: u8, base: u64, top: u64) {
    USER_SEGS.lock().push((tag, base, top));
}

/// Where the user-mode ELF gets mapped.  Plan 9-style non-PIE userspace.
/// User programs are linked at 0x200000 (the kernel's linker base), so we
/// relocate the whole image uniformly to 1 GiB (USER_BASE).  This keeps the
/// kernel's low identity mapping (0..64 MiB) intact in the user PML4 and
/// prevents user program pages from overwriting kernel code/IDT/GDT pages.
/// Base of the relocated user program image.
///
/// x86_64: 1 GiB — just above the preserved low identity map.
/// aarch64: 512 GiB — the boot root's L0[0] covers the whole first 512 GiB
/// (its L1 table holds the Device/RAM/ECAM identity blocks), so the user
/// image must live in L0[1] to avoid colliding with those entries.
#[cfg(target_arch = "aarch64")]
const USER_LOAD_BASE: u64 = 0x0000_0080_0000_0000; // 512 GiB
#[cfg(not(target_arch = "aarch64"))]
const USER_LOAD_BASE: u64 = 0x0000_0000_4000_0000;

/// Where the user stack lives.
const USER_STACK_TOP:  u64 = 0x0000_7FFF_FFFF_F000;
const USER_STACK_PAGES: u64 = 4;
const USER_STACK_SIZE:  u64 = USER_STACK_PAGES * PAGESIZE as u64;

/// PTE flag bits used here.
const PTE_PRESENT:  u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER:     u64 = 1 << 2;
const PTE_PS:       u64 = 1 << 7;   // 2 MiB / 1 GiB huge-page bit
const PTE_NX:       u64 = 1 << 63;

// ============================================================================
// AArch64 descriptor translation
//
// The loader's flag vocabulary is x86_64 (PRESENT | WRITABLE | USER | NX,
// plus a PTE_RDONLY marker at bit 7 written by the exec loader).  On
// aarch64 those bit positions mean different things, so every entry is
// routed through `leaf_flags` (final-level descriptors) or given proper
// table descriptors (`PTE_MID_FLAGS`):
//
//   bit 0        Valid
//   bit 1        Table/Block select — set for level-3 (leaf) descriptors
//                and for L0–L2 *table* descriptors; clear for 1 GiB / 2 MiB
//                block descriptors.
//   bits [4:2]   AttrIndx (MAIR) — must be 0 (Normal cacheable) for user
//                memory; the x86 PTE_USER bit (1<<2) would otherwise select
//                Device memory, which is execute-never.
//   bit 6        AP[1] — EL0 accessibility.
//   bit 7        AP[2] — read-only.
//   bit 10       AF (access flag) — required, or the first access faults.
//   bit 54       UXN.
// ============================================================================

/// Intermediate (L0–L2) table descriptor flags.
#[cfg(target_arch = "aarch64")]
const PTE_MID_FLAGS: u64 = PTE_PRESENT | (1 << 1); // Valid + Table
#[cfg(not(target_arch = "aarch64"))]
const PTE_MID_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_USER;

/// aarch64 access flag (required on leaf descriptors).
#[cfg(target_arch = "aarch64")]
pub const PTE_AF:       u64 = 1 << 10;
#[cfg(not(target_arch = "aarch64"))]
pub const PTE_AF:       u64 = 0;

/// aarch64 AP[1] (EL0 accessibility), set for user pages.
#[cfg(target_arch = "aarch64")]
const PTE_EL0:      u64 = 1 << 6;
#[cfg(not(target_arch = "aarch64"))]
const PTE_EL0:      u64 = 0;

/// aarch64 UXN (bit 54) where x86 uses NX (bit 63).
#[cfg(target_arch = "aarch64")]
const PTE_UXN:      u64 = 1 << 54;
#[cfg(not(target_arch = "aarch64"))]
const PTE_UXN:      u64 = 0;

/// aarch64 AP[2] (read-only) marker in the caller flag vocabulary; a
/// no-op on x86_64 (where bit 7 is the PAT bit, left clear for user
/// pages).
#[cfg(target_arch = "aarch64")]
const PTE_RDONLY:   u64 = 1 << 7;
#[cfg(not(target_arch = "aarch64"))]
const PTE_RDONLY:   u64 = 0;

/// Read-only marker in the caller flag vocabulary (used by the exec
/// loader in `syscall.rs`).  No-op on x86_64.
pub const PTE_RDONLY_CALLER: u64 = PTE_RDONLY;

/// Translate an x86-style leaf flag set into arch-correct descriptor bits.
///
/// `flags` uses the x86 vocabulary: PRESENT | WRITABLE(bit1) | USER(bit2) |
/// RDONLY(bit7) | NX(bit63).  On aarch64 this maps to Valid + leaf + AF +
/// AP[1] (EL0) + AP[2] (read-only) + UXN, with AttrIndx left at 0 (Normal
/// cacheable) so user code stays executable.
#[inline]
fn leaf_flags(flags: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let mut f = PTE_PRESENT          // Valid
            | (1 << 1)                   // leaf (level-3) descriptor
            | PTE_AF                     // Access flag
            | 0b11 << 8;                 // SH = inner-shareable
        if flags & PTE_USER != 0 {
            f |= PTE_EL0;                // AP[1]: accessible at EL0
        }
        if flags & PTE_WRITABLE == 0 || flags & PTE_RDONLY != 0 {
            f |= 1 << 7;                 // AP[2]: read-only
        }
        if flags & PTE_NX != 0 {
            f |= PTE_UXN;                // UXN
        }
        f
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        flags
    }
}

/// True when a descriptor read at an intermediate level is a block/huge
/// entry rather than a next-level table pointer (aarch64: TABLE bit clear;
/// x86: PS bit set).
#[inline]
fn is_block_desc(desc: u64) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        desc & (1 << 1) == 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        desc & PTE_PS != 0
    }
}

/// ELF64 program header types we care about.
const PT_LOAD: u32 = 1;

/// ELF64 program header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct Phdr64 {
    p_type:   u32,
    p_flags:  u32,
    p_offset: u64,
    p_vaddr:  u64,
    p_paddr:  u64,
    p_filesz: u64,
    p_memsz:  u64,
    p_align:  u64,
}

/// Result of loading init: the new PML4, the entry point, and the user
/// stack pointer.
pub struct InitImage {
    pub pml4:      PhysAddr,
    pub entry:     u64,
    pub user_sp:   u64,
}

/// Locate the "init" module in the boot info. We use the first module
/// (which is what grub.cfg's `module2 /path/to/init` produces). The user
/// can supply a command line of `init=<cmd>` to override this; we honour
/// it if non-empty.
pub fn find_init_module<'a>(boot: &'a BootInfo) -> Option<&'a crate::entry::RawModuleInfo> {
    if let Some(name) = boot.cmdline.as_str().strip_prefix("init=") {
        for i in 0..boot.modules.count as usize {
            if let Some(m) = &boot.modules.entries[i] {
                let n = core::str::from_utf8(&m.name[..m.name_len]).unwrap_or("");
                if n.ends_with(name) {
                    return Some(m);
                }
            }
        }
    }
    boot.modules.first()
}

/// Build the init process image and load it into RAM.
pub fn load_init(boot: &BootInfo) -> Option<InitImage> {
    let module = match find_init_module(boot) {
        Some(m) => m,
        None => return None,
    };

    // Validate that the module starts with an ELF magic.
    unsafe {
        let base = module.start as *const u8;
        if core::slice::from_raw_parts(base, 4) != b"\x7FELF" {
            crate::serial::put_bytes(b"[init_loader] module is not ELF\n");
            return None;
        }
    }

    crate::serial::put_bytes(b"[init_loader] module start=");
    crate::serial::put_hex_u64(module.start);
    crate::serial::put_bytes(b" end=");
    crate::serial::put_hex_u64(module.end);
    crate::serial::put_bytes(b"\n");

    // Allocate a fresh PML4 and populate it with copies of the kernel
    // mappings from the boot PML4 (so the kernel can keep servicing
    // interrupts and page faults).
    crate::serial::put_bytes(b"[init_loader] allocating pml4 frame\n");
    let new_pml4 = frame_alloc::frame_alloc_zeroed()?;
    crate::serial::put_bytes(b"[init_loader] pml4=");
    crate::serial::put_hex_u64(new_pml4.as_u64());
    crate::serial::put_bytes(b"\n");
    // Mirror the kernel PML4 entries above PML4[256], but build a
    // dedicated low-half PDPT for the user address space so the user
    // region does not collide with GRUB's huge identity mappings.
    unsafe {
        if copy_kernel_pml4_into(new_pml4).is_none() {
            crate::serial::put_bytes(b"[init_loader] PML4 mirror failed\n");
            return None;
        }
    }

    // Allocate a user stack.
    let stack_top = USER_STACK_TOP;
    let stack_base = stack_top - USER_STACK_SIZE + PAGESIZE as u64;
    crate::serial::put_bytes(b"[init_loader] stack_base=");
    crate::serial::put_hex_u64(stack_base);
    crate::serial::put_bytes(b"\n");
    record_user_seg(crate::proc::SegType::Stack as u8, stack_base, stack_top);
    unsafe {
        for page in 0..USER_STACK_PAGES {
            let phys = match frame_alloc::frame_alloc_zeroed() {
                Some(p) => p,
                None => return None,
            };
            let vaddr = stack_base + page * PAGESIZE as u64;
            if map_user_page(new_pml4, vaddr, phys.as_u64(),
                             PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_AF).is_none() {
                crate::serial::put_bytes(b"[init_loader] stack map failed\n");
                return None;
            }
        }
    }

    // Parse the ELF program headers and map each PT_LOAD segment.
    let entry = unsafe { map_elf_segments(new_pml4, module)? };
    crate::serial::put_bytes(b"[init_loader] entry=");
    crate::serial::put_hex_u64(entry);
    crate::serial::put_bytes(b"\n");

    // DEBUG: walk the user root table to the entry page and dump its
    // first 32 bytes via the TTBR1 direct-map window, so the loaded
    // contents can be compared with the ELF file bytes.
    unsafe {
        let (i4, i3, i2, i1) = virt_indices(entry);
        let l1 = read_pte(new_pml4.as_u64(), i4) & 0x000F_FFFF_FFFF_F000;
        let pd = read_pte(l1, i3) & 0x000F_FFFF_FFFF_F000;
        let pt = read_pte(pd, i2) & 0x000F_FFFF_FFFF_F000;
        let pte = read_pte(pt, i1);
        crate::serial::put_bytes(b"[dbg] l1=");
        crate::serial::put_hex_u64(l1);
        crate::serial::put_bytes(b" pte=");
        crate::serial::put_hex_u64(pte);
        crate::serial::put_bytes(b"\n");
        let page_phys = pte & 0x000F_FFFF_FFFF_F000;
        // Read via the boot root's RAM identity map (VA = PA) — the
        // TTBR1 direct-map window only covers the first identity blocks.
        let win = page_phys + (entry & 0xFFF);
        crate::serial::put_bytes(b"[dbg] entry bytes:");
        let p = win as *const u8;
        const HEX: [u8; 16] = *b"0123456789abcdef";
        for k in 0..32 {
            let b = p.add(k).read_volatile();
            crate::serial::put_bytes(&[HEX[(b >> 4) as usize], HEX[(b & 0xF) as usize], b' ']);
        }
        crate::serial::put_bytes(b"\n");
    }

    Some(InitImage {
        pml4:    new_pml4,
        entry,
        user_sp: stack_top,
    })
}

// ============================================================================
// Paging helpers
// ============================================================================

/// Mapping cache so we don't re-allocate page tables between the user
/// half and the kernel half. Keyed by (pml4_phys, virt_addr).
static TABLE_CACHE: Spinlock<Vec<u64>> = Spinlock::new(Vec::new());

pub unsafe fn alloc_pte_page(_pml4: PhysAddr) -> Option<u64> {
    frame_alloc::frame_alloc_zeroed().map(|p| p.as_u64())
}

fn virt_indices(vaddr: u64) -> (usize, usize, usize, usize) {
    let pml4 = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt = ((vaddr >> 30) & 0x1FF) as usize;
    let pd   = ((vaddr >> 21) & 0x1FF) as usize;
    let pt   = ((vaddr >> 12) & 0x1FF) as usize;
    (pml4, pdpt, pd, pt)
}

/// Map a single 4 KiB user page. Allocates intermediate page tables on
/// demand.
///
/// Intermediate entries may already contain huge (2 MiB or 1 GiB) mappings
/// inherited from GRUB.  A huge PDE cannot be used as a table pointer, so
/// replace it with a fresh, dedicated page table before writing the 4 KiB PTE.
pub unsafe fn map_user_page(
    pml4: PhysAddr,
    vaddr: u64,
    paddr: u64,
    flags: u64,
) -> Option<()> {
    let (i4, i3, i2, i1) = virt_indices(vaddr);
    if i4 >= 256 { return None; }

    let pml4_base = pml4.as_u64();
    let pml4e = read_pte(pml4_base, i4);
    let pdpt_phys = if pml4e & PTE_PRESENT != 0 && !is_block_desc(pml4e) {
        pml4e & 0x000F_FFFF_FFFF_F000
    } else {
        let new = alloc_pte_page(pml4)?;
        write_pte(pml4_base, i4, new | PTE_MID_FLAGS);
        new
    };

    let pdpte = read_pte(pdpt_phys, i3);
    let pd_phys = if (pdpte & PTE_PRESENT) != 0 && !is_block_desc(pdpte) {
        pdpte & 0x000F_FFFF_FFFF_F000
    } else {
        // Allocate a fresh PD, replacing either a missing entry or a 1 GiB
        // huge-page entry.
        let new = alloc_pte_page(pml4)?;
        write_pte(pdpt_phys, i3, new | PTE_MID_FLAGS);
        new
    };

    let pde = read_pte(pd_phys, i2);
    let pt_phys = if (pde & PTE_PRESENT) != 0 && !is_block_desc(pde) {
        pde & 0x000F_FFFF_FFFF_F000
    } else {
        // Allocate a fresh PT, replacing either a missing entry or a 2 MiB
        // huge-page entry.
        let new = alloc_pte_page(pml4)?;
        write_pte(pd_phys, i2, new | PTE_MID_FLAGS);
        new
    };

    write_pte(pt_phys, i1, paddr | leaf_flags(flags));
    let mut cache = TABLE_CACHE.lock();
    cache.push(pt_phys);
    Some(())
}

pub unsafe fn read_pte(table: u64, index: usize) -> u64 {
    let ptr = table as *const u64;
    core::ptr::read_volatile(ptr.add(index))
}

pub unsafe fn write_pte(table: u64, index: usize, val: u64) {
    let ptr = table as *mut u64;
    core::ptr::write_volatile(ptr.add(index), val);
}

/// Copy the kernel PML4 mappings from the boot PML4 to the new PML4.
///
/// The kernel's low identity mapping (0..1 GiB, PDPT slot 0) is preserved so
/// kernel code, IDT, GDT, stacks and trap handlers remain addressable while
/// running in user mode.  A *new* PDPT page is created, and its slot 1 is
/// populated with a fresh PD reserved for the relocated user program
/// (USER_BASE = 1 GiB).  This avoids reusing GRUB's huge 2 MiB PDEs, which
/// would otherwise make `map_user_page` treat a huge mapping as a PT pointer.
/// The high canonical kernel mirror (PML4[256..511]) is copied verbatim.
pub unsafe fn copy_kernel_pml4_into(new_pml4: PhysAddr) -> Option<()> {
    // Read the boot PML4 from the current root table.
    let boot_pml4: u64 = crate::plan9_arch::hal::mmu::cr3_read().as_u64();
    let boot = boot_pml4 & 0x000F_FFFF_FFFF_F000;
    let dst = new_pml4.as_u64();

    let boot_low = read_pte(boot, 0);
    if (boot_low & PTE_PRESENT) == 0 {
        return None;
    }

    // ------------------------------------------------------------------
    // aarch64: the boot root's L0[0] points at an L1 table whose entries
    // are 1 GiB *block* descriptors — the low Device window (PL011, GIC),
    // the RAM identity blocks, and the PCIe ECAM block.  Copy the whole
    // L1 table into a fresh table and link it with a proper table
    // descriptor (Valid + TABLE bit): the kernel keeps executing from its
    // identity mapping (kernel image, stacks, trap code) after the root
    // switch, and the ECAM stays reachable for run-time PCI access.
    // ------------------------------------------------------------------
    #[cfg(target_arch = "aarch64")]
    {
        let src_l1 = boot_low & 0x000F_FFFF_FFFF_F000;
        let new_l1 = alloc_pte_page(new_pml4)?;
        for i in 0..512usize {
            let v = read_pte(src_l1, i);
            write_pte(new_l1, i, v);
        }
        write_pte(dst, 0, new_l1 | PTE_MID_FLAGS);
        return Some(());
    }

    // ------------------------------------------------------------------
    // x86_64: keep the kernel's 0..1 GiB identity map (PDPT slot 0) but
    // do not reuse the boot PDPT page itself; slot 1 belongs to the user
    // image.
    // ------------------------------------------------------------------
    #[cfg(not(target_arch = "aarch64"))]
    {
        let boot_pdpt = boot_low & 0x000F_FFFF_FFFF_F000;
        let new_pdpt = alloc_pte_page(new_pml4)?;
        let low_pdpt0 = read_pte(boot_pdpt, 0);
        if (low_pdpt0 & PTE_PRESENT) == 0 {
            return None;
        }
        write_pte(new_pdpt, 0, low_pdpt0);

        // Preserve the boot kernel's PCI/MMIO mapping at PDPT slot 2
        // (0x80000000..0xBFFFFFFF).  Without this, the AHCI BAR at
        // 0x810c4000 is unavailable while a syscall runs in the user PML4,
        // and filesystem reads fault after user mode starts.
        let low_pdpt2 = read_pte(boot_pdpt, 2);
        if (low_pdpt2 & PTE_PRESENT) != 0 {
            write_pte(new_pdpt, 2, low_pdpt2);
        }

        // Dedicated PD for the user region 1..2 GiB.  Slot 1 is not inherited
        // from GRUB, so no huge 2 MiB PDEs can appear there.
        let new_pd = alloc_pte_page(new_pml4)?;
        write_pte(new_pdpt, 1, new_pd | PTE_PRESENT | PTE_WRITABLE | PTE_USER);

        write_pte(dst, 0, new_pdpt | PTE_PRESENT | PTE_WRITABLE | PTE_USER);

        // High-half kernel mirror.
        for i in 256..512 {
            let v = read_pte(boot, i);
            write_pte(dst, i, v);
        }
    }

    Some(())
}

/// Copy the parent's user-space mappings (virtual addresses >= USER_LOAD_BASE)
/// into a new child PML4.  Every mapped data page is copied to a fresh
/// physical frame, and new page-table pages are allocated for the child, so
/// exec/write in the child cannot modify the parent's image or stack.
pub unsafe fn copy_user_mappings(parent_pml4: u64, child_pml4: PhysAddr) -> Option<()> {
    let page_size = PAGESIZE as usize;

    for i4 in 0..256usize {
        let pml4e = read_pte(parent_pml4, i4);
        if pml4e & PTE_PRESENT == 0 || is_block_desc(pml4e) {
            continue;
        }
        let pdpt = pml4e & 0x000F_FFFF_FFFF_F000;

        for i3 in 0..512usize {
            let pdpte = read_pte(pdpt, i3);
            if pdpte & PTE_PRESENT == 0 || is_block_desc(pdpte) {
                continue;
            }
            let pd = pdpte & 0x000F_FFFF_FFFF_F000;

            for i2 in 0..512usize {
                let pde = read_pte(pd, i2);
                if pde & PTE_PRESENT == 0 || is_block_desc(pde) {
                    continue;
                }
                let pt = pde & 0x000F_FFFF_FFFF_F000;

                for i1 in 0..512usize {
                    let pte = read_pte(pt, i1);
                    if pte & PTE_PRESENT == 0 {
                        continue;
                    }

                    let vaddr = ((i4 as u64) << 39)
                        | ((i3 as u64) << 30)
                        | ((i2 as u64) << 21)
                        | ((i1 as u64) << 12);
                    if vaddr < USER_LOAD_BASE {
                        continue;
                    }

                    let flags = pte & 0xFFF;
                    let parent_frame = pte & 0x000F_FFFF_FFFF_F000;

                    let new_frame = match frame_alloc::frame_alloc_zeroed() {
                        Some(f) => f,
                        None => return None,
                    };

                    let src = parent_frame as *const u8;
                    let dst = new_frame.as_u64() as *mut u8;
                    core::ptr::copy_nonoverlapping(src, dst, page_size);

                    if map_user_page(child_pml4, vaddr, new_frame.as_u64(), flags).is_none() {
                        return None;
                    }
                }
            }
        }
    }

    Some(())
}

/// Walk the ELF program headers and map every PT_LOAD segment into the
/// user half of the new address space.
unsafe fn map_elf_segments(pml4: PhysAddr, module: &crate::entry::RawModuleInfo) -> Option<u64> {
    let base = module.start as *const u8;

    // ELF64 header layout
    #[derive(Copy, Clone)]
    #[repr(C)]
    struct Ehdr64 {
        e_ident:    [u8; 16],
        e_type:     u16,
        e_machine:  u16,
        e_version:  u32,
        e_entry:    u64,
        e_phoff:    u64,
        e_shoff:    u64,
        e_flags:    u32,
        e_ehsize:   u16,
        e_phentsize:u16,
        e_phnum:    u16,
        e_shentsize:u16,
        e_shnum:    u16,
        e_shstrndx: u16,
    }

    let ehdr: &Ehdr64 = &*(base as *const Ehdr64);
    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phsize = ehdr.e_phentsize as usize;
    let entry = ehdr.e_entry + USER_LOAD_BASE;

    // Relocate absolute pointers stored in `.got`.  The ELF is linked at
    // 0x200000 (the kernel's linker base) but mapped at USER_LOAD_BASE.
    // RIP-relative displacements naturally relocate with the code, but GOT
    // entries contain absolute target addresses and must be shifted manually.
    unsafe {
        #[derive(Copy, Clone)]
        #[repr(C)]
        struct Shdr64 {
            sh_name:      u32,
            sh_type:      u32,
            sh_flags:     u64,
            sh_addr:      u64,
            sh_offset:    u64,
            sh_size:      u64,
            sh_link:      u32,
            sh_info:      u32,
            sh_addralign: u64,
            sh_entsize:   u64,
        }

        let shoff = ehdr.e_shoff as usize;
        let shnum = ehdr.e_shnum as usize;
        let shsize = ehdr.e_shentsize as usize;
        let shstrndx = ehdr.e_shstrndx as usize;

        if shoff != 0 && shnum != 0 && shstrndx < shnum {
            let shstr_sh = (base as usize + shoff + shstrndx * shsize) as *const Shdr64;
            let shstr = *shstr_sh;
            let strtab = (base as usize + shstr.sh_offset as usize) as *const u8;
            let strtab_len = shstr.sh_size as usize;

            for i in 0..shnum {
                let sh = *((base as usize + shoff + i * shsize) as *const Shdr64);
                let name_ptr = (strtab as usize + sh.sh_name as usize) as *const u8;
                let mut name_len = 0usize;
                while name_len < strtab_len {
                    let b = *name_ptr.add(name_len);
                    if b == 0 { break; }
                    name_len += 1;
                }
                let name = core::str::from_utf8(
                    core::slice::from_raw_parts(name_ptr, name_len)
                ).unwrap_or("");

                if (name == ".got" || name == ".data.rel.ro") && sh.sh_size >= 8 {
                    let off = sh.sh_offset as usize;
                    let nwords = sh.sh_size as usize / 8;
                    for w in 0..nwords {
                        let p = (base as usize + off + w * 8) as *mut u64;
                        let val = *p;
                        // Relocate only absolute low-image pointers.  The
                        // .data.rel.ro section also contains small integers
                        // and packed table fields that must stay unchanged.
                        if val >= crate::segment::USER_IMAGE_BASE
                            && val < crate::segment::USER_IMAGE_LIMIT
                        {
                            *p = val + USER_LOAD_BASE;
                        }
                    }
                }
            }
        }
    }

    crate::serial::put_bytes(b"[map_elf] phnum=");
    crate::serial::put_hex_u32(phnum as u32);
    crate::serial::put_bytes(b" entry=");
    crate::serial::put_hex_u64(entry);
    crate::serial::put_bytes(b"\n");

    let mut loaded = false;
    for i in 0..phnum {
        let ph_ptr = (base as usize + phoff + i * phsize) as *const Phdr64;
        let ph = *ph_ptr;
        if ph.p_type != PT_LOAD { continue; }
        loaded = true;
        crate::serial::put_bytes(b"[map_elf] segment vaddr=");
        crate::serial::put_hex_u64(ph.p_vaddr + USER_LOAD_BASE);
        crate::serial::put_bytes(b" memsz=");
        crate::serial::put_hex_u64(ph.p_memsz);
        crate::serial::put_bytes(b"\n");

        // Relocate the whole segment uniformly into the user half.
        let seg_start_vaddr = ph.p_vaddr + USER_LOAD_BASE;
        let seg_end_vaddr   = ph.p_vaddr + USER_LOAD_BASE + ph.p_memsz;
        let data_end_vaddr  = seg_start_vaddr + ph.p_filesz;

        // Record the segment layout for /proc (writable -> data, else text).
        let seg_tag = if ph.p_flags & 0x2 != 0 {
            crate::proc::SegType::Data as u8
        } else {
            crate::proc::SegType::Text as u8
        };
        record_user_seg(seg_tag, seg_start_vaddr, seg_end_vaddr);

        let mut cur_vaddr = seg_start_vaddr & !(PAGESIZE as u64 - 1);

        while cur_vaddr < seg_end_vaddr {
            let phys = frame_alloc::frame_alloc_zeroed()?;
            let page_end = cur_vaddr + PAGESIZE as u64;

            // Copy only the portion of this page that has file data.  Bytes
            // before the segment start (or after p_filesz) stay zero.
            let copy_start = core::cmp::max(cur_vaddr, seg_start_vaddr);
            let copy_end   = core::cmp::min(page_end, data_end_vaddr);
            if copy_start < copy_end {
                let dst_off = (copy_start - cur_vaddr) as usize;
                let file_off = ph.p_offset + (copy_start - seg_start_vaddr);
                let copy_len = (copy_end - copy_start) as usize;
                let src = (base as usize + file_off as usize) as *const u8;
                let dst = (phys.as_u64() as *mut u8).add(dst_off);
                core::ptr::copy_nonoverlapping(src, dst, copy_len);
            }

            // Build PTE flags from program-header flags.
            let mut flags = PTE_PRESENT | PTE_USER | PTE_AF;
            if ph.p_flags & 0x2 != 0 {
                flags |= PTE_WRITABLE;
            } else {
                flags |= PTE_RDONLY;
            }
            if ph.p_flags & 0x1 == 0 { flags |= PTE_NX; }
            map_user_page(pml4, cur_vaddr, phys.as_u64(), flags)?;
            cur_vaddr += PAGESIZE as u64;
        }
    }

    if !loaded { return None; }
    Some(entry)
}
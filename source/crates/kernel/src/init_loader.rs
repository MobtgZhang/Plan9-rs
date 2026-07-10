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
use crate::plan9_arch::x86_64::paging::PAGESIZE;
use plan9_common::types::{PhysAddr, VirtAddr};
use crate::plan9_common::sync::Spinlock;

use crate::frame_alloc;

/// Where the user-mode ELF gets mapped.  Plan 9-style non-PIE userspace.
const USER_LOAD_BASE: u64 = 0x0000_0000_0040_0000; // 4 MiB

/// Where the user stack lives.
const USER_STACK_TOP:  u64 = 0x0000_7FFF_FFFF_F000;
const USER_STACK_PAGES: u64 = 4;
const USER_STACK_SIZE:  u64 = USER_STACK_PAGES * PAGESIZE as u64;

/// PTE flag bits used here.
const PTE_PRESENT:  u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER:     u64 = 1 << 2;
const PTE_NX:       u64 = 1 << 63;

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
            return None;
        }
    }

    // Allocate a fresh PML4 and populate it with copies of the kernel
    // mappings from the boot PML4 (so the kernel can keep servicing
    // interrupts and page faults).
    let new_pml4 = frame_alloc::frame_alloc_zeroed()?;
    // Mirror the kernel PML4 entries above PML4[256].
    unsafe {
        copy_kernel_pml4_into(new_pml4);
    }

    // Allocate a user stack.
    let stack_top = USER_STACK_TOP;
    let stack_base = stack_top - USER_STACK_SIZE + PAGESIZE as u64;
    unsafe {
        for page in 0..USER_STACK_PAGES {
            let phys = match frame_alloc::frame_alloc_zeroed() {
                Some(p) => p,
                None => return None,
            };
            let vaddr = stack_base + page * PAGESIZE as u64;
            map_user_page(new_pml4, vaddr, phys.as_u64(),
                          PTE_PRESENT | PTE_WRITABLE | PTE_USER)?;
        }
    }

    // Parse the ELF program headers and map each PT_LOAD segment.
    let entry = unsafe { map_elf_segments(new_pml4, module)? };

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

unsafe fn alloc_pte_page(pml4: PhysAddr) -> Option<u64> {
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
unsafe fn map_user_page(
    pml4: PhysAddr,
    vaddr: u64,
    paddr: u64,
    flags: u64,
) -> Option<()> {
    let (i4, i3, i2, i1) = virt_indices(vaddr);
    if i4 >= 256 { return None; }

    let pml4_base = pml4.as_u64();
    let pml4e = read_pte(pml4_base, i4);
    let pdpt_phys = if pml4e & PTE_PRESENT != 0 {
        pml4e & 0x000F_FFFF_FFFF_F000
    } else {
        let new = alloc_pte_page(pml4)?;
        write_pte(pml4_base, i4, new | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
        new
    };
    let pdpte = read_pte(pdpt_phys, i3);
    let pd_phys = if pdpte & PTE_PRESENT != 0 {
        pdpte & 0x000F_FFFF_FFFF_F000
    } else {
        let new = alloc_pte_page(pml4)?;
        write_pte(pdpt_phys, i3, new | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
        new
    };
    let pde = read_pte(pd_phys, i2);
    let pt_phys = if pde & PTE_PRESENT != 0 {
        pde & 0x000F_FFFF_FFFF_F000
    } else {
        let new = alloc_pte_page(pml4)?;
        write_pte(pd_phys, i2, new | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
        new
    };
    write_pte(pt_phys, i1, paddr | flags);
    let mut cache = TABLE_CACHE.lock();
    cache.push(pt_phys);
    Some(())
}

unsafe fn read_pte(table: u64, index: usize) -> u64 {
    let ptr = table as *const u64;
    core::ptr::read_volatile(ptr.add(index))
}

unsafe fn write_pte(table: u64, index: usize, val: u64) {
    let ptr = table as *mut u64;
    core::ptr::write_volatile(ptr.add(index), val);
}

/// Copy the high-half PML4 entries (kernel mirror) from the boot PML4 to
/// the new PML4 so the kernel can still service page faults.
unsafe fn copy_kernel_pml4_into(new_pml4: PhysAddr) {
    // Read the boot PML4 from CR3.
    let boot_pml4: u64;
    core::arch::asm!("mov {0}, cr3", out(reg) boot_pml4);
    let boot = boot_pml4 & 0x000F_FFFF_FFFF_F000;
    let dst = new_pml4.as_u64();
    // Copy entries 256..=511 verbatim.
    for i in 256..512 {
        let v = read_pte(boot, i);
        write_pte(dst, i, v);
    }
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
    let entry = ehdr.e_entry;

    let mut loaded = false;
    for i in 0..phnum {
        let ph_ptr = (base as usize + phoff + i * phsize) as *const Phdr64;
        let ph = *ph_ptr;
        if ph.p_type != PT_LOAD { continue; }
        loaded = true;

        // Round down the start of the mapping to a page boundary.
        let seg_start_vaddr = ph.p_vaddr;
        let seg_end_vaddr   = ph.p_vaddr + ph.p_memsz;
        let file_off_start  = ph.p_offset;
        let file_off_end    = ph.p_offset + ph.p_filesz;

        let mut cur_vaddr = seg_start_vaddr & !(PAGESIZE as u64 - 1);
        let mut cur_off   = file_off_start.saturating_sub(
            seg_start_vaddr - cur_vaddr
        );

        while cur_vaddr < seg_end_vaddr {
            let phys = frame_alloc::frame_alloc_zeroed()?;
            // Copy file bytes for this page (if any).
            if cur_off < file_off_end {
                let page_file_end = core::cmp::min(
                    cur_off + PAGESIZE as u64,
                    file_off_end,
                );
                let copy_len = (page_file_end - cur_off) as usize;
                let src = (base as usize + cur_off as usize) as *const u8;
                let dst = crate::plan9_arch::x86_64::paging::phys_to_virt(phys).as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(src, dst, copy_len);
            }
            // Build PTE flags from program-header flags.
            let mut flags = PTE_PRESENT | PTE_USER;
            if ph.p_flags & 0x2 != 0 { flags |= PTE_WRITABLE; }
            if ph.p_flags & 0x1 == 0 { flags |= PTE_NX; }
            map_user_page(pml4, cur_vaddr, phys.as_u64(), flags)?;
            cur_vaddr += PAGESIZE as u64;
            cur_off   += PAGESIZE as u64;
        }
    }

    if !loaded { return None; }
    Some(entry)
}
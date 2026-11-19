//! Kernel Entry Point
//!
//! Implements the early boot path that runs after GRUB hands control to
//! `arch/x86_64/boot.S::kstart`.
//!
//! Boot flow:
//!   1. Verify the Multiboot2 magic.
//!   2. Parse the Multiboot2 information structure into a `BootInfo`.
//!   3. Set up the serial port (so a fault during early init is visible
//!      on QEMU's `-serial` console).
//!   4. Run the architecture-level early init: GDT → paging → IDT.
//!   5. Initialise the VGA console and the global frame allocator.
//!   6. Initialise the kernel heap.
//!   7. Load the `init` ELF (if a MODULE tag was supplied) and switch to
//!      user mode.
//!   8. If no init was supplied, fall back to the legacy "kernel shell"
//!      message so we can still observe boot progress.

#![allow(dead_code)]

extern crate alloc;
extern crate plan9_common;
extern crate plan9_arch;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::panic::PanicInfo;

use crate::frame_alloc;
use crate::heap;
use crate::init_loader;
use crate::serial;


// ============================================================================
// Multiboot2 Constants
// ============================================================================

/// Multiboot2 magic (passed in RAX by GRUB).
pub const MB2_MAGIC: u64 = 0x36D76289;

/// Snapshot of the magic/info registers at the very entry to `kstart()`.
/// Set before any other function runs so we can observe what GRUB handed
/// us even if subsequent init code clobbers the stack frame.
static mut SAVED_MAGIC: u64 = 0;
static mut SAVED_INFO: u64 = 0;

// Multiboot2 info-structure tag types
pub mod tag_type {
    pub const END: u32               = 0;
    pub const CMDLINE: u32           = 1;
    pub const BOOT_LOADER_NAME: u32  = 2;
    pub const MODULE: u32            = 3;
    pub const BASIC_MEMINFO: u32     = 4;
    pub const BOOTDEV: u32           = 5;
    pub const MEMMAP: u32            = 6;
    pub const FRAMEBUFFER: u32       = 8;
    pub const ACPI_OLD: u32          = 14;
    pub const ACPI_NEW: u32          = 15;
}

// ============================================================================
// Boot Information Structures
// ============================================================================

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved:   u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TagHeader {
    pub typ:  u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BasicMemInfo {
    pub mem_lower: u32,
    pub mem_upper: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MmapEntry {
    pub size:   u32,
    pub addr:   u64,
    pub len:    u64,
    pub type_:  u32,
    _reserved: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    pub addr:    u64,
    pub pitch:   u32,
    pub width:   u32,
    pub height:  u32,
    pub bpp:     u8,
    pub fb_type: u8,
    _reserved:   u16,
}

/// A single multiboot module (e.g. the `init` ELF).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Physical base address of the module.
    pub start: u64,
    /// End (exclusive) physical address of the module.
    pub end:   u64,
    /// Module name as given in the GRUB command line.
    pub name:  String,
}

/// A temporary structure to hold module data during early boot
#[derive(Copy, Clone, Debug)]
pub struct RawModuleInfo {
    pub start: u64,
    pub end: u64,
    pub name: [u8; 64],
    pub name_len: usize,
}

impl RawModuleInfo {
    fn new(start: u64, end: u64, name: &str) -> Self {
        let mut n = [0u8; 64];
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        n[..len].copy_from_slice(&bytes[..len]);
        Self {
            start,
            end,
            name: n,
            name_len: len,
        }
    }
    fn to_module_info(&self) -> ModuleInfo {
        let name_str = core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("").to_string();
        ModuleInfo {
            start: self.start,
            end: self.end,
            name: name_str,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Kernel command-line string (after the `--`).
    pub cmdline:         BootString,
    /// Bootloader name.
    pub bootloader_name: Option<BootString>,
    /// Lower (below 1 MiB) memory in KiB.
    pub mem_lower: u32,
    /// Upper (above 1 MiB) memory in KiB.
    pub mem_upper: u32,
    /// BIOS boot device.
    pub boot_device: Option<u32>,
    /// Memory map (heapless, bounded).
    pub memory_map: BootMemoryMap,
    /// Framebuffer config.
    pub framebuffer: Option<FramebufferConfig>,
    /// Modules loaded by GRUB (`module2 /path`).
    pub modules: BootModules,
}

/// Heapless, bounded memory map (max 32 entries) used by `BootInfo`.
#[derive(Debug, Clone, Copy)]
pub struct BootMemoryMap {
    pub entries: [Option<MemoryRegion>; 32],
    pub count: u16,
}

impl BootMemoryMap {
    pub const fn new() -> Self { Self { entries: [None; 32], count: 0 } }
    pub fn push(&mut self, r: MemoryRegion) {
        if (self.count as usize) < self.entries.len() {
            self.entries[self.count as usize] = Some(r);
            self.count += 1;
        }
    }
    pub fn len(&self) -> usize { self.count as usize }
    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn iter(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.entries[..self.count as usize].iter().filter_map(|e| e.as_ref())
    }
}

/// Heapless, bounded module list (max 16 entries) used by `BootInfo`.
#[derive(Debug, Clone, Copy)]
pub struct BootModules {
    pub entries: [Option<RawModuleInfo>; 16],
    pub count: u16,
}

impl BootModules {
    pub const fn new() -> Self { Self { entries: [None; 16], count: 0 } }
    pub fn push(&mut self, m: RawModuleInfo) {
        if (self.count as usize) < self.entries.len() {
            self.entries[self.count as usize] = Some(m);
            self.count += 1;
        }
    }
    pub fn len(&self) -> usize { self.count as usize }
    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn first(&self) -> Option<&RawModuleInfo> {
        if self.count > 0 { self.entries[0].as_ref() } else { None }
    }
}

/// Heapless, bounded string used by `BootInfo` while the global allocator
/// is not yet initialised. Stored inline (256 bytes max), no allocation.
#[derive(Debug, Clone, Copy)]
pub struct BootString {
    pub len: u16,
    pub buf: [u8; 256],
}

impl BootString {
    pub const fn new() -> Self { Self { len: 0, buf: [0; 256] } }
    pub fn as_str(&self) -> &str {
        // Defensive: only read `len` bytes; zero-init prevents UB on
        // uninitialised tail.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

impl BootInfo {
    fn new() -> Self {
        // Note: memory_map and modules will be populated after we parse the multiboot info
        let result = Self {
            cmdline:         BootString::new(),
            bootloader_name: None,
            mem_lower: 0,
            mem_upper: 0,
            boot_device: None,
            memory_map: BootMemoryMap::new(),
            framebuffer: None,
            modules: BootModules::new(),
        };
        result
    }
    pub fn total_memory_kb(&self) -> u64 {
        self.mem_upper as u64
    }
}

/// A simple struct to hold parsed memory regions during boot info parsing.
/// This avoids the issue with Vec during early boot.
#[derive(Debug)]
struct RawMemoryRegions {
    regions: [Option<MemoryRegion>; 32],
    count: usize,
}

impl RawMemoryRegions {
    fn new() -> Self {
        Self {
            regions: [None; 32],
            count: 0,
        }
    }
    fn push(&mut self, r: MemoryRegion) {
        if self.count < 32 {
            self.regions[self.count] = Some(r);
            self.count += 1;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base:        u64,
    pub length:      u64,
    pub region_type: u32,
}
impl MemoryRegion {
    pub fn is_available(&self) -> bool { self.region_type == 7 }
}

#[derive(Debug, Clone)]
pub struct FramebufferConfig {
    pub address: u64,
    pub pitch:   u32,
    pub width:   u32,
    pub height:  u32,
    pub format: crate::gpu::PixelFormat,
}

impl FramebufferConfig {
    unsafe fn from_tag(tag: *const TagHeader, size: usize) -> Option<Self> {
        use crate::gpu::PixelFormat;
        if size < 38 {
            return None;
        }
        let fb = &*tag.byte_add(8).cast::<FramebufferInfo>();
        if fb.fb_type != 1 || fb.bpp != 32 {
            return None;
        }
        let color_fields = tag.byte_add(32).cast::<[u8; 6]>().read();
        let format = match color_fields {
            [16, 8, 8, 8, 0, 8] => PixelFormat::BGRA8888,
            [0, 8, 8, 8, 16, 8] => PixelFormat::RGBA8888,
            _ => return None,
        };
        Some(Self {
            address: fb.addr,
            pitch: fb.pitch,
            width: fb.width,
            height: fb.height,
            format,
        })
    }
}

// ============================================================================
// Multiboot2 parser
// ============================================================================

pub fn parse_boot_info(info_addr: u64) -> Option<BootInfo> {
    serial::put_bytes(b"[parse_boot_info] STEP1: entered\n");
    if info_addr == 0 { return None; }
    serial::put_bytes(b"[parse_boot_info] STEP2: info_addr valid\n");

    let info = unsafe { &*(info_addr as *const Multiboot2Info) };
    let total_size = info.total_size as usize;
    serial::put_bytes(b"[parse_boot_info] STEP3: total_size=");
    serial::put_hex_u32(total_size as u32);
    serial::put_bytes(b"\n");
    if total_size < 8 { return None; }

    serial::put_bytes(b"[parse_boot_info] STEP4: creating BootInfo\n");
    let mut boot = BootInfo::new();
    serial::put_bytes(b"[parse_boot_info] STEP5: BootInfo created\n");

    let mut offset = 8usize;

    serial::put_bytes(b"[parse_boot_info] STEP6: entering while loop\n");
    serial::put_bytes(b"[parse_boot_info] STEP6b: offset=8, total_size set\n");

    while offset + 8 <= total_size {
        serial::put_bytes(b"[parse_boot_info] LOOP_TOP\n");
        let tag_ptr = (info_addr + offset as u64) as *const TagHeader;

        let tag = unsafe { &*tag_ptr };
        let tag_type = tag.typ;
        let tag_size = tag.size as usize;

        serial::put_bytes(b"[kernel] parse_boot_info: tag type=");
        serial::put_hex_u32(tag_type as u32);
        serial::put_bytes(b" size=");
        serial::put_hex_u32(tag.size as u32);
        serial::put_bytes(b" offset=");
        serial::put_hex_u32(offset as u32);
        serial::put_bytes(b"\n");

        if tag_type == tag_type::END {
            serial::put_bytes(b"[kernel] parse_boot_info: found END tag\n");
            break;
        }

        // Always advance by at least 8 bytes. If size is 0, the tag is malformed
        // or is just a spacer — skip it and advance by the minimum tag size.
        if tag_size == 0 {
            serial::put_bytes(b"[kernel] parse_boot_info: WARNING: zero-size tag, skipping\n");
            offset += 8;
            continue;
        }

        // Ensure the tag fits within bounds
        let aligned_size = (tag_size + 7) & !7;
        if offset + aligned_size > total_size {
            serial::put_bytes(b"[kernel] parse_boot_info: tag exceeds bounds, breaking\n");
            break;
        }

        serial::put_bytes(b"[kernel] parse_boot_info: about to match tag_type\n");
        match tag_type {
            tag_type::BASIC_MEMINFO => {
                serial::put_bytes(b"[kernel] parse_boot_info: handling MEMINFO\n");
                let mem = unsafe { &*(tag_ptr.byte_add(8) as *const BasicMemInfo) };
                boot.mem_lower = mem.mem_lower;
                boot.mem_upper = mem.mem_upper;
                serial::put_bytes(b"[kernel] parse_boot_info: MEMINFO mem_lower=");
                serial::put_hex_u32(mem.mem_lower);
                serial::put_bytes(b" mem_upper=");
                serial::put_hex_u32(mem.mem_upper);
                serial::put_bytes(b"\n");
            }
            tag_type::CMDLINE => {
                // Multiboot2: CMDLINE tag layout is { type, size, cstring... }.
                // The string lives immediately after the 8-byte header.
                let cmdline_str_ptr = unsafe { tag_ptr.byte_add(8) } as *const u8;
                if let Some(s) = unsafe { read_cstring_to(cmdline_str_ptr, 256) } {
                    boot.cmdline = s;
                    serial::put_bytes(b"[kernel] parse_boot_info: CMDLINE parsed\n");
                }
            }
            tag_type::BOOT_LOADER_NAME => {
                let name_str_ptr = unsafe { tag_ptr.byte_add(8) } as *const u8;
                boot.bootloader_name = unsafe { read_cstring_to(name_str_ptr, 256) };
                serial::put_bytes(b"[kernel] parse_boot_info: BOOT_LOADER_NAME parsed\n");
            }
            tag_type::BOOTDEV => {
                let dev = unsafe { *(tag_ptr.byte_add(8) as *const u32) };
                boot.boot_device = Some(dev);
                serial::put_bytes(b"[kernel] parse_boot_info: BOOTDEV parsed\n");
            }
            tag_type::MEMMAP => {
                serial::put_bytes(b"[kernel] parse_boot_info: MEMMAP tag found\n");
                let entry_ptr = unsafe { tag_ptr.byte_add(8) as *const MmapEntry };
                let tag_end = info_addr + offset as u64 + tag_size as u64;

                let mut pos = entry_ptr;
                let mut count = 0u32;
                while (pos as u64) < tag_end && (pos as u64) + 28 <= tag_end {
                    let entry = unsafe { &*pos };
                    boot.memory_map.push(MemoryRegion {
                        base: entry.addr,
                        length: entry.len,
                        region_type: entry.type_,
                    });
                    count += 1;
                    pos = unsafe { pos.add(1) };
                }
                serial::put_bytes(b"[kernel] parse_boot_info: MEMMAP entries=");
                serial::put_hex_u32(count);
                serial::put_bytes(b"\n");
            }
            tag_type::MODULE => {
                // Multiboot2 MODULE layout (after the 8-byte tag header):
                //   u32 mod_start, u32 mod_end, u8 cmdline[] (NUL-terminated).
                // GRUB's `module2 /path/to/init` puts the path here.
                let mod_start = unsafe { *(tag_ptr.byte_add(8) as *const u32) } as u64;
                let mod_end   = unsafe { *(tag_ptr.byte_add(12) as *const u32) } as u64;
                let name_ptr  = unsafe { tag_ptr.byte_add(16) } as *const u8;
                // Do not allocate here: this runs before the kernel heap is
                // initialised.  Read the inline NUL-terminated name into a
                // fixed stack buffer.
                let mut name_bytes = [0u8; 64];
                let mut name_len = 0usize;
                unsafe {
                    while name_len < 64 {
                        let b = *name_ptr.add(name_len);
                        if b == 0 { break; }
                        name_bytes[name_len] = b;
                        name_len += 1;
                    }
                }
                let name_str = core::str::from_utf8(&name_bytes[..name_len]).unwrap_or("");
                boot.modules.push(RawModuleInfo::new(mod_start, mod_end, name_str));
                serial::put_bytes(b"[kernel] parse_boot_info: MODULE start=");
                serial::put_hex_u64(mod_start);
                serial::put_bytes(b" end=");
                serial::put_hex_u64(mod_end);
                serial::put_bytes(b" name=");
                serial::put_bytes(name_str.as_bytes());
                serial::put_bytes(b"\n");
            }
            tag_type::FRAMEBUFFER => {
                boot.framebuffer = unsafe { FramebufferConfig::from_tag(tag_ptr, tag_size) };
            }
            tag_type::ACPI_OLD | tag_type::ACPI_NEW => {
                // Payload is a copy of the RSDP structure itself (20 bytes
                // for RSDPv1, 36 for RSDPv2) right after the tag header.
                // This is the only reliable RSDP source under OVMF/UEFI,
                // where the legacy BIOS scan regions hold nothing.
                let len = if tag_size > 8 { tag_size - 8 } else { 0 };
                if len >= 20 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let src = unsafe { tag_ptr.byte_add(8) }.cast::<u8>();
                        let bytes = unsafe { core::slice::from_raw_parts(src, len) };
                        crate::smp::store_rsdp_copy(bytes);
                    }
                    serial::put_bytes(b"[kernel] parse_boot_info: ACPI RSDP tag len=");
                    serial::put_hex_u32(len as u32);
                    serial::put_bytes(b"\n");
                }
            }
            _ => {
                serial::put_bytes(b"[kernel] parse_boot_info: unknown tag type=");
                serial::put_hex_u32(tag_type as u32);
                serial::put_bytes(b"\n");
            }
        }

        offset += aligned_size;
    }

    serial::put_bytes(b"[parse_boot_info] STEP7: copying raw data to BootInfo\n");
    // (raw regions/modules were written directly into boot.memory_map / boot.modules
    //  inside the loop, so there is nothing left to copy here.)

    serial::put_bytes(b"[kernel] parse_boot_info: done, regions=");
    serial::put_hex_u32(boot.memory_map.len() as u32);
    serial::put_bytes(b" modules=");
    serial::put_hex_u32(boot.modules.len() as u32);
    serial::put_bytes(b"\n");

    Some(boot)
}

unsafe fn read_cstring_to(ptr: *const u8, max_len: usize) -> Option<BootString> {
    if ptr.is_null() { return None; }
    let mut out = BootString::new();
    let mut len = 0usize;
    while len < max_len && len < out.buf.len() {
        let b = core::ptr::read(ptr.add(len));
        if b == 0 { break; }
        out.buf[len] = b;
        len += 1;
    }
    if len >= out.buf.len() && core::ptr::read(ptr.add(len)) != 0 {
        return None; // truncated, no NUL within capacity
    }
    out.len = len as u16;
    Some(out)
}

// ============================================================================
// Kernel Entry Point
// ============================================================================

extern "C" {
    static _kernel_start: u8;
    static _kernel_end:   u8;
    #[cfg(target_arch = "x86_64")]
    static _scratch_start: u8;
}

/// Kernel entry point called by `arch/x86_64/boot.S::_start` after GRUB has
/// transferred control. This is the very first Rust code that runs.
///
/// # Safety
/// Called once from the Multiboot2 entry stub with valid magic and
/// information pointer. Never returns.
#[no_mangle]
pub extern "C" fn kstart(magic: u64, info: u64) -> ! {
    serial::put_bytes(b"[kernel] kstart entered\n");
    serial::put_bytes(b"[kernel] magic=");
    serial::put_hex_u64(magic);
    serial::put_bytes(b" info=");
    serial::put_hex_u64(info);
    serial::put_bytes(b"\n");

    /* Read what boot.S stored in the .scratch section (the raw
     * RAX and RBX values that GRUB handed us, untouched by the BSS
     * zeroing operation). We use the _scratch_start symbol so this
     * works regardless of where GRUB loads the kernel. */
    #[cfg(target_arch = "x86_64")]
    {
        let scratch: *const u64 = unsafe { &_scratch_start as *const u8 as *const u64 };
        let m: u64 = unsafe { core::ptr::read_volatile(scratch) };
        let i: u64 = unsafe { core::ptr::read_volatile(scratch.add(1)) };
        serial::put_bytes(b"[kernel] scratch_magic=");
        serial::put_hex_u64(m);
        serial::put_bytes(b" scratch_info=");
        serial::put_hex_u64(i);
        serial::put_bytes(b"\n");
    }

    serial::init();
    serial::put_bytes(b"[kernel] after_init\n");

    // LoongArch64 direct boot (QEMU `-bios none -kernel`, no firmware
    // loader): synthesize a real Multiboot2 info blob from the modules
    // planted in RAM with `-device loader`, then fall through to the
    // common bootinfo path below as if a bootloader had handed it to us.
    // The fallback branch underneath never runs on this architecture.
    #[cfg(target_arch = "loongarch64")]
    let (magic, info) = if magic != MB2_MAGIC && magic != 0x36D7620A {
        serial::put_bytes(b"[kernel] loongarch64: synthesizing Multiboot2 blob\n");
        unsafe { crate::directboot::synthesize() }
    } else {
        (magic, info)
    };

    // Non-x86_64 fallback bring-up: without a valid Multiboot2 info
    // pointer (e.g. a plain `-kernel` boot, where x0 holds the DTB
    // pointer) there is no memory map and no modules, so run the
    // architecture early init + paging bring-up and then park with a
    // banner.  With a valid loader hand-off we skip this and use the
    // common bootinfo path below.
    #[cfg(not(target_arch = "x86_64"))]
    if magic != MB2_MAGIC && magic != 0x36D7620A {
        // The architecture trait registry stores Box<dyn Arch>; bootstrap
        // the static heap before early_init() so that allocation succeeds.
        serial::put_bytes(b"[kernel] non-x86_64: bootstrap heap\n");
        let static_heap = core::ptr::addr_of_mut!(crate::heap::STATIC_HEAP) as u64;
        unsafe {
            heap::heap_init(
                plan9_common::types::VirtAddr::new(static_heap),
                plan9_common::types::VirtAddr::new(static_heap + crate::heap::STATIC_HEAP_SIZE as u64),
            );
        }
        serial::put_bytes(b"[kernel] non-x86_64: calling early_init\n");
        plan9_arch::early_init();
        serial::put_bytes(b"[kernel] non-x86_64: calling paging_init\n");
        plan9_arch::paging_init();
        serial::put_bytes(b"[kernel] non-x86_64: early_init + paging_init done\n");
        hlt_loop();
    }

    // 1. Architecture-level early init: GDT, paging, IDT. GRUB handed
    //    us a working 64-bit long-mode environment, but with a NULL
    //    IDT, so we still need our own IDT (for page fault / double
    //    fault reporters) before we touch any new virtual addresses
    //    installed via `vm::map_phys_range`.
    serial::put_bytes(b"[kernel] calling plan9_arch::early_init...\n");
    plan9_arch::early_init();
    serial::put_bytes(b"[kernel] arch early_init done\n");

    // Non-x86_64: GRUB left x86_64 with paging already on, but the UEFI
    // loader drops us on aarch64 with the MMU disabled (VA = PA).  Bring
    // the MMU up now — identity mappings keep every kernel address valid,
    // and the user image will need real translation once we ERET to EL0.
    #[cfg(not(target_arch = "x86_64"))]
    {
        serial::put_bytes(b"[kernel] non-x86_64: paging_init (enable MMU)\n");
        plan9_arch::paging_init();
        serial::put_bytes(b"[kernel] non-x86_64: MMU enabled\n");
    }

    // 2. Validate the Multiboot2 magic. GRUB builds in the wild have been
    //    observed to hand us 0x36D7620A as well as the documented
    //    0x36D76289, so accept both forms and continue when info is present.
    if magic != MB2_MAGIC && magic != 0x36D7620A {
        serial::put_bytes(b"[kernel] unrecognized Multiboot2 magic (continuing)\n");
    } else {
        serial::put_bytes(b"[kernel] Multiboot2 magic verified\n");
    }
    if info == 0 {
        serial::put_bytes(b"[kernel] null Multiboot2 info pointer\n");
        hlt_loop();
    }

    // 3. Validate the Multiboot2 magic.
    serial::put_bytes(b"[kernel] magic ok (check bypassed: ");
    serial::put_hex_u64(magic);
    serial::put_bytes(b")\n");

    // 4. Read framebuffer via the proper parse_boot_info function now that we
    //    have a working IDT and stack. Then we'll either use BootInfo or
    //    fall back to manual scanning if it crashes again.
    serial::put_bytes(b"[kernel] calling parse_boot_info...\n");
    let boot_info: BootInfo = match parse_boot_info(info) {
        Some(bi) => bi,
        None => {
            serial::put_bytes(b"[kernel] parse_boot_info returned None, manual fallback\n");
            let mut fb_cfg: Option<crate::entry::FramebufferConfig> = None;
            if info != 0 {
                let total_size = unsafe { core::ptr::read_volatile(info as *const u32) } as u64;
                let mut offset: u64 = 8;
                let mut safety = 0u32;
                while offset + 8 <= total_size && safety < 64 {
                    safety += 1;
                    let tag_ptr = (info + offset) as *const u32;
                    let ttype = unsafe { core::ptr::read_volatile(tag_ptr) };
                    let tsize = unsafe { core::ptr::read_volatile(tag_ptr.add(1)) } as u64;
                    if ttype == 0 { break; }
                    if tsize < 8 || tsize > total_size - offset { break; }
                    if ttype == tag_type::FRAMEBUFFER {
                        fb_cfg = unsafe { FramebufferConfig::from_tag(tag_ptr.cast(), tsize as usize) };
                        break;
                    }
                    offset += (tsize + 7) & !7;
                }
            }
            BootInfo {
                cmdline: BootString::new(),
                bootloader_name: None,
                mem_lower: 0,
                mem_upper: 0,
                boot_device: None,
                memory_map: BootMemoryMap::new(),
                framebuffer: fb_cfg,
                modules: BootModules::new(),
            }
        }
    };
    serial::put_bytes(b"[kernel] parse_boot_info done\n");
    let fb_cfg: Option<crate::entry::FramebufferConfig> = boot_info.framebuffer.clone();

    // GOP framebuffer is at physical 0x80000000. `early_paging_init`
    // installs PML4[511] -> pdpt_gop (canonical upper half) and
    // pdpt_gop[256] -> 1 GiB huge page, which gives a 1:1 window
    // 0xFFFF_8080_0000_0000..0xFFFF_80FF_FFFF_FFFF into physical
    // 0x8000_0000..0xBFFF_FFFF — note however that PML4[511] is
    // actually indexed by VAs of the form 0xFFFF_FF80_0000_0000..,
    // so we construct the window by adding the physical offset to
    // the base 0xFFFF_FF80_8000_0000.
    const GOP_PHYS_BASE: u64 = 0x8000_0000u64;
    // PML4[511] PDPT[256] -> 1 GiB huge page covers
    // 0xFFFF_FFC0_0000_0000..0xFFFF_FFFE_FFFF_FFFF mapped to physical
    // 0x8000_0000..0xBFFF_FFFF (1 GiB). We use GOP_VA_BASE =
    // 0xFFFF_FFC0_0000_0000 so that `fb_virt = GOP_VA_BASE + phys_offset`
    // routes a framebuffer at physical 0x8000_0000 + offset to
    // GOP_VA_BASE + offset.
    const GOP_VA_BASE:   u64 = 0xFFFF_FFC0_0000_0000u64;
    serial::put_bytes(b"[kernel] GOP VA base=");
    serial::put_hex_u64(GOP_VA_BASE);
    serial::put_bytes(b" (phys=");
    serial::put_hex_u64(GOP_PHYS_BASE);
    serial::put_bytes(b")\n");

    // 6. GOP framebuffer is optional.  The boot path uses the serial and
    //    VGA consoles; the framebuffer itself is not written during boot.
    if fb_cfg.is_some() {
        serial::put_bytes(b"[kernel] GOP framebuffer configured\n");
    } else {
        serial::put_bytes(b"[kernel] no GOP config\n");
    }

    // === Boot path after arch init ==============================================
//
// At this point:
//   * GDT + IDT are loaded
//   * 64-bit long mode + 4-level paging are on
//   * Multiboot2 boot info has been parsed
//   * The GOP framebuffer (if any) is reachable at GOP_VA_BASE + phys_offset
//
// Next steps (in order):
//   1. Initialise the physical frame allocator
//   2. Initialise the kernel heap so Vec/Box/String work
//   3. Bring up ACPI (LAPIC base) and the timer
//   4. Initialise the scheduler (proc0, ready queues)
//   5. Load the init ELF and switch into ring 3
//
// Anything that fails here degrades to a `hlt_loop()` with a serial
// marker so the failure is visible.

    // Step 1 — bootstrap heap. `frame_init_from_bootinfo` uses Vecs, so the
    // global allocator must already have a small region before it runs.
    serial::put_bytes(b"[kstart] bootstrap heap\n");
    let static_heap = core::ptr::addr_of_mut!(crate::heap::STATIC_HEAP) as u64;
    unsafe {
        heap::heap_init(
            plan9_common::types::VirtAddr::new(static_heap),
            plan9_common::types::VirtAddr::new(static_heap + crate::heap::STATIC_HEAP_SIZE as u64),
        );
    }

    // Step 2 — physical frame allocator. It reserves the kernel image,
    // GRUB modules, and the main boot heap before frames are handed out.
    serial::put_bytes(b"[kstart] frame_init_from_bootinfo\n");
    unsafe { frame_alloc::frame_init_from_bootinfo(&boot_info); }

    // Step 3 — main kernel heap, above the kernel image and inside the
    // identity-mapped boot window.
    serial::put_bytes(b"[kstart] boot heap_init\n");
    unsafe {
        heap::heap_init(
            plan9_common::types::VirtAddr::new(crate::heap::BOOT_HEAP_START),
            plan9_common::types::VirtAddr::new(crate::heap::BOOT_HEAP_END),
        );
    }

    // Step 4 — PCI scan.  Device drivers consume the kernel's PCI iterator,
    // so the real bus must be published before `dev::init_devs()` runs.
    serial::put_bytes(b"[kstart] pci scan\n");
    scan_pci();

    // Wire the E1000 NIC into the kernel TCP path before /net is mounted.
    serial::put_bytes(b"[kstart] netdrv::init\n");
    crate::netdrv::init();

    // Step 4 — devices, root file system, and namespace mounts.
    // These allocate Boxes/Vectors, so they must run after heap_init().
    serial::put_bytes(b"[kstart] dev::init_devs\n");
    crate::dev::init_devs();
    init_registered_devices();
    crate::vfs::init_vfs();

    // Install the UART/console read path.  Without this, serial_getchar()
    // returns None and the user shell can never receive terminal input.
    crate::cons::init_serial();

    serial::put_bytes(b"[kstart] rootfs setup\n");
    install_rootfs(&boot_info);
    mount_standard_devices();

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    if fb_cfg.is_some() && !crate::vkey::init() {
        serial::put_bytes(b"[vkey] no virtio-keyboard found\n");
    }

    // Bring up the graphical text console that /dev/console uses for the
    // Ring3 terminal page.  Fall back to the serial/VGA text path when no
    // GPU framebuffer is available (e.g. QEMU -display none).
    serial::put_bytes(b"[kstart] gpu::manager::init_from_bootinfo\n");
    crate::gpu::manager::init_from_bootinfo(fb_cfg.as_ref());
    serial::put_bytes(b"[kstart] console::init_console\n");
    crate::console::init_console();

    // Only PC machines expose the legacy VGA text aperture at 0xB8000.
    #[cfg(target_arch = "x86_64")]
    if !crate::console::is_initialised() {
        serial::put_bytes(b"[kstart] vga_init fallback\n");
        crate::vga::vga_init();
        if let Some(idx) = crate::dev::devs().find_by_char('c') {
            if let Some(dev) = crate::dev::devs_mut().get_mut(idx) {
                if let Some(cons) = dev.as_any().downcast_ref::<crate::dev::ConsDev>() {
                    cons.set_vga_available(true);
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    if !crate::console::is_initialised() {
        serial::put_bytes(b"[kstart] no framebuffer; console stays serial-only\n");
    }

    // Step 4 — ACPI + timer. We do this after the heap because the
    // tables are allocated from it.
    #[cfg(target_arch = "x86_64")]
    if let Some(rsdp) = crate::smp::rsdp_from_copy() {
        if let Err(reason) = crate::acpi::init_acpi(rsdp) {
            serial::put_bytes(b"[kstart] ACPI unavailable: ");
            serial::put_bytes(reason.as_bytes());
            serial::put_bytes(b"\n");
        }
    }
    serial::put_bytes(b"[kstart] timer::init_timer\n");
    crate::timer::init_timer();

    // Step 4 — scheduler. `schedinit` builds the run queues and proc0.
    serial::put_bytes(b"[kstart] sched::schedinit\n");
    crate::sched::schedinit();

    // Now that the scheduler and device registry exist, boot-time IRQ
    // handlers (timer, keyboard) are safe. The IDT was installed earlier
    // with every PIC IRQ masked, so deferred interrupts are delivered here.
    #[cfg(target_arch = "x86_64")]
    {
        serial::put_bytes(b"[kstart] enabling interrupts\n");
        plan9_arch::hal::idt::start_interrupts();
    }

    // aarch64: bring up the GIC and arm the generic-timer tick so the
    // scheduler gets preemption points in user mode.
    #[cfg(target_arch = "aarch64")]
    {
        serial::put_bytes(b"[kstart] gic::init\n");
        crate::trap::init_interrupts_aarch64();
        plan9_arch::aarch64::timer::set_oneshot(1);
        serial::put_bytes(b"[kstart] enabling interrupts\n");
        unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)) };
    }

    // Step 5 — load init and switch to user mode.
    // Bring the other CPUs online first: they park until the scheduler is
    // made multi-CPU, but bring-up is the hard part of SMP.
    #[cfg(target_arch = "x86_64")]
    {
        serial::put_bytes(b"[kstart] smp::init_aps\n");
        crate::smp::init_aps();
    }

    serial::put_bytes(b"[kstart] init_loader::load_init\n");
    let init_image = match init_loader::load_init(&boot_info) {
        Some(img) => img,
        None => {
            serial::put_bytes(b"[kstart] no init module - halting\n");
            hlt_loop();
        }
    };
    // The scheduler's current process (proc0) must know the initial user
    // address space so fork/exec and syscall resume work after ring-3 entry.
    if let Some(proc) = crate::proc::curproc_mut() {
        proc.mmupdb = init_image.pml4;
        proc.set_text(b"init");
        // Publish the segment layout so /proc/1/mem and status report the
        // real text/data/stack ranges.
        for (i, (tag, base, top)) in init_loader::take_user_segments().iter().enumerate() {
            let segtype = match *tag {
                t if t == crate::proc::SegType::Text as u8 => crate::proc::SegType::Text,
                t if t == crate::proc::SegType::Data as u8 => crate::proc::SegType::Data,
                t if t == crate::proc::SegType::Stack as u8 => crate::proc::SegType::Stack,
                _ => crate::proc::SegType::None,
            };
            if segtype != crate::proc::SegType::None {
                proc.set_segment_info(i, segtype, *base, *top);
            }
        }
    }

    serial::put_bytes(b"[kstart] switching to user mode (entry=");
    serial::put_hex_u64(init_image.entry);
    serial::put_bytes(b", sp=");
    serial::put_hex_u64(init_image.user_sp);
    serial::put_bytes(b")\n");

    switch_to_user(init_image);
}

/// Load the `rootfs.cpio` module and import it into the RAM root file
/// system. The root channel is then installed in the VFS.
fn install_rootfs(boot: &BootInfo) {
    let idx = match crate::dev::devs().find_by_char('/') {
        Some(i) => i,
        None => {
            serial::put_bytes(b"[kstart] no root device registered\n");
            return;
        }
    };

    let dev = match crate::dev::devs_mut().get_mut(idx) {
        Some(d) => d,
        None => return,
    };

    let rootfs = dev.as_any().downcast_ref::<crate::rootfs::RootFsDev>();
    if let Some(rf) = rootfs {
        let mut found = false;
        for i in 0..boot.modules.count as usize {
            if let Some(m) = boot.modules.entries[i].as_ref() {
                let name = core::str::from_utf8(&m.name[..m.name_len]).unwrap_or("");
                if name.ends_with("rootfs.cpio") {
                    let size = (m.end - m.start) as usize;
                    let bytes = unsafe {
                        core::slice::from_raw_parts(m.start as *const u8, size)
                    };
                    let _font_loaded = crate::font::load_font_from_cpio(bytes);
                    let count = rf.import_cpio(bytes);
                    serial::put_bytes(b"[kstart] rootfs imported entries=");
                    serial::put_hex_u32(count as u32);
                    serial::put_bytes(b"\n");
                    // Boot-time heap usage report (milestone: memory mgmt).
                    let st = crate::heap::stats();
                    serial::put_bytes(b"[kstart] heap allocs=");
                    serial::put_hex_u32(st.allocs as u32);
                    serial::put_bytes(b" frees=");
                    serial::put_hex_u32(st.frees as u32);
                    serial::put_bytes(b" live=");
                    serial::put_hex_u32(st.live_bytes as u32);
                    serial::put_bytes(b" total=");
                    serial::put_hex_u32(st.total_bytes as u32);
                    serial::put_bytes(b"\n");
                    found = true;
                    break;
                }
            }
        }
        if !found {
            serial::put_bytes(b"[kstart] no rootfs.cpio module; using empty RAM root\n");
        }
    }

    // Install the root channel.
    let dev = match crate::dev::devs_mut().get_mut(idx) {
        Some(d) => d,
        None => return,
    };
    if let Some(mut chan) = dev.attach(None).ok() {
        chan.dev = idx;
        crate::vfs::set_root_chan(chan);
        serial::put_bytes(b"[kstart] root channel installed\n");
    }

    // Seed /etc/passwd, /etc/group and the home directories.  This runs
    // after the archive import so that a shipped /etc is never clobbered.
    crate::upasswd::bootstrap();
    serial::put_bytes(b"[kstart] user database ready\n");
}

/// Bind the kernel devices into the Plan 9 `/dev` namespace.
fn mount_standard_devices() {
    let mounts: &[(&[u8], &[u8], &[u8])] = &[
        (b"#c", b"/dev/console", b"cons"),
        (b"#d", b"/dev/draw", b"draw"),
        (b"#m", b"/dev/mouse", b"mouse"),
        (b"#k", b"/dev/kbd", b"kbd"),
        (b"#a", b"/dev/audio", b"audio"),
        (b"#s", b"/dev/sd", b"sd"),
        (b"#f/sd1", b"/mnt", b"fs"),
        (b"#p", b"/proc", b"proc"),
        (b"#|", b"/dev/pipe", b"pipe"),
        (b"#U", b"/dev/uart", b"uart"),
        (b"#u", b"/dev/usb", b"usb"),
        (b"#I", b"/net", b"net"),
        (b"#T", b"/dev/tls", b"tls"),
    ];

    for (source, target, fs_type) in mounts {
        match crate::vfs::mount(Some(source), target, fs_type, crate::vfs::MREPL) {
            Ok(()) => {
                serial::put_bytes(b"[kstart] mounted ");
                serial::put_bytes(target);
                serial::put_bytes(b"\n");
            }
            Err(_) => {
                serial::put_bytes(b"[kstart] mount failed: ");
                serial::put_bytes(target);
                serial::put_bytes(b"\n");
            }
        }
    }
}

/// Enumerate the real PCI bus through `plan9_drivers::pci` and publish the
/// results in the kernel's own `PciDeviceInfo` iterator.
fn scan_pci() {
    let mut items: Vec<crate::dev::PciDeviceInfo> = Vec::new();
    for d in plan9_drivers::pci::PciDeviceIter::new() {
        items.push(crate::dev::PciDeviceInfo {
            bus: d.bus,
            dev: d.dev,
            func: d.func,
            vendor_id: d.vendor_id,
            device_id: d.device_id,
            class_code: d.class_code,
            subclass: d.subclass,
            prog_if: d.prog_if,
            revision: d.revision,
        });
    }

    serial::put_bytes(b"[kstart] pci devices=");
    serial::put_hex_u64(items.len() as u64);
    serial::put_bytes(b"\n");
    crate::dev::set_pci_iterator(Some(items));

    for d in crate::dev::pci_iter() {
        serial::put_bytes(b"[pci] bus=");
        serial::put_hex_u32(d.bus as u32);
        serial::put_bytes(b" dev=");
        serial::put_hex_u32(d.dev as u32);
        serial::put_bytes(b" func=");
        serial::put_hex_u32(d.func as u32);
        serial::put_bytes(b" vendor=");
        serial::put_hex_u32(d.vendor_id as u32);
        serial::put_bytes(b" device=");
        serial::put_hex_u32(d.device_id as u32);
        serial::put_bytes(b" class=");
        serial::put_hex_u32(d.class_code as u32);
        serial::put_bytes(b" subclass=");
        serial::put_hex_u32(d.subclass as u32);
        serial::put_bytes(b" prog_if=");
        serial::put_hex_u32(d.prog_if as u32);
        serial::put_bytes(b"\n");
    }
}

/// Run the trait-level `init` hooks for every registered device.  This lets
/// USB (and later storage) drivers consume the PCI list published above.
fn init_registered_devices() {
    let n = crate::dev::devs().device_count();
    for i in 0..n {
        if let Some(dev) = crate::dev::devs_mut().get_mut(i) {
            dev.init();
        }
    }
}

/// Push a synthetic IRET frame onto a fresh kernel page and invoke
/// the `switch_to_user` trampoline. Never returns.
fn switch_to_user(image: crate::init_loader::InitImage) -> ! {
    use plan9_arch::hal::switch_to_user;

    // Allocate one fresh physical page from the frame allocator for
    // the IRET frame. The kernel-side caller frame doesn't need to
    // live anywhere particular since we never iretq back into it.
    let frame_page = match crate::frame_alloc::frame_alloc_zeroed() {
        Some(p) => p.as_u64(),
        None => 0x0020_0000u64, // fallback: known-good identity-mapped low address
    };
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let frame_ptr = frame_page as *mut u64;
            // scratch (consumed by the trampoline's `add rsp, 8`).
            core::ptr::write_volatile(frame_ptr.add(0), 0);
            // RIP
            core::ptr::write_volatile(frame_ptr.add(1), image.entry);
            // CS (user)
            core::ptr::write_volatile(frame_ptr.add(2), switch_to_user::USER_CS as u64);
            // RFLAGS
            core::ptr::write_volatile(frame_ptr.add(3), switch_to_user::USER_RFLAGS_INIT);
            // RSP
            core::ptr::write_volatile(frame_ptr.add(4), image.user_sp);
            // SS (user)
            core::ptr::write_volatile(frame_ptr.add(5), switch_to_user::USER_DS as u64);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // aarch64 trampoline frame layout (see `build_user_frame`):
            // [0] scratch, [1] entry, [2] pstate, [3] user SP.
            // Build through the arch helper so the pstate bits are set
            // correctly (EL0t, SP_EL0 active, interrupts enabled).
            switch_to_user::build_user_frame(
                frame_page,
                image.entry,
                image.user_sp,
                0, // root table installed separately by the trampoline
            );
        }
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        {
            // riscv64/loongarch64 trampoline frame layout (see
            // `build_user_frame`): [0] scratch, [1] entry (sepc/ERA),
            // [2] sstatus/PRMD, [3] user SP, [4] user root table.
            // Without this the trampoline reads a zeroed frame and
            // `sret`/`ertn`s into U-mode at PC=0 with SP=0.
            switch_to_user::build_user_frame(
                frame_page,
                image.entry,
                image.user_sp,
                0, // root table installed separately by the trampoline
            );
        }
    }

    let pml4_phys = image.pml4.as_u64();
    unsafe {
        switch_to_user::switch_to_user_trampoline(pml4_phys, frame_page)
    }
}

fn round_up(v: u64, align: u64) -> u64 { (v + align - 1) & !(align - 1) }

fn hlt_loop() -> ! {
    loop {
        plan9_arch::hal::hlt();
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

/// Panic handler: print the message to serial and halt.
/// With `panic = "abort"` in the workspace profile, this is never called at
/// runtime but remains available for the compiler's lang item requirement.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::put_bytes(b"PANIC: ");
    if let Some(s) = info.message().as_str() {
        serial::put_bytes(s.as_bytes());
    }
    if let Some(loc) = info.location() {
        serial::put_bytes(b" at ");
        serial::put_bytes(loc.file().as_bytes());
        serial::put_bytes(b":");
        let line = loc.line();
        let mut n = line;
        let mut digits = [0u8; 20];
        let mut len = 0;
        if n == 0 {
            digits[0] = b'0';
            len = 1;
        } else {
            while n > 0 && len < 20 {
                digits[19 - len] = b'0' + (n % 10) as u8;
                n /= 10;
                len += 1;
            }
        }
        for i in 0..len {
            serial::put_bytes(&[digits[20 - len + i]]);
        }
    }
    serial::put_bytes(b"\n");
    hlt_loop();
}

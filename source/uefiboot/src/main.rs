//! Plan 9 from Outer Space — self-hosted UEFI boot loader (Rust).
//!
//! Replaces GRUB for **all four** architectures:
//!
//! | arch        | rustc target                     | kernel entry contract           |
//! |-------------|----------------------------------|---------------------------------|
//! | x86_64      | x86_64-unknown-uefi (official)   | `_start64`, RAX=MB2 magic, RBX=info ptr (long mode, paging on) |
//! | aarch64     | aarch64-unknown-uefi (official)  | ELF entry at 0x4020_0000, EL1, MMU off, x0=0 x1=0 |
//! | riscv64     | riscv64gc-unknown-none-elf       | ELF entry at 0x8020_0000, S-mode, a0=0 a1=0, MMU off |
//! | loongarch64 | loongarch64-unknown-none         | ELF entry at 0x20_0000, PLV0, CRMD.DA=1 (direct map on) |
//!
//! riscv64/loongarch64 have no official `*-unknown-uefi` rustc target, so
//! those two build as plain bare-metal ELF and are wrapped into PE32+
//! images by the ELF→PE packager in `build_tool`.  The wrapper's entry
//! stub self-relocates the payload, restores the CPU state the kernel
//! expects, and jumps to the ELF entry — see `wrap.rs` in build_tool.
//!
//! Flow (identical for every arch):
//!   1. Print a banner, open `\boot\9kernel.elf` (+ `init`, `rootfs.cpio`
//!      on x86_64) from the ESP via SimpleFileSystem.
//!   2. Show the interactive **Boot Menu** (↑/↓/number/Enter, countdown,
//!      "q" = firmware) and let the user pick an entry.
//!   3. Load + relocate the kernel image at its link address.
//!   4. Build a Multiboot2 info block (memmap, framebuffer, modules,
//!      bootloader name) inside a BootServicesData page.
//!   5. GetMemoryMap, ExitBootServices.
//!   6. Hand off: arch-specific CPU state + jump.

#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::size_of;

// ===========================================================================
// Minimal UEFI API surface
// ===========================================================================

pub const EFI_SUCCESS: usize = 0;
const EFI_LOAD_ERROR: usize = 1 | (1 << 63);
const EFI_INVALID_PARAMETER: usize = 2 | (1 << 63);
const EFI_UNSUPPORTED: usize = 3 | (1 << 63);
const EFI_BUFFER_TOO_SMALL: usize = 5 | (1 << 63);
const EFI_NOT_FOUND: usize = 14 | (1 << 63);

pub type EfiHandle = usize;

#[repr(C)]
pub struct SystemTable {
    hdr: [u64; 3],
    firmware_vendor: u64,
    firmware_revision: u32,
    _pad: u32,
    console_in_handle: EfiHandle,
    con_in: *const SimpleInput,
    console_out_handle: EfiHandle,
    con_out: *const SimpleTextOut,
    standard_err_handle: EfiHandle,
    std_err: *const SimpleTextOut,
    runtime_services: *const u64,
    boot_services: *const BootServices,
}

#[repr(C)]
pub struct SimpleTextOut {
    reset: u64,
    output_string: extern "efiapi" fn(*const SimpleTextOut, *const u16) -> usize,
    test_string: u64,
    query_mode: u64,
    set_mode: u64,
    clear_screen: extern "efiapi" fn(*const SimpleTextOut) -> usize,
    set_attribute: extern "efiapi" fn(*const SimpleTextOut, usize) -> usize,
    mode: *const u8,
    cursor_x: i32,
    cursor_y: i32,
}

#[repr(C)]
pub struct SimpleInput {
    reset: u64,
    read_key_stroke: extern "efiapi" fn(*const SimpleInput, *mut InputKey) -> usize,
    wait_for_key: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputKey {
    pub scan_code: u16,
    pub unicode_char: u16,
}

const SCAN_NULL: u16 = 0x00;
const SCAN_UP: u16 = 0x01;
const SCAN_DOWN: u16 = 0x02;
const SCAN_ESC: u16 = 0x17;

const CHAR_CR: u16 = 0x0D;
const CHAR_LF: u16 = 0x0A;
const CHAR_1: u16 = 0x31;
const CHAR_Q: u16 = 0x71;

// GetMemoryMap / AllocatePages / AllocatePool / LocateHandle /
// HandleProtocol / LocateHandleBuffer / ExitBootServices are reached by
// fixed slot indexes in the raw BootServices pointer array — the UEFI spec
// fixes the order, so this is ABI-safe and avoids typing out the whole
// 100-member struct.
//
// Spec function-pointer order (0-based, after the 24-byte table header
// which occupies 3 slots):
//   0 RaiseTPL           1 RestoreTPL
//   2 AllocatePages      3 FreePages        4 GetMemoryMap
//   5 AllocatePool       6 FreePool
//   ...
//  24 LocateHandleBuffer                    25 LocateProtocol
//  26 InstallMultipleProtocolInterfaces ...
//  27 HandleProtocol
//  ...
//  19+... careful: ExitBootServices is index 17 among "boot services"
//   functions but 3 header slots offset it.  We verified against the spec:
//   ExitBootServices = raw slot 16+3 = 19?  See EBS_SLOT below.
const SLOT_ALLOCATE_PAGES: usize = 2 + 3;
const SLOT_GET_MEMORY_MAP: usize = 4 + 3;
const SLOT_ALLOCATE_POOL: usize = 5 + 3;
const SLOT_WAIT_FOR_EVENT: usize = 9 + 3;
const SLOT_HANDLE_PROTOCOL: usize = 16 + 3; // spec index 16 = HandleProtocol
const SLOT_LOCATE_HANDLE_BUFFER: usize = 36 + 3; // spec index 36 = LocateHandleBuffer
const SLOT_LOCATE_PROTOCOL: usize = 37 + 3; // spec index 37 = LocateProtocol
const SLOT_EXIT_BOOT_SERVICES: usize = 26 + 3; // spec index 26 = ExitBootServices

type RawFn = extern "efiapi" fn();

#[repr(C)]
pub struct BootServices {
    hdr: [u64; 3],
}

// Memory descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub kind: u32,
    _pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub pages: u64,
    pub attribute: u64,
}

fn mem_usable(kind: u32) -> bool {
    // Conventional + loader data/code + boot services data/code + runtime
    // code/data + persistent + ACPI reclaim are the regions a kernel may
    // reuse or must at least know about.  We mark everything except MMIO,
    // unaccepted and firmware-reserved as available.
    matches!(kind, 1..=7 | 12..=17)
}

const MEM_TYPE_LOADER_DATA: usize = 2;
const MEM_TYPE_BOOT_SERVICES_DATA: usize = 4;
const ALLOCATE_ANY_PAGES: usize = 0;

// SimpleFileSystem protocol.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiGuid {
    pub a: u32,
    pub b: u16,
    pub c: u16,
    pub d: [u8; 8],
}

impl EfiGuid {
    const fn new(a: u32, b: u16, c: u16, d: [u8; 8]) -> Self {
        Self { a, b, c, d }
    }
}

const SIMPLE_FS_GUID: EfiGuid =
    EfiGuid::new(0x964e5b22, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);

const FILE_INFO_GUID: EfiGuid = EfiGuid::new(
    0x09576e92,
    0x6d3f,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

const GOP_GUID: EfiGuid = EfiGuid::new(
    0x9042a9de,
    0x23dc,
    0x4a38,
    [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);

#[repr(C)]
pub struct SimpleFileSystemProtocol {
    revision: u64,
    open_volume: extern "efiapi" fn(*const SimpleFileSystemProtocol, *mut *mut FileProto) -> usize,
}

#[repr(C)]
pub struct FileProto {
    revision: u64,
    open: extern "efiapi" fn(*const FileProto, *mut *mut FileProto, *const u16, u64, u64) -> usize,
    close: extern "efiapi" fn(*const FileProto) -> usize,
    delete: u64,
    read: extern "efiapi" fn(*const FileProto, *mut usize, *mut u8) -> usize,
    write: u64,
    get_position: u64,
    set_position: u64,
    get_info: extern "efiapi" fn(*const FileProto, *const EfiGuid, *mut usize, *mut u8) -> usize,
    _pad: [u64; 4],
}

const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;
const BY_PROTOCOL: usize = 2;

// ===========================================================================
// Globals + helpers
// ===========================================================================

static mut ST_PTR: *const SystemTable = core::ptr::null();
static mut IH: EfiHandle = 0;

fn st() -> &'static SystemTable {
    unsafe { &*ST_PTR }
}

fn bs_raw() -> *const u64 {
    st().boot_services as *const u64
}

fn bs_call<T: Copy>(slot: usize) -> T {
    unsafe { core::mem::transmute_copy::<u64, T>(&*bs_raw().add(slot)) }
}

fn con_out() -> &'static SimpleTextOut {
    unsafe { &*st().con_out }
}

fn con_in() -> &'static SimpleInput {
    unsafe { &*st().con_in }
}

fn out(s: &str) {
    let mut buf = [0u16; 256];
    let mut n = 0usize;
    for ch in s.chars() {
        if n + 1 >= buf.len() {
            break;
        }
        buf[n] = ch as u32 as u16;
        n += 1;
    }
    buf[n] = 0;
    (con_out().output_string)(con_out(), buf.as_ptr());
}

fn outln(s: &str) {
    out(s);
    out("\r\n");
}

const ATTR_DEFAULT: usize = 0x07;
const ATTR_HIGHLIGHT: usize = 0x0F;
const ATTR_GREEN: usize = 0x0A;
const ATTR_YELLOW: usize = 0x0E;
const ATTR_CYAN: usize = 0x0B;

fn set_color(attr: usize) {
    (con_out().set_attribute)(con_out(), attr);
}

fn clear_screen() {
    (con_out().clear_screen)(con_out());
}

fn read_key() -> Option<InputKey> {
    let mut k = InputKey::default();
    let rc = (con_in().read_key_stroke)(con_in(), &mut k);
    if rc == EFI_SUCCESS {
        Some(k)
    } else {
        None
    }
}

fn wait_key() -> InputKey {
    // WaitForKey is the third field of SimpleInput (an event).
    let ev = con_in().wait_for_key;
    let mut idx: usize = 0;
    let events = [ev];
    let wait_for_event: extern "efiapi" fn(usize, *const usize, *mut usize) -> usize =
        bs_call(SLOT_WAIT_FOR_EVENT);
    let _ = wait_for_event(1, events.as_ptr(), &mut idx);
    read_key().unwrap_or(InputKey::default())
}

fn hexstr(v: usize) -> &'static str {
    // Bounded static strings for the handful of error codes we print.
    match v {
        _ => "error",
    }
}

// ===========================================================================
// Number formatting (byte-array based; no alloc)
// ===========================================================================

fn utoa(mut v: usize, out: &mut [u8]) -> &str {
    if v == 0 && !out.is_empty() {
        out[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&out[..1]) };
    }
    let mut n = 0usize;
    while v > 0 && n < out.len() {
        out[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n / 2 {
        out.swap(i, n - 1 - i);
    }
    unsafe { core::str::from_utf8_unchecked(&out[..n]) }
}

fn hex(v: usize) -> &'static str {
    // We can't return a formatted &str without a buffer; format into a
    // static buffer (single-threaded boot code, safe in practice).
    static mut HEXBUF: [u8; 20] = [0; 20];
    unsafe {
        const D: &[u8; 16] = b"0123456789ABCDEF";
        HEXBUF[0] = b'0';
        HEXBUF[1] = b'x';
        let mut n = 2usize;
        let mut val = v;
        if val == 0 {
            HEXBUF[2] = b'0';
            n = 3;
        }
        while val > 0 && n < HEXBUF.len() {
            HEXBUF[n] = D[(val & 0xF) as usize];
            val >>= 4;
            n += 1;
        }
        let mut i = 2usize;
        let mut j = n - 1;
        while i < j {
            HEXBUF.swap(i, j);
            i += 1;
            j -= 1;
        }
        core::str::from_utf8_unchecked(&HEXBUF[..n])
    }
}

// ===========================================================================
// Boot menu
// ===========================================================================

struct MenuEntry {
    title: &'static str,
    subtitle: &'static str,
}

const MENU: [MenuEntry; 3] = [
    MenuEntry {
        title: "Boot Plan 9 (Rust kernel)",
        subtitle: "9kernel.elf from the boot volume",
    },
    MenuEntry {
        title: "Boot Plan 9 (verbose)",
        subtitle: "same kernel, extra boot-time chatter",
    },
    MenuEntry {
        title: "Return to UEFI firmware",
        subtitle: "exit to the boot manager",
    },
];

const MENU_TIMEOUT_S: i32 = 5;

fn draw_menu(selected: usize, countdown: Option<i32>) {
    clear_screen();
    set_color(ATTR_CYAN);
    outln("=====================================================");
    outln("  Plan 9 from Outer Space - Rust UEFI Boot Loader");
    outln("=====================================================");
    set_color(ATTR_DEFAULT);
    outln("");
    for (i, e) in MENU.iter().enumerate() {
        if i == selected {
            set_color(ATTR_HIGHLIGHT);
            out("> ");
        } else {
            out("  ");
        }
        let mut nb = [0u8; 24];
        out(utoa(i + 1, &mut nb));
        out(". ");
        outln(e.title);
        if i == selected {
            set_color(ATTR_YELLOW);
            out("     ");
            outln(e.subtitle);
        }
    }
    set_color(ATTR_DEFAULT);
    outln("");
    outln("  Up/Down arrows or number keys, Enter to boot, ESC/q for firmware.");
    if let Some(s) = countdown {
        let mut nb = [0u8; 24];
        out("  Auto-booting in ");
        out(utoa(s.max(0) as usize, &mut nb));
        outln(" seconds...");
    }
}

fn handle_char(c: u16, selected: &mut usize) -> Option<usize> {
    if c == CHAR_CR || c == CHAR_LF {
        return Some(*selected);
    }
    if c >= CHAR_1 && c <= CHAR_1 + (MENU.len() as u16 - 1) {
        return Some((c - CHAR_1) as usize);
    }
    if c == CHAR_Q || c == (CHAR_Q - 32) {
        return Some(MENU.len() - 1);
    }
    None
}

fn menu_interactive(mut selected: usize) -> usize {
    loop {
        let k = wait_key();
        match k.scan_code {
            SCAN_UP => {
                selected = if selected == 0 { MENU.len() - 1 } else { selected - 1 };
                draw_menu(selected, None);
            }
            SCAN_DOWN => {
                selected = (selected + 1) % MENU.len();
                draw_menu(selected, None);
            }
            SCAN_ESC => return MENU.len() - 1,
            SCAN_NULL => {
                if let Some(sel) = handle_char(k.unicode_char, &mut selected) {
                    return sel;
                }
            }
            _ => {}
        }
    }
}

fn run_menu() -> usize {
    let mut selected = 0usize;
    draw_menu(selected, Some(MENU_TIMEOUT_S));

    let mut remaining = MENU_TIMEOUT_S;
    while remaining > 0 {
        // A second is approximated by spinning; any key press cancels the
        // countdown and drops into full interactive mode.
        let spins = 8_000_000u64;
        let mut c = 0u64;
        while c < spins {
            if let Some(k) = read_key() {
                draw_menu(selected, None);
                match k.scan_code {
                    SCAN_UP => {
                        selected = if selected == 0 { MENU.len() - 1 } else { selected - 1 };
                    }
                    SCAN_DOWN => {
                        selected = (selected + 1) % MENU.len();
                    }
                    SCAN_ESC => return MENU.len() - 1,
                    SCAN_NULL => {
                        if let Some(sel) = handle_char(k.unicode_char, &mut selected) {
                            return sel;
                        }
                    }
                    _ => {}
                }
                draw_menu(selected, None);
                return menu_interactive(selected);
            }
            c += 1;
            unsafe { asm!("nop; nop; nop; nop", options(nomem, nostack, preserves_flags)) };
        }
        remaining -= 1;
        draw_menu(selected, Some(remaining));
    }
    selected
}

// ===========================================================================
// ELF64 loader
// ===========================================================================

#[repr(C)]
struct Elf64Ehdr {
    ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    _rest: [u8; 18],
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;
const EM_LOONGARCH: u16 = 258;

fn expected_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        EM_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        EM_AARCH64
    }
    #[cfg(target_arch = "riscv64")]
    {
        EM_RISCV
    }
    #[cfg(target_arch = "loongarch64")]
    {
        EM_LOONGARCH
    }
}

/// Copy every PT_LOAD segment of `elf` to its physical address (p_paddr),
/// zero-filling BSS.  Returns the entry point.
unsafe fn load_elf(elf: &[u8]) -> Result<u64, usize> {
    if elf.len() < size_of::<Elf64Ehdr>() || &elf[..4] != b"\x7fELF" {
        return Err(EFI_LOAD_ERROR);
    }
    let eh = &*(elf.as_ptr() as *const Elf64Ehdr);
    if eh.e_type != ET_EXEC || eh.e_machine != expected_machine() {
        return Err(EFI_UNSUPPORTED);
    }

    let phdr_off = eh.e_phoff as usize;
    let phnum = eh.e_phnum as usize;
    let phentsize = eh.e_phentsize as usize;
    if phdr_off + phnum * phentsize > elf.len() {
        return Err(EFI_LOAD_ERROR);
    }

    for i in 0..phnum {
        let p = &*((elf.as_ptr() as usize + phdr_off + i * phentsize) as *const Elf64Phdr);
        if p.p_type != PT_LOAD || p.p_memsz == 0 {
            continue;
        }
        let dst = p.p_paddr as *mut u8;
        let filesz = p.p_filesz as usize;
        if p.p_offset as usize + filesz > elf.len() {
            return Err(EFI_LOAD_ERROR);
        }
        core::ptr::copy_nonoverlapping(elf.as_ptr().add(p.p_offset as usize), dst, filesz);
        if p.p_memsz > p.p_filesz {
            core::ptr::write_bytes(dst.add(filesz), 0, (p.p_memsz - p.p_filesz) as usize);
        }
    }
    Ok(eh.e_entry)
}

// ===========================================================================
// File access
// ===========================================================================

fn ascii_to_utf16(s: &str, out_buf: &mut [u16]) -> usize {
    let mut n = 0usize;
    for b in s.bytes() {
        if n + 1 >= out_buf.len() {
            break;
        }
        out_buf[n] = b as u16;
        n += 1;
    }
    out_buf[n] = 0;
    n
}

fn handle_protocol(handle: EfiHandle, guid: &EfiGuid) -> Option<*mut u8> {
    let hp: extern "efiapi" fn(EfiHandle, *const u64, *mut *mut u8) -> usize = bs_call(SLOT_HANDLE_PROTOCOL);
    let mut iface: *mut u8 = core::ptr::null_mut();
    // The spec signature takes EFI_GUID*; pack the struct by reference.
    let rc = hp(handle, guid as *const EfiGuid as *const u64, &mut iface);
    if rc == EFI_SUCCESS && !iface.is_null() {
        Some(iface)
    } else {
        None
    }
}

fn locate_handles(guid: &EfiGuid) -> Option<&'static [EfiHandle]> {
    let lhb: extern "efiapi" fn(
        usize,
        *const u64,
        *const u8,
        *mut usize,
        *mut *mut EfiHandle,
    ) -> usize = bs_call(SLOT_LOCATE_HANDLE_BUFFER);
    let mut n = 0usize;
    let mut hs: *mut EfiHandle = core::ptr::null_mut();
    let rc = lhb(BY_PROTOCOL, guid as *const EfiGuid as *const u64, core::ptr::null(), &mut n, &mut hs);
    if rc != EFI_SUCCESS {
        set_color(ATTR_YELLOW);
        out("  LocateHandleBuffer rc=0x");
        out(hex(rc));
        outln("");
        set_color(ATTR_DEFAULT);
    }
    if rc == EFI_SUCCESS && n > 0 && !hs.is_null() {
        Some(unsafe { core::slice::from_raw_parts(hs, n) })
    } else {
        None
    }
}

fn open_boot_volume() -> Option<&'static SimpleFileSystemProtocol> {
    let handles = match locate_handles(&SIMPLE_FS_GUID) {
        Some(h) => h,
        None => {
            set_color(ATTR_YELLOW);
            outln("  LocateHandleBuffer(BY_PROTOCOL, SFS) returned no handles");
            set_color(ATTR_DEFAULT);
            return None;
        }
    };
    out("  SFS volumes: ");
    let mut nb = [0u8; 8];
    out(utoa(handles.len(), &mut nb));
    outln("");
    // OVMF may expose several SimpleFileSystem volumes (the El Torito FAT
    // image, the ISO9660 track, ...).  Pick the first one that can actually
    // open \boot\9kernel.elf.
    for &h in handles {
        if let Some(iface) = handle_protocol(h, &SIMPLE_FS_GUID) {
            let fs = unsafe { &*(iface as *const SimpleFileSystemProtocol) };
            let rc = read_probe(fs, "\\boot\\9kernel.elf");
            if rc == EFI_SUCCESS {
                return Some(fs);
            }
        }
    }
    set_color(ATTR_YELLOW);
    outln("  no SFS volume contains \\boot\\9kernel.elf");
    set_color(ATTR_DEFAULT);
    None
}

/// Cheap existence probe: open the path, close it immediately.
/// Returns the Open() status code (EFI_SUCCESS on success).
fn read_probe(fs: &SimpleFileSystemProtocol, path: &str) -> usize {
    let mut wpath = [0u16; 128];
    ascii_to_utf16(path, &mut wpath);
    let mut root: *mut FileProto = core::ptr::null_mut();
    if (fs.open_volume)(fs as *const SimpleFileSystemProtocol, &mut root) != EFI_SUCCESS {
        return EFI_LOAD_ERROR;
    }
    let root = unsafe { &mut *root };
    let mut file: *mut FileProto = core::ptr::null_mut();
    let rc = (root.open)(
        root as *const FileProto,
        &mut file,
        wpath.as_ptr(),
        EFI_FILE_MODE_READ,
        0,
    );
    if rc == EFI_SUCCESS {
        let f = unsafe { &mut *file };
        (f.close)(f as *mut FileProto);
    }
    rc
}

/// Read a whole file from the boot volume into fresh loader-data pages.
fn read_file(fs: &SimpleFileSystemProtocol, path: &str) -> Result<&'static mut [u8], usize> {
    let mut wpath = [0u16; 128];
    ascii_to_utf16(path, &mut wpath);

    let mut root: *mut FileProto = core::ptr::null_mut();
    let rc = (fs.open_volume)(fs as *const SimpleFileSystemProtocol, &mut root);
    if rc != EFI_SUCCESS {
        return Err(rc);
    }
    let root = unsafe { &mut *root };

    let mut file: *mut FileProto = core::ptr::null_mut();
    let rc = (root.open)(
        root as *const FileProto,
        &mut file,
        wpath.as_ptr(),
        EFI_FILE_MODE_READ,
        0,
    );
    (root.close)(root as *const FileProto);
    if rc != EFI_SUCCESS {
        return Err(EFI_NOT_FOUND);
    }
    let file = unsafe { &mut *file };

    let mut info_buf = [0u8; 256];
    let mut info_size = info_buf.len();
    let rc = (file.get_info)(
        file as *const FileProto,
        &FILE_INFO_GUID as *const EfiGuid,
        &mut info_size,
        info_buf.as_mut_ptr(),
    );
    if rc != EFI_SUCCESS {
        (file.close)(file as *const FileProto);
        return Err(rc);
    }
    // EFI_FILE_INFO: u64 Size, u64 FileSize, ...
    let file_size = unsafe { core::ptr::read_unaligned(info_buf.as_ptr().add(8) as *const u64) } as usize;
    if file_size == 0 || file_size > 64 * 1024 * 1024 {
        (file.close)(file as *const FileProto);
        return Err(EFI_LOAD_ERROR);
    }

    let pages = (file_size + 0xFFF) / 0x1000;
    let mut buf: usize = 0;
    let alloc_pages: extern "efiapi" fn(usize, usize, usize, *mut usize) -> usize =
        bs_call(SLOT_ALLOCATE_PAGES);
    let rc = alloc_pages(ALLOCATE_ANY_PAGES, MEM_TYPE_LOADER_DATA, pages, &mut buf);
    if rc != EFI_SUCCESS {
        (file.close)(file as *const FileProto);
        return Err(rc);
    }

    let mut got = file_size;
    let rc = (file.read)(file as *const FileProto, &mut got, buf as *mut u8);
    let ok = rc == EFI_SUCCESS && got == file_size;
    (file.close)(file as *const FileProto);
    if !ok {
        return Err(EFI_LOAD_ERROR);
    }
    Ok(unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, file_size) })
}

// ===========================================================================
// Multiboot2 info construction
// ===========================================================================

const MB2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

struct TagWriter {
    buf: *mut u8,
    len: usize,
    cap: usize,
}

impl TagWriter {
    unsafe fn w32(&mut self, v: u32) {
        if self.len + 4 <= self.cap {
            core::ptr::write_unaligned(self.buf.add(self.len) as *mut u32, v);
        }
        self.len += 4;
    }
    unsafe fn w64(&mut self, v: u64) {
        if self.len + 8 <= self.cap {
            core::ptr::write_unaligned(self.buf.add(self.len) as *mut u64, v);
        }
        self.len += 8;
    }
    unsafe fn bytes(&mut self, b: &[u8]) {
        for &c in b {
            if self.len < self.cap {
                core::ptr::write(self.buf.add(self.len), c);
            }
            self.len += 1;
        }
    }
    unsafe fn align8(&mut self) {
        while self.len % 8 != 0 {
            self.len += 1;
        }
    }
}

/// Build the Multiboot2 info block: BOOT_LOADER_NAME, BASIC_MEMINFO,
/// MEMMAP (the EFI memory map), FRAMEBUFFER and MODULE tags.
unsafe fn build_mb2_info(
    scratch: *mut u8,
    cap: usize,
    memmap: &[EfiMemoryDescriptor],
    fb: (u64, u32, u32, u32, u8),
    modules: &[(u64, u64, &str)],
) -> u64 {
    let mut w = TagWriter { buf: scratch, len: 8, cap };
    core::ptr::write_bytes(scratch, 0, 8);

    // BOOT_LOADER_NAME (type 2)
    let name = b"Plan9RustUEFI\0";
    w.w32(2);
    w.w32((8 + name.len()) as u32);
    w.bytes(name);
    w.align8();

    // BASIC_MEMINFO (type 4) — placeholder values, MEMMAP is authoritative.
    w.w32(4);
    w.w32(16);
    w.w32(639);
    w.w32(0x3FFF);
    w.align8();

    // MEMMAP (type 6)
    // The kernel's MmapEntry is MB1-style: [size u32][pad u32][addr u64]
    // [len u64][type u32][pad u32] (32 bytes with alignment), entries
    // starting immediately after the 8-byte tag header.
    let tag_start = w.len;
    w.w32(6);
    // After w32(type), w.len points at the tag's size field.
    let size_pos = w.len;
    w.w32(0);
    for e in memmap {
        w.w32(24); // entry size (MB1 convention, includes this field)
        w.w32(0);  // alignment pad
        w.w64(e.phys_start);
        w.w64(e.pages * 4096);
        w.w32(e.kind);
        w.w32(0);
    }
    // Tag size = bytes from tag_start to here (w.len is block-relative).
    core::ptr::write_unaligned(scratch.add(size_pos) as *mut u32, (w.len - tag_start) as u32);
    w.align8();

    // FRAMEBUFFER (type 8)
    // Kernel's FramebufferInfo: [addr u64][pitch u32][width u32][height u32]
    // [bpp u8][fb_type u8][reserved u16] = 24 bytes after the tag header.
    let (fa, fp, fw, fh, fbp) = fb;
    if fw > 0 {
        let tag_start = w.len;
        w.w32(8);
        let fb_size_pos = w.len;
        w.w32(0);
        w.w64(fa);
        w.w32(fp);
        w.w32(fw);
        w.w32(fh);
        w.bytes(&[fbp, 1, 0, 0]); // bpp, fb_type=BGR, reserved
        core::ptr::write_unaligned(
            scratch.add(fb_size_pos) as *mut u32,
            (w.len - tag_start) as u32,
        );
        w.align8();
    }

    // MODULE (type 3)
    for (s, e, name) in modules {
        let tag_start = w.len;
        w.w32(3);
        // After w32(type), w.len points at the tag's size field.
        let sz_pos = w.len;
        w.w32(0);
        w.w32(*s as u32);
        w.w32(*e as u32);
        let mut nb = [0u8; 64];
        let nbts = name.as_bytes();
        let n = nbts.len().min(63);
        nb[..n].copy_from_slice(&nbts[..n]);
        nb[n] = 0;
        w.bytes(&nb[..n + 1]);
        core::ptr::write_unaligned(
            scratch.add(sz_pos) as *mut u32,
            (w.len - tag_start) as u32,
        );
        w.align8();
    }

    // END (type 0)
    w.w32(0);
    w.w32(8);
    w.align8();

    core::ptr::write_unaligned(scratch as *mut u32, w.len as u32);
    core::ptr::write_unaligned(scratch.add(4) as *mut u32, 0);
    scratch as u64
}

// ===========================================================================
// Memory map + ExitBootServices
// ===========================================================================

/// AllocatePool slot helper.
fn allocate_pool(kind: usize, size: usize) -> Result<usize, usize> {
    let ap: extern "efiapi" fn(usize, usize, *mut *mut u8) -> usize = bs_call(SLOT_ALLOCATE_POOL);
    let mut p: *mut u8 = core::ptr::null_mut();
    let rc = ap(kind, size, &mut p);
    if rc == EFI_SUCCESS {
        Ok(p as usize)
    } else {
        Err(rc)
    }
}

/// GetMemoryMap with retry; returns (key, entries) with the entries
/// borrowed from a BootServicesData pool allocation.
unsafe fn get_memmap() -> Result<(usize, &'static [EfiMemoryDescriptor]), usize> {
    let gmm: extern "efiapi" fn(
        *mut usize,
        *mut EfiMemoryDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> usize = bs_call(SLOT_GET_MEMORY_MAP);

    let mut size = 0usize;
    let mut key = 0usize;
    let mut dsize = 0usize;
    let mut dver = 0u32;
    // Learn the needed size.
    let _ = gmm(&mut size, core::ptr::null_mut(), &mut key, &mut dsize, &mut dver);
    let mut buf = allocate_pool(MEM_TYPE_BOOT_SERVICES_DATA, size + 4096)?;

    loop {
        let mut sz = size + 4096;
        let rc = gmm(
            &mut sz,
            buf as *mut EfiMemoryDescriptor,
            &mut key,
            &mut dsize,
            &mut dver,
        );
        if rc == EFI_SUCCESS && dsize > 0 {
            let n = sz / dsize;
            // The firmware may report a descriptor stride (DescriptorSize)
            // larger than sizeof(EfiMemoryDescriptor) — this OVMF build
            // reports 48 instead of 40.  Compact the descriptors in place
            // (forward copy is safe: 40 < stride, dst always trails src).
            // NOTE: no AllocatePool or console output may happen after
            // GetMemoryMap — either can change the memory map and make
            // the returned key stale, so ExitBootServices fails with
            // EFI_INVALID_PARAMETER.
            let src = buf as *const u8;
            let dst = buf as *mut u8;
            for i in 0..n {
                core::ptr::copy(
                    src.add(i * dsize),
                    dst.add(i * core::mem::size_of::<EfiMemoryDescriptor>()),
                    core::mem::size_of::<EfiMemoryDescriptor>(),
                );
            }
            return Ok((key, core::slice::from_raw_parts(buf as *const EfiMemoryDescriptor, n)));
        }
        if rc == EFI_BUFFER_TOO_SMALL || rc == EFI_INVALID_PARAMETER {
            size = sz + 4096;
            buf = allocate_pool(MEM_TYPE_BOOT_SERVICES_DATA, size)?;
            continue;
        }
        return Err(rc);
    }
}

// ===========================================================================
// Arch hand-off
// ===========================================================================

/// x86_64: the kernel's `_start64` runs in long mode with our firmware
/// page tables still active (the kernel installs its own early PML4 before
/// touching anything else).  RAX = MB2 magic, RBX = info pointer.
#[cfg(target_arch = "x86_64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    // Zero the IDT: after ExitBootServices a stray firmware interrupt must
    // not vector into firmware code (the kernel installs its own IDT).
    let idtr: [u16; 5] = [0; 5];
    asm!("lidt [{idt}]", idt = in(reg) idtr.as_ptr(), options(nostack));
    // Mask the legacy PICs.
    asm!("out 0x21, al", in("al") 0xFFu8, options(nostack, nomem));
    asm!("out 0xA1, al", in("al") 0xFFu8, options(nostack, nomem));
    asm!(
        "mov rax, {magic}",
        "mov rbx, {info}",
        "call {entry}",
        magic = in(reg) MB2_BOOTLOADER_MAGIC as u64,
        info = in(reg) mb2_info,
        entry = in(reg) kernel_entry,
        options(noreturn)
    );
    unreachable!()
}

/// aarch64: disable the MMU + caches, then branch with x0=0, x1=0.
#[cfg(target_arch = "aarch64")]
unsafe fn handoff(kernel_entry: u64, mb2_info: u64) -> ! {
    // Pass the Multiboot2 magic in x0 and the info pointer in x1 — the
    // kernel's boot.S forwards them to kstart().  A plain `-kernel` boot
    // (no loader) puts the DTB pointer in x0 instead, which fails the
    // magic check and sends the kernel down its non-bootinfo bring-up
    // path, so both entry paths stay compatible.
    asm!(
        "dsb sy",
        "ic iallu",
        "dsb sy",
        "isb",
        "msr sctlr_el1, xzr",
        "dsb sy",
        "isb",
        "mov x0, {magic}",
        "mov x1, {info}",
        "mov x2, {e}",
        "br x2",
        magic = in(reg) 0x36D76289u64,
        info = in(reg) mb2_info,
        e = in(reg) kernel_entry,
        options(noreturn)
    );
    unreachable!()
}

/// riscv64: bare MMU mode + jump with a0=0, a1=0.
#[cfg(target_arch = "riscv64")]
unsafe fn handoff(kernel_entry: u64, _mb2_info: u64) -> ! {
    asm!(
        "sfence.vma",
        "csrw satp, zero",
        "sfence.vma",
        "li a0, 0",
        "li a1, 0",
        "jr {e}",
        e = in(reg) kernel_entry,
        options(noreturn)
    );
    unreachable!()
}

/// loongarch64: back to direct address translation (CRMD.DA=1, PG=0), then
/// jump — the kernel's boot.S re-installs its DMW windows itself.
#[cfg(target_arch = "loongarch64")]
unsafe fn handoff(kernel_entry: u64, _mb2_info: u64) -> ! {
    asm!(
        "li.d $t0, 0xb0",
        "csrwr $t0, 0x0",
        "dbar 0",
        "ibar 0",
        "jr {e}",
        e = in(reg) kernel_entry,
        options(noreturn)
    );
    unreachable!()
}

// ===========================================================================
// Entry point
// ===========================================================================

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *const SystemTable) -> usize {
    unsafe {
        ST_PTR = system_table;
        IH = image_handle;
    }

    clear_screen();
    set_color(ATTR_GREEN);
    outln("  Plan 9 from Outer Space");
    set_color(ATTR_DEFAULT);
    outln("  Rust UEFI Boot Loader (GRUB-free)\n");

    let fs = match open_boot_volume() {
        Some(f) => f,
        None => {
            set_color(ATTR_YELLOW);
            outln("!! No SimpleFileSystem volume found.");
            set_color(ATTR_DEFAULT);
            outln("Press any key to return to firmware.");
            let _ = wait_key();
            return EFI_NOT_FOUND;
        }
    };

    // ---- Menu ------------------------------------------------------------
    let choice = run_menu();
    if choice == MENU.len() - 1 {
        outln("\nReturning to UEFI boot manager...");
        return EFI_UNSUPPORTED;
    }

    // ---- Load kernel -----------------------------------------------------
    out("Loading \\boot\\9kernel.elf ... ");
    let kernel_elf = match read_file(fs, "\\boot\\9kernel.elf") {
        Ok(b) => b,
        Err(e) => {
            outln("FAILED");
            out("  error: ");
            outln(hex(e));
            outln("Press any key to return to firmware.");
            let _ = wait_key();
            return e;
        }
    };
    outln("ok");

    if kernel_elf.len() < 20 || &kernel_elf[..4] != b"\x7fELF" {
        outln("!! boot\\9kernel.elf is not an ELF image.");
        let _ = wait_key();
        return EFI_LOAD_ERROR;
    }
    let em = unsafe { core::ptr::read_unaligned(kernel_elf.as_ptr().add(18) as *const u16) };
    if em != expected_machine() {
        out("!! kernel ELF machine mismatch: got ");
        let mut nb = [0u8; 8];
        out(utoa(em as usize, &mut nb));
        out(", want ");
        out(utoa(expected_machine() as usize, &mut nb));
        outln("");
        outln("This ISO was built for a different architecture.");
        let _ = wait_key();
        return EFI_UNSUPPORTED;
    }

    let entry = match unsafe { load_elf(kernel_elf) } {
        Ok(v) => v,
        Err(e) => {
            outln("!! ELF load failed.");
            let _ = wait_key();
            return e;
        }
    };

    // ---- Modules (init + rootfs.cpio as MB2 MODULE tags) ---------------
    let mut mods: [(u64, u64, &'static str); 4] = [(0, 0, ""); 4];
    let mut nmods = 0usize;

    // x86_64 passes them through Multiboot2 from GRUB/OVMF; aarch64 uses
    // the same MB2 module tags for the kernel's init_loader.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        for (path, name) in [("\\boot\\init", "init"), ("\\boot\\rootfs.cpio", "rootfs.cpio")] {
            match read_file(fs, path) {
                Ok(data) => {
                    let start = data.as_ptr() as u64;
                    let end = start + data.len() as u64;
                    mods[nmods] = (start, end, name);
                    nmods += 1;
                    let mut nb = [0u8; 24];
                    out("Loaded ");
                    out(path);
                    out(" (");
                    out(utoa(data.len(), &mut nb));
                    outln(" bytes)");
                }
                Err(_) => {
                    out("warning: ");
                    out(path);
                    outln(" not found on boot volume");
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (&mut mods, &mut nmods);
    }

    // ---- GOP framebuffer (x86_64 kernel reads the MB2 FRAMEBUFFER tag) ---
    let mut fb_addr = 0u64;
    let mut fb_pitch = 0u32;
    let mut fb_w = 0u32;
    let mut fb_h = 0u32;
    let mut fb_bpp = 0u8;

    #[cfg(target_arch = "x86_64")]
    {
        if let Some(handles) = locate_handles(&GOP_GUID) {
            if let Some(iface) = handle_protocol(handles[0], &GOP_GUID) {
                // GraphicsOutputProtocol: { QueryMode, SetMode, Blt, Mode* }
                let gop = iface as *const u64;
                let mode_ptr = unsafe { *(gop.add(3)) } as *const u64;
                // Mode: { MaxMode, Mode, Info*, SizeOfInfo, FrameBufferBase, FrameBufferSize }
                let info = unsafe { *(mode_ptr.add(2)) } as *const u32;
                fb_w = unsafe { *info.add(1) };
                fb_h = unsafe { *info.add(2) };
                fb_pitch = unsafe { *info.add(3) };
                let fmt = unsafe { *info.add(5) };
                fb_bpp = match fmt {
                    0 | 1 => 32,
                    2 => 24,
                    3 => 16,
                    _ => 0,
                };
                fb_addr = unsafe { *(mode_ptr.add(4)) };
            }
        }
    }

    // ---- Final memory map → MB2 info → ExitBootServices → jump -----------
    unsafe {
        // All boot-services allocations MUST happen before the final
        // GetMemoryMap, otherwise the returned map key goes stale and
        // ExitBootServices fails with EFI_INVALID_PARAMETER.
        let mut mb2_page: usize = 0;
        let alloc_pages: extern "efiapi" fn(usize, usize, usize, *mut usize) -> usize =
            bs_call(SLOT_ALLOCATE_PAGES);
        let rc = alloc_pages(ALLOCATE_ANY_PAGES, MEM_TYPE_BOOT_SERVICES_DATA, 8, &mut mb2_page);
        if rc != EFI_SUCCESS {
            outln("!! allocate_pages(MB2) failed.");
            let _ = wait_key();
            return rc;
        }

        let (key, mmap) = match get_memmap() {
            Ok(v) => v,
            Err(e) => {
                outln("!! GetMemoryMap failed.");
                let _ = wait_key();
                return e;
            }
        };

        let info = build_mb2_info(
            mb2_page as *mut u8,
            8 * 4096,
            mmap,
            (fb_addr, fb_pitch, fb_w, fb_h, fb_bpp),
            &mods[..nmods],
        );

        // Re-fetch the memory map QUIETLY right before ExitBootServices:
        // console output can change the memory map and invalidate the
        // earlier key.  There must be zero console output between this
        // GetMemoryMap and the ExitBootServices call.
        let (key, _) = match get_memmap() {
            Ok(v) => v,
            Err(e) => {
                outln("!! GetMemoryMap (fresh) failed.");
                let _ = wait_key();
                return e;
            }
        };

        let ebs: extern "efiapi" fn(EfiHandle, usize) -> usize = bs_call(SLOT_EXIT_BOOT_SERVICES);
        let mut rc = ebs(image_handle, key);
        if rc != EFI_SUCCESS {
            // The map may have grown; retry exactly once per spec.
            // Keep zero console output between the fresh GetMemoryMap and
            // the retry ExitBootServices call.
            let (key2, _) = match get_memmap() {
                Ok(v) => v,
                Err(e2) => return e2,
            };
            rc = ebs(image_handle, key2);
            if rc != EFI_SUCCESS {
                return rc;
            }
        }

        handoff(entry, info);
    }
}

#[panic_handler]
fn ph(_info: &core::panic::PanicInfo) -> ! {
    out("\r\n[uefiboot] PANIC\r\n");
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { asm!("hlt", options(nostack, preserves_flags)) };
        #[cfg(not(target_arch = "x86_64"))]
        loop {}
    }
}

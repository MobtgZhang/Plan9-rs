//! ELF64 → PE32+ (UEFI application) packager for riscv64/loongarch64.
//!
//! The bare-metal `uefiboot` ELF (built for `riscv64gc-unknown-none-elf` /
//! `loongarch64-unknown-none`, which have no official `*-unknown-uefi`
//! rustc target) is wrapped into a PE32+ image that UEFI firmware can load.
//!
//! Layout
//! ------
//! UEFI loads a PE image by allocating `SizeOfImage` bytes and copying the
//! sections to `ImageBase + VirtualAddress`.  The image is therefore
//! *relocatable*: the sections are laid out contiguously starting at RVA 0,
//! and `ImageBase` is set to the ELF's link address so the code still runs
//! at the address it was linked for.
//!
//! Each `PT_LOAD` segment becomes one PE section:
//!
//!   * `VirtualAddress` — the segment's offset from `ImageBase`
//!     (`p_paddr - image_base`), rounded down to `SectionAlignment`.
//!   * `VirtualSize`    — the segment's memory size, rounded up so the
//!     next section starts on a `SectionAlignment` boundary.
//!   * `SizeOfRawData`  — the segment's file contents, rounded up to
//!     `FileAlignment`; the tail is zero-filled (that is where .bss
//!     lives).
//!
//! The entry point is the ELF entry (`_start`), which is the stub that
//! sets up the stack and calls `efi_main`.
//!
//! Usage:
//!   wrap <input.elf> <output.efi> <arch>
//!   arch: riscv64 | loongarch64

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const PE_SIG: &[u8; 4] = b"PE\0\0";
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

// COFF machine types.
const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
const IMAGE_FILE_MACHINE_LOONGARCH64: u16 = 0x6264;

// Section characteristics.
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

const PT_LOAD: u32 = 1;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x200;

/// Size of the PE32+ optional header.
///
/// EDK2's PE loader rejects an image whose `SizeOfOptionalHeader` does not
/// equal `sizeof(EFI_IMAGE_OPTIONAL_HEADER64)` (0xF0), so the full header
/// must be emitted even though this image has no data directories.
const OPT_SIZE: u64 = 0xF0;

/// Number of data-directory entries in the PE32+ optional header.
const NUMBER_OF_RVA_AND_SIZES: u32 = 16;

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

// ---------- ELF64 ----------

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    _e_shoff: u64,
    _e_flags: u32,
    _e_ehsize: u16,
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

// ---------- Little-endian writers ----------

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off] = v as u8;
    buf[off + 1] = (v >> 8) as u8;
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off] = v as u8;
    buf[off + 1] = (v >> 8) as u8;
    buf[off + 2] = (v >> 16) as u8;
    buf[off + 3] = (v >> 24) as u8;
}
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    for i in 0..8 {
        buf[off + i] = (v >> (8 * i)) as u8;
    }
}

fn machine_for(arch: &str) -> Result<u16> {
    match arch {
        "riscv64" => Ok(IMAGE_FILE_MACHINE_RISCV64),
        "loongarch64" => Ok(IMAGE_FILE_MACHINE_LOONGARCH64),
        _ => anyhow::bail!("unsupported arch for wrap: {}", arch),
    }
}

pub fn wrap_elf_to_pe(elf_path: &Path, out_path: &Path, arch: &str) -> Result<()> {
    let elf = fs::read(elf_path)
        .with_context(|| format!("reading ELF {}", elf_path.display()))?;

    if elf.len() < 64 || &elf[..4] != ELF_MAGIC {
        anyhow::bail!("{} is not an ELF file", elf_path.display());
    }

    let eh: &Elf64Ehdr = unsafe { &*(elf.as_ptr() as *const Elf64Ehdr) };
    let phnum = eh.e_phnum as usize;
    let phoff = eh.e_phoff as usize;
    let phentsize = eh.e_phentsize as usize;

    if phoff + phnum * phentsize > elf.len() {
        anyhow::bail!("ELF program headers out of bounds");
    }

    let mut segs: Vec<&Elf64Phdr> = Vec::new();
    for i in 0..phnum {
        let p = unsafe { &*((elf.as_ptr().add(phoff + i * phentsize)) as *const Elf64Phdr) };
        if p.p_type == PT_LOAD && p.p_memsz > 0 {
            segs.push(p);
        }
    }
    if segs.is_empty() {
        anyhow::bail!("no PT_LOAD segments in ELF");
    }

    let machine = machine_for(arch)?;
    segs.sort_by_key(|s| s.p_paddr);

    // Place the image base one SectionAlignment below the first segment so
    // that the first section's RVA (and the entry RVA) are non-zero. EDK2's
    // PE loader rejects images whose first section or entry point sits at
    // RVA 0.  ImageBase + VirtualAddress still equals each segment's link
    // address, so the code runs at the address it was linked for.
    let image_base = align_down(segs[0].p_paddr - SECTION_ALIGN, SECTION_ALIGN);
    let entry_rva = eh.e_entry - image_base;

    // ----- Compute the section layout -----
    // Headers: DOS header + PE sig + COFF header + Optional header + section table.
    let dos_size: u64 = 64;
    let pe_sig_size: u64 = 4;
    let coff_size: u64 = 20;
    let opt_size: u64 = OPT_SIZE;
    let sec_table_size: u64 = (segs.len() as u64) * 40;

    let mut raw_offset = align_up(
        dos_size + pe_sig_size + coff_size + opt_size + sec_table_size,
        FILE_ALIGN,
    );

    let mut section_infos: Vec<SectionInfo> = Vec::new();
    let mut image_end = 0u64;

    for s in &segs {
        // RVA of this segment relative to the image base.
        let rva = align_down(s.p_paddr - image_base, SECTION_ALIGN);
        let sec_end = align_up(s.p_paddr - image_base + s.p_memsz, SECTION_ALIGN);
        let sec_vsize = sec_end - rva;

        let raw_start = raw_offset;
        let rsize = s.p_filesz;
        // Raw data covers the full in-memory size (p_memsz), zero-filling
        // the .bss tail so the PE loader allocates those pages (e.g. the
        // boot stack) rather than leaving them unmapped.
        let raw_end = align_up(raw_start + s.p_memsz, FILE_ALIGN);
        let mut raw_data = vec![0u8; (raw_end - raw_start) as usize];
        if rsize > 0 {
            let off = s.p_offset as usize;
            let end = off
                .checked_add(rsize as usize)
                .filter(|e| *e <= elf.len())
                .ok_or_else(|| anyhow::anyhow!("segment data out of ELF bounds"))?;
            raw_data[..rsize as usize].copy_from_slice(&elf[off..end]);
        }

        // ELF p_flags: PF_R=4, PF_W=2, PF_X=1 (NOT 1/2/4 as read/write/exec!).
        let mut characteristics: u32 = 0;
        if s.p_flags & 4 != 0 {
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        if s.p_flags & 2 != 0 {
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }
        if s.p_flags & 1 != 0 {
            characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        } else if rsize > 0 {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        } else {
            characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        }

        image_end = rva + sec_vsize;
        raw_offset = raw_end;        section_infos.push(SectionInfo {
            va_aligned: rva,
            sec_vsize,
            raw_size: raw_end - raw_start,
            raw_ptr: raw_start,
            characteristics,
            raw_data,
        });
    }

    let size_of_image = align_up(image_end, SECTION_ALIGN) as u32;
    let size_of_headers = align_up(
        dos_size + pe_sig_size + coff_size + opt_size + sec_table_size,
        FILE_ALIGN,
    ) as u32;

    // The file is the headers followed by every section's raw data.
    let file_size = raw_offset as usize;

    // ----- Build the PE byte buffer -----
    // DOS header (64 bytes), only e_magic and e_lfanew matter.
    let mut buf = vec![0u8; file_size];
    write_u16(&mut buf, 0, 0x5A4D); // e_magic
    write_u32(&mut buf, 0x3C, dos_size as u32); // e_lfanew -> PE sig

    // PE signature
    let pe_sig_off = dos_size as usize;
    buf[pe_sig_off..pe_sig_off + 4].copy_from_slice(PE_SIG);

    // COFF header (20 bytes) at pe_sig_off + 4
    let coff_off = pe_sig_off + 4;
    write_u16(&mut buf, coff_off, machine);
    write_u16(&mut buf, coff_off + 2, segs.len() as u16);
    write_u32(&mut buf, coff_off + 4, 0); // time date stamp
    write_u32(&mut buf, coff_off + 8, 0); // pointer to symbol table
    write_u32(&mut buf, coff_off + 12, 0); // number of symbols
    write_u16(&mut buf, coff_off + 16, opt_size as u16); // size of optional header
    // Position-dependent image loaded at its link address: no base
    // relocations are needed (and none are emitted), so strip the
    // relocation flag to keep EDK2 from trying to apply them to read-only
    // sections.
    write_u16(
        &mut buf,
        coff_off + 18,
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED,
    ); // characteristics

    // Optional header (PE32+)
    //
    // The PE32+ optional header layout is:
    //   0x00 Magic (u16) = 0x20b
    //   0x02 MajorLinkerVersion, 0x03 MinorLinkerVersion
    //   0x04 SizeOfCode, 0x08 SizeOfInitializedData, 0x0c SizeOfUninitializedData
    //   0x10 AddressOfEntryPoint
    //   0x14 BaseOfCode
    //   0x18 ImageBase (u64)          <- PE32+ only
    //   0x20 SectionAlignment
    //   0x24 FileAlignment
    //   0x28 MajorOperatingSystemVersion, 0x2a MinorOperatingSystemVersion
    //   0x2c MajorImageVersion, 0x2e MinorImageVersion
    //   0x30 MajorSubsystemVersion, 0x32 MinorSubsystemVersion
    //   0x34 Win32VersionValue
    //   0x38 SizeOfImage
    //   0x3c SizeOfHeaders
    //   0x40 CheckSum
    //   0x44 Subsystem (u16)
    //   0x46 DllCharacteristics
    //   0x48 SizeOfStackReserve (u64)
    //   0x50 SizeOfStackCommit
    //   0x58 SizeOfHeapReserve
    //   0x60 SizeOfHeapCommit
    //   0x68 LoaderFlags
    //   0x6c NumberOfRvaAndSizes
    //   0x70 DataDirectory[16]
    //
    // NOTE: PE32 and PE32+ differ after offset 0x24 (PE32 has 4-byte
    // BaseOfData at 0x1c and no ImageBase).  All offsets below are the
    // PE32+ ones.
    let opt_off = coff_off + 20;
    // 0x00 magic (u16) = 0x20b
    write_u16(&mut buf, opt_off, PE32_PLUS_MAGIC);
    // 0x02 MajorLinkerVersion, 0x03 MinorLinkerVersion
    buf[opt_off + 2] = 0;
    buf[opt_off + 3] = 0;
    // 0x04 SizeOfCode, 0x08 SizeOfInitializedData, 0x0c SizeOfUninitializedData (leave 0)
    // 0x10 AddressOfEntryPoint
    write_u32(&mut buf, opt_off + 0x10, entry_rva as u32);
    // 0x14 BaseOfCode (leave 0)
    // 0x18 ImageBase (u64, PE32+)
    write_u64(&mut buf, opt_off + 0x18, image_base);
    // 0x20 SectionAlignment
    write_u32(&mut buf, opt_off + 0x20, SECTION_ALIGN as u32);
    // 0x24 FileAlignment
    write_u32(&mut buf, opt_off + 0x24, FILE_ALIGN as u32);
    // 0x28..0x38 OS/image/subsystem versions (leave 0)
    // 0x38 SizeOfImage
    write_u32(&mut buf, opt_off + 0x38, size_of_image);
    // 0x3c SizeOfHeaders
    write_u32(&mut buf, opt_off + 0x3c, size_of_headers);
    // 0x40 CheckSum (0)
    // 0x44 Subsystem (u16) = 10 EFI_APPLICATION
    write_u16(&mut buf, opt_off + 0x44, SUBSYSTEM_EFI_APPLICATION);
    // 0x46 DllCharacteristics (0)
    // 0x48 SizeOfStackReserve (u64)
    write_u64(&mut buf, opt_off + 0x48, 0x100000);
    // 0x50 SizeOfStackCommit
    write_u64(&mut buf, opt_off + 0x50, 0x1000);
    // 0x58 SizeOfHeapReserve
    write_u64(&mut buf, opt_off + 0x58, 0x100000);
    // 0x60 SizeOfHeapCommit
    write_u64(&mut buf, opt_off + 0x60, 0x1000);
    // 0x68 LoaderFlags (0)
    // 0x6c NumberOfRvaAndSizes
    write_u32(&mut buf, opt_off + 0x6c, NUMBER_OF_RVA_AND_SIZES);
    // 0x70 DataDirectory[16] — all zero: this image needs no imports,
    // no relocations and no debug directory (it is position-dependent
    // and loaded at its link address).

    // Section table
    let sec_off = opt_off + opt_size as usize;
    for (i, si) in section_infos.iter().enumerate() {
        let s = sec_off + i * 40;
        // 8-byte name
        let name = match i {
            0 => b".text\0\0\0",
            1 => b".data\0\0\0",
            _ => b".rsrc\0\0\0",
        };
        buf[s..s + 8].copy_from_slice(name);
        write_u32(&mut buf, s + 8, si.sec_vsize as u32);            // VirtualSize
        write_u32(&mut buf, s + 12, si.va_aligned as u32);          // VirtualAddress
        write_u32(&mut buf, s + 16, si.raw_size as u32);            // SizeOfRawData
        write_u32(&mut buf, s + 20, si.raw_ptr as u32);             // PointerToRawData
        write_u32(&mut buf, s + 24, 0);                              // PointerToRelocations
        write_u32(&mut buf, s + 28, 0);                              // PointerToLinenumbers
        write_u16(&mut buf, s + 32, 0);                              // NumberOfRelocations
        write_u16(&mut buf, s + 34, 0);                              // NumberOfLinenumbers
        write_u32(&mut buf, s + 36, si.characteristics);             // Characteristics
    }

    // Section raw data
    for si in &section_infos {
        let dst_off = si.raw_ptr as usize;
        let end = dst_off + si.raw_data.len();
        if end > buf.len() {
            anyhow::bail!("section data overflows the PE image");
        }
        buf[dst_off..end].copy_from_slice(&si.raw_data);
    }

    fs::write(out_path, &buf)
        .with_context(|| format!("writing PE {}", out_path.display()))?;

    println!(
        "[WRAP] {} -> {}  machine={:#x} sections={} base={:#x} entry={:#x} image_size={:#x}",
        elf_path.display(),
        out_path.display(),
        machine,
        section_infos.len(),
        image_base,
        image_base + entry_rva,
        size_of_image
    );

    Ok(())
}

struct SectionInfo {
    va_aligned: u64,
    sec_vsize: u64,
    raw_size: u64,
    raw_ptr: u64,
    characteristics: u32,
    raw_data: Vec<u8>,
}

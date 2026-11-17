//! ELF64 → PE32+ (UEFI application) packager for riscv64/loongarch64.
//!
//! The bare-metal `uefiboot` ELF (built for `riscv64gc-unknown-none-elf` /
//! `loongarch64-unknown-none`, which have no official `*-unknown-uefi`
//! rustc target) is wrapped into a PE32+ image that UEFI firmware can load.
//!
//! Layout: every PT_LOAD segment becomes one PE section placed at its link
//! address (ImageBase = 0, VirtualAddress = p_paddr, section-aligned to
//! 0x1000).  The entry point is the ELF entry (`efi_main`).  UEFI passes
//! ImageHandle and SystemTable in the architecture's argument registers,
//! which match `efi_main`'s `extern "efiapi"` signature, so no relocation
//! stub is needed — the kernel entry contract is satisfied directly.
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

const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x200;
const IMAGE_BASE: u64 = 0;

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

    if &elf[..4] != ELF_MAGIC {
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

    let entry_rva = eh.e_entry as u32; // ImageBase = 0 => RVA == VA

    // ----- Compute section layout -----
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
        let va_aligned = align_down(s.p_paddr, SECTION_ALIGN);
        let section_end = align_up(s.p_paddr + s.p_memsz, SECTION_ALIGN);
        let sec_vsize = section_end - va_aligned;

        let raw_start = raw_offset;
        let rsize = s.p_filesz;
        let raw_end = align_up(raw_start + rsize, FILE_ALIGN);

        let mut raw_data = vec![0u8; (raw_end - raw_start) as usize];
        if rsize > 0 {
            let off = s.p_offset as usize;
            raw_data[..rsize as usize].copy_from_slice(&elf[off..off + rsize as usize]);
        }

        let mut characteristics: u32 = IMAGE_SCN_MEM_READ;
        if s.p_flags & 1 != 0 {
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        if s.p_flags & 2 != 0 {
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }
        if s.p_flags & 4 != 0 {
            characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        } else if rsize > 0 {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        } else {
            characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        }

        image_end = section_end;
        raw_offset = raw_end;
        section_infos.push(SectionInfo {
            va_aligned,
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

    // ----- Build the PE byte buffer -----
    // DOS header (64 bytes), only e_magic and e_lfanew matter.
    let mut buf = vec![0u8; size_of_headers as usize];
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
    write_u16(&mut buf, coff_off + 18, IMAGE_FILE_EXECUTABLE_IMAGE); // characteristics

    // Optional header (PE32+)
    let opt_off = coff_off + 20;
    // 0x00 magic (u16) = 0x20b
    write_u16(&mut buf, opt_off, PE32_PLUS_MAGIC);
    // 0x02 MajorLinkerVersion, 0x03 MinorLinkerVersion
    buf[opt_off + 2] = 0;
    buf[opt_off + 3] = 0;
    // 0x04 SizeOfCode, 0x08 SizeOfInitializedData, 0x0c SizeOfUninitializedData (leave 0)
    // 0x10 AddressOfEntryPoint
    write_u32(&mut buf, opt_off + 0x10, entry_rva);
    // 0x14 BaseOfCode (leave 0)
    // 0x18 ImageBase (u64, PE32+)
    write_u64(&mut buf, opt_off + 0x18, IMAGE_BASE);
    // 0x20 SectionAlignment
    write_u32(&mut buf, opt_off + 0x20, SECTION_ALIGN as u32);
    // 0x24 FileAlignment
    write_u32(&mut buf, opt_off + 0x24, FILE_ALIGN as u32);
    // 0x28..0x3c OS/image/subsystem versions (leave 0)
    // 0x3c Win32VersionValue (0)
    // 0x40 SizeOfImage
    write_u32(&mut buf, opt_off + 0x40, size_of_image);
    // 0x44 SizeOfHeaders
    write_u32(&mut buf, opt_off + 0x44, size_of_headers);
    // 0x48 Checksum (0)
    // 0x4c Subsystem (u16) = 10 EFI_APPLICATION
    write_u16(&mut buf, opt_off + 0x4c, SUBSYSTEM_EFI_APPLICATION);
    // 0x4e DllCharacteristics (0)
    // 0x50 SizeOfStackReserve (u64)
    write_u64(&mut buf, opt_off + 0x50, 0x100000);
    // 0x58 SizeOfStackCommit
    write_u64(&mut buf, opt_off + 0x58, 0x1000);
    // 0x60 SizeOfHeapReserve
    write_u64(&mut buf, opt_off + 0x60, 0x100000);
    // 0x68 SizeOfHeapCommit
    write_u64(&mut buf, opt_off + 0x68, 0x1000);
    // 0x70 LoaderFlags (0)
    // 0x74 NumberOfRvaAndSizes
    write_u32(&mut buf, opt_off + 0x74, 0); // no data directories
    // optional header size = 0x78 + ... actually PE32+ optional header is 0xE0 (224) with no data dirs?
    // The standard PE32+ optional header with 0 data directories is 0x78 bytes (120).
    // We set size_of_optional_header in COFF to opt_size which should be 0x78.
    // (opt_size computed from Optional64Template must equal 0x78.)

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
        buf[dst_off..dst_off + si.raw_data.len()].copy_from_slice(&si.raw_data);
    }

    fs::write(out_path, &buf)
        .with_context(|| format!("writing PE {}", out_path.display()))?;

    println!(
        "[WRAP] {} -> {}  machine={:#x} sections={} entry={:#x} image_size={:#x}",
        elf_path.display(),
        out_path.display(),
        machine,
        section_infos.len(),
        entry_rva,
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

/// Size of the PE32+ optional header with zero data directories (0x70 bytes).
/// The real header is hand-written above for full layout control; this
/// constant is only used to size the section table / headers region.
const OPT_SIZE: u64 = 0x70;

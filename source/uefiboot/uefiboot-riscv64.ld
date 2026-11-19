/* ============================================================================
 * Plan 9 Rust UEFI boot loader — RISC-V (RV64) linker script
 *
 * The loader runs as a UEFI application, so the firmware loads it at a
 * physical address of its choosing and calls it in S-mode with
 *   a0 = ImageHandle
 *   a1 = EFI SystemTable pointer
 *
 * The image is linked at a fixed address so the PE wrapper (build_tool's
 * wrap.rs) can map every PT_LOAD segment to its physical address.  The
 * address must sit in RAM and must not collide with the kernel image
 * (linked at 0x8020_0000) or with OpenSBI's own region.
 *
 *   0x8020_0000  — kernel image (linked by crates/kernel)
 *   0x8030_0000  — this loader
 * ============================================================================ */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

LOADER_BASE = 0x80300000;

/* Boot stack for the loader itself — 64 KiB, grows downward. */
LOADER_STACK_SIZE = 64K;

SECTIONS
{
    /* .text begins at LOADER_BASE so wrap.rs can derive ImageBase = LOADER_BASE
     * (one section-alignment below) while keeping entry RVA and first-section
     * RVA non-zero. */
    . = LOADER_BASE;

    .text : ALIGN(4K)
    {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }

    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
    }

    .tdata : { *(.tdata .tdata.*) }

    .bss (NOLOAD) : ALIGN(4K)
    {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)

        . = ALIGN(16);
        _bootstack_bottom = .;
        . += LOADER_STACK_SIZE;
        _bootstack_top = .;
    }

    . = ALIGN(4K);

    _loader_end = .;

    /DISCARD/ :
    {
        *(.note .note.*)
        *(.comment)
        *(.llvm_addrsig)
        *(.symtab .strtab)
        *(.debug_*)
    }
}

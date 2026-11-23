/* ============================================================================
 * Plan 9 Rust kernel — LoongArch64 linker script (QEMU virt)
 *
 * The kernel is linked at the physical load address; boot.S installs the
 * DMW direct-mapped windows before switching on paged translation, so the
 * cached-window view of the image is 0x8000_0000_0000_0000 | link address.
 *
 *   0x0020_0000 (2 MiB)   — KERNEL_PHYS_BASE — kernel image begins
 *   0x8000_0000_0020_0000 — cached-window view of the image
 *   ...                   — .text, .rodata, .data, .bss
 *   _kernel_end           — heap / frame allocator takes over from here
 * ============================================================================ */

OUTPUT_FORMAT("elf64-loongarch")
OUTPUT_ARCH(loongarch64)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x200000;

/* Stack size — 64 KiB for early boot. */
KERNEL_STACK_SIZE = 64K;

PHDRS {
    text     PT_LOAD FLAGS(5);    /* R+X */
    rodata   PT_LOAD FLAGS(4);    /* R   */
    data     PT_LOAD FLAGS(6);    /* R+W */
}

SECTIONS
{
    . = KERNEL_PHYS_BASE;

    .text : ALIGN(4K)
    {
        _text_start = .;
        *(.text._start)
        *(.text .text.*)
        _text_end = .;
    } :text

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    } :rodata

    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .tdata : { *(.tdata .tdata.*) } :data
    .tbss  : { *(.tbss  .tbss.*)  } :data

    .bss : ALIGN(4K)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;

        /* Kernel static stack — 64 KiB, grows downward. */
        . = ALIGN(16);
        _bootstack_bottom = .;
        . += KERNEL_STACK_SIZE;
        _bootstack_top = .;

        . = ALIGN(4K);
    } :data

    . = ALIGN(4K);

    _kernel_start = KERNEL_PHYS_BASE;
    _kernel_end   = .;

    /DISCARD/ :
    {
        *(.note .note.*)
        *(.comment)
        *(.llvm_addrsig)
        *(.symtab .strtab)
        *(.debug_*)
    }
}

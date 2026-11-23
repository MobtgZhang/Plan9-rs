/* ============================================================================
 * Plan 9 Rust kernel — AArch64 linker script (QEMU virt)
 *
 * The virt machine's RAM starts at 0x4000_0000. We link the kernel image
 * 32 MiB in (2 MiB-aligned) to keep it clear of the firmware/device-tree
 * region that QEMU places at the bottom of RAM.
 *
 *   0x4000_0000            — RAM base (QEMU virt)
 *   0x4020_0000            — KERNEL_PHYS_BASE — kernel image begins
 *   ...                    — .text, .rodata, .data, .bss
 *   _kernel_end            — heap / frame allocator takes over from here
 * ============================================================================ */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x40200000;

/* Stack size — 256 KiB for early boot (console/font paths are deep). */
KERNEL_STACK_SIZE = 256K;

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

    .vectors : ALIGN(2K)
    {
        KEEP(*(.vectors .vectors.*))
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
        *(.symtab .strtab)
        *(.debug_*)
    }
}

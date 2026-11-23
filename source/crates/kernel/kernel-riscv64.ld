/* ============================================================================
 * Plan 9 Rust kernel — RISC-V (RV64) linker script (QEMU virt + OpenSBI)
 *
 * OpenSBI occupies RAM below 0x8020_0000 and hands control to the kernel
 * there in S-mode.
 *
 *   0x8000_0000            — OpenSBI firmware
 *   0x8030_0000            — uefiboot loader image (UEFI boot path)
 *   0x8100_0000            — KERNEL_PHYS_BASE — kernel image begins
 *   ...                    — .text, .rodata, .data, .bss
 *   _kernel_end            — heap / frame allocator takes over from here
 *
 * The kernel sits 16 MiB above the RAM base: low allocations (the UEFI
 * loader image and its buffers cluster right above OpenSBI) must never
 * overlap the kernel image the loader copies into place.
 * ============================================================================ */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x81000000;

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
        *(.sdata .sdata.*)
        *(.got .got.*)
    } :data

    .tdata : { *(.tdata .tdata.*) } :data
    .tbss  : { *(.tbss  .tbss.*)  } :data

    .bss : ALIGN(4K)
    {
        _bss_start = .;
        *(.sbss .sbss.*)
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
        /* .symtab .strtab */
        /* .debug_* */
    }
}

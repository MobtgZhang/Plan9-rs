/* ============================================================================
 * Plan 9 Rust kernel — x86_64 linker script
 *
 * Builds a flat non-PIE ELF that can be loaded by GRUB via the Multiboot2
 * protocol. The Multiboot2 header (boot.S) must be the very first thing in
 * the file (within the first 32 KB) so we place .multiboot2 first in the
 * link order.
 *
 * Address layout (physical == virtual; we stay identity-mapped until paging
 * is enabled by the paging module):
 *
 *   0x0010_0000 (1 MB)    — GRUB typically starts loading here, leave room.
 *   0x0020_0000 (2 MB)    — KERNEL_PHYS_BASE — kernel image begins.
 *   ...                   — .multiboot2, .text, .rodata, .data, .bss
 *   _kernel_end           — end of image; kernel heap / page-table storage
 *                           is allocated by FrameAllocator starting just
 *                           after this point.
 *
 * The kernel stack is a static 64 KiB region in .bss (zero-initialised by
 * boot.S before kstart() is called).
 * ============================================================================ */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Physical load address. The kernel has historically been linked at
 * 2 MiB; we keep that to preserve compatibility with the well-tested
 * boot path used by GRUB and the existing multiboot2 stack. */
KERNEL_PHYS_BASE = 0x200000;

/* Stack size — 64 KiB is plenty for early boot before per-process stacks
 * are set up. */
KERNEL_STACK_SIZE = 64K;

PHDRS {
    text     PT_LOAD FLAGS(5);    /* R+X */
    rodata   PT_LOAD FLAGS(4);    /* R   */
    data     PT_LOAD FLAGS(6);    /* R+W */
}

SECTIONS
{
    /* -----------------------------------------------------------------------
     * 1. Multiboot2 header — must be first so GRUB finds it.
     * --------------------------------------------------------------------- */
    . = KERNEL_PHYS_BASE;

    .multiboot2 : ALIGN(8)
    {
        KEEP(*(.multiboot2 .multiboot2.*))
    } :text

    /* -----------------------------------------------------------------------
     * 2. Executable code. Text sections, including .text._start (where the
     *    real _start symbol lives, immediately after the multiboot header
     *    for cache locality).
     * --------------------------------------------------------------------- */
    .text : ALIGN(4K)
    {
        _text_start = .;
        *(.text._start)                   /* MUST be first: GRUB multiboot2 entry */
        *(.text._start_low)
        *(.text._start_init)
        *(.text._start_gdt)
        *(.text.reload_segments)
        *(.text .text.*)
        _text_end = .;
    } :text

    /* -----------------------------------------------------------------------
     * 3. Read-only data.
     * --------------------------------------------------------------------- */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    } :rodata

    /* -----------------------------------------------------------------------
     * 4. Initialised data (.data) + small uninitialised data (.tdata, .tbss).
     * --------------------------------------------------------------------- */
    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .tdata : { *(.tdata .tdata.*) } :data
    .tbss  : { *(.tbss  .tbss.*)  } :data

    /* -----------------------------------------------------------------------
     * 5. BSS — zero-initialised data + kernel stack.
     *
     *    boot.S zeros .bss after _start runs so we have a clean slate.
     * --------------------------------------------------------------------- */
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

    /* -----------------------------------------------------------------------
     * 5a. Scratch area — NOT cleared by boot.S. Used by boot.S to stash
     *     GRUB-provided RAX/RBX values before the BSS clear so kstart()
     *     can verify what GRUB actually handed us.
     *
     *     This sits after the BSS/stack block so it doesn't get zeroed.
     *     We place 16 bytes here (two u64s for magic + info pointer).
     * ----------------------------------------------------------------------- */
    .scratch : ALIGN(8)
    {
        . = ALIGN(16);
        _scratch_start = .;
        . += 16;
        _scratch_end = .;
    } :data

    /* -----------------------------------------------------------------------
     * 5b. Static page-table pool — placed in a separate 2 MiB-aligned,
     *     4 MiB-sized region. Must be reachable via the identity map
     *     (see MAPPED_BYTES in arch/src/x86_64/paging_init.rs). The pool
     *     lives outside .bss so the boot-time BSS clear doesn't touch it
     *     after our early page tables are built.
     * ----------------------------------------------------------------------- */
    .pagetable_pool : ALIGN(2M)
    {
        _pagetable_pool_start = .;
        KEEP(*(.pagetable_pool .pagetable_pool.*))
        . = _pagetable_pool_start + 4M;
        _pagetable_pool_end = .;
    } :data

    /* -----------------------------------------------------------------------
     * 6. Convenience symbols exposed to Rust.
     * --------------------------------------------------------------------- */
    _kernel_start = KERNEL_PHYS_BASE;
    _kernel_end   = .;

    /* Discard everything we don't need; this shrinks the ELF and avoids
     * accidentally keeping `.eh_frame` or `.note.*` in the loadable image. */
    /DISCARD/ :
    {
        *(.note .note.*)
        *(.comment)
        *(.llvm_addrsig)
        *(.symtab .strtab)
        *(.debug_*)
    }
}

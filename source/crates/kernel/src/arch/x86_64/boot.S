/* ============================================================================
 * Plan 9 Rust — Dual-mode boot entry point (x86_64)
 *
 * This file provides TWO entry points for GRUB:
 *
 *   _start64 (native 64-bit, used by GRUB UEFI x86_64):
 *     GRUB enters here directly in 64-bit long mode with paging enabled.
 *     The kernel is already running; we just set up stack and call kstart().
 *     RAX = 0x36D76289 (Multiboot2 magic)
 *     RDI = pointer to Multiboot2 info
 *
 *   _start_low (32-bit protected mode, used by legacy GRUB 32-bit):
 *     GRUB enters here in 32-bit protected mode without paging.
 *     We set up 4-level paging, enable PAE/long mode, then jump to _start.
 *
 * GRUB UEFI x86_64 prefers the native 64-bit entry over the 32-bit one.
 * ============================================================================ */

#include <arch/x86_64/multiboot2_constants.S>

/* --------------------------------------------------------------------------
 * Multiboot2 fixed header (16 bytes)
 * ------------------------------------------------------------------------ */
    .section .multiboot2, "a"
    .align 8

multiboot2_header:
    .long   MB2_MAGIC
    .long   MB2_ARCH_I386
    .long   multiboot2_header_end - multiboot2_header
    .long   -(MB2_MAGIC + MB2_ARCH_I386 + (multiboot2_header_end - multiboot2_header))

    /* Information request tag */
    .align 8
multiboot2_info_request:
    .short  HDR_TAG_INFORMATION_REQUEST
    .short  0
    .long   (multiboot2_info_request_end - multiboot2_info_request)
    .long   INFO_TAG_CMDLINE
    .long   INFO_TAG_MODULE
    .long   INFO_TAG_BOOTDEV
    .long   INFO_TAG_MEMORY_MAP
    .long   INFO_TAG_FRAMEBUFFER
    .long   INFO_TAG_ACPI_OLD
    .long   INFO_TAG_ACPI_NEW
multiboot2_info_request_end:

    /* Framebuffer tag */
    .align 8
multiboot2_framebuffer:
    .short  HDR_TAG_FRAMEBUFFER
    .short  0
    .long   (multiboot2_framebuffer_end - multiboot2_framebuffer)
    .long   1024
    .long   768
    .long   32
multiboot2_framebuffer_end:

    /* Module alignment tag */
    .align 8
multiboot2_module_align:
    .short  HDR_TAG_MODULE_ALIGN
    .short  0
    .long   (multiboot2_module_align_end - multiboot2_module_align)
multiboot2_module_align_end:

    /* EFI Boot Services termination tag */
    .align 8
multiboot2_efi_bs:
    .short  HDR_TAG_EFI_BS
    .short  0
    .long   (multiboot2_efi_bs_end - multiboot2_efi_bs)
multiboot2_efi_bs_end:

    /* End tag */
    .align 8
multiboot2_end:
    .short  HDR_TAG_END
    .short  0
    .long   (multiboot2_end_end - multiboot2_end)
multiboot2_end_end:

multiboot2_header_end:

/* ============================================================================
 * _start64 — Native 64-bit Multiboot2 entry point (used by GRUB UEFI x86_64)
 *
 * GRUB enters here directly in 64-bit long mode with:
 *   - Paging enabled
 *   - CR3 pointing to GRUB's page tables
 *   - RAX = 0x36D76289 (Multiboot2 magic)
 *   - RDI = pointer to Multiboot2 info structure
 *   - CS = 64-bit code segment (selector 0x08 or similar)
 *   - All other registers caller-saved (SysV ABI)
 *
 * We need to:
 *   1. Save magic/info to .scratch (in case BSS clear overwrites registers)
 *   2. Load our kernel stack pointer
 *   3. Set up a proper GDT (GRUB's GDT might not be right for us)
 *   4. Load segment registers
 *   5. Call kstart(magic, info_ptr)
 * ============================================================================ */

    .section .text._start64, "ax", @progbits
    .code64
    .global _start64
    .type   _start64, @function

_start64:
    /* Disable hardware interrupts until we have our own IDT set up.
     * Without this, the firmware's timer IRQ can fire while we are still
     * using the firmware's IDT (at 0x0F138xxx, not mapped in our page
     * tables), causing a triple-fault / reboot. */
    cli

    /* Serial marker: confirms we landed in 64-bit mode. */
    movw    $0x3F8, %dx
    movb    $'S', %al
    outb    %al, %dx
    movb    $'6', %al
    outb    %al, %dx
    movb    $'4', %al
    outb    %al, %dx
    movb    $'\n', %al
    outb    %al, %dx

    /* ------------------------------------------------------------
     * 1. Save Multiboot2 magic (RAX) and info pointer (RBX) to .scratch.
     *    GRUB multiboot2 on x86_64 passes: RAX = magic, RBX = info.
     * ------------------------------------------------------------ */
    leaq    _scratch_start(%rip), %rsi
    movq    %rax, (%rsi)
    movq    %rbx, 8(%rsi)

    /* ------------------------------------------------------------
     * 2. Load kernel stack pointer (provided by linker script).
     * ------------------------------------------------------------ */
    leaq    _bootstack_top(%rip), %rsp
    andq    $-16, %rsp                    /* 16-byte stack alignment */

    movw    $0x3F8, %dx
    movb    $'K', %al
    outb    %al, %dx

    /* ------------------------------------------------------------
     * 3. Reload segments to use known-good selectors. We re-use the
     *    GDT that `early_init()` will install (just the kernel
     *    code/data selectors from gdt::SEL_*). Until that runs we
     *    keep GRUB's selectors but flat-map them via a far return
     *    so future calls see consistent selectors.
     *
     *    Strategy: don't load our own GDT here. Just install a
     *    minimal GDT with NULL + flat 64-bit code (0x08) + flat
     *    64-bit data (0x10). This avoids conflicting with the GDT
     *    that `gdt_init()` will install later in Rust.
     * ------------------------------------------------------------ */
    lgdt    _start_gdt_ptr(%rip)

    /* CS reload via far return. retfq pops RIP from [rsp+0] then CS from
     * [rsp+8], so we must push CS first (lands higher on stack) and RIP
     * second (lands at [rsp+0]). */
    pushq   $0x08                /* [rsp+8] after second push = new CS  */
    leaq    .Lcs_reload64(%rip), %rax
    pushq   %rax                 /* [rsp]   after second push = new RIP */
    retfq
.Lcs_reload64:

    /* Now reload data segments */
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs

    movw    $0x3F8, %dx
    movb    $'G', %al
    outb    %al, %dx

    /* ------------------------------------------------------------
     * 4. CR4 / EFER are already configured by GRUB UEFI; do not touch.
     * ------------------------------------------------------------ */
    movw    $0x3F8, %dx
    movb    $'P', %al
    outb    %al, %dx

    /* ------------------------------------------------------------
     * 5. Call kstart(magic, info_ptr).
     *    We stash both into the scratch area in step 1; reload them
     *    here so kstart gets the right SysV-ABI arguments.
     * ------------------------------------------------------------ */
    movw    $0x3F8, %dx
    movb    $'C', %al
    outb    %al, %dx

    /* Reload magic and info from .scratch (safe against any register clobbering) */
    leaq    _scratch_start(%rip), %rax
    movq    0(%rax), %rdi              /* magic */
    movq    8(%rax), %rsi              /* info pointer */

    /* Print info pointer for debugging */
    movw    $0x3F8, %dx
    movb    $'[', %al
    outb    %al, %dx
    movb    $']', %al
    outb    %al, %dx
    movb    $'\n', %al
    outb    %al, %dx

    /* Call kstart(magic=RAX, info=RBX) */
    movq    %rax, %rdi
    movq    %rbx, %rsi
    call    kstart

    /* kstart never returns; halt if it does. */
0:  hlt
    jmp     0b

    .size   _start64, . - _start64

/* ============================================================================
 * _start_low — 32-bit protected-mode entry (legacy GRUB)
 *
 * This entry point is used when GRUB boots in 32-bit protected mode (no UEFI).
 * We set up 4-level paging, enable PAE/long mode, then far-jump to _start.
 * ============================================================================ */

    .section .text._start_low, "ax", @progbits
    .code32
    .global _start_low
    .type   _start_low, @function

_start_low:
    /* Disable hardware interrupts until we have our own IDT set up. */
    cli

    /* Serial marker: confirms we landed in 32-bit mode. */
    movw    $0x3F8, %dx
    movb    $'S', %al
    outb    %al, %dx
    movb    $'1', %al
    outb    %al, %dx

    /* Save multiboot2 magic in %eax and info pointer in %ebx to .scratch */
    movl    %eax, %esi
    movl    %ebx, %edi
    movl    $_scratch_start, %eax
    movl    %esi, (%eax)
    movl    %edi, 8(%eax)

    /* ------------------------------------------------------------------
     * Minimal page tables: PML4 + 1 PDPT. PML4[0] -> PDPT; PDPT[0]
     * is a 1 GiB huge page identity-mapping the first GiB of RAM.
     * ------------------------------------------------------------------ */
    movl    $_start_pgt, %edi
    movl    $(0x2000 / 4), %ecx
    xorl    %eax, %eax
    cld
    rep stosl

    /* Write PML4[0] -> PDPT at _start_pgt + 0x1000 */
    leal    _start_pgt + 0x1000, %eax
    orl     $0x03, %eax               /* P=1, R/W=1 */
    movl    %eax, _start_pgt

    /* Write PDPT[0] as 1 GiB huge page (identity map 0..1 GiB) */
    movl    $0x83, _start_pgt + 0x1000 /* phys=0, PS=1, R/W=1, P=1 */

    /* Load CR3 with our PML4 */
    movl    $_start_pgt, %eax
    movl    %eax, %cr3

    /* Set PAE in CR4 */
    movl    %cr4, %eax
    orl     $0x20, %eax
    movl    %eax, %cr4

    /* Set LME + NXE in EFER MSR */
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $0x900, %eax              /* LME=1, NXE=1 */
    wrmsr

    /* Set CR0.PG to enable paging (triggers long mode) */
    movl    %cr0, %eax
    orl     $0x80000000, %eax
    movl    %eax, %cr0

    /* Load our GDT */
    lgdt    _start_gdt_ptr

    /* Far jump to 64-bit code segment */
    pushl   $0x18                      /* 64-bit CS selector */
    pushl   $_start
    .byte   0x48, 0xcb                 /* lretq */

    .size   _start_low, . - _start_low

/* ----------------------------------------------------------------------------
 * GDT — null (0x00), 32-bit code (0x08), 32-bit data (0x10),
 * 64-bit code (0x18), 64-bit data (0x20). Flat memory model.
 * ------------------------------------------------------------------------- */
    .section .text._start_gdt, "a", @progbits
    .align  8
_start_gdt:
    .quad   0
    .quad   0x00CF9A000000FFFF        /* 0x08: 32-bit code */
    .quad   0x00CF92000000FFFF        /* 0x10: 32-bit data */
    .quad   0x00AF9A0000000000        /* 0x18: 64-bit code */
    .quad   0x00AF920000000000        /* 0x20: 64-bit data */
_start_gdt_end:

    .align  8
_start_gdt_ptr:
    .short  _start_gdt_end - _start_gdt
    .long   _start_gdt

/* ----------------------------------------------------------------------------
 * Page tables for _start_low (2 x 4 KiB): PML4 + PDPT.
 * PDPT[0] used as 1 GiB huge page.
 * ------------------------------------------------------------------------- */
    .section .bss._start_pgt, "aw", @nobits
    .align  4096
_start_pgt:
    .skip   4096                        /* PML4 */
    .skip   4096                        /* PDPT (entry #0 = 1 GiB huge) */
_start_pgt_end:

/* ----------------------------------------------------------------------------
 * _start — 64-bit long-mode entry (called by _start64 after stack/GDT setup,
 * or by _start_low after enabling long mode).
 *
 * In _start64 path: everything is already set up — just call kstart().
 * In _start_low path: long mode is enabled, GDT was loaded, CS was reloaded.
 * ---------------------------------------------------------------------------- */

    .section .text._start, "ax", @progbits
    .code64
    .global _start
    .type   _start, @function

_start:
    /* Disable hardware interrupts until we have our own IDT set up. */
    cli

    /* Serial debug: confirms we reached _start */
    movw    $0x3F8, %dx
    movb    $'S', %al
    outb    %al, %dx
    movb    $'3', %al
    outb    %al, %dx
    movb    $'\n', %al
    outb    %al, %dx

    /* Multiboot2 magic in RAX (from GRUB), info pointer in RBX.
     * Save to .scratch so kstart can read them safely (stack might not be ready). */
    leaq    _scratch_start(%rip), %rcx
    movq    %rax, (%rcx)             /* scratch[0] = magic */
    movq    %rbx, 8(%rcx)           /* scratch[8] = info pointer */

    /* Load kernel stack */
    leaq    _bootstack_top(%rip), %rsp
    andq    $-16, %rsp

    /* Call kstart(magic=RAX, info=RBX) */
    movq    %rax, %rdi
    movq    %rbx, %rsi
    call    kstart

    /* Should never return */
0:  hlt
    jmp     0b

    .size   _start, . - _start

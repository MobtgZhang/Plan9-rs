/* ============================================================================
 * Plan 9 Rust — AArch64 boot entry (QEMU virt, EL1)
 *
 * QEMU (`-M virt -bios none -kernel kernel.elf`) loads the ELF at its link
 * addresses (RAM base 0x4000_0000) and starts the CPU at the ELF entry in
 * AArch64 EL1 with the MMU and caches off.
 *
 * This stub:
 *   1. Masks all interrupts (DAIF).
 *   2. Installs a minimal EL1 exception vector table (VBAR_EL1).
 *   3. Loads the boot stack pointer from the linker script.
 *   4. Calls kstart(magic = 0, info = 0).
 *
 * The kernel never returns; the halt loop below is just a safe fallback.
 * ============================================================================ */

    .section .text._start, "ax"
    .global _start
_start:
    /* Mask all (D,A,I,F) interrupts. */
    msr     daifset, #0xF

    /* Install the minimal vector table. */
    ldr     x9, =_vectors_start
    msr     vbar_el1, x9
    isb

    /* Boot stack (from the linker script, in .bss). */
    ldr     x9, =_bootstack_top
    mov     sp, x9

    /* kstart(magic = 0, info = 0) — no Multiboot2 on this platform.
     * (Future firmware integration passes the device-tree pointer here.) */
    mov     x0, #0
    mov     x1, #0
    bl      kstart

    /* kstart never returns. */
hang:
    wfe
    b       hang

/* ----------------------------------------------------------------------------
 * Minimal AArch64 vector table: 16 entries × 128-byte slots (EL1 SP0 and
 * current-EL entries share spin loops; the kernel installs its real trap
 * handling later). Any exception halts with the PC parked on its slot.
 * -------------------------------------------------------------------------- */
    .section .vectors, "ax"
    .balign 2048                    /* 2 KiB-aligned, 2 KiB total. */
_vectors_start:
    .rept 16
    .balign 128
    b       .                       /* park on this slot forever        */
    .endr
_vectors_end:

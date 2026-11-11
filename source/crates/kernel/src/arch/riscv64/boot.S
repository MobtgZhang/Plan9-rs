/* ============================================================================
 * Plan 9 Rust — RISC-V (RV64) boot entry (S-mode, OpenSBI)
 *
 * Boot contract (OpenSBI fw_dynamic, `-bios opensbi...fw_dynamic.bin`):
 * OpenSBI loads the kernel ELF at its link address (0x8020_0000) and jumps
 * to the ELF entry in S-mode with:
 *   a0 = hart id
 *   a1 = device-tree blob pointer (DTB)
 *   All general registers otherwise unspecified.
 *
 * This stub:
 *   1. Saves the hart id into `tp` (the kernel's per-CPU convention).
 *   2. Loads the boot stack pointer from the linker script.
 *   3. Calls kstart(magic = 0, info = dtb).
 * ============================================================================ */

    .section .text._start, "ax"
    .global _start
_start:
    /* Save the hart id (a0) before it is reused for the C call. */
    mv      tp, a0

    /* Boot stack (from the linker script, in .bss). */
    la      sp, _bootstack_top

    /* kstart(magic = 0, info = dtb).
     * a1 (dtb) is already the second argument; clear a0. */
    li      a0, 0
    call    kstart

    /* kstart never returns. */
hang:
    wfi
    j       hang

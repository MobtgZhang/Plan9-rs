/* ============================================================================
 * Plan 9 Rust — LoongArch64 boot entry (QEMU virt)
 *
 * Boot contract: the CPU starts in PLV0 with CRMD.DA=1 / PG=0 (direct
 * address translation) at the kernel's link address (physical 0x200000).
 *
 * This stub installs three direct-mapped windows before enabling paged
 * translation:
 *
 *   DMW0 — VSEG 0  (0x0000...), coherent cached, PLV0.  Keeps the low
 *          physical link-space kernel image, stack and absolute data
 *          pointers addressable after PG is turned on.  VSEG=0 is a
 *          valid window (it matches addresses whose bits [63:60] are 0).
 *   DMW1 — VSEG 8  (0x8000...), coherent cached, PLV0.  Cached view of
 *          physical memory (kernel image and direct map).
 *   DMW2 — VSEG 9  (0x9000...), strongly uncached, PLV0.  MMIO (UART).
 *
 * DMW0 and DMW1 are fetch-capable; DMW2 is load/store-only, which is
 * enough for MMIO.  Because the low link-space image is mapped by DMW0,
 * we do not need to jump into a cached window: every absolute/low pointer
 * in the Rust image remains valid in paged mode.
 *
 * The kernel is linked at physical 0x200000 (see kernel-loongarch64.ld).
 * ============================================================================ */

    .section .text._start, "ax"
    .global _start
_start:
    /* DMW0: VSEG 0, MAT=1 (coherent cached), PLV0.  Keep the low kernel
     * image, boot stack and low data pointers mapped. */
    li.d    $t0, 0x0000000000000011
    csrwr   $t0, 0x180                   /* CSR.DMWIN0 */

    /* DMW1: VSEG 8, MAT=1 (coherent cached), PLV0.  Cached direct-map
     * view of physical memory used by the kernel. */
    li.d    $t0, 0x8000000000000011
    csrwr   $t0, 0x181                   /* CSR.DMWIN1 */

    /* DMW2: VSEG 9, MAT=0 (strongly uncached), PLV0.  MMIO window. */
    li.d    $t0, 0x9000000000000001
    csrwr   $t0, 0x182                   /* CSR.DMWIN2 */

    /* DMW3 unused. */
    csrwr   $zero, 0x183

    /* Enable paged translation: PLV=0, IE=0, PG=1. */
    li.w    $t0, 0xb0
    csrwr   $t0, 0x0                     /* CSR.CRMD */
    dbar    0
    ibar    0

    /* Boot stack (from the linker script, in .bss). */
    la.pcrel $sp, _bootstack_top

    /* kstart(magic = 0, info = 0). */
    li.d    $a0, 0
    li.d    $a1, 0
    bl      kstart

1:  b       1b                          /* kstart never returns. */

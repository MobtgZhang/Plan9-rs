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
 * User space deliberately lives OUTSIDE the DMW windows (VSEG 0xF — see
 * init_loader's USER_LOAD_BASE): a DMW window applies at PLV0 whenever
 * VA[63:60] matches, so user VAs under VSEG 0 would be translated
 * identity-style for the kernel too and user-pointer dereferences in the
 * syscall path would bypass the user page tables entirely.  VSEG 0xF is
 * covered by no window, so both PLV0 (kernel copyin/copyout) and PLV3
 * (user code) reach those addresses through the page-mapped TLB with
 * CSR.PGDL = the running process's root.
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

    /* Enable the FPU: CSR.EUEN.FPEN = 1.  The kernel's font/console
     * code contains float math and there is no lazy FP context
     * switching to support. */
    li.d    $t0, 0x1
    csrwr   $t0, 0x2                   /* CSR.EUEN */

    /* Exception vector config: ECFG.VS = 0 (every normal exception
     * vectors exactly to EENTRY — no per-code spacing) and ECFG.LIE = 0
     * (all interrupt lines masked; the kernel is interrupt-free). */
    csrwr   $zero, 0x4                   /* CSR.ECFG */

    /* Normal exception entry (syscalls, TLB-invalid, everything else). */
    la.pcrel $t0, _user_trap
    csrwr   $t0, 0xc                     /* CSR.EENTRY */

    /* TLB-refill exception entry (no TLB match for a page-mapped VA). */
    la.pcrel $t0, _user_trap_refill
    csrwr   $t0, 0x88                    /* CSR.TLBRENTRY */

    /* KS0 (saved-data register 0) = user trap frame base.  The trap
     * entries swap it with the user $sp, mirroring RISC-V's sscratch. */
    la.pcrel $t0, _user_trap_frame
    csrwr   $t0, 0x30                    /* CSR.KS0 */

    /* Enable paged translation: PLV=0, IE=0, PG=1. */
    li.w    $t0, 0xb0
    csrwr   $t0, 0x0                     /* CSR.CRMD */
    dbar    0
    ibar    0

    /* Boot stack (from the linker script, in .bss). */
    la.pcrel $sp, _bootstack_top

    /* kstart(magic, info) — the UEFI loader passes the Multiboot2 magic
     * in $a0 and the info pointer in $a1; forward them unchanged.  With
     * no loader both are zero, which fails the magic check inside
     * kstart and selects the architecture bring-up fallback path. */
    bl      kstart

1:  b       1b                          /* kstart never returns. */

/* ----------------------------------------------------------------------------
 * User trap frame area.
 *
 * 8 KiB in .bss: the top 34 u64 slots (272 bytes, 16-byte aligned at the
 * top) are the trap frame; everything below it is the scratch stack the
 * Rust handler runs on.
 *
 * Trap frame layout (u64 slots — mirrors the aarch64/riscv64 frames):
 *   [i]      $r(i+1)   for i = 0..30  ($r1..$r31; sp = $r3 is [2];
 *                      a0..a5 = $r4..$r9 are [3]..[8]; a7 = $r11 is [10])
 *   [31]     ERA  (offset 248)
 *   [32]     PRMD (offset 256, as trapped)
 *   [33]     padding
 * -------------------------------------------------------------------------- */

    .section .bss.user_trap, "aw", @nobits
    .balign 4096
    .global _user_trap_area
_user_trap_area:
    .space  8192
    .global _user_trap_frame
    .set    _user_trap_frame, _user_trap_area + 8192 - 34*8

/* ----------------------------------------------------------------------------
 * User-mode trap entries.
 *
 * On a trap from PLV3 the CPU switches to PLV0 with interrupts off but
 * keeps the user's $sp — like RISC-V, no hardware stack switch — so KS0
 * holds the frame base and the entry swaps sp <-> KS0 as its first
 * instruction. The separate, stackless TLB refill vector can also run
 * while the kernel is handling a syscall on this stack.
 *
 * Interrupts are off everywhere (kernel policy), so only exceptions
 * reach these entries:
 *   * ECODE 11    — `syscall`: the Plan 9 gate (number in $a7 = $r11,
 *     arguments in $a0..$a5 = $r4..$r9, result returned in $a0 = $r4).
 *     The syscall instruction does not advance ERA itself, so the
 *     handler adds 4 to the saved PC.
 *   * anything else is fatal and dumped by the handler.
 * -------------------------------------------------------------------------- */

    .section .text.user_trap, "ax"
    .balign 4
    .global _user_trap
_user_trap:
    csrwr   $t0, 0x31
    csrrd   $t0, 0x1
    andi    $t0, $t0, 3
    beqz    $t0, _kernel_fault
    csrrd   $t0, 0x31
    /* Swap sp (user sp) with KS0 (&frame): $sp = &frame, KS0 = user sp. */
    csrwr   $sp, 0x30
    st.d    $r1,  $sp, 0
    st.d    $r2,  $sp, 8
    st.d    $r12, $sp, 88
    /* The user sp moved into KS0 — store it into the $r3 slot. */
    csrrd   $t0, 0x30
    st.d    $t0,  $sp, 16
    st.d    $r4,  $sp, 24
    st.d    $r5,  $sp, 32
    st.d    $r6,  $sp, 40
    st.d    $r7,  $sp, 48
    st.d    $r8,  $sp, 56
    st.d    $r9,  $sp, 64
    st.d    $r10, $sp, 72
    st.d    $r11, $sp, 80
    st.d    $r13, $sp, 96
    st.d    $r14, $sp, 104
    st.d    $r15, $sp, 112
    st.d    $r16, $sp, 120
    st.d    $r17, $sp, 128
    st.d    $r18, $sp, 136
    st.d    $r19, $sp, 144
    st.d    $r20, $sp, 152
    st.d    $r21, $sp, 160
    st.d    $r22, $sp, 168
    st.d    $r23, $sp, 176
    st.d    $r24, $sp, 184
    st.d    $r25, $sp, 192
    st.d    $r26, $sp, 200
    st.d    $r27, $sp, 208
    st.d    $r28, $sp, 216
    st.d    $r29, $sp, 224
    st.d    $r30, $sp, 232
    st.d    $r31, $sp, 240
    csrrd   $t0, 0x6                   /* ERA */
    st.d    $t0,  $sp, 248
    csrrd   $t0, 0x1                   /* PRMD, as trapped */
    st.d    $t0,  $sp, 256

    or      $a0, $sp, $r0
    bl      loongarch64_user_trap_handler
    /* a0 = frame pointer (the syscall result sits in the $r4 slot). */

    ld.d    $t0,  $sp, 248
    csrwr   $t0, 0x6                   /* ERA := saved PC */
    ld.d    $t0,  $sp, 256
    ori     $t0, $t0, 0x3              /* PRMD.PPLV = 3 (return to PLV3) */
    csrwr   $t0, 0x1                   /* PRMD */

    /* KS0 := &frame for the next trap.  This must happen here, while
     * $sp still holds the frame base: after the register restore below
     * every GPR is user state (riscv64 likewise does `csrw sscratch,
     * sp` before its restore loop).  Writing KS0 from $sp at the end —
     * after $r3 (the user sp) has been loaded into it — would point
     * KS0 at the user stack, and the next trap would save its frame
     * there.  The old-KS0 read-back lands in $t0, which the restore
     * below reloads from the frame. */
    or      $t0, $sp, $r0
    csrwr   $t0, 0x30

    ld.d    $r1,  $sp, 0
    ld.d    $r2,  $sp, 8
    ld.d    $r4,  $sp, 24
    ld.d    $r5,  $sp, 32
    ld.d    $r6,  $sp, 40
    ld.d    $r7,  $sp, 48
    ld.d    $r8,  $sp, 56
    ld.d    $r9,  $sp, 64
    ld.d    $r10, $sp, 72
    ld.d    $r11, $sp, 80
    ld.d    $r12, $sp, 88
    ld.d    $r13, $sp, 96
    ld.d    $r14, $sp, 104
    ld.d    $r15, $sp, 112
    ld.d    $r16, $sp, 120
    ld.d    $r17, $sp, 128
    ld.d    $r18, $sp, 136
    ld.d    $r19, $sp, 144
    ld.d    $r20, $sp, 152
    ld.d    $r21, $sp, 160
    ld.d    $r22, $sp, 168
    ld.d    $r23, $sp, 176
    ld.d    $r24, $sp, 184
    ld.d    $r25, $sp, 192
    ld.d    $r26, $sp, 200
    ld.d    $r27, $sp, 208
    ld.d    $r28, $sp, 216
    ld.d    $r29, $sp, 224
    ld.d    $r30, $sp, 232
    ld.d    $r31, $sp, 240
    /* User sp (possibly rewritten by the handler) — the very last load
     * relative to the frame; after it $sp is user state. */
    ld.d    $r3,  $sp, 16
    ertn

_kernel_fault:
    bl      loongarch64_kernel_fault

/* Refill runs in direct-address mode and must leave the normal exception
 * CSRs and syscall stack alone: kernel accesses to user pages can miss too.
 * Walk the process root (PGDL) and load the 4 KiB pair using the dedicated
 * refill CSRs. Invalid leaves stay invalid and fault through EENTRY. */
    .global _user_trap_refill
_user_trap_refill:
    csrwr   $t0, 0x32
    csrwr   $t1, 0x33
    csrwr   $t2, 0x34
    csrrd   $t0, 0x89                  /* TLBRBADV */
    csrrd   $t1, 0x19                  /* PGDL */
    beqz    $t1, .Lrefill_invalid
    .irp shift,39,30,21
    bstrpick.d $t2, $t0, \shift+8, \shift
    alsl.d  $t2, $t2, $t1, 3
    ld.d    $t1, $t2, 0
    andi    $t2, $t1, 1
    beqz    $t2, .Lrefill_invalid
    bstrpick.d $t1, $t1, 47, 12
    slli.d  $t1, $t1, 12
    .endr
    bstrpick.d $t2, $t0, 20, 13
    alsl.d  $t1, $t2, $t1, 4
    ld.d    $t0, $t1, 0
    ld.d    $t1, $t1, 8
    ori     $t0, $t0, 0x10              /* MAT = coherent cached */
    ori     $t1, $t1, 0x10
    b       .Lrefill_fill
.Lrefill_invalid:
    or      $t0, $r0, $r0
    or      $t1, $r0, $r0
.Lrefill_fill:
    csrwr   $t0, 0x8c                   /* TLBRELO0 */
    csrwr   $t1, 0x8d                   /* TLBRELO1 */
    csrrd   $t0, 0x8e                   /* TLBREHI */
    li.d    $t1, 12                     /* PS = log2(4096) */
    bstrins.d $t0, $t1, 5, 0
    csrwr   $t0, 0x8e
    tlbfill
    csrrd   $t2, 0x34
    csrrd   $t1, 0x33
    csrrd   $t0, 0x32
    ertn

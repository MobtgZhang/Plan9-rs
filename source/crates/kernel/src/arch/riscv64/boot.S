/* ============================================================================
 * Plan 9 Rust — RISC-V (RV64) boot entry (S-mode)
 *
 * Boot contract (OpenSBI fw_dynamic, `-bios opensbi...fw_dynamic.bin`):
 * OpenSBI loads the kernel ELF at its link address (0x8100_0000) and jumps
 * to the ELF entry in S-mode with:
 *   a0 = hart id
 *   a1 = device-tree blob pointer (DTB)
 *   All general registers otherwise unspecified.
 *
 * This stub:
 *   1. Saves the hart id into `tp` (the kernel's per-CPU convention).
 *   2. Installs the supervisor trap entry (`stvec`) and points `sscratch`
 *      at the user trap frame — the pair makes user-mode syscalls and
 *      faults routable before the first `sret` into U-mode.
 *   3. Loads the boot stack pointer from the linker script.
 *   4. Calls kstart(magic, info).
 * ============================================================================ */

    .section .text._start, "ax"
    .global _start
_start:
    /* Save the hart id (a0) before it is reused for the C call. */
    mv      tp, a0

    /* The firmware may leave S-mode interrupt sources enabled (EDK2 sets
     * SSIE/STIE/SEIE in `sie` and can leave a timer armed, so STIP stays
     * pending). Clear the firmware's enables. The kernel arms and enables
     * its supervisor timer after the scheduler is initialized. */
    li      t0, -1
    csrc    sie, t0

    /* The kernel uses its current stack for supervisor traps. */
    la      t0, _user_trap
    csrw    stvec, t0
    csrw    sscratch, zero

    /* Boot stack (from the linker script, in .bss). */
    la      sp, _bootstack_top

    /* kstart(magic, info) — the UEFI loader passes the Multiboot2 magic
     * in a0 and the info pointer in a1; forward them unchanged.  When
     * booted via OpenSBI (-bios fw_dynamic) a0 holds the hart id instead,
     * which fails the magic check inside kstart and selects the
     * architecture bring-up fallback path.  The hart id was already
     * saved into tp above. */
    call    kstart

    /* kstart never returns. */
hang:
    wfi
    j       hang

/* ----------------------------------------------------------------------------
 * User-mode trap entry (stvec target).
 *
 * On a U-mode trap the CPU stays on the user's `sp` — RISC-V (unlike
 * AArch64) does not switch stacks automatically, so `sscratch` holds the
 * address of a dedicated kernel-side trap frame and the entry swaps
 * sp <-> sscratch as its very first instruction. The trap frame area also
 * provides the stack the Rust handler runs on. In S-mode sscratch is zero;
 * a supervisor fault saves its frame below the interrupted kernel stack.
 *
 * Trap frame layout (u64 slots, mirrors the aarch64 frame):
 *   [ 0..32]  x0..x31   (a0..a5 = [10..15]; syscall number in a7 = [17];
 *                        x2 = [2] holds the user sp)
 *   [32]      sepc
 *   [33]      sstatus   (as trapped: SPP=0, SIE=0; boot.S clears SPP/SPIE
 *                        on the way back out)
 *
 * The supervisor timer can interrupt U-mode. S-mode keeps interrupts masked.
 * -------------------------------------------------------------------------- */

    .section .bss.user_trap, "aw", @nobits
    .balign 4096
    .global _user_trap_area
_user_trap_area:
    .space  65536 - 34*8
    .global _user_trap_frame
_user_trap_frame:
    .space  34*8
    .global _user_trap_end
_user_trap_end:

    .section .text.user_trap, "ax"
    .balign 4
    .global _user_trap
_user_trap:
    csrrw   sp, sscratch, sp
    bnez    sp, 1f
    csrr    sp, sscratch
    addi    sp, sp, -34*8
1:

    sd      x1, 1*8(sp)
    sd      x3, 3*8(sp)
    sd      x4, 4*8(sp)
    sd      x5, 5*8(sp)
    sd      x6, 6*8(sp)
    sd      x7, 7*8(sp)
    sd      x8, 8*8(sp)
    sd      x9, 9*8(sp)
    sd      x10, 10*8(sp)
    sd      x11, 11*8(sp)
    sd      x12, 12*8(sp)
    sd      x13, 13*8(sp)
    sd      x14, 14*8(sp)
    sd      x15, 15*8(sp)
    sd      x16, 16*8(sp)
    sd      x17, 17*8(sp)
    sd      x18, 18*8(sp)
    sd      x19, 19*8(sp)
    sd      x20, 20*8(sp)
    sd      x21, 21*8(sp)
    sd      x22, 22*8(sp)
    sd      x23, 23*8(sp)
    sd      x24, 24*8(sp)
    sd      x25, 25*8(sp)
    sd      x26, 26*8(sp)
    sd      x27, 27*8(sp)
    sd      x28, 28*8(sp)
    sd      x29, 29*8(sp)
    sd      x30, 30*8(sp)
    sd      x31, 31*8(sp)

    /* Save the interrupted stack pointer and mark subsequent traps as S-mode. */
    csrrw   t0, sscratch, zero
    sd      t0, 2*8(sp)
    csrr    t0, sepc
    sd      t0, 32*8(sp)
    csrr    t0, sstatus
    sd      t0, 33*8(sp)

    /* Let the supervisor dereference user pointers (syscall arguments). */
    li      t0, (1 << 18)           /* sstatus.SUM */
    csrs    sstatus, t0

    mv      a0, sp
    call    riscv64_user_trap_handler
    /* a0 = frame pointer (the syscall result sits in slot 10). */

    ld      t0, 32*8(sp)
    csrw    sepc, t0
    /* Clear SPP (bit 8) and SPIE (bit 5): return to U-mode with the
     * kernel's interrupts-off policy intact. */
    ld      t0, 33*8(sp)
    li      t1, (1 << 8) | (1 << 5)
    not     t1, t1
    and     t0, t0, t1
    csrw    sstatus, t0
    /* Keep sscratch pointing at the frame for the next trap. */
    csrw    sscratch, sp

    ld      x1, 1*8(sp)
    ld      x3, 3*8(sp)
    ld      x4, 4*8(sp)
    ld      x5, 5*8(sp)
    ld      x6, 6*8(sp)
    ld      x7, 7*8(sp)
    ld      x8, 8*8(sp)
    ld      x9, 9*8(sp)
    ld      x10, 10*8(sp)
    ld      x11, 11*8(sp)
    ld      x12, 12*8(sp)
    ld      x13, 13*8(sp)
    ld      x14, 14*8(sp)
    ld      x15, 15*8(sp)
    ld      x16, 16*8(sp)
    ld      x17, 17*8(sp)
    ld      x18, 18*8(sp)
    ld      x19, 19*8(sp)
    ld      x20, 20*8(sp)
    ld      x21, 21*8(sp)
    ld      x22, 22*8(sp)
    ld      x23, 23*8(sp)
    ld      x24, 24*8(sp)
    ld      x25, 25*8(sp)
    ld      x26, 26*8(sp)
    ld      x27, 27*8(sp)
    ld      x28, 28*8(sp)
    ld      x29, 29*8(sp)
    ld      x30, 30*8(sp)
    ld      x31, 31*8(sp)
    /* User sp from the x2 slot — the last load relative to the frame. */
    ld      sp, 2*8(sp)
    sret

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

    /* kstart(magic, info) — the UEFI loader passes the Multiboot2 magic
     * in x0 and the info pointer in x1; forward them unchanged.  When
     * booted via `-kernel` (no loader) x0 holds the DTB pointer instead,
     * which fails the magic check inside kstart and selects the
     * architecture bring-up fallback path. */
    bl kstart

    /* kstart never returns. */
hang:
    wfe
    b       hang

/* ----------------------------------------------------------------------------
 * AArch64 vector table: 16 entries × 128-byte slots.
 *
 * ARMv8 layout (VBAR_EL1):
 *   0x000-0x180  current EL + SP0      (unused — kernel runs with SPx)
 *   0x200-0x380  current EL + SPx      (EL1: sync, IRQ, FIQ, error)
 *   0x400-0x580  lower EL, AArch64     (EL0: sync, IRQ, FIQ, error)
 *   0x600-0x780  lower EL, AArch32     (unused)
 *
 * SVC from EL0 is a *synchronous* exception (EC=0x15) and vectors to the
 * 0x400 sync slot; the Rust dispatcher splits SVC from real faults.
 *
 * Trap frame layout (on the kernel stack, 272 bytes):
 *   [8*i]  x0..x30    (i = 0..30; syscall number in x8, return in x0)
 *   [248]  PC         (ELR_EL1)
 *   [256]  PSTATE     (SPSR_EL1)
 *   [264]  user SP    (SP_EL0)
 * -------------------------------------------------------------------------- */
    .section .vectors, "ax"
    .balign 2048                    /* 2 KiB-aligned, 2 KiB total. */
_vectors_start:
    /* ---- 0x000: current EL (EL1) with SP0 — unused ---- */
    .rept 4
    b       vec_park
    .space  124
    .endr
    /* ---- 0x200: current EL (EL1) with SPx ---- */
    b       vec_el1_sync            /* 0x200 sync                        */
    .space  124
    b       vec_el1_irq             /* 0x280 IRQ                         */
    .space  124
    b       vec_el1_sync            /* 0x300 FIQ → fatal                 */
    .space  124
    b       vec_park                /* 0x380 error                       */
    .space  124
    /* ---- 0x400: lower EL (EL0), AArch64 ---- */
    b       vec_el0_sync            /* 0x400 sync: SVC (EC=0x15) or fault */
    .space  124
    b       vec_el0_irq             /* 0x480 IRQ                         */
    .space  124
    b       vec_park                /* 0x500 FIQ                         */
    .space  124
    b       vec_park                /* 0x580 error                       */
    .space  124
    /* ---- 0x600: lower EL, AArch32 — unused ---- */
    .rept 4
    b       vec_park
    .space  124
    .endr
_vectors_end:

/* ----------------------------------------------------------------------------
 * Trap-frame save/restore macros.
 * -------------------------------------------------------------------------- */
    .text

/* Save x0..x30, PC, PSTATE and (EL0) user SP into the 272-byte frame at
 * the current SP.  Clobbers x20-x22 as scratch. */
.macro SAVE_FRAME_FROM_EL0
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x20, elr_el1
    str     x20, [sp, #248]
    mrs     x21, spsr_el1
    str     x21, [sp, #256]
    mrs     x22, sp_el0
    str     x22, [sp, #264]
.endm

/* Restore a full trap frame; x0 holds the frame pointer on entry.
 * The base register (x28) is reloaded last.
 *
 * PC/PSTATE/user-SP are staged in x9/x10/x11 *before* the GPR restore
 * sequence so the msr's can run after every user register has been
 * loaded.  Using x22/x23/x24 as the staging registers (an earlier
 * version) destroyed the user's own x22/x23/x24: on every return from
 * an exception the user saw its SP/PC/PSTATE state copied into those
 * registers, corrupting e.g. a callee-saved length in init and making
 * memcpy run off the stack. */
.macro RESTORE_AND_ERET
    mov     x28, x0
    ldr     x9,  [x28, #264]        /* stage user SP                      */
    ldr     x10, [x28, #248]        /* stage PC                           */
    ldr     x11, [x28, #256]        /* stage PSTATE                       */
    /* Install the system-register state now: these msr's only take
     * effect at the final eret, and x9-x11 are reloaded with the user's
     * own values by the ldp sequence below. */
    msr     sp_el0, x9
    msr     elr_el1, x10
    msr     spsr_el1, x11
    ldp     x0, x1, [x28]
    ldp     x2, x3, [x28, #16]
    ldp     x4, x5, [x28, #32]
    ldp     x6, x7, [x28, #48]
    ldp     x8, x9, [x28, #64]
    ldp     x10, x11, [x28, #80]
    ldp     x12, x13, [x28, #96]
    ldp     x14, x15, [x28, #112]
    ldp     x16, x17, [x28, #128]
    ldp     x18, x19, [x28, #144]
    ldp     x20, x21, [x28, #160]
    ldp     x22, x23, [x28, #176]
    ldp     x24, x25, [x28, #192]
    ldp     x26, x27, [x28, #208]
    ldr     x29, [x28, #232]
    ldr     x30, [x28, #240]
    ldr     x28, [x28, #224]
    /* Restore SP_EL1 to its value at exception entry: the stub reserved
     * 272 bytes below it, so adding them back makes each EL0 excursion
     * stack-neutral.  Without this, SP_EL1 decays 272 bytes per exception
     * and eventually runs off the bottom of the kernel boot stack,
     * corrupting the .bss objects that live below it (e.g. the syscall
     * table's function pointers). */
    add     sp, sp, #272
    eret
.endm

/* ---- Vector targets ------------------------------------------------------ */
    .balign 16
vec_park:
    b       vec_park

/* EL0 synchronous exception: SVC (EC=0x15) goes to the syscall path;
 * anything else is fatal.  The Rust dispatcher reads ESR_EL1 itself. */
vec_el0_sync:
    sub     sp, sp, #272
    SAVE_FRAME_FROM_EL0
    mov     x0, sp
    bl      aarch64_el0_sync_handler
    RESTORE_AND_ERET

vec_el0_irq:
    sub     sp, sp, #272
    SAVE_FRAME_FROM_EL0
    mov     x0, sp
    bl      aarch64_irq_handler
    RESTORE_AND_ERET

/* Kernel-mode IRQ (EL1): a light ack-and-return.  The stub must preserve
 * every caller-saved register (x0-x18, x29, x30) — the handler may fire
 * in the middle of any kernel code path (e.g. a UART polling loop whose
 * scratch registers live in x8).  ELR is restored last. */
    .balign 16
vec_el1_irq:
    sub     sp, sp, #256
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    str     x18, [sp, #144]
    stp     x30, x29, [sp, #152]
    mrs     x29, elr_el1
    str     x29, [sp, #168]
    bl      aarch64_irq_el1_handler
    ldp     x0, x1, [sp]
    ldp     x2, x3, [sp, #16]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x9, [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x30, x29, [sp, #152]
    ldr     x18, [sp, #168]         /* ELR via scratch (x18 reloaded next) */
    msr     elr_el1, x18
    ldr     x18, [sp, #144]
    add     sp, sp, #256
    eret

/* Kernel-mode sync/data abort: fatal.  Pass ESR, FAR and ELR straight
 * to the Rust handler (no frame save needed — it never returns). */
    .balign 16
vec_el1_sync:
    sub     sp, sp, #272
    SAVE_FRAME_FROM_EL0
    mov     x0, sp
    b       aarch64_sync_el1_handler
    b       vec_park

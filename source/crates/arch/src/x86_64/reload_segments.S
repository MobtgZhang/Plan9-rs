/* ============================================================================
 * Plan 9 Rust — gdt reload stub (x86_64)
 *
 * Implements `reload_segments_trampoline()` declared in `gdt.rs`.
 *
 * Steps:
 *   1. Push the kernel CS selector (0x08) onto the stack.
 *   2. Push the address of label 1 (in 64-bit kernel CS) as the new RIP.
 *   3. retfq atomically switches CS:RIP.
 *   4. Reload DS / ES / SS with the kernel data selector (0x10).
 *
 * Live alongside the arch crate rather than the kernel crate's `boot.S`
 * so the trampoline travels with `gdt::reload_segments()`.
 * ============================================================================ */

    .section .text.reload_segments, "ax", @progbits
    .code64
    .global reload_segments_trampoline
    .type   reload_segments_trampoline, @function

reload_segments_trampoline:
    /* Step 1: kernel CS = 0x08 — first word, will be the new CS selector. */
    pushq    $0x08

    /* Step 2: new RIP = address of label 1 — pushed second so it sits
     * above the CS on the stack. After both pushes, [rsp] = RIP and
     * [rsp+8] = CS. */
    leaq     1f(%rip), %rax
    pushq    %rax

    /* Step 3: atomic CS:RIP reload. retfq pops RIP from [rsp] then CS
     * from [rsp+8] (per Intel SDM). We use this because the far-jump
     * opcode is not encodable in 64-bit mode and far returns are the
     * documented idiom. */
    retfq
1:
    /* Step 4: reload data segments with kernel DS = 0x10. */
    movw     $0x10, %ax
    mov      %ax, %ds
    mov      %ax, %es
    mov      %ax, %ss
    /* FS/GS already zeroed by boot.S; safe to leave as-is. */

    /* Return to the Rust caller. The trampoline consumed no caller
     * stack, so a plain ret is enough. */
    ret

    .size   reload_segments_trampoline, . - reload_segments_trampoline

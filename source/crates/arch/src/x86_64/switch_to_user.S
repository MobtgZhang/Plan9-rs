/* ============================================================================
 * switch_to_user — first transition into ring 3
 *
 * Called once from `kernel::entry::switch_to_user` with the kernel stack
 * arranged as:
 *
 *     rsp + 40:  user SS
 *     rsp + 32:  user RSP
 *     rsp + 24:  user RFLAGS (with IF set, IOPL=0)
 *     rsp + 16:  user CS
 *     rsp + 8:   user RIP (entry point of the loaded ELF)
 *     rsp + 0:   scratch slot the trampoline writes into
 *
 * On entry, rdi holds the physical address of the new PML4. We load it
 * into CR3, swap the data segments to ring-3 selectors, and iretq.
 *
 * The user SS/CS values are the canonical Plan 9 user selectors
 * (DSEL=0x2B | RPL 3 = 0x2B and CSEL=0x33). We trust the caller to have
 * pushed those onto the stack.
 * ============================================================================ */

    .section .text.switch_to_user, "ax", @progbits
    .code64
    .global switch_to_user_trampoline
    .type   switch_to_user_trampoline, @function

switch_to_user_trampoline:
    /* Save callee-preserved regs around CR3 write. */
    push    %rbx
    push    %rbp
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    /* rdi = new PML4 physical address. */
    mov     %rdi, %cr3

    /* Load user data-segment selectors. CS is restored by iretq. */
    mov     $0x2b, %ax         /* UDSEG | RPL 3 = 0x20 | 3 = 0x2B */
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %fs
    mov     %ax, %gs

    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbp
    pop     %rbx

    /* The kernel-side Rust glue pushed:
     *   [rsp+0]  scratch
     *   [rsp+8]  RIP
     *   [rsp+16] CS
     *   [rsp+24] RFLAGS
     *   [rsp+32] RSP
     *   [rsp+40] SS
     * Adjust rsp to skip the scratch slot, then iretq. */
    add     $8, %rsp
    iretq
    .size   switch_to_user_trampoline, . - switch_to_user_trampoline
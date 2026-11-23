/* ============================================================================
 * Plan 9 Rust — Interrupt/exception stubs for x86_64 IDT
 * ============================================================================ */

    .section .text.isr_stubs, "ax", @progbits
    .code64

/* --------------------------------------------------------------------------
 * Syscall, interrupt and exception handlers are defined in kernel/trap.rs.
 * ----------------------------------------------------------------------- */
    .extern kernel_exception_from_kernel
    .extern kernel_syscall_from_user
    .extern kernel_interrupt_from_user
    .extern kernel_exception_from_user

.macro SAVE_USER_REGISTERS
    pushq   %rax
    pushq   %rbx
    pushq   %rcx
    pushq   %rdx
    pushq   %rsi
    pushq   %rdi
    pushq   %rbp
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    cld
.endm

.macro ISR_STUB name, vector, has_err
    .align 8
    .global \name
    .type   \name, @function
\name:
    .if \vector != 2 && \vector != 8 && \vector != 18
        testb   $3, (8+8*\has_err)(%rsp)
        jz      1f
        SAVE_USER_REGISTERS
        movq    %rsp, %rsi
        andq    $-16, %rsp
        movq    $\vector, %rdi
        movq    $\has_err, %rdx
        call    kernel_exception_from_user
        ud2
1:
    .endif
    .if \has_err
        mov     0(%rsp), %rsi
        mov     8(%rsp), %rdx
        mov     $\vector, %rdi
    .else
        mov     0(%rsp), %rdx
        xor     %rsi, %rsi
        mov     $\vector, %rdi
    .endif
    cld
    andq    $-16, %rsp
    call    kernel_exception_from_kernel
    ud2
    .size   \name, . - \name
.endm

/* Exception stubs */
    ISR_STUB __isr_stub_0,   0,  0
    ISR_STUB __isr_stub_1,   1,  0
    ISR_STUB __isr_stub_2,   2,  0
    ISR_STUB __isr_stub_3,   3,  0
    ISR_STUB __isr_stub_4,   4,  0
    ISR_STUB __isr_stub_5,   5,  0
    ISR_STUB __isr_stub_6,   6,  0
    ISR_STUB __isr_stub_7,   7,  0
    ISR_STUB __isr_stub_8,   8,  1
    ISR_STUB __isr_stub_10, 10,  1
    ISR_STUB __isr_stub_11, 11,  1
    ISR_STUB __isr_stub_12, 12,  1
    ISR_STUB __isr_stub_13, 13,  1
    ISR_STUB __isr_stub_14, 14,  1
    ISR_STUB __isr_stub_16, 16,  0
    ISR_STUB __isr_stub_17, 17,  0
    ISR_STUB __isr_stub_18, 18,  0
    ISR_STUB __isr_stub_19, 19,  0
    ISR_STUB __isr_stub_20, 20,  0
    ISR_STUB __isr_stub_30, 30,  1

    .global __isr_stub_num_stubs
    .type   __isr_stub_num_stubs, @object
__isr_stub_num_stubs:
    .byte 0
    .size __isr_stub_num_stubs, . - __isr_stub_num_stubs

/* --------------------------------------------------------------------------
 * Hardware IRQ stubs (vectors 32..47).
 *
 * The CPU has already pushed the user IRET frame onto the kernel stack
 * selected by TSS.RSP0.  Save the user-visible registers, call the
 * kernel's interrupt dispatcher, restore the registers, and iretq so the
 * interrupted user program resumes exactly where it was.
 * ----------------------------------------------------------------------- */
.macro IRQ_STUB name, vector
    .align 8
    .global \name
    .type   \name, @function
\name:
    SAVE_USER_REGISTERS

    movq    %rsp, %rbp
    andq    $-16, %rsp
    movq    $\vector, %rdi
    movq    %rbp, %rsi
    call    kernel_interrupt_from_user
    movq    %rbp, %rsp

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rbp
    popq    %rdi
    popq    %rsi
    popq    %rdx
    popq    %rcx
    popq    %rbx
    popq    %rax

    iretq
    .size   \name, . - \name
.endm

    .section .text.irq_stubs, "ax", @progbits
    .code64
    IRQ_STUB __irq_stub_32, 32
    IRQ_STUB __irq_stub_33, 33
    IRQ_STUB __irq_stub_34, 34
    IRQ_STUB __irq_stub_35, 35
    IRQ_STUB __irq_stub_36, 36
    IRQ_STUB __irq_stub_37, 37
    IRQ_STUB __irq_stub_38, 38
    IRQ_STUB __irq_stub_39, 39
    IRQ_STUB __irq_stub_40, 40
    IRQ_STUB __irq_stub_41, 41
    IRQ_STUB __irq_stub_42, 42
    IRQ_STUB __irq_stub_43, 43
    IRQ_STUB __irq_stub_44, 44
    IRQ_STUB __irq_stub_45, 45
    IRQ_STUB __irq_stub_46, 46
    IRQ_STUB __irq_stub_47, 47

/* --------------------------------------------------------------------------
 * syscall_stub_entry
 *
 * Entry via `int 0x80` from ring 3.  The CPU has already pushed the
 * user IRET frame (RIP, CS, RFLAGS, RSP, SS) onto the kernel stack
 * selected by TSS.RSP0.  We save the user-visible registers above that
 * frame, call the kernel syscall handler, restore the registers, and
 * finally iretq using the original CPU frame.
 *
 * ----------------------------------------------------------------------- */
    .section .text.syscall_stub, "ax", @progbits
    .code64
    .global syscall_stub_entry
    .type   syscall_stub_entry, @function

syscall_stub_entry:
    SAVE_USER_REGISTERS

    /* Load the handler's four arguments from the saved slots. */
    movq    112(%rsp), %rdi
    movq    72(%rsp), %rsi
    movq    80(%rsp), %rdx
    movq    88(%rsp), %rcx

    /* Keep a stable anchor for the saved-register area and align the
     * stack for the C call.  The callee may change RSP, so restore it
     * from rbp afterwards.  Pass the anchor as the fifth argument (r8)
     * so the kernel can copy the saved user registers and CPU IRET frame. */
    movq    %rsp, %rbp
    movq    %rbp, %r8
    andq    $-16, %rsp

    call    kernel_syscall_from_user

    movq    %rbp, %rsp

    /* Restore user registers.  RAX intentionally keeps the syscall
     * return value, so the saved syscall number slot is discarded. */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rbp
    popq    %rdi
    popq    %rsi
    popq    %rdx
    popq    %rcx
    popq    %rbx
    addq    $8, %rsp        /* discard saved syscall number */

    iretq
    .size syscall_stub_entry, . - syscall_stub_entry

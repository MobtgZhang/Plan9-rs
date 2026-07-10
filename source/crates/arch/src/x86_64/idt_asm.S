/* ============================================================================
 * Plan 9 Rust — Interrupt/exception stubs for x86_64 IDT
 * ============================================================================ */

    .section .text.isr_stubs, "ax", @progbits
    .code64

/* --------------------------------------------------------------------------
 * default_exception_handler is defined in Rust (plan9-arch idt.rs).
 * We just declare it extern so the stubs can reference it.
 * ----------------------------------------------------------------------- */
    .extern default_exception_handler

.macro ISR_STUB name, vector, has_err
    .align 8
    .global \name
    .type   \name, @function
\name:
    .if \has_err
        pop     %rsi
        mov     0(%rsp), %rdx
        mov     $\vector, %rdi
    .else
        mov     0(%rsp), %rdx
        xor     %rsi, %rsi
        mov     $\vector, %rdi
    .endif
    jmp     default_exception_handler
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
    ISR_STUB __isr_stub_30, 30,  0

    .global __isr_stub_num_stubs
    .type   __isr_stub_num_stubs, @object
__isr_stub_num_stubs:
    .byte 0
    .size __isr_stub_num_stubs, . - __isr_stub_num_stubs

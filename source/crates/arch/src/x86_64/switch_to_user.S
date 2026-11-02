/* ============================================================================
 * switch_to_user — first transition into ring 3
 *
 * Called once from `kernel::entry::switch_to_user`.
 *
 *   rdi = physical address of the new PML4
 *   rsi = virtual address of the IRET frame page
 *
 * The IRET frame page layout (in increasing address order):
 *   [0] scratch slot (skipped by `add $8`)
 *   [1] user RIP
 *   [2] user CS
 *   [3] user RFLAGS (IF set, IOPL=0)
 *   [4] user RSP
 *   [5] user SS
 *
 * We replace the kernel stack with the IRET frame page, install the new
 * PML4, switch data segments to the ring-3 selectors, skip the scratch
 * slot, and iretq.  The user PML4 retains the kernel's low identity mapping
 * so the kernel's IDT/GDT handlers and this trampoline remain executable.
 * ============================================================================ */

    .section .text.switch_to_user, "ax", @progbits
    .code64
    .global switch_to_user_trampoline
    .type   switch_to_user_trampoline, @function

switch_to_user_trampoline:
    /* Debug markers: 'A' entering, 'B' stack switched, 'C' CR3 installed,
       'D' about to iretq. */
    mov     $0x3f8, %dx
    mov     $'A', %al
    out     %al, %dx

    /* Use the IRET frame page as the active stack. */
    mov     %rsi, %rsp

    mov     $'B', %al
    out     %al, %dx

    /* Install the user address space. */
    mov     %rdi, %cr3

    mov     $'C', %al
    out     %al, %dx

    /* Load user data-segment selectors. CS is restored by iretq. */
    mov     $0x2b, %ax         /* UDSEG | RPL 3 = 0x2B */
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %fs
    mov     %ax, %gs

    mov     $'D', %al
    out     %al, %dx

    /* RAX has been mutated by the debug output and segment loads.  The
       user entry stub's first instruction is `push %rax`; clear it so the
       push does not place a garbage value on the user stack (and so the
       first data access cannot fault on a bogus address). */
    xor     %eax, %eax

    /* Skip the scratch slot and iretq into ring 3. */
    add     $8, %rsp
    iretq
    .size   switch_to_user_trampoline, . - switch_to_user_trampoline

/* ============================================================================
 * kernel_resume_user — resume a saved ring-3 context
 *
 *   rdi = address of a SavedUserFrame (R15 at offset 0)
 *   rsi = physical address of the process PML4
 *
 * The frame layout is:
 *    0  r15      8  r14     16 r13     24 r12
 *   32  rbp     40 rbx     48 rdx     56 rsi
 *   64  rdi     72 rax     80 rip     88 cs
 *   96  rflags 104 rsp    112 ss
 *
 * Install the process address space, restore the user-visible registers,
 * point RSP at the IRET part of the frame, and iretq into ring 3.
 * ============================================================================ */
    .section .text.resume_user, "ax", @progbits
    .code64
    .global kernel_resume_user
    .type   kernel_resume_user, @function

kernel_resume_user:
    mov     %rsi, %cr3

    /* Keep the frame address in R11; RDI is overwritten by the user's RDI. */
    mov     %rdi, %r11

    mov     0(%r11),   %r15
    mov     8(%r11),   %r14
    mov     16(%r11),  %r13
    mov     24(%r11),  %r12
    mov     32(%r11),  %rbp
    mov     40(%r11),  %rbx
    mov     48(%r11),  %rdx
    mov     56(%r11),  %rsi
    mov     64(%r11),  %rdi
    mov     72(%r11),  %rax

    /* Load user data segments; use R10 so RAX keeps its return value. */
    mov     $0x2b, %r10
    mov     %r10w, %ds
    mov     %r10w, %es
    mov     %r10w, %fs
    mov     %r10w, %gs

    /* IRET frame starts at offset 80 inside the saved frame. */
    lea     80(%r11), %rsp
    iretq
    .size   kernel_resume_user, . - kernel_resume_user

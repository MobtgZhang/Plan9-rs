// AP startup trampoline.
//
// Linked as a flat binary at AP_TRAMPOLINE (0x50000) — the page whose
// physical address the BSP hands to APs with the SIPI vector.  The first
// 0x800 bytes hold code; the mailbox starts 0x800 bytes into the page.
// The BSP fills the mailbox before sending the INIT + SIPI sequence:
//
//   0x08  u64    ap_stack_top   (kernel virtual address)
//   0x10  u64    ap_entry       (Rust fn: ap_main(cpu_id))
//   0x18  u32    ap_cr3         (AP PML4 physical address)
//   0x28  u8[6]  lgdt operand   (limit16, base32 linear address)
//   0x30  u32    ap_cpu_id
//
// The AP wakes in 16-bit real mode at 0x50000, enables PAE + the AP page
// tables (which keep the 0..1 GiB identity map and the kernel-half mirror),
// turns on paging with EFER.LME, far-jumps to 64-bit mode, then calls the
// Rust entry with the per-CPU id in EDI.  If that ever returns, park.

.code16
.text
.globl ap_trampoline_start
ap_trampoline_start:
    cli
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x4f00, %sp
    mov $0x50800, %ebx
    mov %cr4, %eax
    or  $(1<<5), %eax
    mov %eax, %cr4
    mov 0x18(%ebx), %eax
    mov %eax, %cr3
    mov $0xC0000080, %ecx
    rdmsr
    or  $(1<<8), %eax
    wrmsr
    lgdt 0x28(%ebx)
    mov %cr0, %eax
    or  $((1<<31)|(1<<0)), %eax
    mov %eax, %cr0
    .byte 0x66
    .byte 0xEA
    .long stub64
    .word 0x08

.code64
stub64:
    mov 0x08(%rbx), %rsp
    mov 0x30(%rbx), %edi
    callq *0x10(%rbx)
park:
    cli
    hlt
    jmp park

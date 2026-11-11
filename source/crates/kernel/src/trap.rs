//! Trap and Interrupt Handling
//!
//! Implements the x86_64 trap/interrupt handling framework including:
//! - IDT (Interrupt Descriptor Table) setup
//! - Exception handlers
//! - System call handling
//! - Page fault handling

use crate::proc::{ curproc, curproc_mut, Proc, SavedUserFrame };use crate::sched::{scheduler, sched_ticks};
use crate::fault::page_fault_handler as do_page_fault;

/// Exec context for syscall return
/// Entry point stored here, retrieved before sysret after exec
#[no_mangle]
static mut SYSCALL_EXEC_ENTRY: u64 = 0;

/// Flag indicating exec context should be used for return
#[no_mangle]
static mut SYSCALL_USE_EXEC_CONTEXT: bool = false;

// ============================================================================
// Exception Frame
// ============================================================================

/// Exception frame - pushed by the CPU on interrupt/trap
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// Error code (for some exceptions)
    pub error_code: u64,
    /// Instruction pointer
    pub rip: u64,
    /// Code segment
    pub cs: u64,
    /// RFLAGS
    pub rflags: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Stack segment
    pub ss: u64,
}

/// System call frame - extends exception frame with syscall args
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    /// Parent frame
    pub exc: ExceptionFrame,
    /// Syscall number
    pub syscall_num: u64,
    /// Argument 0
    pub arg0: u64,
    /// Argument 1
    pub arg1: u64,
    /// Argument 2
    pub arg2: u64,
    /// Argument 3
    pub arg3: u64,
    /// Argument 4
    pub arg4: u64,
    /// Argument 5
    pub arg5: u64,
    /// Return value (set by handler)
    pub ret: u64,
}

impl SyscallFrame {
    /// Get argument by index (0-5)
    pub fn arg(&self, n: usize) -> u64 {
        match n {
            0 => self.arg0,
            1 => self.arg1,
            2 => self.arg2,
            3 => self.arg3,
            4 => self.arg4,
            5 => self.arg5,
            _ => 0,
        }
    }

    /// Set return value
    pub fn set_ret(&mut self, val: u64) {
        self.ret = val;
    }
}

// ============================================================================
// Exception Numbers
// ============================================================================

/// Exception vector numbers
pub mod exc {
    pub const DE: usize = 0;      // Divide by zero
    pub const DB: usize = 1;      // Debug
    pub const NMI: usize = 2;     // Non-maskable interrupt
    pub const BP: usize = 3;      // Breakpoint
    pub const OF: usize = 4;      // Overflow
    pub const BR: usize = 5;      // Bound range exceeded
    pub const UD: usize = 6;      // Undefined opcode
    pub const NM: usize = 7;      // No math coprocessor
    pub const DF: usize = 8;      // Double fault
    pub const TS: usize = 10;     // Invalid TSS
    pub const NP: usize = 11;     // Segment not present
    pub const SS: usize = 12;     // Stack fault
    pub const GP: usize = 13;     // General protection fault
    pub const PF: usize = 14;     // Page fault
    pub const MF: usize = 16;     // Math fault
    pub const AC: usize = 17;     // Alignment check
    pub const MC: usize = 18;     // Machine check
    pub const XM: usize = 19;     // SIMD floating point
    pub const VE: usize = 20;     // Virtualization exception

    /// Number of exceptions
    pub const NUM: usize = 32;
}

/// Interrupt numbers (external interrupts)
pub mod irq {
    pub const TIMER: usize = 32;      // Timer interrupt (PIT/HPET)
    pub const KEYBOARD: usize = 33;   // Keyboard
    pub const COM1: usize = 36;       // Serial port 1
    pub const COM2: usize = 35;       // Serial port 2
    pub const DISK: usize = 46;       // IDE/SATA disk
    pub const NETWORK: usize = 47;    // Network card
    pub const LAPIC: usize = 239;     // Local APIC timer

    /// Number of interrupts
    pub const NUM: usize = 16;
}

/// Total number of vectors (exceptions + interrupts)
#[cfg(target_arch = "x86_64")]
pub const NUM_VECTORS: usize = 256;

// ============================================================================
// IDT Entry
// ============================================================================

/// IDT entry structure (8 bytes)
#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg(target_arch = "x86_64")]
struct IdtEntry {
    /// Offset low 16 bits
    offset_low: u16,
    /// Code segment selector
    selector: u16,
    /// IST stack
    ist: u8,
    /// Type and attributes
    attr: u8,
    /// Offset middle 16 bits
    offset_mid: u16,
    /// Offset high 32 bits
    offset_high: u32,
    /// Reserved
    reserved: u32,
}

#[cfg(target_arch = "x86_64")]
impl IdtEntry {
    /// Create a new IDT entry
    const fn new(offset: u64, selector: u16, ist: u8, attr: u8) -> Self {
        Self {
            offset_low: offset as u16,
            selector,
            ist,
            attr,
            offset_mid: (offset >> 16) as u16,
            offset_high: (offset >> 32) as u32,
            reserved: 0,
        }
    }
}

/// IDT entry attributes
pub mod attr {
    pub const PRESENT: u8 = 0x80;
    pub const RING0: u8 = 0x00;
    pub const RING1: u8 = 0x20;
    pub const RING2: u8 = 0x40;
    pub const RING3: u8 = 0x60;

    // Gate types
    pub const TASK: u8 = 0x05;     // 386 task gate
    pub const INTR: u8 = 0x0E;     // 386 interrupt gate
    pub const TRAP: u8 = 0x0F;     // 386 trap gate
}

/// IDT register (loaded with lidt)
#[repr(C, packed)]
#[cfg(target_arch = "x86_64")]
struct IdtReg {
    /// IDT limit
    limit: u16,
    /// IDT base address
    base: u64,
}

// ============================================================================
// Global IDT
// ============================================================================

/// Global IDT storage
#[cfg(target_arch = "x86_64")]
static mut IDT: [IdtEntry; NUM_VECTORS] = [IdtEntry::new(0, 0, 0, 0); NUM_VECTORS];

// ============================================================================
// Exception Handlers
// ============================================================================

/// Exception handler function type
type ExHandler = fn(&ExceptionFrame);

/// Panic handler for unrecoverable exceptions
fn panic_handler(frame: &ExceptionFrame) {
    // Print exception info
    let _exc = frame.error_code;
    
    // Disable interrupts
    crate::plan9_arch::hal::cli();
    
    // Halt
    loop {
        crate::plan9_arch::hal::hlt();
    }
}

/// Page fault handler - calls the real implementation from fault.rs
fn page_fault_handler(frame: &ExceptionFrame) {
    do_page_fault(frame);
}

/// General protection fault handler
fn gp_fault_handler(frame: &ExceptionFrame) {
    panic!("General protection fault at {:#x}, error={:#x}", 
           frame.rip, frame.error_code);
}

/// Divide by zero handler
fn de_handler(frame: &ExceptionFrame) {
    panic!("Divide by zero at {:#x}", frame.rip);
}

/// Invalid opcode handler
fn ud_handler(frame: &ExceptionFrame) {
    panic!("Invalid opcode at {:#x}", frame.rip);
}

/// Double fault handler
fn df_handler(frame: &ExceptionFrame) {
    panic!("Double fault at {:#x}, error={:#x}", frame.rip, frame.error_code);
}

/// Exception handler table
static HANDLERS: [ExHandler; exc::NUM] = [
    de_handler,           // 0: Divide by zero
    panic_handler,        // 1: Debug
    panic_handler,        // 2: NMI
    panic_handler,        // 3: Breakpoint
    panic_handler,        // 4: Overflow
    panic_handler,        // 5: Bound range
    ud_handler,           // 6: Invalid opcode
    panic_handler,        // 7: No FPU
    df_handler,           // 8: Double fault
    panic_handler,        // 9: Coprocessor segment
    panic_handler,        // 10: Invalid TSS
    panic_handler,        // 11: Segment not present
    panic_handler,       // 12: Stack fault
    gp_fault_handler,    // 13: General protection
    page_fault_handler,  // 14: Page fault
    panic_handler,       // 15: Reserved
    panic_handler,       // 16: Math fault
    panic_handler,       // 17: Alignment check
    panic_handler,       // 18: Machine check
    panic_handler,       // 19: SIMD FP
    panic_handler,       // 20: Virtualization
    panic_handler,       // 21: Reserved
    panic_handler,       // 22: Reserved
    panic_handler,       // 23: Reserved
    panic_handler,       // 24: Reserved
    panic_handler,       // 25: Reserved
    panic_handler,       // 26: Reserved
    panic_handler,       // 27: Reserved
    panic_handler,       // 28: Reserved
    panic_handler,       // 29: Reserved
    panic_handler,       // 30: Reserved
    panic_handler,       // 31: Reserved
];

// ============================================================================
// Interrupt Handlers
// ============================================================================

/// Timer interrupt handler
/// 
/// This is called on every timer tick and handles:
/// - Scheduler time accounting
/// - Process preemption
/// - Alarm delivery
fn timer_interrupt() {
    // Update scheduler
    let sched = scheduler();
    sched.timer_tick();
    
    // Update process time
    if let Some(proc) = curproc_mut() {
        proc.utime += 1;

        // Check if we need to preempt
        if sched.should_preempt() && !proc.insyscall {
            // Set preempt flag
            proc.preempted = true;
        }
    }
    
    // Check for expired alarms and deliver SIGALRM
    check_and_deliver_alarms();
}

/// Check for expired alarms and deliver them to processes
/// 
/// This should be called from the timer interrupt handler.
/// It checks all registered alarms and delivers signals to processes
/// whose alarms have expired.
fn check_and_deliver_alarms() {
    // Get current ticks
    let current_ticks = sched_ticks();
    
    // Check the global alarm handler if it exists
    // For now, we check the current process's alarm directly
    if let Some(proc) = curproc_mut() {
        // Check if current process's alarm has expired
        if proc.alarm.expired(current_ticks) {
            // Consume the alarm
            proc.alarm.consume();

            // Post SIGALRM note to the process
            // In Plan 9, alarm fires as a note with "alarm" message.
            // We ignore the result since alarm delivery is fire-and-forget;
            // a failure to enqueue the note is not fatal to the kernel.
            let _ = proc.postnote(0, b"alarm\0");
        }
    }
}

/// Keyboard interrupt handler
///
/// Reads a PS/2 scancode from port 0x60, maps the common alphanumeric keys
/// to ASCII, and pushes the character into the console device's input buffer
/// so that reads on `/dev/console` (fd 0) can return typed characters.
fn keyboard_interrupt() {
    // Diagnostic: mark that we entered the keyboard interrupt.
    crate::serial::put_bytes(b"[kbd] irq\n");

    // Read scancode from PS/2 keyboard data port.
    let scan: u8 = crate::plan9_arch::hal::io::inb(0x60);

    crate::serial::put_bytes(b"[kbd] scan=");
    crate::serial::put_hex_u32(scan as u32);
    crate::serial::put_bytes(b"\n");

    // Ignore break codes (bit 7 set) and the 0xE0 extended prefix.
    let is_press = (scan & 0x80) == 0;
    let scan = scan & 0x7F;
    if scan == 0xE0 || !is_press {
        // Send EOI and wait for the next scan code.
        pic_eoi(1);
        return;
    }

    // Scan-code set 1 -> ASCII (lowercase, no modifier tracking).
    let ascii = match scan {
        0x02 => Some(b'1'), 0x03 => Some(b'2'), 0x04 => Some(b'3'), 0x05 => Some(b'4'),
        0x06 => Some(b'5'), 0x07 => Some(b'6'), 0x08 => Some(b'7'), 0x09 => Some(b'8'),
        0x0A => Some(b'9'), 0x0B => Some(b'0'), 0x0C => Some(b'-'), 0x0D => Some(b'='),
        0x0E => Some(0x7F), // Backspace
        0x0F => Some(b'\t'), // Tab
        0x10 => Some(b'q'), 0x11 => Some(b'w'), 0x12 => Some(b'e'), 0x13 => Some(b'r'),
        0x14 => Some(b't'), 0x15 => Some(b'y'), 0x16 => Some(b'u'), 0x17 => Some(b'i'),
        0x18 => Some(b'o'), 0x19 => Some(b'p'), 0x1A => Some(b'['), 0x1B => Some(b']'),
        0x1C => Some(b'\n'), // Enter
        0x1E => Some(b'a'), 0x1F => Some(b's'), 0x20 => Some(b'd'), 0x21 => Some(b'f'),
        0x22 => Some(b'g'), 0x23 => Some(b'h'), 0x24 => Some(b'j'), 0x25 => Some(b'k'),
        0x26 => Some(b'l'), 0x27 => Some(b';'), 0x28 => Some(b'\''), 0x29 => Some(b'`'),
        0x2B => Some(b'\\'), 0x2C => Some(b'z'), 0x2D => Some(b'x'), 0x2E => Some(b'c'),
        0x2F => Some(b'v'), 0x30 => Some(b'b'), 0x31 => Some(b'n'), 0x32 => Some(b'm'),
        0x33 => Some(b','), 0x34 => Some(b'.'), 0x35 => Some(b'/'),
        0x39 => Some(b' '), // Space
        _ => None,
    };

    if let Some(c) = ascii {
        // Deliver to the console device so `/dev/console` reads return input.
        if let Some(idx) = crate::dev::devs().find_by_char('c') {
            if let Some(dev) = crate::dev::devs_mut().get_mut(idx) {
                if let Some(cons) =
                    dev.as_any_mut().downcast_mut::<crate::dev::ConsDev>()
                {
                    cons.add_input(&[c]);
                }
            }
        }
    }

    // Acknowledge the keyboard interrupt on the PIC (IRQ1).
    pic_eoi(1);
}

/// Send End-Of-Interrupt to the master PIC for the given IRQ line.
fn pic_eoi(_irq: u8) {
    crate::plan9_arch::hal::io::outb(0x20, 0x20);
}

/// Spurious interrupt handler
fn spurious_interrupt() {
    // Do nothing
}

/// Handle a generic interrupt
pub fn handle_interrupt(vector: usize) {
    match vector {
        irq::TIMER => timer_interrupt(),
        irq::KEYBOARD => keyboard_interrupt(),
        _ => spurious_interrupt(),
    }
}

// ============================================================================
// System Call Handler
// ============================================================================

/// System call handler - dispatches to syscall module
/// Called from the syscall entry stub with the syscall number in rdi
fn syscall_handler(
    num: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    user_frame_ptr: u64,
) -> i64 {
    // Copy the CPU's IRET frame and the saved user registers into a stable
    // per-process frame.  The assembly stub points `user_frame_ptr` at the
    // first saved register (R15), and the IRET fields begin at +80 bytes.
    let saved = if user_frame_ptr != 0 {
        unsafe { core::ptr::read_unaligned(user_frame_ptr as *const SavedUserFrame) }
    } else {
        SavedUserFrame::default()
    };

    // Set up process context
    if let Some(proc) = curproc() {
        unsafe {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            p.insyscall = true;
            p.nsyscall += 1;
            p.user_frame = Some(saved);

            // Clear any previous exec context
            SYSCALL_USE_EXEC_CONTEXT = false;
            SYSCALL_EXEC_ENTRY = 0;
        }
    }

    // Create a syscall frame from the real user IRET frame.
    let frame = SyscallFrame {
        exc: ExceptionFrame {
            error_code: 0,
            rip: saved.rip,
            cs: saved.cs,
            rflags: saved.rflags,
            rsp: saved.rsp,
            ss: saved.ss,
        },
        syscall_num: num as u64,
        arg0: a0,
        arg1: a1,
        arg2: a2,
        arg3: a3,
        arg4: a4,
        arg5: a5,
        ret: 0,
    };

    // Dispatch to syscall handler in syscall.rs
    let result = crate::syscall::dispatch(num, &frame);

    // Check if exec was successful (exec sets exec_context in the process).
    // In Plan 9, exec replaces the process image, so resume user mode at the
    // new entry/stack directly instead of returning to the old syscall frame.
    if num == crate::syscall::nr::EXEC {
        if let Some(proc) = curproc() {
            unsafe {
                let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
                if p.has_exec_context() && result >= 0 {
                    let mut f = p.user_frame.unwrap_or_default();
                    f.rip = p.get_exec_entry();
                    f.rsp = p.get_exec_stack();
                    f.rax = 0;
                    f.cs = 0x23;
                    f.ss = 0x2B;
                    f.rflags = 1 << 9;
                    p.user_frame = Some(f);
                    p.clear_exec_context();
                    p.insyscall = false;

                    let frame_ptr = p
                        .user_frame
                        .as_ref()
                        .map(|fr| fr as *const SavedUserFrame as u64)
                        .unwrap_or(0);
                    let pml4 = p.mmupdb.as_u64();
                    plan9_arch::hal::switch_to_user::kernel_resume_user(
                        frame_ptr,
                        pml4,
                    );
                }
            }
        }
    }

    // Clear syscall context
    if let Some(proc) = curproc() {
        unsafe {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            p.insyscall = false;
        }
    }

    result
}

/// Get whether to use exec context for syscall return
#[inline]
pub fn should_use_exec_context() -> bool {
    unsafe { SYSCALL_USE_EXEC_CONTEXT }
}

// ============================================================================
// IDT Setup
// ============================================================================

/// Initialize the IDT
#[cfg(target_arch = "x86_64")]
pub fn init_idt() {
    let code_sel = 0x08; // Kernel code segment selector
    
    // Set up exception handlers
    for i in 0..exc::NUM {
        let handler = HANDLERS[i];
        let addr = handler as u64;
        let entry = IdtEntry::new(
            addr,
            code_sel,
            0, // No IST
            attr::PRESENT | attr::RING0 | attr::TRAP,
        );
        unsafe {
            IDT[i] = entry;
        }
    }
    
    // Set up syscall entry (interrupt 0x80 / 128)
    let syscall_addr = syscall_entry_stub as *const () as u64;
    let syscall_entry = IdtEntry::new(
        syscall_addr,
        code_sel,
        0,
        attr::PRESENT | attr::RING3 | attr::TRAP,
    );
    unsafe {
        IDT[0x80] = syscall_entry;
    }
    
    // Load IDT
    let idtr = IdtReg {
        limit: (NUM_VECTORS * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base: (&raw const IDT) as *const _ as u64,
    };
    
    unsafe {
        load_idt(&idtr);
    }
}

/// Load IDT via lidt instruction
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn load_idt(idtr: &IdtReg) {
    core::arch::asm!(
        "lidt [{0}]",
        in(reg) idtr,
        options(nostack, preserves_flags)
    );
}

// ============================================================================
// Assembly Stubs
// ============================================================================

/// System call entry assembly stub
///
/// This implements the syscall entry point for x86_64.
/// On syscall entry:
/// - RCX contains the return RIP
/// - R11 contains the RFLAGS
/// - RAX contains the syscall number
///
/// We save user context and call the handler.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn syscall_entry_stub() {
    unsafe {
        core::arch::asm!(
            // Save user return address and flags (clobbered by syscall)
            "push rcx",         // User RIP
            "push r11",         // User RFLAGS

            // Save syscall arguments (syscall clobbers rcx and r11)
            "push rax",         // Syscall number
            "push rdi",         // arg0
            "push rsi",         // arg1
            "push rdx",         // arg2
            "push r10",         // arg3 (not r8!)
            "push r8",          // arg4
            "push r9",          // arg5

            // Save callee-saved registers
            "push rbp",
            "push rbx",
            "push r12",
            "push r13",
            "push r14",
            "push r15",

            // Align stack to 16 bytes for C call
            "mov rbp, rsp",
            "and rsp, -16",

            // Load the syscall number and arguments from the saved stack.
            // Layout from rbp: r15, r14, r13, r12, rbx, rbp,
            // arg5, arg4, arg3, arg2, arg1, arg0, syscall_num, rflags, rip.
            // syscall_num is at rbp + 96; arg0..arg5 at rbp + 88 .. +48.
            "mov rdi, [rbp + 96]",
            "mov rsi, [rbp + 88]",
            "mov rdx, [rbp + 80]",
            "mov rcx, [rbp + 72]",
            "mov r8,  [rbp + 64]",
            "mov r9,  [rbp + 56]",
            "push qword ptr [rbp + 48]",

            // Call syscall handler (7 arguments: num + 6 syscall args)
            "call syscall_handler",

            // Restore stack pointer
            "mov rsp, rbp",

            // Check if we should return to exec context
            // Use r10 for the flag address so RAX keeps the syscall result.
            "mov r10, SYSCALL_USE_EXEC_CONTEXT",
            "cmp byte ptr [r10], 0",
            "jne 2f",

            // Exec return path: clear flag and use exec entry point
            "mov byte ptr [r10], 0",  // Clear flag
            "mov r12, SYSCALL_EXEC_ENTRY",  // Load exec entry into r12

            // Restore callee-saved registers
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",         // Restore original r12
            "pop rbx",
            "pop rbp",

            // Skip saved args (syscall number + 6 args = 7)
            "add rsp, 7*8",

            // Pop user RFLAGS but discard it
            "pop r11",
            // Use exec entry point as new RIP
            "mov rcx, r12",
            // Use default RFLAGS for user mode (IF set)
            "mov r11, 0x200",

            // Return to user mode to exec'd program
            "sysretq",

            "2:",  // normal return label
            // Restore callee-saved registers
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp",

            // Skip saved args (syscall number + 6 args = 7)
            "add rsp, 7*8",

            // Restore user RFLAGS and RIP for sysret
            "pop r11",         // RFLAGS
            "pop rcx",         // RIP (was user RIP, now goes to RCX for sysret)

            // Return to user mode
            "sysretq",

            options(noreturn)
        );
    }
}

/// Return to user mode after a system call or interrupt
///
/// # Safety
/// Must only be called when ready to return to user mode with valid state
#[inline]
#[cfg(target_arch = "x86_64")]
pub fn return_to_user(rip: u64, rsp: u64, rflags: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, {rsp}",
            "mov rcx, {rip}",
            "mov r11, {rflags}",
            "sysretq",
            rip = in(reg) rip,
            rsp = in(reg) rsp,
            rflags = in(reg) rflags,
            options(noreturn)
        );
    }
}

/// Alternative user return using iretq (for compatibility)
/// # Safety
/// Must only be called when in valid user context with proper stack
#[cfg(target_arch = "x86_64")]
pub fn return_to_user_iret(rip: u64, cs: u64, rsp: u64, ss: u64, rflags: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, {rsp}",
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            rip = in(reg) rip,
            cs = in(reg) cs,
            rsp = in(reg) rsp,
            ss = in(reg) ss,
            rflags = in(reg) rflags,
            options(noreturn)
        );
    }
}

/// Generic interrupt/exception entry stub
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn exception_entry_stub() {
    unsafe {
        core::arch::asm!(
            // Push error code (or 0 for those that don't)
            "push 0",
            
            // Push trap number
            "mov rsi, [rsp + 8]",
            "sub rsi, 1", // Adjust for pushed 0
            
            // Save registers
            "push rax",
            "push rbx",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "push rbp",
            
            // Get CR2 for page fault
            "mov rdi, cr2",
            
            // Get error code
            "mov rsi, [rsp + 16*8]", // Skip saved registers to error code
            
            // Call handler
            // handler(exc_frame_ptr, cr2_or_zero)
            
            // Restore (would restore from frame)
            "add rsp, 17*8",
            
            // Return from interrupt
            "iretq",
            
            options(noreturn)
        );
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize trap handling
#[cfg(target_arch = "x86_64")]
pub fn init() {
    init_idt();
}

/// Bridge used by the architecture crate's syscall stub.
///
/// The arch crate cannot depend on the kernel crate, so it declares this
/// symbol externally. The kernel provides the real implementation here and
/// routes the call through the full VFS/process-aware syscall table.
#[no_mangle]
pub extern "C" fn kernel_syscall_from_user(
    num: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    user_frame_ptr: u64,
) -> i64 {
    syscall_handler(num as usize, a0, a1, a2, 0, 0, 0, user_frame_ptr)
}

/// Bridge used by the architecture crate's hardware-IRQ stubs.
///
/// The stubs save the interrupted user register state and call this
/// function with the vector number.  We dispatch through the kernel's
/// existing interrupt table.  A timer tick also acknowledges the interrupt
/// controller so the source can deliver the next tick.
#[no_mangle]
pub extern "C" fn kernel_interrupt_from_user(vector: u64) {
    handle_interrupt(vector as usize);

    // The boot timer is normally IRQ0 / vector 32.  Acknowledge the
    // legacy 8259 PIC so a pending timer interrupt is not held forever.
    if vector == irq::TIMER as u64 {
        // Acknowledge the legacy 8259 PIC (master EOI, port 0x20).
        crate::plan9_arch::hal::io::outb(0x20, 0x20);
    }
}

/// Trigger a software interrupt (syscall)
#[cfg(target_arch = "x86_64")]
pub fn syscall(num: u64, arg0: u64, arg1: u64, arg2: u64,
               arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, {num}",
            "mov rdi, {a0}",
            "mov rsi, {a1}",
            "mov rdx, {a2}",
            "mov r10, {a3}",
            "mov r8, {a4}",
            "mov r9, {a5}",
            "int 0x80",
            "mov {ret}, rax",
            ret = lateout(reg) ret,
            num = in(reg) num,
            a0 = in(reg) arg0,
            a1 = in(reg) arg1,
            a2 = in(reg) arg2,
            a3 = in(reg) arg3,
            a4 = in(reg) arg4,
            a5 = in(reg) arg5,
        );
    }
    ret
}

/// Set up interrupt descriptor table with handler functions
#[cfg(target_arch = "x86_64")]
pub fn setup_idt_handlers() {
    init_idt();
}

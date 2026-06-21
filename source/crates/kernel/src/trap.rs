//! Trap and Interrupt Handling
//!
//! Implements the x86_64 trap/interrupt handling framework including:
//! - IDT (Interrupt Descriptor Table) setup
//! - Exception handlers
//! - System call handling
//! - Page fault handling

use crate::proc::{curproc, State, Proc};
use crate::sched::{scheduler, sched_ticks};
use crate::plan9_arch::x86_64::{cr2_read, cr3_read, cr3_write};
use crate::fault::page_fault_handler as do_page_fault;

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
pub const NUM_VECTORS: usize = 256;

// ============================================================================
// IDT Entry
// ============================================================================

/// IDT entry structure (8 bytes)
#[repr(C, packed)]
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

impl IdtEntry {
    /// Create a new IDT entry
    fn new(offset: u64, selector: u16, ist: u8, attr: u8) -> Self {
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
static mut IDT: [IdtEntry; NUM_VECTORS] = [IdtEntry::new(0, 0, 0, 0); NUM_VECTORS];

// ============================================================================
// Exception Handlers
// ============================================================================

/// Exception handler function type
type ExHandler = fn(&ExceptionFrame);

/// Panic handler for unrecoverable exceptions
fn panic_handler(frame: &ExceptionFrame) {
    // Print exception info
    let exc = frame.error_code;
    
    // Disable interrupts
    crate::plan9_arch::x86_64::cli();
    
    // Halt
    loop {
        crate::plan9_arch::x86_64::hlt();
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
    if let Some(proc) = curproc() {
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
    if let Some(proc) = curproc() {
        // Check if current process's alarm has expired
        if proc.alarm.expired(current_ticks) {
            // Consume the alarm
            proc.alarm.consume();
            
            // Post SIGALRM note to the process
            // In Plan 9, alarm fires as a note with "alarm" message
            proc.post_note(0, b"alarm\0".as_ptr() as u64);
        }
    }
}

/// Keyboard interrupt handler
fn keyboard_interrupt() {
    // Read keyboard scancode from PS/2 controller
    // For now, just acknowledge the interrupt
    
    // Send EOI if using PIC
    // pic_eoi(1); // IRQ1 for keyboard
    
    // TODO: Add scancode to keyboard buffer
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
fn syscall_handler(num: usize) -> i64 {
    // Set up process context
    if let Some(proc) = curproc() {
        unsafe {
            let p = &mut *(proc as *const Proc as *mut Proc);
            p.insyscall = true;
            p.nsyscall += 1;
        }
    }

    // Create a minimal syscall frame
    let frame = SyscallFrame {
        exc: ExceptionFrame {
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        },
        syscall_num: num as u64,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        ret: 0,
    };

    // Dispatch to syscall handler in syscall.rs
    let result = crate::syscall::dispatch(num, &frame);

    // Clear syscall context
    if let Some(proc) = curproc() {
        unsafe {
            let p = &mut *(proc as *const Proc as *mut Proc);
            p.insyscall = false;
        }
    }

    match result {
        Ok(n) => n as i64,
        Err(e) => e.to_usize() as isize as i64,
    }
}

// ============================================================================
// IDT Setup
// ============================================================================

/// Initialize the IDT
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
    let syscall_addr = syscall_entry_stub as u64;
    let syscall_entry = IdtEntry::new(
        syscall_addr,
        code_sel,
        0,
        attr::PRESENT | attr::RING0 | attr::INTR,
    );
    unsafe {
        IDT[0x80] = syscall_entry;
    }
    
    // Load IDT
    let idtr = IdtReg {
        limit: (NUM_VECTORS * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base: unsafe { &IDT as *const _ as u64 },
    };
    
    unsafe {
        load_idt(&idtr);
    }
}

/// Load IDT via lidt instruction
#[inline(always)]
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

            // Get syscall number from stack
            "mov rdi, [rbp + 7*8]",

            // Call syscall handler
            "call syscall_handler",

            // Restore stack pointer
            "mov rsp, rbp",

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
pub fn init() {
    init_idt();
}

/// Trigger a software interrupt (syscall)
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
pub fn setup_idt_handlers() {
    init_idt();
}

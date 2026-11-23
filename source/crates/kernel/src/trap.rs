//! Trap and Interrupt Handling
//!
//! Implements the x86_64 trap/interrupt handling framework including:
//! - IDT (Interrupt Descriptor Table) setup
//! - Exception handlers
//! - System call handling
//! - Page fault handling

use crate::proc::{curproc, Proc, SavedUserFrame};
use crate::sched::scheduler;
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
    panic!("unhandled kernel exception: pc={:#x} sp={:#x} error={:#x}",
        frame.rip, frame.rsp, frame.error_code);
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
fn timer_interrupt() {
    scheduler().timer_tick();
}

/// Keyboard interrupt handler
///
/// Reads a PS/2 scancode from port 0x60, maps the common alphanumeric keys
/// to ASCII, and pushes the character into the console device's input buffer
/// so that reads on `/dev/console` (fd 0) can return typed characters.
fn keyboard_interrupt() {
    // Claim the keyboard controller so the polling read path stands down
    // while this interrupt is being processed.
    crate::keymap::in_irq_mark();
    let delivered = keyboard_interrupt_inner();
    if delivered {
        crate::keymap::mark_irq_delivered();
    }
    crate::keymap::in_irq_clear();
    // Acknowledge the keyboard interrupt on the PIC (IRQ1).
    pic_eoi(1);
}

/// Body of the keyboard interrupt; returns true when a keystroke was
/// delivered to the console input buffer.
fn keyboard_interrupt_inner() -> bool {
    // Read scancode from PS/2 keyboard data port.
    let scan: u8 = crate::plan9_arch::hal::io::inb(0x60);

    // Translate through the shared keymap so that modifiers, Caps Lock and
    // the extended cursor keys behave the same here and in the polling path.
    let bytes = crate::keymap::translate(scan);
    if !bytes.is_empty() {
        if let Some(idx) = crate::dev::devs().find_by_char('c') {
            if let Some(dev) = crate::dev::devs_mut().get_mut(idx) {
                if let Some(cons) = dev
                    .as_any_mut()
                    .and_then(|device| device.downcast_mut::<crate::dev::ConsDev>())
                {
                    cons.add_input(bytes);
                    return true;
                }
            }
        }
    }
    false
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
#[cfg(target_arch = "x86_64")]
fn syscall_handler(
    num: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    user_frame_ptr: u64,
) -> i64 {
    #[cfg(target_arch = "x86_64")]
    unsafe { crate::userfp::capture() };
    // Copy the CPU's IRET frame and the saved user registers into a stable
    // per-process frame.  The assembly stub points `user_frame_ptr` at the
    // first saved register (R15), and the IRET fields begin at +120 bytes.
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
        arg3: saved.r10,
        arg4: saved.r8,
        arg5: saved.r9,
        ret: 0,
    };

    crate::syscall::user_syscall_entry(2);
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
                    f.set_entry(p.get_exec_entry());
                    f.set_stack(p.get_exec_stack());
                    f.set_ret(0);
                    #[cfg(target_arch = "x86_64")]
                    {
                        f.cs = 0x23;
                        f.ss = 0x2B;
                        f.rflags = 1 << 9;
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        f.pstate = plan9_arch::hal::switch_to_user::USER_PSTATE_INIT;
                    }
                    p.user_frame = Some(f);
                    p.clear_exec_context();
                    p.insyscall = false;
                    crate::syscall::user_exec_return();

                    crate::userfp::resume(p);
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

    crate::syscall::user_return(result);
    result
}

/// ============================================================================
// AArch64 trap entry (called from arch/aarch64/boot.S vector table)
// ============================================================================

/// EL0 synchronous exception dispatcher.
///
/// SVC from EL0 (EC=0x15) vectors to the sync slot; everything else is a
/// genuine fault.  `fp` points at the 800-byte trap frame saved by the
/// vector stub: x0..x30 at [8*i], PC at [248], PSTATE at [256], user SP
/// at [264].
///
/// Returns the frame pointer for the stub's restore-and-ERET. Faults
/// dispatch a note through the process's saved frame or exit the process.
///
/// # Safety
/// `fp` must point at a live trap frame on the kernel stack.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_el0_sync_handler(fp: *mut u64) -> u64 {
    let esr = read_esr_el1();
    let ec = (esr >> 26) & 0x3F;
    if ec == 0x15 {
        // SVC — the Plan 9 syscall gate.
        return aarch64_svc_handler(fp);
    }
    let saved = fp.cast::<SavedUserFrame>().read();
    let (reason, address) = match ec {
        0x20 => ("fault execute", Some(read_far_el1())),
        0x24 => {
            let reason = if esr & (1 << 6) == 0 { "fault read" } else { "fault write" };
            (reason, Some(read_far_el1()))
        }
        0x22 | 0x26 => ("alignment fault", None),
        0x3c => ("breakpoint", None),
        _ => ("illegal instruction", None),
    };
    crate::syscall::user_fault(saved, reason, address)
}

/// SVC from EL0: the Plan 9 syscall gate.
///
/// `fp` points at the 272-byte trap frame saved by the vector stub:
/// x0..x30 at [8*i], PC at [248], PSTATE at [256], user SP at [264].
/// The syscall number travels in x8, arguments in x0-x5, the return
/// value is written back into x0.
///
/// # Safety
/// `fp` must point at a live trap frame on the kernel stack.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_svc_handler(fp: *mut u64) -> u64 {
    let num = *fp.add(8) as usize;
    let a0 = *fp.add(0);
    let a1 = *fp.add(1);
    let a2 = *fp.add(2);
    let a3 = *fp.add(3);
    let a4 = *fp.add(4);
    let a5 = *fp.add(5);

    let saved = fp.cast::<SavedUserFrame>().read();

    // Process context, mirroring the x86_64 syscall path.
    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = true;
        p.nsyscall += 1;
        p.user_frame = Some(saved);
        SYSCALL_USE_EXEC_CONTEXT = false;
        SYSCALL_EXEC_ENTRY = 0;
    }

    let frame = SyscallFrame {
        exc: crate::trap::ExceptionFrame {
            error_code: 0,
            rip: saved.pc,
            cs: 0,
            rflags: saved.pstate,
            rsp: saved.sp,
            ss: 0,
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

    crate::syscall::user_syscall_entry(4);
    let result = crate::syscall::dispatch(num, &frame);

    if num == crate::syscall::nr::EXEC {
        if let Some(proc) = curproc() {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            if p.has_exec_context() && result >= 0 {
                let mut f = p.user_frame.unwrap_or_default();
                f.set_entry(p.get_exec_entry());
                f.set_stack(p.get_exec_stack());
                f.set_ret(0);
                f.pstate = plan9_arch::hal::switch_to_user::USER_PSTATE_INIT;
                p.user_frame = Some(f);
                p.clear_exec_context();
                p.insyscall = false;
                crate::syscall::user_exec_return();

                crate::userfp::resume(p);
            }
        }
    }

    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = false;
    }

    crate::syscall::user_return(result);
    *fp = result as u64;
    fp as u64
}

/// IRQ from EL0 (timer tick): acknowledge, rearm, and maybe preempt.
///
/// # Safety
/// `fp` must point at a live trap frame on the kernel stack.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_irq_handler(fp: *mut u64) -> u64 {
    if gic_irq_eoi() {
        crate::syscall::user_tick(fp.cast::<SavedUserFrame>().read());
    }
    fp as u64
}

/// Synchronous exception (data abort, bad instruction, ...) — fatal.
///
/// # Safety
/// `fp` must point at a live trap frame on the kernel stack.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_sync_handler(fp: *mut u64) -> ! {
    let esr = read_esr_el1();
    let far = read_far_el1();
    crate::cons::puts(b"\nPANIC: aarch64 sync exception\n");
    crate::cons::puts(b"  ESR=");
    crate::serial::put_hex_u64(esr);
    crate::cons::puts(b" FAR=");
    crate::serial::put_hex_u64(far);
    crate::cons::puts(b"\n  frame pc=");
    crate::serial::put_hex_u64(*fp.add(31));
    crate::cons::puts(b" sp=");
    crate::serial::put_hex_u64(*fp.add(33));
    crate::cons::puts(b"\n");
    hlt_forever();
}

/// Kernel-mode synchronous exception (from the EL1 vector stub, which now
/// passes a pointer to the full 272-byte trap frame in x0).  Fatal.
/// Dumps ESR/FAR/ELR and every GPR so a clobbered return address or
/// function pointer (e.g. a jump to PC=0x65) can be identified.
///
/// # Safety
/// Never returns; called only from `vec_el1_sync`.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_sync_el1_handler(fp: *mut u64) -> ! {
    let esr = read_esr_el1();
    let far = read_far_el1();
    let elr = *fp.add(31); // ELR saved at frame offset 248
    panic!("aarch64 kernel exception: ESR={esr:#x} FAR={far:#x} ELR={elr:#x}");
}

/// Kernel-mode IRQ (EL1): acknowledge the GIC and return.  No scheduling
/// from kernel mode — preemption happens at the next user-mode tick.
///
/// # Safety
/// Called only from the EL1 IRQ vector with a minimal 64-byte frame.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aarch64_irq_el1_handler() {
    gic_irq_eoi();
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn hlt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_esr_el1() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) v, options(nomem, nostack)) };
    v
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_far_el1() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) v, options(nomem, nostack)) };
    v
}

// ---- GICv2 (QEMU virt: GICD @0x0800_0000, GICC @0x0801_0000) ------------

#[cfg(target_arch = "aarch64")]
mod gic {
    const GICD_BASE: u64 = 0x0800_0000;
    const GICC_BASE: u64 = 0x0801_0000;
    /// Generic timer virtual interrupt (PPI 11 → GIC id 27).
    pub const IRQ_CNTV: usize = 27;

    #[inline]
    pub unsafe fn gicd_read(off: usize) -> u32 {
        core::ptr::read_volatile((GICD_BASE + off as u64) as *const u32)
    }

    #[inline]
    pub unsafe fn gicd_write(off: usize, v: u32) {
        core::ptr::write_volatile((GICD_BASE + off as u64) as *mut u32, v);
    }

    #[inline]
    pub unsafe fn gicc_read(off: usize) -> u32 {
        core::ptr::read_volatile((GICC_BASE + off as u64) as *const u32)
    }

    #[inline]
    pub unsafe fn gicc_write(off: usize, v: u32) {
        core::ptr::write_volatile((GICC_BASE + off as u64) as *mut u32, v);
    }

    /// Bring up the GIC CPU interface and enable the generic timer IRQ.
    pub fn init() {
        unsafe {
            // Distributor: enable group 0 + group 1.
            gicd_write(0x000, 0x3);
            // Route the timer PPI to this CPU and enable it.
            let id = IRQ_CNTV;
            // GICD_ISENABLER<n> for ids 32n..; id 27 lives in ISENABLER0.
            gicd_write(0x100, 1u32 << (id & 31));
            // GICC: priority mask (all), enable.
            gicc_write(0x004, 0xFF);
            gicc_write(0x000, 0x1);
        }
    }

    /// Acknowledge the pending IRQ and send EOI.  Rearm the timer when
    /// the tick interrupt fired.
    pub unsafe fn irq_eoi() -> bool {
        let iar = gicc_read(0x00C);
        let id = (iar & 0x3FF) as usize;
        if id < 1020 {
            if id == IRQ_CNTV {
                // Rearm the oneshot comparator for the next tick.
                plan9_arch::aarch64::timer::set_oneshot(1);
                // Account the tick so `sched_ticks()` advances.
                crate::sched::scheduler().timer_tick();
            }
            gicc_write(0x010, iar);
        }
        id == IRQ_CNTV
    }
}

#[cfg(target_arch = "aarch64")]
fn gic_irq_eoi() -> bool {
    unsafe { gic::irq_eoi() }
}

/// Initialize the aarch64 interrupt subsystem (GIC + timer IRQ).
#[cfg(target_arch = "aarch64")]
pub fn init_interrupts_aarch64() {
    gic::init();
}

// Get whether to use exec context for syscall return
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
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn kernel_syscall_from_user(
    num: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    user_frame_ptr: u64,
) -> i64 {
    syscall_handler(num as usize, a0, a1, a2, user_frame_ptr)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn kernel_exception_from_kernel(vector: u64, error: u64, rip: u64) -> ! {
    let cr2: u64;
    core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    if vector == 1 {
        let dr6: u64;
        let dr7: u64;
        core::arch::asm!("mov {}, dr6", "mov {}, dr7", out(reg) dr6, out(reg) dr7,
            options(nomem, nostack, preserves_flags));
        panic!("x86 kernel exception: vector={vector} error={error:#x} rip={rip:#x} cr2={cr2:#x} dr6={dr6:#x} dr7={dr7:#x}");
    }
    panic!("x86 kernel exception: vector={vector} error={error:#x} rip={rip:#x} cr2={cr2:#x}");
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn kernel_exception_from_user(
    vector: u64,
    registers: *const u64,
    has_error_code: usize,
) -> ! {
    crate::userfp::capture();
    let mut saved = SavedUserFrame::default();
    let frame = core::ptr::addr_of_mut!(saved).cast::<u64>();
    core::ptr::copy_nonoverlapping(registers, frame, 15);
    core::ptr::copy_nonoverlapping(registers.add(15 + has_error_code), frame.add(15), 5);
    let (reason, address) = match vector {
        0 => ("divide error", None),
        1 => ("debug exception", None),
        3 => ("breakpoint", None),
        6 => ("illegal instruction", None),
        13 => ("general protection fault", None),
        14 => {
            let address: u64;
            core::arch::asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
            let reason = match *registers.add(15) {
                error if error & 16 != 0 => "fault execute",
                error if error & 2 != 0 => "fault write",
                _ => "fault read",
            };
            (reason, Some(address))
        }
        _ => ("processor exception", None),
    };
    crate::syscall::user_fault(saved, reason, address)
}

/// Bridge used by the architecture crate's hardware-IRQ stubs.
///
/// The stubs save the interrupted user register state and call this
/// function with the vector number.  We dispatch through the kernel's
/// existing interrupt table.  A timer tick also acknowledges the interrupt
/// controller so the source can deliver the next tick.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn kernel_interrupt_from_user(vector: u64, registers: *const u64) {
    handle_interrupt(vector as usize);

    // The boot timer is normally IRQ0 / vector 32.  Acknowledge the
    // legacy 8259 PIC so a pending timer interrupt is not held forever.
    if vector == irq::TIMER as u64 {
        // Acknowledge the legacy 8259 PIC (master EOI, port 0x20).
        crate::plan9_arch::hal::io::outb(0x20, 0x20);
        if *registers.add(16) & 3 == 3 {
            crate::userfp::capture();
            crate::syscall::user_tick(registers.cast::<SavedUserFrame>().read());
        }
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

// ===========================================================================
// RISC-V user trap (stvec target; entered from boot.S `_user_trap` with the
// frame pointer in a0, and returned through the same frame).
//
// Frame layout (u64 slots, mirrors the aarch64 trap frame):
//   [0..32]  x0..x31  (a0..a5 = [10..15]; syscall number in a7 = [17];
//                      x2 = [2] holds the user sp)
//   [32]     sepc
//   [33]     sstatus  (SPP=0 on a user trap; SIE=0 in the handler)
//
// S-mode interrupts stay disabled while running kernel code. The
// supervisor timer can still interrupt U-mode.
// ===========================================================================
#[cfg(target_arch = "riscv64")]
#[inline]
fn read_scause() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, scause", out(reg) v, options(nomem, nostack)) };
    v
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn read_stval() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, stval", out(reg) v, options(nomem, nostack)) };
    v
}

/// Trap from U-mode, including system calls and synchronous faults.
///
/// # Safety
/// `fp` must point at the live 34-slot trap frame built by boot.S.
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub unsafe extern "C" fn riscv64_user_trap_handler(fp: *mut u64) -> u64 {
    let scause = read_scause();
    let code = scause & !(1u64 << 63);
    let interrupt = scause & (1u64 << 63) != 0;
    if *fp.add(33) & (1 << 8) == 0 {
        crate::userfp::capture();
    }

    let mut registers = [0; 32];
    core::ptr::copy_nonoverlapping(fp, registers.as_mut_ptr(), registers.len());
    let mut saved = SavedUserFrame {
        x: registers,
        pc: *fp.add(32),
        sstatus: *fp.add(33),
        sp: *fp.add(2),
    };
    if interrupt && code == 5 && saved.sstatus & (1 << 8) == 0 {
        plan9_arch::riscv64::timer::set_oneshot(1);
        scheduler().timer_tick();
        crate::syscall::user_tick(saved);
        return fp as u64;
    }
    if saved.sstatus & (1 << 8) != 0 || interrupt {
        panic!("RISC-V trap: scause={scause:#x} sepc={:#x} stval={:#x}", saved.pc, read_stval());
    }
    if code != 8 {
        let (reason, address) = match code {
            0 | 4 | 6 => ("alignment fault", Some(read_stval())),
            1 | 12 => ("fault execute", Some(read_stval())),
            3 => ("breakpoint", None),
            5 | 13 => ("fault read", Some(read_stval())),
            7 | 15 => ("fault write", Some(read_stval())),
            _ => ("illegal instruction", None),
        };
        crate::syscall::user_fault(saved, reason, address);
    }

    // ---- ecall: the Plan 9 syscall gate (number in a7, args a0..a5) ----
    let num = *fp.add(17) as usize;
    let a0 = *fp.add(10);
    let a1 = *fp.add(11);
    let a2 = *fp.add(12);
    let a3 = *fp.add(13);
    let a4 = *fp.add(14);
    let a5 = *fp.add(15);

    // Unlike AArch64's SVC (whose hardware return address is already the
    // following instruction), RISC-V's `ecall` leaves sepc pointing at the
    // ecall itself.  Advance the saved pc so the eret resumes *after* the
    // gate; otherwise every syscall would re-execute its own ecall with
    // x10 holding the previous return value.  The exec path overrides the
    // pc anyway, so this is unconditionally safe on the ecall path.
    saved.pc = saved.pc.wrapping_add(4);
    *fp.add(32) = saved.pc;

    // Process context, mirroring the x86_64 syscall path.
    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = true;
        p.nsyscall += 1;
        p.user_frame = Some(saved);
        SYSCALL_USE_EXEC_CONTEXT = false;
        SYSCALL_EXEC_ENTRY = 0;
    }

    let frame = SyscallFrame {
        exc: crate::trap::ExceptionFrame {
            error_code: 0,
            rip: saved.pc,
            cs: 0,
            rflags: saved.sstatus,
            rsp: saved.sp,
            ss: 0,
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

    crate::syscall::user_syscall_entry(4);
    let result = crate::syscall::dispatch(num, &frame);

    if num == crate::syscall::nr::EXEC {
        if let Some(proc) = curproc() {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            if p.has_exec_context() && result >= 0 {
                let mut f = p.user_frame.unwrap_or_default();
                f.set_entry(p.get_exec_entry());
                f.set_stack(p.get_exec_stack());
                f.set_ret(0);
                f.sstatus = crate::userfp::user_sstatus();
                p.user_frame = Some(f);
                p.clear_exec_context();
                p.insyscall = false;
                crate::syscall::user_exec_return();

                crate::userfp::resume(p);
            }
        }
    }

    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = false;
    }

    crate::syscall::user_return(result);
    *fp.add(10) = result as u64;
    fp as u64
}

// ============================================================================
// LoongArch64 user trap handler
// ============================================================================

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub extern "C" fn loongarch64_kernel_fault() -> ! {
    use plan9_arch::loongarch64::cpu::{csr, csr_read};

    let estat = csr_read::<{ csr::ESTAT }>();
    panic!(
        "LoongArch kernel fault: ecode={} ESTAT={estat:#x} ERA={:#x} BADV={:#x}",
        (estat >> 16) & 0x3f,
        csr_read::<{ csr::ERA }>(),
        csr_read::<{ csr::BADV }>(),
    );
}

/// LoongArch64 user trap entry, called from boot.S's `_user_trap`
/// with $a0 = the trap frame pointer.
///
/// Trap frame layout (u64 slots — see boot.S): `[i]` = $r(i+1) for
/// i = 0..30 (so a0..a5 = $r4..$r9 are slots 3..8, a7 = $r11 is slot 10
/// and the user sp = $r3 is slot 2), ERA in slot 31 and the trapped
/// PRMD in slot 32.
#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub unsafe extern "C" fn loongarch64_user_trap_handler(fp: *mut u64) -> u64 {
    use plan9_arch::loongarch64::cpu::{csr, csr_read};

    crate::userfp::capture();
    let estat = csr_read::<{ csr::ESTAT }>();
    let code = (estat >> 16) & 0x3F;

    let mut registers = [0; 31];
    core::ptr::copy_nonoverlapping(fp, registers.as_mut_ptr(), registers.len());
    let mut saved = SavedUserFrame {
        x: registers,
        pc: *fp.add(31),
        prmd: *fp.add(32),
        sp: *fp.add(2),
    };
    if code == 0 && estat & (1 << 11) != 0 {
        plan9_arch::loongarch64::timer::clear_interrupt();
        plan9_arch::loongarch64::timer::set_oneshot(1);
        scheduler().timer_tick();
        crate::syscall::user_tick(saved);
        return fp as u64;
    }
    if code != 11 {
        let badv = csr_read::<{ csr::BADV }>();
        let (reason, address) = match code {
            1 | 5 => ("fault read", Some(badv)),
            2 | 4 | 6 => ("fault write", Some(badv)),
            3 => ("fault execute", Some(badv)),
            7 | 8 | 9 => ("address or alignment fault", Some(badv)),
            12 => ("breakpoint", None),
            _ => ("illegal instruction", None),
        };
        crate::syscall::user_fault(saved, reason, address);
    }

    // ---- syscall: the Plan 9 syscall gate (number in a7, args a0..a5) ----
    let num = *fp.add(10) as usize;
    let a0 = *fp.add(3);
    let a1 = *fp.add(4);
    let a2 = *fp.add(5);
    let a3 = *fp.add(6);
    let a4 = *fp.add(7);
    let a5 = *fp.add(8);

    // The `syscall` instruction leaves ERA pointing at the gate itself;
    // advance the saved PC so the ertn resumes *after* it.  The exec
    // path overrides the pc anyway, so this is unconditionally safe.
    saved.pc = saved.pc.wrapping_add(4);
    *fp.add(31) = saved.pc;

    // Process context, mirroring the x86_64 syscall path.
    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = true;
        p.nsyscall += 1;
        p.user_frame = Some(saved);
        SYSCALL_USE_EXEC_CONTEXT = false;
        SYSCALL_EXEC_ENTRY = 0;
    }

    let frame = SyscallFrame {
        exc: crate::trap::ExceptionFrame {
            error_code: 0,
            rip: saved.pc,
            cs: 0,
            rflags: saved.prmd,
            rsp: saved.sp,
            ss: 0,
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

    crate::syscall::user_syscall_entry(4);
    let result = crate::syscall::dispatch(num, &frame);

    if num == crate::syscall::nr::EXEC {
        if let Some(proc) = curproc() {
            let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
            if p.has_exec_context() && result >= 0 {
                let mut f = p.user_frame.unwrap_or_default();
                f.set_entry(p.get_exec_entry());
                f.set_stack(p.get_exec_stack());
                f.set_ret(0);
                f.prmd = plan9_arch::hal::switch_to_user::USER_PRMD_INIT;
                p.user_frame = Some(f);
                p.clear_exec_context();
                p.insyscall = false;
                crate::syscall::user_exec_return();

                crate::userfp::resume(p);
            }
        }
    }

    if let Some(proc) = curproc() {
        let p = &mut *(core::ptr::addr_of!(*proc) as *mut Proc);
        p.insyscall = false;
    }

    crate::syscall::user_return(result);
    *fp.add(3) = result as u64;
    fp as u64
}

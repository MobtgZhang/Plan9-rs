//! Kernel Debugging Support
//!
//! Implements kernel debugging facilities including:
//! - Register dumps (dump_regs)
//! - Process dumps (procdump)
//! - Memory dumps (hexdump)
//! - Stack traces
//!
//! ## Reference
//! - Plan 9: `/sys/src/9/port/proc.c` (procdump)

use crate::proc::{Proc, Pid, State, curproc, proctable};
use crate::trap::ExceptionFrame;

use crate::{ debug_printf };
// ============================================================================
// Register Dumps
// ============================================================================

/// Dump all registers from an exception frame
pub fn dump_regs(frame: &ExceptionFrame) {
    debug_puts("Registers:\n");
    debug_printf!("  RIP: {:016x}  RFLAGS: {:016x}\n", frame.rip, frame.rflags);
    debug_printf!("  RSP: {:016x}\n", frame.rsp);
    debug_printf!("  CS:  {:04x}     SS:  {:04x}\n", frame.cs as u16, frame.ss as u16);
    debug_printf!("  Error Code: {:016x}\n", frame.error_code);
}

/// Dump general purpose registers only
pub fn dump_gp_regs(frame: &ExceptionFrame) {
    debug_puts("GP Registers (limited in ExceptionFrame):\n");
    debug_printf!("  RSP: {:016x}\n", frame.rsp);
}

/// Dump segment registers and control registers
pub fn dump_control_regs() {
    let cr0 = crate::plan9_arch::hal::cr0_read();
    let cr2 = crate::plan9_arch::hal::cr2_read();
    let cr3 = crate::plan9_arch::hal::cr3_read();
    let cr4 = crate::plan9_arch::hal::cr4_read();

    debug_puts("Control Registers:\n");
    debug_printf!("  CR0: {:016x}\n", cr0);
    debug_printf!("  CR2: {:016x} (Page Fault Address)\n", cr2);
    debug_printf!("  CR3: {:016x} (Page Directory Base)\n", cr3);
    debug_printf!("  CR4: {:016x}\n", cr4);
}

/// Dump debug registers
pub fn dump_debug_regs() {
    // DR0-DR7 are not directly readable in a safe way
    // In real implementation, would use inline assembly
    debug_puts("Debug Registers: (use 'info registers dr' in gdb)\n");
}

// ============================================================================
// Process Dumps
// ============================================================================

/// Dump all processes in the system
pub fn procdump() {
    debug_puts("\n=== Process Dump ===\n");
    debug_puts("PID   PPID  STATE          PRI   CPU    NSYSC  KSTACK\n");
    debug_puts("----  ----  -------------  ----  -----  -----  -------\n");

    let table = proctable();
    for proc in table.iter() {
        if proc.pid == 0 {
            continue;  // Skip idle process
        }
        dump_proc(proc);
    }

    debug_puts("=== End Process Dump ===\n\n");
}

/// Dump a single process
pub fn dump_proc(proc: &Proc) {
    let state_str = match proc.state {
        State::Dead => "Dead",
        State::Moribund => "Moribund",
        State::Ready => "Ready",
        State::Running => "Running",
        State::Scheding => "Scheding",
        State::Wakeme => "Wakeme",
        State::Rendez => "Rendez",
        State::Wait => "Wait",
        State::Broken => "Broken",
        State::Stopped => "Stopped",
    };

    let ppid = proc.parent.unwrap_or(0);

    debug_printf!("{:4}  {:4}  {:13}  {:4}  {:5}  {:6}  {:016x}\n",
        proc.pid,
        ppid,
        state_str,
        proc.pri,
        proc.cpu,
        proc.nsyscall,
        proc.kstack as u64
    );
}

/// Dump detailed process information
pub fn procdump_detailed(pid: Pid) {
    let table = proctable();

    if let Some(proc) = table.get(pid) {
        dump_proc_detailed(proc);
    } else {
        debug_printf!("Process {} not found\n", pid);
    }
}

/// Dump detailed information about a process
pub fn dump_proc_detailed(proc: &Proc) {
    let state_str = match proc.state {
        State::Dead => "Dead",
        State::Moribund => "Moribund",
        State::Ready => "Ready",
        State::Running => "Running",
        State::Scheding => "Scheding",
        State::Wakeme => "Wakeme",
        State::Rendez => "Rendez",
        State::Wait => "Wait",
        State::Broken => "Broken",
        State::Stopped => "Stopped",
    };

    let ppid = proc.parent.unwrap_or(0);

    debug_puts("\n=== Process Detail ===\n");
    debug_printf!("PID:        {}\n", proc.pid);
    debug_printf!("Parent:     {}\n", ppid);
    debug_printf!("State:      {}\n", state_str);
    debug_printf!("Priority:   {}\n", proc.pri);
    debug_printf!("CPU:        {}\n", proc.cpu);

    debug_puts("\n--- Timing ---\n");
    debug_printf!("User Time:  {} ms\n", proc.utime);
    debug_printf!("Kernel Time: {} ms\n", proc.ktime);
    debug_printf!("Child Time: {} ms\n", proc.ctime);
    debug_printf!("Wall Time:  {} ms\n", proc.wtime);

    debug_puts("\n--- Memory ---\n");
    debug_printf!("KStack:     {:016x}\n", proc.kstack as u64);
    debug_printf!("MMU PDB:    {:016x}\n", proc.mmupdb.as_u64());

    debug_puts("\n--- Syscall ---\n");
    debug_printf!("In Syscall: {}\n", proc.insyscall);
    debug_printf!("Syscalls:   {}\n", proc.nsyscall);

    debug_puts("\n--- Scheduling ---\n");
    debug_printf!("Preempted:  {}\n", proc.preempted);
    debug_printf!("Children:    {}\n", proc.nchild);
    debug_printf!("Waiters:    {}\n", proc.nwait);

    debug_puts("=== End Process Detail ===\n\n");
}

// ============================================================================
// Memory Dumps
// ============================================================================

/// Dump memory in hex and ASCII format (like hexdump -C)
pub fn hexdump(addr: u64, len: usize) {
    debug_printf!("\n--- Memory at {:016x} ({} bytes) ---\n", addr, len);

    let mut offset = 0usize;
    while offset < len {
        let line_len = (len - offset).min(16);

        // Print offset
        debug_printf!("{:016x}  ", addr + offset as u64);

        // Print hex bytes
        for i in 0..16 {
            if i < line_len {
                let byte = unsafe { *(addr as *const u64).add(offset + i) };
                debug_printf!("{:02x} ", byte);
            } else {
                debug_puts("   ");
            }
            if i == 7 {
                debug_puts(" ");
            }
        }

        debug_puts(" |");

        // Print ASCII
        for i in 0..line_len {
            let byte = unsafe { *(addr as *const u8).add(offset + i) };
            let c = if byte >= 0x20 && byte < 0x7f {
                byte as char
            } else {
                '.'
            };
            debug_putchar(c as u8);
        }

        debug_puts("|\n");
        offset += line_len;
    }

    debug_printf!("--- End Memory Dump ---\n\n");
}

/// Dump a specific memory range with virtual address translation
pub fn hexdump_virt(vaddr: u64, len: usize) {
    // For now, just dump as physical
    // Real implementation would handle virtual address translation
    hexdump(vaddr, len);
}

// ============================================================================
// Stack Traces
// ============================================================================

/// Dump the current stack trace
#[cfg(target_arch = "x86_64")]
pub fn dump_stack() {
    debug_puts("\n=== Stack Trace ===\n");

    // Get current frame pointer
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp);
    }

    dump_stack_frames(rbp, 16);  // Dump up to 16 frames

    debug_puts("=== End Stack Trace ===\n\n");
}

/// Stub dump_stack for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn dump_stack() {
    debug_puts("\n=== Stack Trace ===\n");
    debug_puts("  <not available on this architecture>\n");
    debug_puts("=== End Stack Trace ===\n\n");
}

/// Dump stack frames from a given frame pointer
#[cfg(target_arch = "x86_64")]
pub fn dump_stack_frames(mut rbp: u64, max_frames: usize) {
    let mut frames = 0;

    while rbp != 0 && frames < max_frames {
        // Get return address (at rbp + 8)
        let ret_addr = unsafe { *(rbp as *const u64).add(1) };

        if ret_addr == 0 {
            break;
        }

        debug_printf!("  #{}  {:016x}\n", frames, ret_addr);

        // Move to next frame
        rbp = unsafe { *(rbp as *const u64) };

        frames += 1;
    }
}

/// Stub dump_stack_frames for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn dump_stack_frames(_rbp: u64, _max_frames: usize) {
    // Stack frame walking is architecture-specific
}

/// Dump stack for a specific process
pub fn dump_proc_stack(proc: &Proc) {
    debug_puts("\n=== Process Stack ===\n");
    debug_printf!("PID:     {}\n", proc.pid);
    debug_printf!("KStack:  {:016x}\n", proc.kstack as u64);

    // Dump top of stack
    let stack_top = proc.kstack;
    let dump_size = 128.min(4096);  // Dump 128 or 4KB

    hexdump(stack_top as u64, dump_size);

    debug_puts("=== End Process Stack ===\n\n");
}

// ============================================================================
// Kernel Panic/Error Handling
// ============================================================================

/// Kernel panic handler
pub fn kernel_panic(msg: &[u8]) {
    // Disable interrupts
    crate::plan9_arch::hal::cli();

    debug_puts("\n!!! KERNEL PANIC !!!\n");
    debug_puts("Message: ");
    // Convert bytes to string if valid UTF-8
    if let Ok(s) = core::str::from_utf8(msg) {
        debug_putstr(s);
    } else {
        // Fallback: print as hex
        debug_puts("<binary data: ");
        for &b in msg.iter().take(32) {
            debug_printf!("{:02x}", b);
        }
        if msg.len() > 32 {
            debug_puts("...>");
        } else {
            debug_puts(">");
        }
    }
    debug_puts("\n\n");

    // Dump current process if any
    if let Some(proc) = curproc() {
        debug_puts("Current Process:\n");
        dump_proc_detailed(proc);
    }

    // Dump all processes
    procdump();

    // Halt
    debug_puts("\nSystem halted. Press reset to reboot.\n");
    halt();
}

/// Kernel error handler
pub fn kernel_error(msg: &[u8]) {
    debug_puts("!!! KERNEL ERROR !!!\n");
    debug_puts("Message: ");
    debug_putstr(core::str::from_utf8(msg).unwrap_or("<invalid utf8>"));
    debug_puts("\n");
}

/// Assert failed handler
pub fn assert_failed(file: &str, line: u32, expr: &str) {
    debug_puts("\n!!! ASSERTION FAILED !!!\n");
    debug_printf!("File:    {}\n", file);
    debug_printf!("Line:    {}\n", line);
    debug_printf!("Expr:    {}\n", expr);
    kernel_panic(b"assertion failed");
}

// ============================================================================
// Debug Output Helpers
// ============================================================================

/// Simple putchar without going through full console
pub fn debug_putchar(c: u8) {
    // Write to serial port for early debug
    crate::cons::serial_putchar(c);

    // Also write to kmesg if available
    if c == b'\n' {
        crate::kmesg::kmesg_putc(b'\r');
    }
    crate::kmesg::kmesg_putc(c);
}

/// Simple puts without formatting
pub fn debug_puts(s: &str) {
    for &c in s.as_bytes() {
        debug_putchar(c);
    }
}

/// Simple puts for &str (alias)
pub fn debug_putstr(s: &str) {
    for &c in s.as_bytes() {
        debug_putchar(c);
    }
}

/// Simple formatted printf (limited support)
pub fn debug_printf_str(_format: &str, args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;

    struct DebugWriter;
    impl Write for DebugWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            debug_puts(s);
            Ok(())
        }
    }

    let mut writer = DebugWriter;
    let _ = write!(writer, "{}", args).map_err(|_| ());
}

/// Print debug message with newline
#[macro_export]
macro_rules! debugln {
    ($($arg:tt)*) => {{
        $crate::debug::debug_printf_str(stringify!($($arg)*), format_args!($($arg)*));
    }};
}

/// Print debug message
#[macro_export]
macro_rules! debug_printf {
    ($($arg:tt)*) => {{
        $crate::debug::debug_printf_str(stringify!($($arg)*), format_args!($($arg)*));
    }};
}

/// Alias for debugln macro
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::debugln!($($arg)*);
    };
}

/// Halt the system
pub fn halt() -> ! {
    loop {
        crate::plan9_arch::hal::hlt();
    }
}

/// Reboot the system
pub fn reboot() -> ! {
    debug_puts("\nRebooting...\n");

    // Try ACPI reset
    // In real implementation, would send ACPI reset or triple-fault

    // If that fails, halt
    halt();
}

// ============================================================================
// Debug Device
// ============================================================================

use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

/// Debug device
pub struct DebugDev {
    name: &'static str,
    dev_char: char,
}

impl DebugDev {
    pub fn new() -> Self {
        Self {
            name: "debug",
            dev_char: 'D',  // 'D' for Debug
        }
    }
}

impl Dev for DebugDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Err(Error::Enoent)
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Read debug info
        // For now, just dump current process
        procdump();

        let msg = b"Debug info printed to console\n";
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // Debug commands
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| Error::Einval)?
            .trim();

        match cmd {
            "procdump" => {
                procdump();
                Ok(buf.len())
            }
            "dumpstack" => {
                dump_stack();
                Ok(buf.len())
            }
            "dumpregs" => {
                // Would need to pass frame
                debug_puts("Use procdump or dump_proc_detailed\n");
                Ok(buf.len())
            }
            "hexdump" => {
                // Would need address and length
                debug_puts("Usage: hexdump <addr> <len>\n");
                Ok(buf.len())
            }
            "reset" => {
                reboot();
            }
            _ => {
                debug_puts("Unknown debug command\n");
                Err(Error::Einval)
            }
        }
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"debug".to_vec(),
            uid: 0,
            gid: 0,
})
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

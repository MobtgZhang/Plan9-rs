//! Init Process
//!
//! Implements the first user-space process (init).

use crate::proc::{Proc, State, Pid};
use crate::sched::scheduler;
use crate::syscall;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Init Process
// ============================================================================

/// Init process entry function
pub fn init_main() -> ! {
    // Initialize the console
    init_console();
    
    // Print welcome message
    println!("Plan 9 from Outer Space\n");
    println!("kernel booting...\n");
    
    // Initialize file systems
    init_filesystems();
    
    // Start essential services
    start_services();
    
    // Run the shell
    run_shell();
    
    // Should never return
    loop {}
}

/// Initialize console
fn init_console() {
    // The console is already initialized by the kernel
    // Just configure it for init
}

/// Initialize file systems
fn init_filesystems() {
    // Mount the root file system
    // This would be done by the kernel during boot
    println!("Initializing file systems...\n");
    
    // Mount /proc
    // mount("#p", "/proc", "", None);
    
    // Mount /dev
    // mount("#d", "/dev", "", None);
    
    // Mount /net
    // mount("#I", "/net", "", None);
}

/// Start essential system services
fn start_services() {
    println!("Starting services...\n");
    
    // Start the Factotum authentication service
    // if let Ok(_) = rfork(rfork::FLAGFPROC | rfork::FLAGFENV) {
    //     exec("/bin/factotum", &[]);
    // }
    
    // Start the Venti fossil storage system
    // if let Ok(_) = rfork(rfork::FLAGFPROC) {
    //     exec("/bin/fossil", &[]);
    // }
}

/// Run the shell
fn run_shell() {
    println!("Starting shell...\n");
    
    // Create a new process for the shell
    let pid = rfork_shell();
    
    if pid == 0 {
        // Child: exec the shell
        exec_shell();
    } else {
        // Parent: wait for shell to exit
        loop {
            let mut status: i32 = 0;
            // waitpid(pid, &mut status, 0);
            if status != 0 {
                println!("Shell exited with status {}\n", status);
                break;
            }
        }
    }
}

/// Fork for shell
fn rfork_shell() -> Pid {
    // In a real implementation, this would call the scheduler's fork
    let sched = scheduler();
    
    match sched.fork(curproc(), shell_entry) {
        Some(pid) => pid,
        None => 0,
    }
}

/// Shell process entry
extern "C" fn shell_entry() {
    // This would be the shell's entry point
    // After fork, the child would jump here
    loop {}
}

/// Exec the shell
fn exec_shell() -> ! {
    // Path to shell
    let shell_path = b"/bin/rc\0";
    
    // Arguments
    let argv: [&[u8]; 2] = [
        b"rc\0",
        b"-c\0",
    ];
    
    // Environment
    let envp: [&[u8]; 4] = [
        b"PATH=/bin\0",
        b"home=/\0",
        b"term=vt100\0",
        b"\0",
    ];
    
    // Exec the shell
    // In a real implementation:
    // syscall::sys_exec(shell_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    
    loop {}
}

/// Get current process
fn curproc() -> Option<&'static Proc> {
    crate::proc::curproc()
}

// ============================================================================
// Shutdown
// ============================================================================

/// Shutdown the system
pub fn shutdown() {
    static SHUTDOWN_INITIATED: AtomicBool = AtomicBool::new(false);
    
    // Ensure shutdown is only initiated once
    if SHUTDOWN_INITIATED.swap(true, Ordering::SeqCst) {
        return;
    }
    
    println!("Shutting down...\n");
    
    // Sync file systems
    sync_filesystems();
    
    // Stop services
    stop_services();
    
    // Final halt
    println!("System halted.\n");
    halt();
}

/// Sync all file systems
fn sync_filesystems() {
    println!("Syncing file systems...\n");
    // fsyncall();
}

/// Stop all services
fn stop_services() {
    println!("Stopping services...\n");
    // Send TERM signal to all processes
    // kill(-1, SIGTERM);
    // sleep(1);
    // kill(-1, SIGKILL);
}

/// Halt the CPU
fn halt() -> ! {
    loop {
        crate::arch::x86_64::hlt();
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

/// Panic handler for init process
pub fn init_panic(msg: &[u8]) {
    println!("PANIC: ");
    for &b in msg {
        print!("{}", b as char);
    }
    println!("\n");
    
    // Dump stack trace if possible
    dump_stack();
    
    // Enter debugger or reboot
    reboot();
}

/// Dump current stack
fn dump_stack() {
    // In a real implementation, this would print the stack trace
    println!("Stack trace:");
    // Walk the stack and print return addresses
}

/// Reboot the system
fn reboot() -> ! {
    println!("Rebooting...\n");
    
    // Try to sync first
    sync_filesystems();
    
    // Trigger a software reset
    // This would typically use the keyboard controller or ACPI
    
    loop {}
}

// ============================================================================
// Console Output
// ============================================================================

/// Print a character to console
pub fn putchar(c: u8) {
    // Write to console device
    // In a real implementation, this would call the console driver's putc
    // syscall::sys_write(1, &c, 1);
    let _ = c;
}

/// Print a string to console
pub fn puts(s: &[u8]) {
    for &c in s {
        if c == b'\n' {
            putchar(b'\r');
        }
        putchar(c);
    }
}

/// Print formatted string (simple implementation)
macro_rules! println {
    ($($arg:tt)*) => {
        print!($($arg)*);
        puts(b"\n");
    };
}

/// Print formatted string (no newline)
macro_rules! print {
    ($($arg:tt)*) => {
        // Simple print implementation
        // In real impl, would use formatted printing
        let _ = format_args!($($arg)*);
    };
}

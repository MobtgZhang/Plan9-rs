//! Plan 9 init — user-mode bootstrap process. It runs entirely in ring 3,
//! only talks to the kernel via syscall, and execs `/rc/bin/rc`, respawning
//! it forever whenever it terminates (Plan 9's init behavior).

#![no_std]
#![no_main]

use plan9_init::syscall::{exec, exit, fork, getpid, puts, wait, write, yield_cpu};

fn print(s: &str) {
    let (_, buf) = cstr(s);
    puts(buf.as_ptr());
}

fn cstr(s: &str) -> (usize, [u8; 256]) {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 256];
    let n = if bytes.len() < 255 { bytes.len() } else { 255 };
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
    (n, buf)
}

fn write_str(fd: i64, s: &str) {
    // Copy the string into a user-stack buffer before passing it to the
    // kernel.  Static string literals live in the ELF image at a low linker
    // address, but the image is mapped at USER_BASE; passing `s.as_ptr()`
    // directly would make the kernel read unrelated kernel memory.
    let (n, buf) = cstr(s);
    write(fd, buf.as_ptr(), n);
}

fn main() -> ! {
    print("\n[init] Plan 9 from Outer Space — Rust kernel\n");
    print("[init] pid=");
    let mut pid_buf = [0u8; 16];
    let p = format_u64(getpid() as u64, &mut pid_buf);
    print(p);
    print("\n");

    // Plan 9 bootstrap split: init is just a loader, the boot script
    // lives in `rc`.  Like Plan 9's init, respawn `/rc/bin/rc` forever
    // whenever it terminates — there is no built-in fallback shell.
    loop {
        let (_n, path_buf) = cstr("/rc/bin/rc");
        let argv_arr: [*const u8; 2] = [path_buf.as_ptr(), core::ptr::null()];
        let pid = fork();
        if pid == 0 {
            // Child: exec the rc script.
            let r = exec(path_buf.as_ptr(), argv_arr.as_ptr(), 1);
            // exec failed: report the kernel error code, then exit so
            // init's loop respawns rc.
            print("[init] exec rc failed r=");
            let mut b = [0u8; 24];
            print(format_u64(r as u64, &mut b));
            print("\n");
            exit(127);
        } else if pid > 0 {
            // Parent: wait for rc, then respawn it like init would.
            let status = wait(pid as i32);
            print("[init] rc exited with status ");
            let mut b = [0u8; 16];
            print(format_u64(status as u64, &mut b));
            print("\n");
        } else {
            // fork failed; give the kernel a chance to reap and retry.
            yield_cpu();
        }
    }
}


fn format_u64(mut v: u64, buf: &mut [u8]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut n = 0usize;
    let mut tmp = [0u8; 20];
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
    }
    unsafe { core::str::from_utf8_unchecked(&buf[..n]) }
}

/// Simple serial writer for formatting panic messages.
struct PanicWriter;
impl core::fmt::Write for PanicWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(1, s);
        Ok(())
    }
}

/// Panic handler: report the source location and message, then halt.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    write_str(1, "[user panic] ");
    if let Some(loc) = info.location() {
        write_str(1, loc.file());
        write_str(1, ":");
        let mut b = [0u8; 16];
        let s = format_u64(loc.line() as u64, &mut b);
        write_str(1, s);
    } else {
        write_str(1, "unknown");
    }
    write_str(1, " ");
    let mut out = PanicWriter;
    let _ = core::fmt::write(&mut out, format_args!("{}", info.message()));
    write_str(1, "\n");
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)) }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfi", options(nostack, preserves_flags)) }
    }
}

/// Binary entry point.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

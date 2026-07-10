//! Plan 9 init — minimal user-mode shell that demonstrates kernel/user
//! separation. Runs entirely in ring 3, only talks to the kernel via
//! `int 0x80` syscalls.

#![no_std]
#![no_main]

mod syscall;

use core::arch::asm;

use syscall::{brk, chdir, close, dup, exec, exit, fork, getpid, list, open, puts, read, stat, wait, write, yield_cpu};

const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;

fn print(s: &str) {
    puts(s.as_ptr());
}

fn println(s: &str) {
    print(s);
    print("\n");
}

fn print_prompt() {
    print("term% ");
}

fn cstr(s: &str) -> (usize, [u8; 256]) {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 256];
    let n = if bytes.len() < 255 { bytes.len() } else { 255 };
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
    (n, buf)
}

fn open_console() -> i64 {
    let (_, p) = cstr("/dev/console");
    open(p.as_ptr(), O_WRONLY)
}

fn write_str(fd: i64, s: &str) {
    write(fd, s.as_ptr(), s.len());
}

fn main() -> ! {
    print("\n[init] Plan 9 from Outer Space — Rust kernel\n");
    print("[init] pid=");
    let mut pid_buf = [0u8; 16];
    let p = format_u64(getpid() as u64, &mut pid_buf);
    print(p);
    print("\n");

    // Try to exec `/rc/bin/rc` first (Plan 9 bootstrap split: init
    // is just a loader, the boot script lives in `rc`). Falls back
    // to the built-in shell if `rc` cannot be executed.
    let (n, path_buf) = cstr("/rc/bin/rc");
    let argv_arr: [*const u8; 1] = [path_buf.as_ptr()];
    let pid = fork();
    if pid == 0 {
        // Child: exec the rc script.
        exec(path_buf.as_ptr(), argv_arr.as_ptr(), 1);
        // exec failed: exit so init's parent loop continues.
        exit(127);
    } else if pid > 0 {
        // Parent: wait for rc, then continue with the shell fallback.
        let _ = wait(pid as i32);
    }

    let con_fd = open_console();
    if con_fd < 0 {
        print("[init] failed to open console\n");
    }
    let mut input = [0u8; 256];

    loop {
        print_prompt();
        // Read one byte at a time.
        let mut idx = 0usize;
        loop {
            let n = read(0, &mut input[idx], 1);
            if n <= 0 {
                yield_cpu();
                continue;
            }
            let b = input[idx];
            if b == b'\n' || b == b'\r' {
                break;
            }
            if idx + 1 < input.len() {
                idx += 1;
            }
        }
        if idx == 0 {
            continue;
        }

        let line = &input[..idx];
        let cmd = match core::str::from_utf8(line) {
            Ok(s) => s.trim(),
            Err(_) => {
                println("?");
                continue;
            }
        };
        if cmd.is_empty() {
            continue;
        }

        if cmd == "help" {
            cmd_help();
        } else if let Some(rest) = cmd.strip_prefix("echo ") {
            write_str(con_fd, rest);
            write_str(con_fd, "\n");
        } else if cmd == "echo" {
            write_str(con_fd, "\n");
        } else if cmd == "ls" {
            cmd_ls("/");
        } else if let Some(path) = cmd.strip_prefix("cat ") {
            cmd_cat(path.trim());
        } else if cmd == "pwd" {
            write_str(con_fd, "/\n");
        } else if cmd == "ps" {
            cmd_ps();
        } else if cmd == "exit" {
            print("goodbye\n");
            exit(0);
        } else if cmd == "halt" {
            loop {
                unsafe { asm!("hlt", options(nostack, preserves_flags)) }
            }
        } else if cmd == "fork" {
            let p = fork();
            if p == 0 {
                print("[init] child\n");
            } else {
                print("[init] forked pid=");
                let mut b = [0u8; 16];
                let s = format_u64(p as u64, &mut b);
                print(s);
                print("\n");
                wait(p as i32);
            }
        } else if let Some(path) = cmd.strip_prefix("cd ") {
            let (_, p) = cstr(path.trim());
            let rc = chdir(p.as_ptr());
            if rc < 0 {
                print("cd: failed\n");
            }
        } else if let Some(path) = cmd.strip_prefix("stat ") {
            let (_, p) = cstr(path.trim());
            let mut buf = [0u8; 256];
            let rc = stat(p.as_ptr(), buf.as_mut_ptr(), buf.len());
            if rc < 0 {
                print("stat: failed\n");
            } else {
                let s = unsafe { core::str::from_utf8_unchecked(&buf[..rc as usize]) };
                print(s);
                print("\n");
            }
        } else if let Some(addr_str) = cmd.strip_prefix("brk ") {
            // Allow the user to grow the heap to a decimal address.
            let addr = parse_u64(addr_str.trim());
            let rc = brk(addr);
            let mut b = [0u8; 16];
            let s = format_u64(rc as u64, &mut b);
            print("brk -> ");
            print(s);
            print("\n");
        } else if let Some(rest) = cmd.strip_prefix("dup ") {
            // `dup N` opens /dev/console and then duplicates fd N to it.
            let src = rest.trim().parse::<i64>().unwrap_or(-1);
            let newfd = dup(src);
            let mut b = [0u8; 16];
            let s = format_u64(newfd as u64, &mut b);
            print("dup -> ");
            print(s);
            print("\n");
        } else if let Some(rest) = cmd.strip_prefix("exec ") {
            // Bare-bones exec: replace the current process with `/bin/<name>`.
            let name = rest.trim();
            let mut path_buf = [0u8; 256];
            let path_str = b"/bin/";
            let n = path_str.len();
            path_buf[..n].copy_from_slice(path_str);
            let copy_len = name.len().min(255 - n);
            path_buf[n..n + copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
            path_buf[n + copy_len] = 0;
            let argv = [path_buf.as_ptr(), core::ptr::null()];
            let rc = exec(path_buf.as_ptr(), argv.as_ptr(), 1);
            let mut b = [0u8; 16];
            let s = format_u64(rc as u64, &mut b);
            print("exec -> ");
            print(s);
            print("\n");
        } else {
            print("unknown: ");
            println(cmd);
        }
    }
}

fn cmd_help() {
    print("Available commands:\n");
    print("  help   - this message\n");
    print("  echo   - echo text\n");
    print("  ls     - list current directory\n");
    print("  cat F  - print file F\n");
    print("  pwd    - print working directory\n");
    print("  ps     - list processes\n");
    print("  fork   - fork and wait\n");
    print("  cd D   - change directory\n");
    print("  stat F - stat file F\n");
    print("  brk N  - grow heap to N\n");
    print("  dup N  - duplicate fd N\n");
    print("  exec N - exec /bin/N\n");
    print("  exit   - exit init\n");
    print("  halt   - halt the CPU\n");
}

fn cmd_ls(path: &str) {
    let (_, p) = cstr(path);
    let mut buf = [0u8; 1024];
    let n = list(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if n < 0 {
        print("ls failed\n");
        return;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..n as usize]) };
    print(s);
}

fn cmd_cat(path: &str) {
    let (_, p) = cstr(path);
    let fd = open(p.as_ptr(), O_RDONLY);
    if fd < 0 {
        print("cat: open failed\n");
        return;
    }
    let mut buf = [0u8; 256];
    loop {
        let n = read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        write(1, buf.as_ptr(), n as usize);
    }
    close(fd);
}

fn cmd_ps() {
    cmd_ls("/proc");
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

/// Parse a decimal unsigned integer. Returns 0 on parse failure.
fn parse_u64(s: &str) -> usize {
    let mut value: usize = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' {
            return 0;
        }
        value = value * 10 + (b - b'0') as usize;
    }
    value
}

/// Panic handler: halt on any panic.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)) }
    }
}

/// Binary entry point.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

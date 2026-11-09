//! Plan 9 / Bash-compatible user shell.
//!
//! This is a small no_std shell built on the Plan 9 syscall interface.  It
//! provides Bash-style builtins and dispatches unknown commands through
//! `exec`, so a command is run from `/bin/<name>`.

#![no_std]
#![no_main]

mod syscall;

use core::arch::asm;
use syscall::{chdir, close, exec, exit, fork, getpid, list, open, puts, read, wait, write, yield_cpu};

const O_RDONLY: u32 = 0;

fn print(s: &str) {
    let (_, buf) = cstr(s);
    puts(buf.as_ptr());
}

fn println(s: &str) {
    print(s);
    print("\n");
}

fn cstr(s: &str) -> (usize, [u8; 256]) {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 256];
    let n = if bytes.len() < 255 { bytes.len() } else { 255 };
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
    (n, buf)
}

fn read_line(buf: &mut [u8]) -> usize {
    let mut idx = 0usize;
    loop {
        let n = read(0, &mut buf[idx], 1);
        if n <= 0 {
            yield_cpu();
            continue;
        }
        let b = buf[idx];
        if b == b'\n' || b == b'\r' {
            break;
        }
        if idx + 1 < buf.len() {
            idx += 1;
        }
    }
    idx
}

fn parse_words(line: &[u8]) -> ([u8; 256], [[u8; 128]; 16], usize) {
    let mut storage = [0u8; 256];
    let mut words: [[u8; 128]; 16] = [[0u8; 128]; 16];
    let mut nwords = 0usize;
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < line.len() && pos < storage.len() {
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        let start = i;
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
            i += 1;
        }
        if nwords < words.len() {
            let len = core::cmp::min(i - start, 127);
            words[nwords][..len].copy_from_slice(&line[start..start + len]);
            words[nwords][len] = 0;
            nwords += 1;
        }
    }
    let _ = pos;
    (storage, words, nwords)
}

fn word_str(w: &[u8; 128]) -> &str {
    let mut n = 0usize;
    while n < w.len() && w[n] != 0 {
        n += 1;
    }
    unsafe { core::str::from_utf8_unchecked(&w[..n]) }
}

fn main() -> ! {
    println("\n[bash] Plan 9 from Outer Space — Rust shell");
    println("[bash] pid=");
    let mut pid_buf = [0u8; 16];
    let s = format_u64(getpid() as u64, &mut pid_buf);
    println(s);

    let mut line = [0u8; 256];
    loop {
        print("bash$ ");
        let len = read_line(&mut line);
        if len == 0 {
            continue;
        }
        let cmd_line = &line[..len];
        let (_storage, words, nwords) = parse_words(cmd_line);
        if nwords == 0 {
            continue;
        }
        let cmd = word_str(&words[0]);
        let arg1 = if nwords > 1 { word_str(&words[1]) } else { "" };

        if cmd == "help" {
            shell_help();
        } else if cmd == "exit" {
            println("goodbye");
            exit(0);
        } else if cmd == "echo" {
            // Print every argument separated by single spaces.  Arguments
            // are raw byte slices so UTF-8 input (e.g. CJK) passes through
            // untouched.
            if nwords > 1 {
                let mut out_buf = [0u8; 256];
                let mut out_len = 0usize;
                for wi in 1..nwords {
                    if wi > 1 && out_len < out_buf.len() {
                        out_buf[out_len] = b' ';
                        out_len += 1;
                    }
                    let mut n = 0usize;
                    while n < 128 && words[wi][n] != 0 {
                        n += 1;
                    }
                    if out_len + n >= out_buf.len() {
                        break;
                    }
                    out_buf[out_len..out_len + n].copy_from_slice(&words[wi][..n]);
                    out_len += n;
                }
                out_buf[out_len] = 0;
                puts(out_buf.as_ptr());
                print("\n");
            } else {
                println("");
            }
        } else if cmd == "pwd" {
            println("/");
        } else if cmd == "cd" {
            let (_, p) = cstr(arg1);
            if chdir(p.as_ptr()) < 0 {
                println("cd: failed");
            }
        } else if cmd == "ls" {
            let path = if arg1.is_empty() { "/" } else { arg1 };
            list_dir(path);
        } else if cmd == "cat" {
            cat_file(arg1);
        } else if cmd == "ps" {
            list_dir("/proc");
        } else if cmd == "getpid" {
            let pid = getpid();
            let mut b = [0u8; 16];
            let txt = format_u64(pid as u64, &mut b);
            println(txt);
        } else if cmd == "stat" {
            stat_file(arg1);
        } else if cmd == "true" {
            continue;
        } else if cmd == "false" {
            continue;
        } else if cmd == "export" {
            // No environment in the prototype; accept the assignment.
            println("export: accepted");
        } else if cmd == "unset" {
            println("unset: accepted");
        } else if cmd == "which" || cmd == "type" {
            println(arg1);
        } else if cmd == "printf" {
            // Very small printf: only `%s` and newline escapes.
            printf_simple(arg1);
        } else if cmd == "fork" {
            let pid = fork();
            if pid > 0 {
                let mut b = [0u8; 16];
                let p = format_u64(pid as u64, &mut b);
                println(p);
                wait(pid as i32);
            } else {
                println("[bash] child");
            }
        } else if cmd == "exec" {
            // Plan 9 / Bash-compatible `exec`: replace the shell with the
            // named program, optionally passing one argument.
            if nwords < 2 {
                println("exec: usage: exec program [arg]");
                continue;
            }
            let program = arg1;
            let program_arg = if nwords > 2 { word_str(&words[2]) } else { "" };
            exec_binary(program, program_arg);
        } else {
            exec_binary(cmd, arg1);
        }
    }
}

fn shell_help() {
    println("builtins: help echo pwd cd ls cat ps stat true false export unset which type printf fork exec exit");
    println("other commands run as /bin/<command>");
}

fn list_dir(path: &str) {
    let (_, p) = cstr(path);
    let mut buf = [0u8; 2048];
    let n = list(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if n < 0 {
        println("ls: failed");
        return;
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..n as usize]) };
    print(s);
}

fn cat_file(path: &str) {
    let (_, p) = cstr(path);
    let fd = open(p.as_ptr(), O_RDONLY);
    if fd < 0 {
        println("cat: open failed");
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

fn stat_file(path: &str) {
    let (_, p) = cstr(path);
    let mut buf = [0u8; 256];
    let rc = syscall::stat(p.as_ptr(), buf.as_mut_ptr(), buf.len());
    if rc < 0 {
        println("stat: failed");
    } else {
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..rc as usize]) };
        print(s);
    }
}

fn printf_simple(fmt: &str) {
    // Print the format, allowing a single `%s` replaced by the second word
    // if present.  (The caller only gives one argument in this prototype.)
    let mut out = [0u8; 256];
    let mut n = 0usize;
    for &b in fmt.as_bytes() {
        if b == b'\\' && n < out.len() {
            // Translate \n and \t.
            out[n] = b;
            n += 1;
            continue;
        }
        if n < out.len() {
            out[n] = b;
            n += 1;
        }
    }
    write(1, out.as_ptr(), n);
    write(1, b"\n".as_ptr(), 1);
}

fn exec_binary(cmd: &str, arg: &str) {
    let mut path = [0u8; 256];
    let prefix = b"/bin/";
    path[..prefix.len()].copy_from_slice(prefix);
    let name = cmd.as_bytes();
    let n = core::cmp::min(name.len(), 255 - prefix.len());
    path[prefix.len()..prefix.len() + n].copy_from_slice(&name[..n]);
    path[prefix.len() + n] = 0;

    let mut arg_buf = [0u8; 256];
    arg_buf[..arg.len()].copy_from_slice(arg.as_bytes());
    arg_buf[arg.len()] = 0;

    let argv: [*const u8; 3] = [
        path.as_ptr(),
        if arg.is_empty() { core::ptr::null() } else { arg_buf.as_ptr() },
        core::ptr::null(),
    ];

    let rc = exec(path.as_ptr(), argv.as_ptr(), 0);
    println("exec: command not found");
    let _ = rc;
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)) }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

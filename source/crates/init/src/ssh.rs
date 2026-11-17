//! Plan 9 SSH client.
//!
//! The client uses the Plan 9 `/net` device rather than a host socket API:
//!
//!   1. open `/net/tcp/clone`
//!   2. write `connect <ip>!<port>` to the connection file
//!   3. read the server's SSH version banner
//!   4. write the client banner `SSH-2.0-Plan9`
//!
//! Full SSH key exchange and authentication are not implemented by the
//! protocol crate yet; this binary validates the real TCP path through
//! the kernel's E1000 driver and the `/net` filesystem.

#![no_std]
#![no_main]

mod syscall;

use core::arch::global_asm;

// The kernel starts a user program at the ELF entry point with the
// System V argument stack: [rsp] = argc, [rsp+8] = argv.  A Rust `_start`
// function would get a normal function prologue before its body and would
// no longer see that stack layout.  Use a tiny assembly entry stub that
// reads argc/argv and then calls the Rust implementation.
#[cfg(target_arch = "x86_64")]
global_asm!(r#"
    .section .text.start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    mov     rdi, qword ptr [rsp]
    lea     rsi, [rsp + 8]
    mov     rdx, rsp
    call    ssh_main
    hlt
    .size _start, . - _start
"#);

// aarch64 build of the ssh binary is a placeholder — the SSH port is
// x86_64-only; provide a valid entry point that exits immediately.
#[cfg(target_arch = "aarch64")]
global_asm!(r#"
    .section .text.start, "ax", @progbits
    .global _start
    .type _start, @function
_start:
    mov     x8, #2                      /* SYS_EXITS */
    svc     #0
hang_ssh:
    wfi
    b       hang_ssh
    .size _start, . - _start
"#);

const O_RDWR: u32 = 2;
const DEFAULT_SSH_PORT: u16 = 22;

fn print(s: &str) {
    let mut buf = [0u8; 256];
    let n = s.len().min(255);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    buf[n] = 0;
    syscall::puts(buf.as_ptr());
}

fn println(s: &str) {
    print(s);
    print("\n");
}

fn cstring_at(ptr: u64) -> Option<&'static str> {
    if ptr == 0 {
        return None;
    }
    let mut len = 0usize;
    while len < 255 {
        let b = unsafe { core::ptr::read((ptr + len as u64) as *const u8) };
        if b == 0 {
            break;
        }
        len += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    core::str::from_utf8(bytes).ok()
}

fn open_path(path: &str, mode: u32) -> i64 {
    let mut buf = [0u8; 256];
    let n = path.len().min(255);
    buf[..n].copy_from_slice(&path.as_bytes()[..n]);
    buf[n] = 0;
    syscall::open(buf.as_ptr(), mode)
}

fn write_fd(fd: i64, data: &[u8]) -> i64 {
    let mut buf = [0u8; 256];
    let n = data.len().min(255);
    buf[..n].copy_from_slice(&data[..n]);
    syscall::write(fd, buf.as_ptr(), n)
}

fn usage() {
    println("usage: ssh [user@]host[!port] [command]");
    println("Plan 9 SSH client: connects through /net/tcp/clone.");
    println("example: ssh 10.0.2.2!2222");
}

fn split_host_port(host_part: &str) -> Option<(&str, u16)> {
    let sep = if host_part.contains('!') {
        '!'
    } else if host_part.contains(':') {
        ':'
    } else {
        return Some((host_part, DEFAULT_SSH_PORT));
    };

    let mut pieces = host_part.split(sep);
    let host = pieces.next().unwrap_or("");
    let port_text = pieces.next().unwrap_or("");
    if host.is_empty() || port_text.is_empty() {
        return None;
    }
    match port_text.parse::<u16>() {
        Ok(port) => Some((host, port)),
        Err(_) => None,
    }
}

fn parse_remote(first: &str) -> Option<(&str, &str, u16)> {
    let (user, host_part) = if let Some(pos) = first.find('@') {
        (&first[..pos], &first[pos + 1..])
    } else {
        ("glenda", first)
    };

    let (host, port) = match split_host_port(host_part) {
        Some(v) => v,
        None => return None,
    };
    if user.is_empty() || host.is_empty() {
        return None;
    }
    Some((user, host, port))
}

fn format_u16(mut v: u16, buf: &mut [u8]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut n = 0usize;
    let mut tmp = [0u8; 5];
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

#[no_mangle]
pub extern "C" fn ssh_main(argc: u64, argv: u64, initial_rsp: u64) -> ! {
    let _ = initial_rsp;
    if argc < 2 {
        usage();
        syscall::exit(0);
    }

    let first = cstring_at(unsafe { *(argv as *const u64).add(1) });
    let command = if argc >= 3 {
        cstring_at(unsafe { *(argv as *const u64).add(2) })
    } else {
        None
    };

    let first = match first {
        Some(s) => s,
        None => {
            usage();
            syscall::exit(1);
        }
    };

    let (user, host, port) = match parse_remote(first) {
        Some(v) => v,
        None => {
            println("ssh: invalid host");
            usage();
            syscall::exit(1);
        }
    };

    println("[ssh] Plan 9 SSH client");
    print("[ssh] host=");
    print(host);
    print(" port=");
    let mut port_buf = [0u8; 8];
    println(format_u16(port, &mut port_buf));
    print("[ssh] user=");
    println(user);

    let fd = open_path("/net/tcp/clone", O_RDWR);
    if fd < 0 {
        println("ssh: open /net/tcp/clone failed");
        syscall::exit(1);
    }

    // Build the Plan 9 address command, e.g. `connect 10.0.2.2!2222`.
    let mut cmd = [0u8; 128];
    let prefix = b"connect ";
    let mut n = 0usize;
    cmd[..prefix.len()].copy_from_slice(prefix);
    n += prefix.len();
    let host_bytes = host.as_bytes();
    let hlen = host_bytes.len().min(64);
    cmd[n..n + hlen].copy_from_slice(&host_bytes[..hlen]);
    n += hlen;
    cmd[n] = b'!';
    n += 1;
    let mut port_buf2 = [0u8; 8];
    let port_text = format_u16(port, &mut port_buf2);
    let plen = port_text.len();
    cmd[n..n + plen].copy_from_slice(port_text.as_bytes());
    n += plen;

    let wrote = write_fd(fd, &cmd[..n]);
    if wrote < 0 {
        println("ssh: connect command failed");
        syscall::close(fd);
        syscall::exit(1);
    }

    // Read the server banner.  A real sshd sends `SSH-2.0-...` immediately.
    let mut banner = [0u8; 256];
    let got = syscall::read(fd, banner.as_mut_ptr(), banner.len());
    if got <= 0 {
        println("ssh: no server banner received");
        syscall::close(fd);
        syscall::exit(1);
    }
    let text = unsafe { core::str::from_utf8_unchecked(&banner[..got as usize]) };
    println("[ssh] server banner:");
    print(text);
    if !text.ends_with('\n') {
        println("");
    }

    // Send our SSH version banner.  The protocol crate defines
    // SSH-2.0-Plan9 as the client identifier.
    let client_banner = b"SSH-2.0-Plan9\r\n";
    let sent = write_fd(fd, client_banner);
    if sent < 0 {
        println("ssh: client banner write failed");
        syscall::close(fd);
        syscall::exit(1);
    }
    println("[ssh] sent SSH-2.0-Plan9");

    if let Some(cmd_text) = command {
        println("[ssh] remote command requested:");
        println(cmd_text);
        println("[ssh] key exchange/authentication not implemented");
    } else {
        println("[ssh] interactive session ready (banner exchange only)");
    }

    syscall::close(fd);
    println("[ssh] disconnected");
    syscall::exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nostack, preserves_flags)) }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfi", options(nostack, preserves_flags)) }
    }
}

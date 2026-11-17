//! `mkdir` — create directories (Plan 9 `mkdir [-p] dir...`).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: mkdir [-p] directory...");
        return 1;
    }
    let mut parents = false;
    let mut status = 0;
    for i in 1..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) if p != "-p" => p,
            Some("-p") => {
                parents = true;
                continue;
            }
            _ => continue,
        };
        if parents {
            if !mkdir_parents(path) {
                status = 1;
            }
            continue;
        }
        let cs = crate::syscall::make_cstr(path);
        let fd = crate::syscall::create3(cs.as_ptr(), crate::syscall::OREAD,
            crate::syscall::DMDIR | 0o755);
        if fd < 0 {
            crate::out_str("mkdir: can't create ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
        } else {
            crate::syscall::close(fd);
        }
    }
    status
}

/// Create every component of `path` (Plan 9 `mkdir -p`).
fn mkdir_parents(path: &str) -> bool {
    let mut buf = [0u8; 256];
    let bytes = path.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'/' && i > 0 {
            buf[..i].copy_from_slice(&bytes[..i]);
            buf[i] = 0;
            let fd = crate::syscall::create3(buf.as_ptr(), crate::syscall::OREAD,
                crate::syscall::DMDIR | 0o755);
            if fd >= 0 {
                crate::syscall::close(fd);
            }
        }
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    let fd = crate::syscall::create3(buf.as_ptr(), crate::syscall::OREAD,
        crate::syscall::DMDIR | 0o755);
    if fd < 0 {
        return false;
    }
    crate::syscall::close(fd);
    true
}

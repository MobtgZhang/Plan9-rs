use crate::{arg, outln, syscall};

pub fn mount(argc: usize, argv: *const *const u8) -> i32 {
    change(argc, argv, true)
}

pub fn bind(argc: usize, argv: *const *const u8) -> i32 {
    change(argc, argv, false)
}

fn change(argc: usize, argv: *const *const u8, mount: bool) -> i32 {
    let mut position = 1;
    let mut flags = 0;
    let mut authenticate = true;
    let mut quiet = false;
    let mut keys = "";
    while let Some(options) = arg(argc, argv, position).and_then(|word| word.strip_prefix('-')) {
        position += 1;
        if options == "-" {
            break;
        }
        for (index, option) in options.bytes().enumerate() {
            match option {
                b'b' => flags |= 1,
                b'a' => flags |= 2,
                b'c' => flags |= 4,
                b'n' if mount => authenticate = false,
                b'q' if mount => quiet = true,
                b'k' if mount => {
                    keys = &options[index + 1..];
                    if keys.is_empty() {
                        let Some(pattern) = arg(argc, argv, position) else { return usage(true) };
                        keys = pattern;
                        position += 1;
                    }
                    break;
                }
                _ => return usage(mount),
            }
        }
    }
    let Some(source) = arg(argc, argv, position) else { return usage(mount) };
    let Some(target) = arg(argc, argv, position + 1) else { return usage(mount) };
    if argc > position + if mount { 3 } else { 2 } || flags & 3 == 3 {
        return usage(mount);
    }
    let target = syscall::make_cstr(target);
    let result = if mount {
        let fd = open_service(source);
        if fd < 0 {
            if quiet { return 0; }
            outln("mount: cannot open service");
            return 1;
        }
        let spec = syscall::make_cstr(arg(argc, argv, position + 2).unwrap_or(""));
        let auth = if authenticate { syscall::fauth(fd, spec.as_ptr()) } else { -1 };
        let result = if auth >= 0 && !authenticate_mount(auth, keys) {
            if !quiet {
                outln("mount: authentication exchange with /mnt/factotum/rpc failed");
            }
            -1
        } else {
            syscall::mount(fd, auth.max(-1), target.as_ptr(), flags, spec.as_ptr())
        };
        if auth >= 0 {
            syscall::close(auth);
        }
        syscall::close(fd);
        result
    } else {
        let source = syscall::make_cstr(source);
        syscall::bind(source.as_ptr(), target.as_ptr(), flags)
    };
    if result < 0 && !quiet {
        outln(if mount { "mount: failed" } else { "bind: failed" });
        1
    } else {
        0
    }
}

fn open_service(source: &str) -> i64 {
    if source.len() >= 256 {
        return -1;
    }
    let path = syscall::make_cstr(source);
    let fd = syscall::open(path.as_ptr(), syscall::ORDWR);
    if fd >= 0 || source.contains('/') || source.starts_with('#') {
        return fd;
    }
    let prefix = b"/srv/";
    let mut path = [0; 256];
    let end = prefix.len() + source.len();
    if end >= path.len() {
        return fd;
    }
    path[..prefix.len()].copy_from_slice(prefix);
    path[prefix.len()..end].copy_from_slice(source.as_bytes());
    syscall::open(path.as_ptr(), syscall::ORDWR)
}

const RPC_MAX: usize = 4096;

fn authenticate_mount(auth: i64, keys: &str) -> bool {
    let rpc = syscall::open(b"/mnt/factotum/rpc\0".as_ptr(), 2);
    if rpc < 0 {
        return false;
    }
    let result = proxy_mount_auth(auth, rpc, keys).is_some();
    syscall::close(rpc);
    result
}

fn proxy_mount_auth(auth: i64, rpc: i64, keys: &str) -> Option<()> {
    let mut request = [0; RPC_MAX];
    let mut response = [0; RPC_MAX];
    let start = b"start proto=p9any role=client";
    let length = start.len() + 1 + keys.len();
    request.get_mut(..start.len())?.copy_from_slice(start);
    request[start.len()] = b' ';
    request.get_mut(start.len() + 1..length)?.copy_from_slice(keys.as_bytes());
    if rpc_exchange(rpc, &request[..length], &mut response)?.0 != b"ok" {
        return None;
    }
    loop {
        match rpc_exchange(rpc, b"read", &mut response)? {
            (b"done", _) => {
                let (status, info) = rpc_exchange(rpc, b"authinfo", &mut response)?;
                return (status == b"ok" && valid_auth_info(info)).then_some(());
            }
            (b"ok", data) if syscall::write(auth, data.as_ptr(), data.len()) == data.len() as i64 => {}
            (b"phase", _) => {
                let prefix = b"write ";
                request[..prefix.len()].copy_from_slice(prefix);
                let mut length = prefix.len();
                loop {
                    match rpc_exchange(rpc, &request[..length], &mut response)? {
                        (b"ok", _) => break,
                        (b"toosmall", size) => {
                            let end = core::str::from_utf8(size).ok()?.trim().parse::<usize>().ok()?
                                .checked_add(prefix.len())?;
                            let output = request.get_mut(length..end)?;
                            if output.is_empty() {
                                return None;
                            }
                            let count = syscall::read(auth, output.as_mut_ptr(), output.len());
                            if count <= 0 || count as usize > output.len() {
                                return None;
                            }
                            length += count as usize;
                        }
                        _ => return None,
                    }
                }
            }
            _ => return None,
        }
    }
}

fn valid_auth_info(mut data: &[u8]) -> bool {
    for _ in 0..4 {
        let Some((length, rest)) = data.split_first_chunk::<2>() else {
            return false;
        };
        let Some(remainder) = rest.get(u16::from_le_bytes(*length) as usize..) else {
            return false;
        };
        data = remainder;
    }
    data.is_empty()
}

fn rpc_exchange<'a>(rpc: i64, request: &[u8], response: &'a mut [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if syscall::write(rpc, request.as_ptr(), request.len()) != request.len() as i64 {
        return None;
    }
    let count = syscall::read(rpc, response.as_mut_ptr(), response.len());
    if count <= 0 {
        return None;
    }
    let response = response.get(..count as usize)?;
    Some(if let Some(separator) = response.iter().position(|byte| *byte == b' ') {
        (&response[..separator], &response[separator + 1..])
    } else {
        (response, &[])
    })
}

fn usage(mount: bool) -> i32 {
    outln(if mount { "usage: mount [-abcnq] [-k keypattern] service target [aname]" } else { "usage: bind [-abc] source target" });
    1
}

pub fn unmount(argc: usize, argv: *const *const u8) -> i32 {
    let (source, target) = match argc {
        2 => (None, arg(argc, argv, 1)),
        3 => (arg(argc, argv, 1), arg(argc, argv, 2)),
        _ => (None, None),
    };
    let Some(target) = target else {
        outln("usage: unmount [source] target");
        return 1;
    };
    let target = syscall::make_cstr(target);
    let name = source.map(syscall::make_cstr);
    let source = name.as_ref().map_or(core::ptr::null(), |value| value.as_ptr());
    if syscall::unmount(source, target.as_ptr()) < 0 {
        outln("unmount: failed");
        1
    } else {
        0
    }
}

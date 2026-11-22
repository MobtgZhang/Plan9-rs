//! `env` — print the environment (Plan 9 keeps this in /env).

use crate::syscall;

fn env_path<'a>(name: &[u8], path: &'a mut [u8; 256]) -> Option<&'a str> {
    let prefix = b"/env/";
    let end = prefix.len() + name.len();
    if end >= path.len() || name.is_empty() || name.contains(&b'/') {
        return None;
    }
    path[..prefix.len()].copy_from_slice(prefix);
    path[prefix.len()..end].copy_from_slice(name);
    core::str::from_utf8(&path[..end]).ok()
}

pub fn read_value(name: &str, output: &mut [u8]) -> Option<usize> {
    let mut path = [0u8; 256];
    read_path(env_path(name.as_bytes(), &mut path)?, output)
}

pub fn read_path(path: &str, output: &mut [u8]) -> Option<usize> {
    let fd = crate::open_read(path);
    if fd < 0 {
        return None;
    }
    let count = syscall::read(fd, output.as_mut_ptr(), output.len());
    syscall::close(fd);
    usize::try_from(count).ok()
}

pub fn set_value(name: &str, value: &[u8]) -> bool {
    let mut path = [0u8; 256];
    let Some(path) = env_path(name.as_bytes(), &mut path) else {
        return false;
    };
    let fd = crate::create_write(path);
    if fd < 0 {
        return false;
    }
    let success = value.is_empty() || syscall::write(fd, value.as_ptr(), value.len()) == value.len() as i64;
    syscall::close(fd);
    success
}

pub fn words(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    let limit = if value.is_empty() { 0 } else { usize::MAX };
    value.strip_suffix(b"\0").unwrap_or(value).split(|&byte| byte == 0).take(limit)
}

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let directory = crate::open_read("/env");
    if directory < 0 {
        return 1;
    }
    let mut reader = crate::DirReader::new(directory);
    let mut value = [0u8; 4096];
    while let Some(name) = reader.next_name() {
        let Ok(name) = core::str::from_utf8(name) else {
            continue;
        };
        if let Some(count) = read_value(name, &mut value) {
            crate::out(name.as_bytes());
            crate::out(b"=");
            for (index, word) in words(&value[..count]).enumerate() {
                if index != 0 {
                    crate::out(b" ");
                }
                crate::out(word);
            }
            crate::out(b"\n");
        }
    }
    syscall::close(directory);
    0
}

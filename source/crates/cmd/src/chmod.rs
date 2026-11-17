//! `chmod` — change file permission bits.
//!
//! Accepts both octal (`chmod 755 file`) and symbolic (`chmod u+x file`,
//! `chmod go-w file`) modes, like the Plan 9 command.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: chmod mode file...");
        return 1;
    }
    let mode_arg = match crate::arg(argc, argv, 1) {
        Some(m) => m,
        None => return 1,
    };

    let mut status = 0;
    for i in 2..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) => p,
            None => continue,
        };
        if !apply(path, mode_arg) {
            crate::out_str("chmod: can't change ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
        }
    }
    status
}

fn apply(path: &str, mode_arg: &str) -> bool {
    let cs = crate::syscall::make_cstr(path);

    // Octal form.
    if mode_arg.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        let mode = match u32::from_str_radix(mode_arg, 8) {
            Ok(m) => m,
            Err(_) => return false,
        };
        return crate::syscall::chmod(cs.as_ptr(), mode) >= 0;
    }

    // Symbolic form: modify the current mode reported by stat.
    let current = match current_mode(path) {
        Some(m) => m,
        None => return false,
    };
    let new = match apply_symbolic(current, mode_arg) {
        Some(m) => m,
        None => return false,
    };
    crate::syscall::chmod(cs.as_ptr(), new) >= 0
}

/// Read the low permission bits of `path`.
fn current_mode(path: &str) -> Option<u32> {
    let mut sb = [0u8; 256];
    let n = crate::stat_text(path, &mut sb)?;
    // stat text is "name mode length qid\n".
    let text = &sb[..n];
    let mut it = text.split(|&b| b == b' ');
    let _name = it.next()?;
    let mode_field = it.next()?;
    let mode = core::str::from_utf8(mode_field).ok()?.parse::<u64>().ok()?;
    Some((mode & 0o777) as u32)
}

/// Apply a symbolic mode expression such as `u+x,g-w`.
fn apply_symbolic(current: u32, expr: &str) -> Option<u32> {
    let mut mode = current;
    for clause in expr.split(',') {
        if clause.is_empty() {
            continue;
        }
        let bytes = clause.as_bytes();
        let mut who_mask: u32 = 0;
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'u' => who_mask |= 0o700,
                b'g' => who_mask |= 0o070,
                b'o' => who_mask |= 0o007,
                b'a' => who_mask |= 0o777,
                _ => break,
            }
            i += 1;
        }
        if who_mask == 0 {
            who_mask = 0o777;
        }
        if i >= bytes.len() {
            return None;
        }
        let op = bytes[i];
        i += 1;
        let mut bits: u32 = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'r' => bits |= 0o444,
                b'w' => bits |= 0o222,
                b'x' => bits |= 0o111,
                b'X' => bits |= 0o111,
                b's' | b't' => {}
                _ => return None,
            }
            i += 1;
        }
        let bits = bits & who_mask;
        match op {
            b'+' => mode |= bits,
            b'-' => mode &= !bits,
            b'=' => mode = (mode & !who_mask) | bits,
            _ => return None,
        }
    }
    Some(mode & 0o777)
}

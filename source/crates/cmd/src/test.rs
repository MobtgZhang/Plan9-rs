//! `test` — evaluate a simple expression (Plan 9 test supports many
//! primaries; this port covers file tests, string and integer compares).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        return 1;
    }
    let r = eval(argc, argv);
    if r {
        0
    } else {
        1
    }
}

fn eval(argc: usize, argv: *const *const u8) -> bool {
    let a = |i: usize| crate::arg(argc, argv, i).unwrap_or("");

    // Single argument: true when non-empty.
    if argc == 2 {
        return !a(1).is_empty();
    }

    match a(1) {
        "-e" => return stat_exists(a(2)),
        "-f" => return stat_kind(a(2)) == Some(false),
        "-d" => return stat_kind(a(2)) == Some(true),
        "-n" => return !a(2).is_empty(),
        "-z" => return a(2).is_empty(),
        _ => {},
    }

    if argc == 3 {
        return false; // unknown primary
    }

    // Three-argument binary operators.
    if argc == 4 {
        let l = a(1);
        let op = a(2);
        let r = a(3);
        return match op {
            "=" => l == r,
            "!=" => l != r,
            "-eq" => num(l) == num(r),
            "-ne" => num(l) != num(r),
            "-gt" => num(l) > num(r),
            "-lt" => num(l) < num(r),
            "-ge" => num(l) >= num(r),
            "-le" => num(l) <= num(r),
            _ => false,
        };
    }

    false
}

fn num(s: &str) -> i64 {
    crate::parse_i64(s).unwrap_or(0)
}

/// Some(true) when the path is a directory; None when missing.
fn stat_kind(path: &str) -> Option<bool> {
    let mut sb = [0u8; 256];
    let n = crate::stat_text(path, &mut sb)?;
    let text = &sb[..n];
    let mut fields = text.split(|&b| b == b' ' || b == b'\n');
    let _name = fields.next();
    let mode = fields
        .next()
        .and_then(|f| core::str::from_utf8(f).ok())
        .and_then(crate::parse_u64)
        .unwrap_or(0);
    Some(mode & 0x4000_0000 != 0)
}

fn stat_exists(path: &str) -> bool {
    let mut sb = [0u8; 256];
    crate::stat_text(path, &mut sb).is_some()
}

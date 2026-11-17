//! `basename` — strip directory and suffix from a path.
//!
//! ```text
//! basename /bin/ls        -> ls
//! basename /bin/ls .old   -> ls (suffix stripped when it matches)
//! ```

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: basename path [suffix]");
        return 1;
    }
    let path = crate::arg(argc, argv, 1).unwrap_or("");
    let suffix = if argc > 2 { crate::arg(argc, argv, 2) } else { None };

    // Strip trailing slashes (but keep a bare "/" intact).
    let mut end = path.len();
    while end > 1 && path.as_bytes()[end - 1] == b'/' {
        end -= 1;
    }
    let path = &path[..end];

    let base = match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    };

    let out = match suffix {
        Some(sfx) if !sfx.is_empty() && base.len() > sfx.len() && base.ends_with(sfx) => {
            &base[..base.len() - sfx.len()]
        }
        _ => base,
    };
    crate::out_str(out);
    crate::out(b"\n");
    0
}

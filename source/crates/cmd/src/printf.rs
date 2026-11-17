//! `printf` — formatted output: `printf format [args...]`.
//! Supports %s %d %u %x %c %% and \n \t \\ escapes (subset of Plan 9).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: printf format [args...]");
        return 1;
    }
    let fmt = crate::arg(argc, argv, 1).unwrap_or("");
    let mut next_arg = 2usize;
    let fb = fmt.as_bytes();
    let mut i = 0usize;
    while i < fb.len() {
        let b = fb[i];
        if b != b'%' {
            if b == b'\\' && i + 1 < fb.len() {
                i += 1;
                match fb[i] {
                    b'n' => crate::out(b"\n"),
                    b't' => crate::out(b"\t"),
                    b'r' => crate::out(b"\r"),
                    b'\\' => crate::out(b"\\"),
                    other => {
                        crate::out(&[b'\\', other]);
                    }
                }
                i += 1;
                continue;
            }
            crate::out(&[b]);
            i += 1;
            continue;
        }
        // A conversion.
        i += 1;
        if i >= fb.len() {
            crate::out(b"%");
            break;
        }
        match fb[i] {
            b'%' => crate::out(b"%"),
            b's' => {
                let a = crate::arg(argc, argv, next_arg).unwrap_or("");
                next_arg += 1;
                crate::out_str(a);
            }
            b'd' | b'i' => {
                let a = crate::arg(argc, argv, next_arg)
                    .and_then(crate::parse_i64)
                    .unwrap_or(0);
                next_arg += 1;
                let mut nb = [0u8; 24];
                crate::out_str(crate::itoa(a, &mut nb));
            }
            b'u' => {
                let a = crate::arg(argc, argv, next_arg)
                    .and_then(crate::parse_u64)
                    .unwrap_or(0);
                next_arg += 1;
                let mut nb = [0u8; 24];
                crate::out_str(crate::utoa(a, &mut nb));
            }
            b'x' => {
                let a = crate::arg(argc, argv, next_arg)
                    .and_then(crate::parse_u64)
                    .unwrap_or(0);
                next_arg += 1;
                let mut nb = [0u8; 24];
                hex_out(a, &mut nb);
            }
            b'c' => {
                let a = crate::arg(argc, argv, next_arg).unwrap_or("");
                next_arg += 1;
                let ab = a.as_bytes();
                if !ab.is_empty() {
                    crate::out(&[ab[0]]);
                }
            }
            other => {
                crate::out(&[b'%', other]);
            }
        }
        i += 1;
    }
    0
}

/// Render `v` in lowercase hex.
fn hex_out(v: u64, buf: &mut [u8; 24]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if v == 0 {
        crate::out(b"0");
        return;
    }
    let mut n = 0usize;
    let mut v = v;
    while v > 0 && n < buf.len() {
        buf[n] = HEX[(v & 0xf) as usize];
        v >>= 4;
        n += 1;
    }
    for i in (0..n).rev() {
        crate::out(&[buf[i]]);
    }
}

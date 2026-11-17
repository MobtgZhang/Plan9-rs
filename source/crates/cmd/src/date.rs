//! `date` — print the wall-clock time, Plan 9 style.
//!
//! `date`         -> "Mon Nov 16 08:15:23 GMT 2026"
//! `date -n`      -> seconds since the Unix epoch (raw /dev/time value)

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let raw = argc > 1 && crate::arg(argc, argv, 1) == Some("-n");
    let secs = match crate::syscall::time(0) {
        t if t >= 0 => t as i64,
        _ => {
            crate::outln("date: no clock");
            return 1;
        }
    };
    if raw {
        let mut b = [0u8; 20];
        crate::out_str(crate::itoa(secs, &mut b));
        crate::out(b"\n");
        return 0;
    }
    crate::out_str(render_gmt(secs));
    crate::out(b"\n");
    0
}

/// Day/month/weekday names, Plan 9 date style.
const WDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Render Unix seconds as "Mon Nov 16 08:15:23 GMT 2026".
///
/// Uses a leaked static buffer because a `&str` cannot borrow a local.
fn render_gmt(secs: i64) -> &'static str {
    static mut BUF: [u8; 40] = [0u8; 40];
    static mut LEN: usize = 0;

    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let wday = WDAYS[days.rem_euclid(7) as usize];

    let mut b = [0u8; 40];
    let mut i = 0usize;
    push(&mut b, &mut i, wday);
    push(&mut b, &mut i, " ");
    push(&mut b, &mut i, MONTHS[(m - 1) as usize]);
    push(&mut b, &mut i, " ");
    pad2(&mut b, &mut i, d as u32);
    push(&mut b, &mut i, " ");
    pad2(&mut b, &mut i, hh as u32);
    push(&mut b, &mut i, ":");
    pad2(&mut b, &mut i, mm as u32);
    push(&mut b, &mut i, ":");
    pad2(&mut b, &mut i, ss as u32);
    push(&mut b, &mut i, " GMT ");
    let mut yb = [0u8; 8];
    let ys = crate::utoa(y as u64, &mut yb);
    for _ in ys.len()..4 {
        push(&mut b, &mut i, "0");
    }
    push(&mut b, &mut i, ys);

    unsafe {
        BUF = b;
        LEN = i;
        core::str::from_utf8_unchecked(&BUF[..LEN])
    }
}

fn push(b: &mut [u8; 40], i: &mut usize, s: &str) {
    for &c in s.as_bytes() {
        if *i < b.len() {
            b[*i] = c;
            *i += 1;
        }
    }
}

fn pad2(b: &mut [u8; 40], i: &mut usize, v: u32) {
    let mut t = [0u8; 4];
    let s = crate::utoa(v as u64, &mut t);
    if s.len() < 2 {
        b[*i] = b'0';
        *i += 1;
    }
    push(b, i, s);
}

/// Howard Anton's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

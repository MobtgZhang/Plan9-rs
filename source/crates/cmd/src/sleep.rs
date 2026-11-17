//! `sleep` — suspend execution for the given number of seconds
//! (Plan 9 sleep takes seconds; fractional values round up to one).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: sleep seconds");
        return 1;
    }
    let secs = match crate::arg(argc, argv, 1).and_then(crate::parse_i64) {
        Some(v) if v > 0 => v,
        Some(v) if v == 0 => return 0,
        _ => {
            crate::outln("usage: sleep seconds");
            return 1;
        }
    };
    crate::syscall::sleep_ms((secs as u64).saturating_mul(1000));
    0
}

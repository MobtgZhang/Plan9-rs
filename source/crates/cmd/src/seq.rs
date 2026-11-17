//! `seq` — print a sequence of numbers (Plan 9 `seq [first [incr]] last`).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let (first, incr, last) = match argc {
        2 => (
            1i64,
            1i64,
            crate::arg(argc, argv, 1).and_then(crate::parse_i64).unwrap_or(0),
        ),
        3 => (
            crate::arg(argc, argv, 1).and_then(crate::parse_i64).unwrap_or(0),
            1i64,
            crate::arg(argc, argv, 2).and_then(crate::parse_i64).unwrap_or(0),
        ),
        4 => (
            crate::arg(argc, argv, 1).and_then(crate::parse_i64).unwrap_or(0),
            crate::arg(argc, argv, 2).and_then(crate::parse_i64).unwrap_or(1),
            crate::arg(argc, argv, 3).and_then(crate::parse_i64).unwrap_or(0),
        ),
        _ => {
            crate::outln("usage: seq [first [incr]] last");
            return 1;
        }
    };
    if incr == 0 || (last - first) * incr < 0 {
        // Zero step or a step that never reaches `last`: print nothing.
        if first == last {
            print_one(first);
        }
        return 0;
    }
    let mut v = first;
    while (incr > 0 && v <= last) || (incr < 0 && v >= last) {
        print_one(v);
        v += incr;
    }
    0
}

fn print_one(v: i64) {
    let mut b = [0u8; 20];
    crate::out_str(crate::itoa(v, &mut b));
    crate::out(b"\n");
}

//! `yes` — repeat a string until killed (Plan 9 /bin/yes).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let word = if argc > 1 {
        crate::arg(argc, argv, 1).unwrap_or("y")
    } else {
        "y"
    };
    loop {
        crate::out_str(word);
        crate::out(b"\n");
        crate::syscall::yield_cpu();
        crate::syscall::sleep_ms(200);
    }
}

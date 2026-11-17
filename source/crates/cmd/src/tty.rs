//! `tty` — print the terminal device path (Plan 9: /dev/console).

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // The console is always fd 0/1 in this kernel.
    crate::outln("/dev/console");
    0
}

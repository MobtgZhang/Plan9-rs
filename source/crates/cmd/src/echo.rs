//! `echo` — Plan 9 style: `echo [-n] args...`
//!
//! Writes its arguments separated by spaces, terminated by a newline
//! unless `-n` is given.  No escape interpretation (Plan 9 semantics).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let newline = match crate::arg(argc, argv, 1) {
        Some("-n") => false,
        _ => true,
    };
    let first = if !newline { 2 } else { 1 };
    for i in first..argc {
        if let Some(a) = crate::arg(argc, argv, i) {
            if i > first {
                crate::out(b" ");
            }
            crate::out_str(a);
        }
    }
    if newline {
        crate::out(b"\n");
    }
    0
}

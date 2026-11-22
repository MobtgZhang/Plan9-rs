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
    let mut output = [0; 4096];
    let mut length = 0;
    for index in first..argc {
        if let Some(argument) = crate::arg(argc, argv, index) {
            let separator = usize::from(index > first);
            let end = length + separator + argument.len();
            if end > output.len() - usize::from(newline) {
                return write_stream(first, argc, argv, newline);
            }
            if separator != 0 {
                output[length] = b' ';
            }
            output[length + separator..end].copy_from_slice(argument.as_bytes());
            length = end;
        }
    }
    if newline {
        output[length] = b'\n';
        length += 1;
    }
    if length == 0 {
        return 0;
    }
    let written = crate::syscall::write(1, output.as_ptr(), length);
    if written <= 0 {
        return 1;
    }
    crate::out(&output[written as usize..length]);
    0
}

fn write_stream(first: usize, argc: usize, argv: *const *const u8, newline: bool) -> i32 {
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

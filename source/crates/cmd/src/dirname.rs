//! `dirname` — print the directory part of a path.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: dirname path");
        return 1;
    }
    let path = crate::arg(argc, argv, 1).unwrap_or("");

    let mut end = path.len();
    while end > 1 && path.as_bytes()[end - 1] == b'/' {
        end -= 1;
    }
    let path = &path[..end];

    let dir = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => ".",
    };
    crate::out_str(dir);
    crate::out(b"\n");
    0
}

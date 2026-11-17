//! `uname` — print kernel identity (`-s` system name, `-r` release).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut all = argc == 1;
    let mut s = false;
    let mut r = false;
    let mut v = false;
    for i in 1..argc {
        match crate::arg(argc, argv, i) {
            Some("-s") => s = true,
            Some("-r") => r = true,
            Some("-v") => v = true,
            Some("-a") => all = true,
            _ => {}
        }
    }
    if all || (!s && !r && !v) {
        crate::outln("Plan9 plan9rs 1.0 x86_64");
        return 0;
    }
    let mut wrote = false;
    if s || all {
        crate::out_str("Plan9");
        wrote = true;
    }
    if r || all {
        if wrote {
            crate::out(b" ");
        }
        crate::out_str("1.0");
        wrote = true;
    }
    if v || all {
        if wrote {
            crate::out(b" ");
        }
        crate::out_str("plan9rs-rust");
        wrote = true;
    }
    crate::out(b"\n");
    0
}

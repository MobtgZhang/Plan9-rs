//! `ln` — create a hard link is not supported by the RAM root; this
//! version copies (documented deviation, matching the kernel's
//! capability set) unless `-s`, which is rejected outright.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    let mut targets: [&str; 2] = [""; 2];
    let mut n = 0usize;
    for i in 1..argc {
        match crate::arg(argc, argv, i) {
            Some("-s") => {
                crate::outln("ln: symbolic links are not supported by this kernel");
                return 1;
            }
            Some(a) => {
                if n < 2 {
                    targets[n] = a;
                    n += 1;
                }
            }
            None => {}
        }
    }
    if n < 2 {
        crate::outln("usage: ln source destination");
        return 1;
    }
    if crate::copy_path(targets[0], targets[1]) {
        0
    } else {
        crate::outln("ln: cannot link");
        1
    }
}

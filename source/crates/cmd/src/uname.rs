//! `uname` — print kernel identity (`-s` system name, `-r` release).

/// Architecture of the running kernel; the command is compiled per
/// target, so this resolves at build time.
#[cfg(target_arch = "aarch64")]
const KERNEL_ARCH: &str = "aarch64";
#[cfg(target_arch = "riscv64")]
const KERNEL_ARCH: &str = "riscv64";
#[cfg(target_arch = "loongarch64")]
const KERNEL_ARCH: &str = "loongarch64";
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64")))]
const KERNEL_ARCH: &str = "x86_64";

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
        crate::out(b"Plan9 plan9rs 1.0 ");
        crate::out_str(KERNEL_ARCH);
        crate::out(b"\n");
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
    }
    crate::out(b"\n");
    0
}

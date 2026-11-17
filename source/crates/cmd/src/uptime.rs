//! `sleep` already exists; `touch` too.  This is `mkfile`-less
//! `readable`-free `uptime`: print how long the kernel has been up.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // SYS_TIME with mode 1 returns monotonic uptime in milliseconds.
    let ms = crate::syscall::time(1);
    if ms < 0 {
        crate::outln("uptime: unavailable");
        return 1;
    }
    let secs = ms as u64 / 1000;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let mut b = [0u8; 20];
    crate::out_str("up ");
    crate::out_str(crate::utoa(h, &mut b));
    crate::out_str(" hours, ");
    crate::out_str(crate::utoa(m, &mut b));
    crate::out_str(" minutes, ");
    crate::out_str(crate::utoa(s, &mut b));
    crate::out_str(" seconds\n");
    0
}

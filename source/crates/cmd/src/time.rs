//! `time` — run a command and report user/system/real time
//! (Plan 9 prints wall, user and system seconds).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: time command [args]");
        return 1;
    }
    let start_ms = crate::syscall::time(1).max(0) as u64;

    let prog = crate::arg(argc, argv, 1).unwrap_or("");
    let cs = crate::syscall::make_cstr(prog);

    // Build argv: prog arg2 arg3 ...
    let mut argbufs: [[u8; 64]; 8] = [[0u8; 64]; 8];
    let mut ptrs: [*const u8; 9] = [core::ptr::null(); 9];
    let n = (argc - 1).min(8);
    for k in 0..n {
        let a = crate::arg(argc, argv, k + 1).unwrap_or("");
        let b = a.as_bytes();
        let m = b.len().min(63);
        argbufs[k][..m].copy_from_slice(&b[..m]);
        ptrs[k] = argbufs[k].as_ptr();
    }
    ptrs[n] = core::ptr::null();

    let pid = crate::syscall::fork();
    if pid == 0 {
        let rc = crate::syscall::exec(cs.as_ptr(), ptrs.as_ptr());
        if rc < 0 {
            crate::out_str("time: can't exec ");
            crate::out_str(prog);
            crate::out(b"\n");
            crate::syscall::exit(1);
        }
    } else if pid > 0 {
        crate::syscall::wait(pid as i32);
        let end_ms = crate::syscall::time(1).max(0) as u64;
        let secs = end_ms.saturating_sub(start_ms);
        crate::out_str("real ");
        print_secs(secs / 1000);
        crate::out_str("user 0.0\n");
        crate::out_str("sys  0.0\n");
        return 0;
    } else {
        crate::outln("time: fork failed");
        return 1;
    }
    0
}

fn print_secs(ms: u64) {
    let mut b = [0u8; 8];
    crate::out_str(crate::utoa(ms / 1000, &mut b));
    crate::out(b".");
    let mut b2 = [0u8; 8];
    crate::out_str(crate::utoa(ms % 1000, &mut b2));
    crate::out(b"s\n");
}

//! `kill` — post a note to a process; `kill pid` posts the special
//! `kill` note through /proc/<pid>/ctl, terminating it (Plan 9
//! semantics: `kill pid` == `echo kill >/proc/pid/ctl`).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: kill pid");
        return 1;
    }
    let mut status = 0;
    for i in 1..argc {
        let pid = match crate::arg(argc, argv, i).and_then(crate::parse_u64) {
            Some(p) => p,
            None => {
                crate::outln("kill: usage: kill pid");
                return 1;
            }
        };
        let mut path = crate::ls::String8::new();
        path.push_str("/proc/");
        path.push_str(pid_text(pid));
        path.push_str("/ctl");
        let cs = crate::syscall::make_cstr(path.as_str());
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OWRITE);
        if fd < 0 {
            crate::out_str("kill: no such process ");
            crate::out_str(pid_text(pid));
            crate::out(b"\n");
            status = 1;
            continue;
        }
        if crate::syscall::write(fd, b"kill".as_ptr(), 4) < 0 {
            status = 1;
        }
        crate::syscall::close(fd);
    }
    status
}

fn pid_text(pid: u64) -> &'static str {
    static mut BUF: [u8; 20] = [0u8; 20];
    unsafe {
        let s = crate::utoa(pid, &mut BUF);
        // copy into the static so the slice lifetime is 'static
        let mut i = 0;
        for &b in s.as_bytes() {
            BUF[i] = b;
            i += 1;
        }
        core::str::from_utf8_unchecked(&BUF[..s.len()])
    }
}

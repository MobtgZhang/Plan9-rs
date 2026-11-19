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
        let mut pid_buffer = [0; 20];
        let pid_text = crate::utoa(pid, &mut pid_buffer);
        path.push_str("/proc/");
        path.push_str(pid_text);
        path.push_str("/ctl");
        let cs = crate::syscall::make_cstr(path.as_str());
        let fd = crate::syscall::open(cs.as_ptr(), crate::syscall::OWRITE);
        if fd < 0 {
            crate::out_str("kill: no such process ");
            crate::out_str(pid_text);
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

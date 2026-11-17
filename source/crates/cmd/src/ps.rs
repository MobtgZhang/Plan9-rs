//! `ps` — process status: lists /proc entries with their state and
//! memory, mirroring Plan 9's ps output columns.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let mut buf = [0u8; 2048];
    let n = crate::list_dir("/proc", &mut buf);
    if n < 0 {
        crate::outln("ps: cannot list /proc");
        return 1;
    }
    crate::out_str("USER   PID  STATE  MEM   COMMAND\n");
    let text = &buf[..n as usize];
    let mut start = 0usize;
    while start < text.len() {
        let end = text[start..].iter().position(|&b| b == b'\n')
            .map(|p| start + p).unwrap_or(text.len());
        let pidb = &text[start..end];
        start = end + 1;
        let pid = core::str::from_utf8(pidb).unwrap_or("").trim();
        if pid.is_empty() {
            continue;
        }
        print_one(pid);
    }
    0
}

fn print_one(pid: &str) {
    // /proc/<pid>/status text: "PID\t..\nState\t..\nSegments\t..\nMemBytes\t..\n"
    let mut path = crate::ls::String8::new();
    path.push_str("/proc/");
    path.push_str(pid);
    path.push_str("/status");
    let mut sb = [0u8; 512];
    let got = crate::stat_text(path.as_str(), &mut sb);
    if got.is_none() {
        return;
    }
    let text = core::str::from_utf8(&sb[..got.unwrap()]).unwrap_or("");
    let mut state = "?";
    let mut mem = 0u64;
    for field in text.split('\n') {
        let mut it = field.split('\t');
        if let Some(k) = it.next() {
            match k {
                "State" => state = it.next().unwrap_or("?"),
                "MemBytes" => mem = it.next().and_then(crate::parse_u64).unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut mb = [0u8; 16];
    let mems = crate::utoa(mem, &mut mb);
    crate::out_str("glenda ");
    pad(pid, 5);
    crate::out_str(" ");
    pad(state, 6);
    crate::out_str(" ");
    pad(mems, 6);
    crate::out_str(" ");
    crate::out_str(pid);
    crate::out(b"\n");
}

/// Print `s` padded to at least `width` columns.
fn pad(s: &str, width: usize) {
    crate::out_str(s);
    for _ in s.len()..width {
        crate::out(b" ");
    }
}

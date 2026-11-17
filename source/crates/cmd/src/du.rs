//! `du` — disk usage: total bytes of each file or directory tree
//! (the RAM root reports file lengths; there are no blocks).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        let mut b = [0u8; 24];
        let total = du("/");
        crate::out_str(crate::utoa(total as u64, &mut b));
        crate::out(b"\t/\n");
        return 0;
    }
    let mut status = 0;
    for i in 1..argc {
        if let Some(path) = crate::arg(argc, argv, i) {
            let total = du(path);
            if total < 0 {
                crate::out_str("du: can't read ");
                crate::out_str(path);
                crate::out(b"\n");
                status = 1;
                continue;
            }
            let mut b = [0u8; 24];
            crate::out_str(crate::utoa(total as u64, &mut b));
            crate::out(b"\t");
            crate::out_str(path);
            crate::out(b"\n");
        }
    }
    status
}

/// Recursive byte total; negative on error.
fn du(path: &str) -> i64 {
    let mut sb = [0u8; 256];
    let st = match crate::stat_text(path, &mut sb) {
        Some(n) => n,
        None => return -1,
    };
    let text = &sb[..st];
    // "name mode length qid\n"
    let mut fields = text.split(|&b| b == b' ' || b == b'\n');
    let _name = fields.next();
    let mode = fields.next().and_then(|f| core::str::from_utf8(f).ok()).and_then(crate::parse_u64).unwrap_or(0);
    let length = fields.next().and_then(|f| core::str::from_utf8(f).ok()).and_then(crate::parse_u64).unwrap_or(0);
    if mode & 0x4000_0000 == 0 {
        return length as i64;
    }
    // Directory: sum children.
    let mut buf = [0u8; 4096];
    let n = crate::list_dir(path, &mut buf);
    if n <= 0 {
        return 0;
    }
    let mut total = 0i64;
    let text = &buf[..n as usize];
    let mut start = 0usize;
    while start < text.len() {
        let end = text[start..].iter().position(|&b| b == b'\n')
            .map(|p| start + p).unwrap_or(text.len());
        let nameb = &text[start..end];
        start = end + 1;
        if nameb.is_empty() {
            continue;
        }
        let child = crate::ls::String8::from_two(path, unsafe {
            core::str::from_utf8_unchecked(nameb)
        });
        total += du(child.as_str());
    }
    total
}

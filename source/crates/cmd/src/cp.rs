//! `cp` — copy files (Plan 9 `cp file1 ... filen destdir|destfile`).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: cp source... destination");
        return 1;
    }
    let mut status = 0;
    let single = argc == 3;
    for i in 1..argc - 1 {
        let src = match crate::arg(argc, argv, i) {
            Some(s) => s,
            None => continue,
        };
        let dst_dir = crate::arg(argc, argv, argc - 1).unwrap_or("");
        // Build the destination path in a fixed buffer that outlives the
        // copy (no allocation on the bare metal).
        let mut dst_buf = [0u8; 256];
        let dst_len: usize;
        if single {
            dst_len = dst_dir.len().min(255);
            dst_buf[..dst_len].copy_from_slice(dst_dir.as_bytes());
        } else {
            let base = src.rsplit('/').next().unwrap_or(src);
            let mut k = dst_dir.len().min(200);
            dst_buf[..k].copy_from_slice(&dst_dir.as_bytes()[..k]);
            if !dst_dir.ends_with('/') {
                dst_buf[k] = b'/';
                k += 1;
            }
            let m = base.len().min(255 - k);
            dst_buf[k..k + m].copy_from_slice(&base.as_bytes()[..m]);
            dst_len = k + m;
        }
        let dst = unsafe { core::str::from_utf8_unchecked(&dst_buf[..dst_len]) };
        if !crate::copy_path(src, dst) {
            crate::out_str("cp: can't copy ");
            crate::out_str(src);
            crate::out(b"\n");
            status = 1;
        }
    }
    status
}

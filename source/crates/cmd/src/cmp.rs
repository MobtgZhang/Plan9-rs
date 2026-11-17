//! `cmp` — compare two files byte by byte (Plan 9 /bin/cmp).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: cmp file1 file2");
        return 1;
    }
    let f1 = crate::arg(argc, argv, 1).unwrap_or("");
    let f2 = crate::arg(argc, argv, 2).unwrap_or("");

    let fd1 = crate::open_read(f1);
    let fd2 = crate::open_read(f2);
    if fd1 < 0 {
        crate::out_str("cmp: can't open ");
        crate::outln(f1);
        return 2;
    }
    if fd2 < 0 {
        crate::out_str("cmp: can't open ");
        crate::outln(f2);
        crate::syscall::close(fd1);
        return 2;
    }

    let mut b1 = [0u8; 512];
    let mut b2 = [0u8; 512];
    let mut line = 1u64;
    let mut pos = 0u64;
    let mut off1 = 0usize;
    let mut off2 = 0usize;
    let mut len1 = 0usize;
    let mut len2 = 0usize;
    let mut status = 0;

    loop {
        if off1 >= len1 {
            len1 = crate::syscall::read(fd1, b1.as_mut_ptr(), b1.len()) as usize;
            off1 = 0;
        }
        if off2 >= len2 {
            len2 = crate::syscall::read(fd2, b2.as_mut_ptr(), b2.len()) as usize;
            off2 = 0;
        }
        if len1 == 0 && len2 == 0 {
            break;
        }
        if len2 == 0 || (len1 > 0 && off1 >= len1) {
            crate::out_str("cmp: EOF on ");
            crate::outln(f1);
            status = 1;
            break;
        }
        if len1 == 0 {
            crate::out_str("cmp: EOF on ");
            crate::outln(f2);
            status = 1;
            break;
        }
        let a = b1[off1];
        let b = b2[off2];
        pos += 1;
        if a == b'\n' {
            line += 1;
        }
        if a != b {
            crate::out_str("cmp: ");
            crate::out_str(f1);
            crate::out_str(" ");
            crate::out_str(f2);
            crate::out_str(" differ: char ");
            let mut nb = [0u8; 20];
            crate::out_str(crate::utoa(pos, &mut nb));
            crate::out_str(" line ");
            crate::out_str(crate::utoa(line, &mut nb));
            crate::out(b"\n");
            status = 1;
            break;
        }
        off1 += 1;
        off2 += 1;
    }

    crate::syscall::close(fd1);
    crate::syscall::close(fd2);
    status
}

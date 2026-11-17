//! `stat` — print file status (Plan 9 prints name, size, owner, times;
//! the RAM root provides name, mode, length and qid).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 {
        crate::outln("usage: stat file...");
        return 1;
    }
    let mut status = 0;
    for i in 1..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) => p,
            None => continue,
        };
        let mut buf = [0u8; 256];
        match crate::stat_text(path, &mut buf) {
            Some(n) => {
                crate::out(&buf[..n]);
            }
            None => {
                crate::out_str("stat: can't stat ");
                crate::out_str(path);
                crate::out(b"\n");
                status = 1;
            }
        }
    }
    status
}

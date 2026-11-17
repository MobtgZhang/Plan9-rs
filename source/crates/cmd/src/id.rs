//! `id` — print the numeric user and group identity.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let uid = crate::syscall::getuid();
    let gid = crate::syscall::getgid();

    let mut name = [0u8; 64];
    let n = crate::syscall::getuser(&mut name);
    let name: &[u8] = if n > 0 { &name[..n as usize] } else { b"?" };

    crate::out_str("uid=");
    let mut b = [0u8; 20];
    crate::out_str(crate::itoa(uid, &mut b));
    crate::out_str("(");
    crate::out(name);
    crate::out_str(") gid=");
    let mut b2 = [0u8; 20];
    crate::out_str(crate::itoa(gid, &mut b2));

    // Supplementary groups.
    let mut groups = [0u32; 32];
    let ng = crate::syscall::getgroups(&mut groups);
    if ng > 0 {
        crate::out_str(" groups=");
        for i in 0..ng as usize {
            if i > 0 {
                crate::out(b",");
            }
            let mut gb = [0u8; 20];
            crate::out_str(crate::itoa(groups[i] as i64, &mut gb));
        }
    }
    crate::out(b"\n");
    0
}

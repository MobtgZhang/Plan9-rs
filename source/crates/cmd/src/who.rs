//! `who` — list logged-in users.  The kernel has no utmp; report the
//! console owner the way Plan 9 reports `$user` on the console.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let mut user = [0u8; 32];
    let n = crate::syscall::getuser(&mut user);
    let user: &[u8] = if n > 0 { &user[..n as usize] } else { b"glenda" };
    crate::out(user);
    crate::out_str("  console  ");
    // Current wall time from the RTC, printed as a raw timestamp.
    let t = crate::syscall::time(0);
    let mut b = [0u8; 20];
    crate::out_str(crate::utoa(t.max(0) as u64, &mut b));
    crate::out(b"\n");
    0
}

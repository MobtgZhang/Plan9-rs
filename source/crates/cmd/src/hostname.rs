//! `hostname` — print or set the system name.
//!
//! The kernel keeps no mutable host name in this prototype, so only the
//! query form is implemented; setting prints a diagnostic.

pub fn main(argc: usize, _argv: *const *const u8) -> i32 {
    if argc > 1 {
        crate::outln("hostname: changing the host name is not supported");
        return 1;
    }
    crate::out(crate::lineedit::hostname());
    crate::out(b"\n");
    0
}

//! `fortune` — print a random adage (Plan 9 ships one in /bin).

const FORTUNES: [&str; 12] = [
    "Plan 9 was designed with three goals in mind.",
    "Those who don't understand Plan 9 are doomed to reinvent it, poorly.",
    "A file system is a wonderful thing: everything is one.",
    "You can't trust code that you did not totally create yourself.",
    "The best way to predict the future is to implement it.",
    "Simplicity is a feature, not a compromise.",
    "9P: everything is a file, everywhere.",
    "UNIX is very simple, it just needs a genius to understand its simplicity.",
    "Pipes are the duct tape of Plan 9.",
    "Namespaces are the poor man's private universe.",
    "Rust rewrites all the world's kernels.",
    "From Outer Space, with love.",
];

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // The kernel has no entropy source; derive pseudo-randomness from the
    // monotonic clock's low bits.
    let ms = crate::syscall::time(1).max(0) as u64;
    let idx = (ms.wrapping_mul(2654435761) >> 13) as usize % FORTUNES.len();
    crate::outln(FORTUNES[idx]);
    0
}

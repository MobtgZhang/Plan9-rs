//! `clear` — clear the terminal screen (VT100 `ESC[2J ESC[H`).

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    // Clear the whole screen and home the cursor: the graphical console
    // and any serial terminal both understand this pair.
    crate::out(b"\x1b[2J\x1b[H");
    0
}

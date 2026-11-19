//! PS/2 keyboard scancode translation.
//!
//! The kernel keeps no input line discipline: whatever bytes the keyboard
//! produces land in the console device verbatim.  This module owns the
//! scan-code-set-1 to byte mapping, the modifier state (Shift, Caps Lock,
//! Ctrl) and the escape sequences for the cursor keys that the shell's line
//! editor understands.
//!
//! Modifier state is plain atomics rather than a lock because the mapping
//! runs from interrupt context and from the polling path in `dev.rs`.

use core::sync::atomic::{AtomicBool, Ordering};

/// Shift is currently held (either shift key).
static SHIFT: AtomicBool = AtomicBool::new(false);
/// Caps Lock is engaged.
static CAPS: AtomicBool = AtomicBool::new(false);
/// Control is currently held.
static CTRL: AtomicBool = AtomicBool::new(false);
/// Set when an 0xE0 prefix was seen, so the next code is "extended".
static EXTENDED: AtomicBool = AtomicBool::new(false);
/// Set while the keyboard IRQ handler is processing a scancode.  The
/// polling read path in `dev.rs` consults it to avoid consuming the same
/// keystroke a second time when the interrupt arrives mid-poll.
static IN_IRQ: AtomicBool = AtomicBool::new(false);

/// Claim the keyboard controller from the IRQ handler.
pub fn in_irq_mark() {
    IN_IRQ.store(true, Ordering::Release);
}

/// Release the keyboard controller after the IRQ handler finished.
pub fn in_irq_clear() {
    IN_IRQ.store(false, Ordering::Release);
}

/// Set when the *interrupt* path has already consumed a scancode that the
/// polling path has not yet seen, so the poller must not read port 0x60
/// again for this keystroke (QEMU keeps the port readable for a moment
/// after the IRQ, which otherwise produces double-delivered keys).
static IRQ_DELIVERED: AtomicBool = AtomicBool::new(false);

/// Returns true while the IRQ handler owns the keyboard controller.
pub fn irq_in_progress() -> bool {
    IN_IRQ.load(Ordering::Acquire)
}

/// Mark that the interrupt path has consumed a scancode that is now
/// queued in the console input buffer.
pub fn mark_irq_delivered() {
    IRQ_DELIVERED.store(true, Ordering::Release);
}

/// Clear the "delivered" flag once the polling path has observed it.
pub fn clear_irq_delivered() {
    IRQ_DELIVERED.store(false, Ordering::Release);
}

/// True when the last keystroke was consumed by the interrupt path and
/// the polling path should stand down for this round.
pub fn irq_delivered_pending() -> bool {
    IRQ_DELIVERED.load(Ordering::Acquire)
}

/// Cursor/navigation escape sequences produced by the extended keypad
/// scancodes.
const ESC_UP: &[u8] = b"\x1b[A";
const ESC_DOWN: &[u8] = b"\x1b[B";
const ESC_RIGHT: &[u8] = b"\x1b[C";
const ESC_LEFT: &[u8] = b"\x1b[D";
const ESC_HOME: &[u8] = b"\x1b[H";
const ESC_END: &[u8] = b"\x1b[F";
const ESC_DEL: &[u8] = b"\x1b[3~";
const ESC_PGUP: &[u8] = b"\x1b[5~";
const ESC_PGDN: &[u8] = b"\x1b[6~";

/// Unshifted and shifted legends for the main keyboard block, indexed by
/// scan code.
fn base(scan: u8) -> Option<(u8, u8)> {
    Some(match scan {
        0x02 => (b'1', b'!'),
        0x03 => (b'2', b'@'),
        0x04 => (b'3', b'#'),
        0x05 => (b'4', b'$'),
        0x06 => (b'5', b'%'),
        0x07 => (b'6', b'^'),
        0x08 => (b'7', b'&'),
        0x09 => (b'8', b'*'),
        0x0A => (b'9', b'('),
        0x0B => (b'0', b')'),
        0x0C => (b'-', b'_'),
        0x0D => (b'=', b'+'),
        0x10 => (b'q', b'Q'),
        0x11 => (b'w', b'W'),
        0x12 => (b'e', b'E'),
        0x13 => (b'r', b'R'),
        0x14 => (b't', b'T'),
        0x15 => (b'y', b'Y'),
        0x16 => (b'u', b'U'),
        0x17 => (b'i', b'I'),
        0x18 => (b'o', b'O'),
        0x19 => (b'p', b'P'),
        0x1A => (b'[', b'{'),
        0x1B => (b']', b'}'),
        0x1E => (b'a', b'A'),
        0x1F => (b's', b'S'),
        0x20 => (b'd', b'D'),
        0x21 => (b'f', b'F'),
        0x22 => (b'g', b'G'),
        0x23 => (b'h', b'H'),
        0x24 => (b'j', b'J'),
        0x25 => (b'k', b'K'),
        0x26 => (b'l', b'L'),
        0x27 => (b';', b':'),
        0x28 => (b'\'', b'"'),
        0x29 => (b'`', b'~'),
        0x2B => (b'\\', b'|'),
        0x2C => (b'z', b'Z'),
        0x2D => (b'x', b'X'),
        0x2E => (b'c', b'C'),
        0x2F => (b'v', b'V'),
        0x30 => (b'b', b'B'),
        0x31 => (b'n', b'N'),
        0x32 => (b'm', b'M'),
        0x33 => (b',', b'<'),
        0x34 => (b'.', b'>'),
        0x35 => (b'/', b'?'),
        0x39 => (b' ', b' '),
        _ => return None,
    })
}

/// Translate one raw scan code (with its break/release bit) into zero or
/// more bytes to append to the console input stream.
///
/// Returns a static slice: the mapping never builds a buffer, so the
/// interrupt handler can hand the bytes straight to the console device.
pub fn translate(scan: u8) -> &'static [u8] {
    let released = scan & 0x80 != 0;
    let code = scan & 0x7F;

    // The 0xE0 prefix marks the grey navigation keys.
    if code == 0xE0 {
        EXTENDED.store(!released, Ordering::Release);
        return b"";
    }
    let extended = EXTENDED.load(Ordering::Acquire);
    if extended {
        EXTENDED.store(false, Ordering::Release);
    }

    // Modifier keys change state on both press and release.
    match code {
        0x2A | 0x36 => {
            SHIFT.store(!released, Ordering::Release);
            return b"";
        }
        0x1D => {
            // Ctrl on the main block only; 0xE0 0x1D is Right Ctrl and is
            // treated as plain Ctrl as well.
            CTRL.store(!released, Ordering::Release);
            return b"";
        }
        0x3A => {
            if !released {
                CAPS.store(!CAPS.load(Ordering::Acquire), Ordering::Release);
            }
            return b"";
        }
        _ => {}
    }

    if released {
        return b"";
    }

    if extended {
        return match code {
            // The cursor pad sends the usual VT100 sequences so the shell's
            // line editor can implement history and movement.
            0x48 => ESC_UP,
            0x50 => ESC_DOWN,
            0x4D => ESC_RIGHT,
            0x4B => ESC_LEFT,
            0x47 => ESC_HOME,
            0x4F => ESC_END,
            0x53 => ESC_DEL,
            0x49 => ESC_PGUP,
            0x51 => ESC_PGDN,
            // Grey Enter.
            0x1C => b"\n",
            // Keypad slash.
            0x35 => b"/",
            _ => b"",
        };
    }

    let out: &'static [u8] = match code {
        0x0E => b"\x7f", // Backspace: DEL, what the line editor erases on
        0x0F => b"\t",
        0x1C => b"\n", // Enter (main block)
        _ => {
            let (lo, hi) = match base(code) {
                Some(p) => p,
                None => return b"",
            };
            let shift = SHIFT.load(Ordering::Acquire);
            let caps = CAPS.load(Ordering::Acquire);
            let mut ch = if shift { hi } else { lo };
            // Caps Lock affects letters only, and combines with Shift by
            // cancelling it (the usual behaviour).
            if caps && lo.is_ascii_lowercase() {
                let flipped = shift;
                ch = if flipped { lo } else { hi };
            }
            if CTRL.load(Ordering::Acquire) {
                // Ctrl-A .. Ctrl-Z map to 0x01 .. 0x1A.
                let upper = ch.to_ascii_uppercase();
                if upper.is_ascii_uppercase() {
                    return ctrl_byte(upper - b'A' + 1);
                }
                if ch == b'[' {
                    return ctrl_byte(0x1b);
                }
                if ch == b'\\' {
                    return ctrl_byte(0x1c);
                }
            }
            return single(ch);
        }
    };
    out
}

/// Single-byte slice for the common printable case.
fn single(ch: u8) -> &'static [u8] {
    ONE_BYTES.get(ch as usize).map(|b| &b[..]).unwrap_or(b"")
}

/// One-byte static array for every byte value, used by `single`.
static ONE_BYTES: [[u8; 1]; 256] = {
    let mut t = [[0u8; 1]; 256];
    let mut i = 0;
    while i < 256 {
        t[i][0] = i as u8;
        i += 1;
    }
    t
};

fn ctrl_byte(v: u8) -> &'static [u8] {
    ONE_BYTES.get(v as usize).map(|b| &b[..]).unwrap_or(b"")
}

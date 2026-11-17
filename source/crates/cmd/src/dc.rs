//! `dc` — tiny stack calculator reading expressions from stdin:
//! numbers push, `+ - * / %` operate, `p` prints the top, `q` quits.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    let mut stack = [0i64; 64];
    let mut sp = 0usize;
    let mut lr = crate::LineReader::new(0);
    let mut line = [0u8; 256];
    let mut status = 0;

    'outer: while let Some(n) = lr.next_line(&mut line) {
        let text = core::str::from_utf8(&line[..n]).unwrap_or("");
        for tok in text.split_whitespace() {
            if let Some(v) = crate::parse_i64(tok) {
                if sp < stack.len() {
                    stack[sp] = v;
                    sp += 1;
                }
                continue;
            }
            let cmd = tok.as_bytes();
            match cmd {
                b"+" | b"-" | b"*" | b"/" | b"%" => {
                    if sp < 2 {
                        crate::outln("dc: stack underflow");
                        status = 1;
                        continue;
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    let r = match cmd[0] {
                        b'+' => a.wrapping_add(b),
                        b'-' => a.wrapping_sub(b),
                        b'*' => a.wrapping_mul(b),
                        b'/' => {
                            if b == 0 {
                                crate::outln("dc: division by zero");
                                status = 1;
                                0
                            } else {
                                a / b
                            }
                        }
                        _ => {
                            if b == 0 {
                                crate::outln("dc: division by zero");
                                status = 1;
                                0
                            } else {
                                a % b
                            }
                        }
                    };
                    if sp < stack.len() {
                        stack[sp] = r;
                        sp += 1;
                    }
                }
                b"p" => {
                    if sp > 0 {
                        let mut b1 = [0u8; 24];
                        crate::out_str(crate::itoa(stack[sp - 1], &mut b1));
                        crate::out(b"\n");
                    }
                }
                b"f" => {
                    for i in (0..sp).rev() {
                        let mut b1 = [0u8; 24];
                        crate::out_str(crate::itoa(stack[i], &mut b1));
                        crate::out(b"\n");
                    }
                }
                b"c" => sp = 0,
                b"q" => break 'outer,
                _ => {
                    crate::out_str("dc: syntax error: ");
                    crate::outln(tok);
                    status = 1;
                }
            }
        }
    }
    status
}

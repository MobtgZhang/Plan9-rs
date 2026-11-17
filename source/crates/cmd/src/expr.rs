//! `expr` — evaluate a simple integer expression:
//! `expr a op b` with op one of + - \* / % or the comparison
//! = != < <= > >= (Plan 9 /bin/expr subset, argv form).

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 4 {
        crate::outln("usage: expr a op b");
        return 1;
    }
    let a = match crate::arg(argc, argv, 1).and_then(crate::parse_i64) {
        Some(v) => v,
        None => {
            crate::outln("expr: numeric operand expected");
            return 2;
        }
    };
    let op = crate::arg(argc, argv, 2).unwrap_or("");
    let b = match crate::arg(argc, argv, 3).and_then(crate::parse_i64) {
        Some(v) => v,
        None => {
            crate::outln("expr: numeric operand expected");
            return 2;
        }
    };

    let r = match op {
        "+" => Some(a.wrapping_add(b)),
        "-" => Some(a.wrapping_sub(b)),
        "*" | "\\*" => Some(a.wrapping_mul(b)),
        "/" => {
            if b == 0 {
                None
            } else {
                Some(a / b)
            }
        }
        "%" => {
            if b == 0 {
                None
            } else {
                Some(a % b)
            }
        }
        "=" | "==" => Some((a == b) as i64),
        "!=" => Some((a != b) as i64),
        "<" => Some((a < b) as i64),
        "<=" => Some((a <= b) as i64),
        ">" => Some((a > b) as i64),
        ">=" => Some((a >= b) as i64),
        _ => {
            crate::out_str("expr: unknown operator ");
            crate::outln(op);
            return 2;
        }
    };

    match r {
        Some(v) => {
            let mut b1 = [0u8; 24];
            crate::out_str(crate::itoa(v, &mut b1));
            crate::out(b"\n");
            0
        }
        None => {
            crate::outln("expr: division by zero");
            2
        }
    }
}

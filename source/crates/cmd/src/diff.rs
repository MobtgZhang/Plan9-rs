//! `diff` — line-oriented diff with a proper LCS core, printing
//! `a`/`c`/`d` hunks in the usual format.
//!
//! All working tables are statics: the user stack is 64 KiB and the LCS
//! table alone is over half a megabyte.

const MAX_LINES: usize = 512;
const MAX_LINE: usize = 200;
const N1: usize = MAX_LINES + 1;

static mut LINEA: [[u8; MAX_LINE]; MAX_LINES] = [[0; MAX_LINE]; MAX_LINES];
static mut LENA: [usize; MAX_LINES] = [0; MAX_LINES];
static mut NA: usize = 0;
static mut LINEB: [[u8; MAX_LINE]; MAX_LINES] = [[0; MAX_LINE]; MAX_LINES];
static mut LENB: [usize; MAX_LINES] = [0; MAX_LINES];
static mut NB: usize = 0;
// LCS lengths: LCSC[x][y] = LCS length of A[x..] vs B[y..].
static mut LCSC: [[u16; N1]; N1] = [[0; N1]; N1];
// Edit script, backtracked from the LCS table then reversed.
static mut OPK: [u8; 2 * MAX_LINES] = [0; 2 * MAX_LINES]; // 0 eq, 1 del, 2 ins
static mut OPA: [u16; 2 * MAX_LINES] = [0; 2 * MAX_LINES]; // A line index
static mut OPB: [u16; 2 * MAX_LINES] = [0; 2 * MAX_LINES]; // B line index
static mut NOPS: usize = 0;

unsafe fn read_lines(fd: i64, which: usize) {
    let mut raw = [0u8; 8192];
    let total = crate::syscall::read(fd, raw.as_mut_ptr(), raw.len());
    let total = if total < 0 { 0 } else { total as usize };
    let (mut i, mut count) = (0usize, 0usize);
    while i < total && count < MAX_LINES {
        let start = i;
        while i < total && raw[i] != b'\n' {
            i += 1;
        }
        let end = i.min(total);
        let line = &raw[start..end];
        let m = line.len().min(MAX_LINE);
        match which {
            0 => {
                LINEA[count][..m].copy_from_slice(&line[..m]);
                LENA[count] = m;
            }
            _ => {
                LINEB[count][..m].copy_from_slice(&line[..m]);
                LENB[count] = m;
            }
        }
        count += 1;
        i += 1;
    }
    match which {
        0 => NA = count,
        _ => NB = count,
    }
}

unsafe fn get(which: usize, i: usize) -> &'static [u8] {
    match which {
        0 => &LINEA[i][..LENA[i]],
        _ => &LINEB[i][..LENB[i]],
    }
}

unsafe fn eq(i: usize, j: usize) -> bool {
    get(0, i) == get(1, j)
}

/// Fill LCSC with LCS table lengths, then backtrack the edit script.
unsafe fn build_script() {
    // Bottom-up LCS lengths.
    let (na, nb) = (NA, NB);
    let mut x = na;
    while x > 0 {
        x -= 1;
        let mut y = nb;
        while y > 0 {
            y -= 1;
            LCSC[x][y] = if eq(x, y) {
                LCSC[x + 1][y + 1] + 1
            } else {
                LCSC[x + 1][y].max(LCSC[x][y + 1])
            };
        }
    }
    // Backtrack from (0,0) forwards using the table.
    let (mut i, mut j) = (0usize, 0usize);
    let mut n = 0usize;
    while i < na && j < nb {
        if eq(i, j) {
            if n < OPK.len() {
                OPK[n] = 0;
                OPA[n] = i as u16;
                OPB[n] = j as u16;
                n += 1;
            }
            i += 1;
            j += 1;
        } else if LCSC[i + 1][j] >= LCSC[i][j + 1] {
            if n < OPK.len() {
                OPK[n] = 1;
                OPA[n] = i as u16;
                OPB[n] = j as u16;
                n += 1;
            }
            i += 1;
        } else {
            if n < OPK.len() {
                OPK[n] = 2;
                OPA[n] = i as u16;
                OPB[n] = j as u16;
                n += 1;
            }
            j += 1;
        }
    }
    while i < na {
        if n < OPK.len() {
            OPK[n] = 1;
            OPA[n] = i as u16;
            OPB[n] = j as u16;
            n += 1;
        }
        i += 1;
    }
    while j < nb {
        if n < OPK.len() {
            OPK[n] = 2;
            OPA[n] = i as u16;
            OPB[n] = j as u16;
            n += 1;
        }
        j += 1;
    }
    NOPS = n;
}

/// "N" or "N,M" for a 1-based inclusive range.
fn range_text(first: usize, last: usize) -> String8 {
    let mut s = String8::new();
    let mut b = [0u8; 20];
    s.push_str(crate::utoa(first as u64, &mut b));
    if last > first {
        s.push(b',');
        s.push_str(crate::utoa(last as u64, &mut b));
    }
    s
}

pub type String8 = crate::ls::String8;

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: diff file1 file2");
        return 1;
    }
    let f1 = crate::arg(argc, argv, 1).unwrap_or("");
    let f2 = crate::arg(argc, argv, 2).unwrap_or("");

    let fd1 = crate::open_read(f1);
    if fd1 < 0 {
        crate::out_str("diff: can't open ");
        crate::outln(f1);
        return 2;
    }
    let fd2 = crate::open_read(f2);
    if fd2 < 0 {
        crate::out_str("diff: can't open ");
        crate::outln(f2);
        crate::syscall::close(fd1);
        return 2;
    }

    unsafe {
        NA = 0;
        NB = 0;
        NOPS = 0;
        read_lines(fd1, 0);
        read_lines(fd2, 1);
        build_script();
    }
    crate::syscall::close(fd1);
    crate::syscall::close(fd2);

    // Emit hunks: consecutive non-eq operations are one change.
    let nops = unsafe { NOPS };
    let mut k = 0usize;
    let mut status = 0;
    while k < nops {
        let kind = unsafe { OPK[k] };
        if kind == 0 {
            k += 1;
            continue;
        }
        status = 1;
        let start = k;
        while k < nops && unsafe { OPK[k] } != 0 {
            k += 1;
        }
        let end = k; // exclusive

        // Range over A lines and B lines inside [start, end).
        let (mut afirst, mut alast, mut bfirst, mut blast) = (0usize, 0usize, 0usize, 0usize);
        let mut has_a = false;
        let mut has_b = false;
        for t in start..end {
            let op = unsafe { OPK[t] };
            if op == 1 {
                let a = unsafe { OPA[t] } as usize;
                if !has_a {
                    afirst = a;
                    has_a = true;
                }
                alast = a;
            } else if op == 2 {
                let b = unsafe { OPB[t] } as usize;
                if !has_b {
                    bfirst = b;
                    has_b = true;
                }
                blast = b;
            }
        }
        let mut letter = b'c';
        if !has_a {
            letter = b'a';
        } else if !has_b {
            letter = b'd';
        }
        crate::out_str(range_text(afirst + 1, alast + 1).as_str());
        let mut one = [0u8; 1];
        one[0] = letter;
        crate::out(&one);
        crate::out_str(range_text(bfirst + 1, blast + 1).as_str());
        crate::out(b"\n");
        for t in start..end {
            if unsafe { OPK[t] } == 1 {
                crate::out_str("< ");
                crate::out(unsafe { get(0, unsafe { OPA[t] } as usize) });
                crate::out(b"\n");
            }
        }
        if has_a && has_b {
            crate::outln("---");
        }
        for t in start..end {
            if unsafe { OPK[t] } == 2 {
                crate::out_str("> ");
                crate::out(unsafe { get(1, unsafe { OPB[t] } as usize) });
                crate::out(b"\n");
            }
        }
    }
    status
}

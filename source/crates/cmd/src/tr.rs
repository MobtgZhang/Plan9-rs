//! `tr` — translate characters: `tr set1 [set2]` maps each character in
//! set1 to the character at the same position in set2; deleting unmapped
//! characters when set2 is absent.  Supports ranges like `a-z`.

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 2 || argc > 3 {
        crate::outln("usage: tr set1 [set2]");
        return 1;
    }
    let set1 = crate::arg(argc, argv, 1).unwrap_or("");
    let set2 = crate::arg(argc, argv, 2);

    let map = build_map(set1, set2);
    let mut buf = [0u8; 1024];
    loop {
        let n = crate::syscall::read(0, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        for &c in buf[..n as usize].iter() {
            let m = map[c as usize];
            if m == 0xFF {
                continue; // deleted
            }
            if m == 0 {
                crate::out(&[c]);
            } else {
                crate::out(&[m - 1]);
            }
        }
    }
    0
}

/// 256-entry translation table.
///
/// 0 = identity, `v` (1..=255) = output byte `v-1`, 0xFF = delete.
fn build_map(set1: &str, set2: Option<&str>) -> [u8; 256] {
    let mut map = [0u8; 256];
    let s1 = set1.as_bytes();
    let s2 = set2.unwrap_or("").as_bytes();

    if s2.is_empty() {
        // Delete mode: characters present in set1 are removed.
        expand(s1, &mut |c| map[c as usize] = 0xFF);
        return map;
    }

    // Expand both sets over their full lengths; extra set2 characters are
    // ignored, and the last set2 character repeats for trailing set1
    // range entries (Plan 9 semantics).
    let mut s2v: [u8; 256] = [0u8; 256];
    let mut n2 = 0usize;
    expand(s2, &mut |c| {
        if n2 < s2v.len() {
            s2v[n2] = c;
            n2 += 1;
        }
    });

    let mut idx = 0usize;
    let mut last = s2v[n2.saturating_sub(1)];
    expand(s1, &mut |c| {
        let target = if idx < n2 { s2v[idx] } else { last };
        map[c as usize] = target + 1;
        idx += 1;
        last = target;
    });
    map
}

/// Expand a set expression with ranges (`a-z`, `0-9`) into characters,
/// feeding each to `emit`.
fn expand(set: &[u8], emit: &mut impl FnMut(u8)) {
    let mut i = 0usize;
    while i < set.len() {
        if i + 2 < set.len() && set[i + 1] == b'-' && set[i + 2] >= set[i] {
            let mut c = set[i];
            while c <= set[i + 2] {
                emit(c);
                c += 1;
            }
            i += 3;
        } else {
            emit(set[i]);
            i += 1;
        }
    }
}

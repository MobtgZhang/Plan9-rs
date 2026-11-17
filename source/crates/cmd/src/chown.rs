//! `chown` — change a file's owner and group.
//!
//! `chown user file`        set the owner (the group follows the user's
//!                          primary group)
//! `chown user:group file`  set both
//! `chown :group file`      set only the group

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    if argc < 3 {
        crate::outln("usage: chown [user][:group] file...");
        return 1;
    }
    let spec = match crate::arg(argc, argv, 1) {
        Some(s) => s,
        None => return 1,
    };

    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    let mut status = 0;
    for i in 2..argc {
        let path = match crate::arg(argc, argv, i) {
            Some(p) => p,
            None => continue,
        };
        if !apply(path, user_part, group_part) {
            crate::out_str("chown: can't change ");
            crate::out_str(path);
            crate::out(b"\n");
            status = 1;
        }
    }
    status
}

fn apply(path: &str, user: &str, group: Option<&str>) -> bool {
    let cs = crate::syscall::make_cstr(path);

    let uid = if user.is_empty() {
        crate::syscall::NO_CHANGE
    } else {
        match resolve_user(user) {
            Some(u) => u,
            None => return false,
        }
    };

    let gid = match group {
        None => {
            // Bare user name: adopt that user's primary group too.
            if user.is_empty() {
                crate::syscall::NO_CHANGE
            } else {
                match resolve_user_group(user) {
                    Some(g) => g,
                    None => crate::syscall::NO_CHANGE,
                }
            }
        }
        Some(g) if g.is_empty() => crate::syscall::NO_CHANGE,
        Some(g) => match resolve_group(g) {
            Some(v) => v,
            None => return false,
        },
    };

    crate::syscall::chown(cs.as_ptr(), uid, gid) >= 0
}

fn resolve_user(name: &str) -> Option<u32> {
    if let Some(v) = crate::parse_u64(name) {
        return Some(v as u32);
    }
    crate::passwd::lookup_name(name).map(|u| u.uid)
}

fn resolve_user_group(name: &str) -> Option<u32> {
    if crate::parse_u64(name).is_some() {
        return None;
    }
    crate::passwd::lookup_name(name).map(|u| u.gid)
}

fn resolve_group(name: &str) -> Option<u32> {
    if let Some(v) = crate::parse_u64(name) {
        return Some(v as u32);
    }
    crate::passwd::lookup_group(name).map(|g| g.gid)
}

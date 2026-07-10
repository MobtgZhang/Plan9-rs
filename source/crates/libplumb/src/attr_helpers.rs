//! Plumb Attribute Helpers
//!
//! Implements the user-facing helpers from
//! `sys/src/libplumb/`:

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::attr::Plumbattr;
use crate::error::PlumbError;

/// Add an attribute to a packed attribute list.
///
/// `data` is a `key=value\0` encoded blob (the on-the-wire form
/// produced by `plumbpack`). This helper appends `name=value` to the
/// end of the blob. Returns the new blob on success.
///
/// If `name` or `value` contain a `=` or NUL the function returns
/// [`PlumbError::InvalidFormat`].
pub fn plumbaddattr(name: &str, value: &str, data: &[u8]) -> Result<Vec<u8>, PlumbError> {
    if name.is_empty() {
        return Err(PlumbError::InvalidFormat(alloc::string::String::from("invalid format")));
    }
    if name.contains('=') || name.contains('\0') {
        return Err(PlumbError::InvalidFormat(alloc::string::String::from("invalid format")));
    }
    if value.contains('\0') {
        return Err(PlumbError::InvalidFormat(alloc::string::String::from("invalid format")));
    }

    let mut out = Vec::with_capacity(data.len() + name.len() + value.len() + 3);
    out.extend_from_slice(data);
    out.extend_from_slice(name.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    Ok(out)
}

/// Delete every occurrence of `name` from the packed attribute list.
///
/// Returns the new (potentially shorter) blob. If `name` does not
/// appear in `data` the original blob is returned unchanged.
pub fn plumbdelattr(name: &str, data: &[u8]) -> Vec<u8> {
    if name.is_empty() {
        return data.to_vec();
    }

    // The packed format is a sequence of NUL-terminated `key=value`
    // pairs, followed by a final NUL.
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        // Find end of this attribute.
        let mut j = i;
        while j < data.len() && data[j] != 0 {
            j += 1;
        }
        let attr_bytes = &data[i..j];
        if let Some(eq) = attr_bytes.iter().position(|&b| b == b'=') {
            let key = &attr_bytes[..eq];
            if key != name.as_bytes() {
                out.extend_from_slice(attr_bytes);
                out.push(0);
            }
        } else {
            // Malformed entry, copy verbatim.
            out.extend_from_slice(attr_bytes);
            out.push(0);
        }
        i = j + 1;
        if j == data.len() {
            // Trailing empty attribute (the terminator) — drop it.
            break;
        }
    }
    out
}

/// Look up `name` in a packed attribute blob. Returns the value if
/// found.
pub fn plumblook(name: &str, data: &[u8]) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let mut i = 0;
    while i < data.len() {
        let mut j = i;
        while j < data.len() && data[j] != 0 {
            j += 1;
        }
        let attr_bytes = &data[i..j];
        if let Some(eq) = attr_bytes.iter().position(|&b| b == b'=') {
            let key = &attr_bytes[..eq];
            if key == name.as_bytes() {
                return Some(
                    alloc::str::from_utf8(&attr_bytes[eq + 1..])
                        .ok()?
                        .to_string(),
                );
            }
        }
        if j == data.len() {
            break;
        }
        i = j + 1;
    }
    None
}

/// Same as [`plumbaddattr`] but operating on a [`Plumbattr`] linked
/// list.
pub fn plumbaddattr_link(name: &str, value: &str, head: Option<&mut Plumbattr>) -> Result<(), PlumbError> {
    if name.is_empty() || name.contains('=') {
        return Err(PlumbError::InvalidFormat(alloc::string::String::from("invalid format")));
    }
    if value.contains('\0') {
        return Err(PlumbError::InvalidFormat(alloc::string::String::from("invalid format")));
    }
    match head {
        Some(h) => {
            h.add(name, value);
            Ok(())
        }
        None => Err(PlumbError::AttributeNotFound),
    }
}

/// Remove `name` from a [`Plumbattr`] linked list. Returns true if a
/// matching attribute was removed.
pub fn plumbdelattr_link(name: &str, head: &mut Plumbattr) -> bool {
    head.delete(name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_attr_empty() {
        let out = plumbaddattr("src", "edit", &[]).expect("add should succeed");
        let s = core::str::from_utf8(&out).unwrap();
        assert_eq!(s, "src=edit\0");
    }

    #[test]
    fn test_add_attr_existing() {
        let data = b"src=edit\0";
        let out = plumbaddattr("click", "1", data).expect("add should succeed");
        let s = core::str::from_utf8(&out).unwrap();
        assert_eq!(s, "src=edit\0click=1\0");
    }

    #[test]
    fn test_add_attr_rejects_empty_name() {
        let res = plumbaddattr("", "value", &[]);
        let expected = PlumbError::InvalidFormat(alloc::string::String::from("invalid format"));
        assert!(matches!(res, Err(e) if e == expected));
    }

    #[test]
    fn test_add_attr_rejects_equals_in_name() {
        let res = plumbaddattr("foo=bar", "value", &[]);
        let expected = PlumbError::InvalidFormat(alloc::string::String::from("invalid format"));
        assert!(matches!(res, Err(e) if e == expected));
    }

    #[test]
    fn test_add_attr_rejects_nul_in_value() {
        let res = plumbaddattr("foo", "val\0ue", &[]);
        let expected = PlumbError::InvalidFormat(alloc::string::String::from("invalid format"));
        assert!(matches!(res, Err(e) if e == expected));
    }

    #[test]
    fn test_del_attr_present() {
        let data = b"src=edit\0click=1\0dir=acme\0";
        let out = plumbdelattr("click", data);
        let s = core::str::from_utf8(&out).unwrap();
        assert_eq!(s, "src=edit\0dir=acme\0");
    }

    #[test]
    fn test_del_attr_absent() {
        let data = b"src=edit\0click=1\0";
        let out = plumbdelattr("missing", data);
        assert_eq!(out, data);
    }

    #[test]
    fn test_del_attr_empty_name() {
        let data = b"src=edit\0";
        let out = plumbdelattr("", data);
        assert_eq!(out, data);
    }

    #[test]
    fn test_del_attr_first() {
        let data = b"src=edit\0click=1\0";
        let out = plumbdelattr("src", data);
        let s = core::str::from_utf8(&out).unwrap();
        assert_eq!(s, "click=1\0");
    }

    #[test]
    fn test_look_attr_found() {
        let data = b"src=edit\0click=1\0";
        assert_eq!(plumblook("click", data), Some("1".to_string()));
        assert_eq!(plumblook("src", data), Some("edit".to_string()));
    }

    #[test]
    fn test_look_attr_missing() {
        let data = b"src=edit\0";
        assert_eq!(plumblook("missing", data), None);
    }

    #[test]
    fn test_look_attr_empty_name() {
        let data = b"src=edit\0";
        assert_eq!(plumblook("", data), None);
    }

    #[test]
    fn test_add_attr_linked_list() {
        let mut head = Plumbattr::new("src", "edit");
        plumbaddattr_link("click", "1", Some(&mut head)).expect("add should succeed");
        assert_eq!(head.len(), 2);
        assert_eq!(head.find("click"), Some("1"));
    }

    #[test]
    fn test_del_attr_linked_list() {
        let mut head = Plumbattr::new("src", "edit");
        head.add("click", "1");
        head.add("dir", "acme");
        assert!(plumbdelattr_link("click", &mut head));
        assert_eq!(head.len(), 2);
        assert_eq!(head.find("click"), None);
    }

    #[test]
    fn test_del_attr_linked_list_missing() {
        let mut head = Plumbattr::new("src", "edit");
        assert!(!plumbdelattr_link("missing", &mut head));
        assert_eq!(head.len(), 1);
    }
}
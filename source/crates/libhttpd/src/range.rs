//! HTTP `Range` request handling (RFC 7233).
//!
//! Parses `Range` request headers into a list of [`RangeSpec`]
//! and resolves them against a known resource size to produce
//! concrete byte ranges.

use alloc::string::String;
use alloc::vec::Vec;

/// One half-open byte range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte (inclusive).
    pub start: u64,
    /// Last byte + 1 (exclusive). Always > start.
    pub end: u64,
}

impl ByteRange {
    /// Number of bytes in this range.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// True if the range contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// A range specification as parsed from a `Range` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeSpec {
    /// Closed byte range `start-end`.
    Bytes(ByteRange),
    /// Open-ended range starting at `start`.
    From(u64),
    /// Suffix range (last `n` bytes).
    Suffix(u64),
}

impl RangeSpec {
    /// Resolve a [`RangeSpec`] against a known total size, returning
    /// a concrete [`ByteRange`]. Returns `None` if the resulting
    /// range is invalid (e.g. `start >= size` for closed ranges, or
    /// `n == 0` for suffix ranges).
    pub fn resolve(&self, size: u64) -> Option<ByteRange> {
        if size == 0 {
            return None;
        }
        match *self {
            RangeSpec::Bytes(ByteRange { start, end }) => {
                if start >= size {
                    return None;
                }
                let end = end.min(size);
                if start >= end {
                    return None;
                }
                Some(ByteRange { start, end })
            }
            RangeSpec::From(start) => {
                if start >= size {
                    None
                } else {
                    Some(ByteRange { start, end: size })
                }
            }
            RangeSpec::Suffix(n) => {
                if n == 0 {
                    return None;
                }
                let n = n.min(size);
                Some(ByteRange {
                    start: size - n,
                    end: size,
                })
            }
        }
    }
}

/// Parse a `Range` header value.
///
/// Only `bytes` units are supported. Multiple ranges separated by
/// commas are supported. Whitespace is ignored.
///
/// # Examples
/// ```
/// use libhttpd::range::{parse_range, RangeSpec};
/// let specs = parse_range("bytes=0-99").unwrap();
/// assert_eq!(specs.len(), 1);
/// ```
pub fn parse_range(s: &str) -> Result<Vec<RangeSpec>, ()> {
    let s = s.trim();
    let rest = s.strip_prefix("bytes=").ok_or(())?;
    let mut out = Vec::new();
    for spec in rest.split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(());
        }
        if let Some(idx) = spec.find('-') {
            let (a, b) = (&spec[..idx], &spec[idx + 1..]);
            match (a.is_empty(), b.is_empty()) {
                (true, true) => return Err(()),
                (true, false) => {
                    let n: u64 = b.parse().map_err(|_| ())?;
                    out.push(RangeSpec::Suffix(n));
                }
                (false, true) => {
                    let start: u64 = a.parse().map_err(|_| ())?;
                    out.push(RangeSpec::From(start));
                }
                (false, false) => {
                    let start: u64 = a.parse().map_err(|_| ())?;
                    let end: u64 = b.parse().map_err(|_| ())?;
                    if end < start {
                        return Err(());
                    }
                    out.push(RangeSpec::Bytes(ByteRange { start, end: end + 1 }));
                }
            }
        } else {
            return Err(());
        }
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out)
}

/// Render a `Content-Range` header value (RFC 7233 §4.2).
pub fn content_range(range: ByteRange, size: u64) -> String {
    alloc::format!("bytes {}-{}/{}", range.start, range.end - 1, size)
}

/// Render an `Accept-Ranges` header value.
pub fn accept_ranges_header() -> &'static str {
    "bytes"
}

/// Decide whether a `Range` header can be satisfied for a given size.
pub fn is_range_satisfiable(header: &str, size: u64) -> bool {
    match parse_range(header) {
        Ok(specs) => {
            if size == 0 {
                return false;
            }
            specs.iter().any(|s| s.resolve(size).is_some())
        }
        Err(()) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_range_len() {
        let r = ByteRange { start: 10, end: 20 };
        assert_eq!(r.len(), 10);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_byte_range_empty() {
        let r = ByteRange { start: 10, end: 10 };
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_parse_single() {
        let specs = parse_range("bytes=0-99").unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0], RangeSpec::Bytes(ByteRange { start: 0, end: 100 }));
    }

    #[test]
    fn test_parse_open_ended() {
        let specs = parse_range("bytes=500-").unwrap();
        assert_eq!(specs, alloc::vec![RangeSpec::From(500)]);
    }

    #[test]
    fn test_parse_suffix() {
        let specs = parse_range("bytes=-500").unwrap();
        assert_eq!(specs, alloc::vec![RangeSpec::Suffix(500)]);
    }

    #[test]
    fn test_parse_multi() {
        let specs = parse_range("bytes=0-99,200-299,-500").unwrap();
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn test_parse_invalid_no_bytes() {
        assert!(parse_range("items=0-99").is_err());
    }

    #[test]
    fn test_parse_invalid_double_dash() {
        assert!(parse_range("bytes=-").is_err());
    }

    #[test]
    fn test_parse_invalid_reversed() {
        assert!(parse_range("bytes=100-50").is_err());
    }

    #[test]
    fn test_resolve_closed() {
        let r = RangeSpec::Bytes(ByteRange { start: 10, end: 50 });
        assert_eq!(r.resolve(100), Some(ByteRange { start: 10, end: 50 }));
    }

    #[test]
    fn test_resolve_closed_clamps_end() {
        let r = RangeSpec::Bytes(ByteRange { start: 50, end: 1000 });
        // Clamps to file end.
        assert_eq!(r.resolve(100), Some(ByteRange { start: 50, end: 100 }));
    }

    #[test]
    fn test_resolve_closed_out_of_range() {
        let r = RangeSpec::Bytes(ByteRange { start: 200, end: 500 });
        assert_eq!(r.resolve(100), None);
    }

    #[test]
    fn test_resolve_from() {
        let r = RangeSpec::From(50);
        assert_eq!(r.resolve(100), Some(ByteRange { start: 50, end: 100 }));
        assert_eq!(r.resolve(1000), Some(ByteRange { start: 50, end: 1000 }));
        assert_eq!(r.resolve(40), None);
    }

    #[test]
    fn test_resolve_suffix() {
        let r = RangeSpec::Suffix(50);
        assert_eq!(r.resolve(100), Some(ByteRange { start: 50, end: 100 }));
        assert_eq!(r.resolve(30), Some(ByteRange { start: 0, end: 30 }));
    }

    #[test]
    fn test_resolve_zero_size() {
        assert_eq!(RangeSpec::From(0).resolve(0), None);
        assert_eq!(RangeSpec::Suffix(1).resolve(0), None);
    }

    #[test]
    fn test_content_range_header() {
        assert_eq!(
            content_range(ByteRange { start: 0, end: 100 }, 1000),
            "bytes 0-99/1000"
        );
        assert_eq!(
            content_range(ByteRange { start: 950, end: 1000 }, 1000),
            "bytes 950-999/1000"
        );
    }

    #[test]
    fn test_is_range_satisfiable() {
        assert!(is_range_satisfiable("bytes=0-99", 1000));
        assert!(is_range_satisfiable("bytes=-500", 1000));
        assert!(!is_range_satisfiable("bytes=5000-5999", 1000));
        assert!(!is_range_satisfiable("bytes=0-99", 0));
        assert!(!is_range_satisfiable("garbage", 1000));
    }
}
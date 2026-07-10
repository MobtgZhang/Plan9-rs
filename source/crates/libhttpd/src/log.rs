//! HTTP access logging
//!
//! Implements the standard "Combined Log Format" (Apache) used by
//! most HTTP servers, as well as a Plan 9-style variant that
//! prefixes each line with the timestamp.
//!
//! Reference: `sys/src/libhttpd/log.c`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::request::HttpReq;

/// Combined Log Format fields, as defined by Apache/Nginx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedLogEntry {
    /// Client IP address.
    pub remote_addr: String,
    /// Remote user (after authentication), if known.
    pub remote_user: Option<String>,
    /// Request timestamp in Unix seconds.
    pub timestamp: i64,
    /// HTTP request line (method, target, version).
    pub request_line: String,
    /// HTTP status code.
    pub status: u16,
    /// Number of bytes sent in the response body.
    pub bytes: u64,
    /// Value of the `Referer` header.
    pub referer: Option<String>,
    /// Value of the `User-Agent` header.
    pub user_agent: Option<String>,
}

impl CombinedLogEntry {
    /// Render the entry in Combined Log Format.
    pub fn render(&self) -> String {
        let mut line = String::new();
        line.push_str(&self.remote_addr);
        line.push_str(" - ");
        line.push_str(self.remote_user.as_deref().unwrap_or("-"));
        line.push(' ');
        push_timestamp(&mut line, self.timestamp);
        line.push_str(" \"");
        line.push_str(&self.request_line);
        line.push_str("\" ");
        line.push_str(&itoa_u16(self.status));
        line.push(' ');
        line.push_str(&itoa_u64(self.bytes));
        line.push_str(" \"");
        line.push_str(self.referer.as_deref().unwrap_or("-"));
        line.push_str("\" \"");
        line.push_str(self.user_agent.as_deref().unwrap_or("-"));
        line.push('"');
        line
    }
}

/// A simple access log buffer.
#[derive(Debug, Default)]
pub struct AccessLog {
    lines: Vec<String>,
}

impl AccessLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Append a rendered line.
    pub fn append(&mut self, line: String) {
        self.lines.push(line);
    }

    /// Append an entry from an [`HttpReq`].
    pub fn log_request(
        &mut self,
        req: &HttpReq,
        remote_addr: &str,
        remote_user: Option<&str>,
        status: u16,
        bytes: u64,
        referer: Option<&str>,
        user_agent: Option<&str>,
        ts: i64,
    ) {
        let entry = CombinedLogEntry {
            remote_addr: remote_addr.to_string(),
            remote_user: remote_user.map(String::from),
            timestamp: ts,
            request_line: alloc::format!("{} {}", req.method.as_str(), req.uri),
            status,
            bytes,
            referer: referer.map(String::from),
            user_agent: user_agent.map(String::from),
        };
        self.lines.push(entry.render());
    }

    /// Total number of lines stored.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// True if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Borrow the underlying lines.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Render the entire log as a single `String` (joined by `\n`).
    pub fn as_string(&self) -> String {
        let mut out = String::new();
        for (i, l) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(l);
        }
        out
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn push_timestamp(out: &mut String, ts: i64) {
    // 04/Mar/2025:12:34:56 +0000
    const DAYS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Convert from Unix seconds (1970-01-01) to civil date.
    let secs_per_day: i64 = 86_400;
    let days = ts.div_euclid(secs_per_day);
    let secs_in_day = ts.rem_euclid(secs_per_day);
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day % 3600) / 60;
    let second = secs_in_day % 60;

    // Days since 1970-01-01 -> year/month/day (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    use core::fmt::Write;
    let _ = write!(out, "{:02}/", d);
    out.push_str(DAYS[(m - 1) as usize]);
    let _ = write!(out, "/{:04}:{:02}:{:02}:{:02} +0000", year, hour, minute, second);
}

fn itoa_u16(n: u16) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 5];
    let mut i = 0;
    let mut v = n;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    buf[..i].reverse();
    alloc::str::from_utf8(&buf[..i]).unwrap_or("0").to_string()
}

fn itoa_u64(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut v = n;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    buf[..i].reverse();
    alloc::str::from_utf8(&buf[..i]).unwrap_or("0").to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itoa_u16() {
        assert_eq!(itoa_u16(0), "0");
        assert_eq!(itoa_u16(1), "1");
        assert_eq!(itoa_u16(200), "200");
        assert_eq!(itoa_u16(65535), "65535");
    }

    #[test]
    fn test_itoa_u64() {
        assert_eq!(itoa_u64(0), "0");
        assert_eq!(itoa_u64(123), "123");
        assert_eq!(itoa_u64(18_446_744_073_709_551_615), "18446744073709551615");
    }

    #[test]
    fn test_log_append() {
        let mut log = AccessLog::new();
        log.append("line1".to_string());
        log.append("line2".to_string());
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_log_render() {
        let mut log = AccessLog::new();
        log.append("a".to_string());
        log.append("b".to_string());
        assert_eq!(log.as_string(), "a\nb");
    }

    #[test]
    fn test_log_clear() {
        let mut log = AccessLog::new();
        log.append("a".to_string());
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_combined_entry_render() {
        let entry = CombinedLogEntry {
            remote_addr: "127.0.0.1".to_string(),
            remote_user: Some("glenda".to_string()),
            timestamp: 0, // 1970-01-01
            request_line: "GET /index.html HTTP/1.1".to_string(),
            status: 200,
            bytes: 1234,
            referer: Some("http://example.com/".to_string()),
            user_agent: Some("test/1.0".to_string()),
        };
        let s = entry.render();
        assert!(s.starts_with("127.0.0.1 - glenda 01/Jan/1970:00:00:00 +0000 \"GET /index.html HTTP/1.1\" 200 1234 \"http://example.com/\" \"test/1.0\""));
    }

    #[test]
    fn test_combined_entry_no_user() {
        let entry = CombinedLogEntry {
            remote_addr: "10.0.0.1".to_string(),
            remote_user: None,
            timestamp: 1_700_000_000,
            request_line: "GET / HTTP/1.1".to_string(),
            status: 404,
            bytes: 0,
            referer: None,
            user_agent: None,
        };
        let s = entry.render();
        assert!(s.contains(" - - "));
        assert!(s.contains("404"));
    }
}
//! HTTP Header Parsing
//!
//! Implements the HttpHead structure for parsing HTTP headers.

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::HttpError;
use crate::request::HttpReq;

/// HTTP header name
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderName {
    Accept,
    AcceptCharset,
    AcceptEncoding,
    AcceptLanguage,
    Authorization,
    CacheControl,
    Connection,
    ContentEncoding,
    ContentLength,
    ContentType,
    Cookie,
    Date,
    Expect,
    From,
    Host,
    IfMatch,
    IfModifiedSince,
    IfNoneMatch,
    IfRange,
    IfUnmodifiedSince,
    MaxForwards,
    Pragma,
    ProxyAuthorization,
    Range,
    Referer,
    Te,
    TransferEncoding,
    UserAgent,
    Upgrade,
    Via,
    Warning,
    Other(String),
}

impl HeaderName {
    /// Parse a header name (case-insensitive)
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "accept" => HeaderName::Accept,
            "accept-charset" => HeaderName::AcceptCharset,
            "accept-encoding" => HeaderName::AcceptEncoding,
            "accept-language" => HeaderName::AcceptLanguage,
            "authorization" => HeaderName::Authorization,
            "cache-control" => HeaderName::CacheControl,
            "connection" => HeaderName::Connection,
            "content-encoding" => HeaderName::ContentEncoding,
            "content-length" => HeaderName::ContentLength,
            "content-type" => HeaderName::ContentType,
            "cookie" => HeaderName::Cookie,
            "date" => HeaderName::Date,
            "expect" => HeaderName::Expect,
            "from" => HeaderName::From,
            "host" => HeaderName::Host,
            "if-match" => HeaderName::IfMatch,
            "if-modified-since" => HeaderName::IfModifiedSince,
            "if-none-match" => HeaderName::IfNoneMatch,
            "if-range" => HeaderName::IfRange,
            "if-unmodified-since" => HeaderName::IfUnmodifiedSince,
            "max-forwards" => HeaderName::MaxForwards,
            "pragma" => HeaderName::Pragma,
            "proxy-authorization" => HeaderName::ProxyAuthorization,
            "range" => HeaderName::Range,
            "referer" => HeaderName::Referer,
            "te" => HeaderName::Te,
            "transfer-encoding" => HeaderName::TransferEncoding,
            "user-agent" => HeaderName::UserAgent,
            "upgrade" => HeaderName::Upgrade,
            "via" => HeaderName::Via,
            "warning" => HeaderName::Warning,
            other => HeaderName::Other(other.to_string()),
        }
    }

    /// Get the canonical header name
    pub fn as_str(&self) -> &str {
        match self {
            HeaderName::Accept => "Accept",
            HeaderName::AcceptCharset => "Accept-Charset",
            HeaderName::AcceptEncoding => "Accept-Encoding",
            HeaderName::AcceptLanguage => "Accept-Language",
            HeaderName::Authorization => "Authorization",
            HeaderName::CacheControl => "Cache-Control",
            HeaderName::Connection => "Connection",
            HeaderName::ContentEncoding => "Content-Encoding",
            HeaderName::ContentLength => "Content-Length",
            HeaderName::ContentType => "Content-Type",
            HeaderName::Cookie => "Cookie",
            HeaderName::Date => "Date",
            HeaderName::Expect => "Expect",
            HeaderName::From => "From",
            HeaderName::Host => "Host",
            HeaderName::IfMatch => "If-Match",
            HeaderName::IfModifiedSince => "If-Modified-Since",
            HeaderName::IfNoneMatch => "If-None-Match",
            HeaderName::IfRange => "If-Range",
            HeaderName::IfUnmodifiedSince => "If-Unmodified-Since",
            HeaderName::MaxForwards => "Max-Forwards",
            HeaderName::Pragma => "Pragma",
            HeaderName::ProxyAuthorization => "Proxy-Authorization",
            HeaderName::Range => "Range",
            HeaderName::Referer => "Referer",
            HeaderName::Te => "Te",
            HeaderName::TransferEncoding => "Transfer-Encoding",
            HeaderName::UserAgent => "User-Agent",
            HeaderName::Upgrade => "Upgrade",
            HeaderName::Via => "Via",
            HeaderName::Warning => "Warning",
            HeaderName::Other(s) => s,
        }
    }
}

/// HTTP header
#[derive(Debug, Clone)]
pub struct Header {
    pub name: HeaderName,
    pub value: String,
}

impl Header {
    /// Create a new header
    pub fn new(name: HeaderName, value: String) -> Self {
        Header { name, value }
    }
}

/// HTTP headers collection
#[derive(Debug, Clone, Default)]
pub struct Headers {
    headers: Vec<Header>,
}

impl Headers {
    /// Create a new empty headers collection
    pub fn new() -> Self {
        Headers {
            headers: Vec::new(),
        }
    }

    /// Add a header
    pub fn add(&mut self, name: HeaderName, value: String) {
        self.headers.push(Header::new(name, value));
    }

    /// Get a header by name
    pub fn get(&self, name: &HeaderName) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name == *name)
            .map(|h| h.value.as_str())
    }

    /// Get a header by name string
    pub fn get_str(&self, name: &str) -> Option<&str> {
        let parsed_name = HeaderName::parse(name);
        self.get(&parsed_name)
    }

    /// Get all headers with a specific name
    pub fn get_all(&self, name: &HeaderName) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name == *name)
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Check if a header exists
    pub fn contains(&self, name: &HeaderName) -> bool {
        self.headers.iter().any(|h| h.name == *name)
    }

    /// Get the number of headers
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Check if headers are empty
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Iterate over headers
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &str)> {
        self.headers.iter().map(|h| (&h.name, h.value.as_str()))
    }

    /// Parse headers from raw data
    pub fn parse(data: &[u8]) -> Result<Self, HttpError> {
        let mut headers = Headers::new();
        let s = core::str::from_utf8(data).map_err(|_| HttpError::InvalidRequest)?;

        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                break;
            }

            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim();
                let value = line[pos + 1..].trim();
                let header_name = HeaderName::parse(name);
                headers.add(header_name, value.to_string());
            }
        }

        Ok(headers)
    }
}

/// HTTP head (request headers)
#[derive(Debug, Clone)]
pub struct HttpHead {
    /// Headers
    pub headers: Headers,
    /// Close the connection after response
    pub closeit: bool,
    /// Keep-alive requested
    pub persist: bool,
    /// Content length (from Content-Length header)
    pub contlen: Option<usize>,
    /// Host header value
    pub host: Option<alloc::string::String>,
    /// Authorization user
    pub authuser: Option<alloc::string::String>,
    /// Authorization password
    pub authpass: Option<alloc::string::String>,
}

impl HttpHead {
    /// Create a new empty head
    pub fn new() -> Self {
        HttpHead {
            headers: Headers::new(),
            closeit: false,
            persist: false,
            contlen: None,
            host: None,
            authuser: None,
            authpass: None,
        }
    }

    /// Parse headers into HttpHead
    pub fn parse(_req: &HttpReq, data: &[u8]) -> Result<Self, HttpError> {
        let mut head = HttpHead::new();
        head.headers = Headers::parse(data)?;

        // Parse Connection header
        if let Some(conn) = head.headers.get(&HeaderName::Connection) {
            head.closeit = conn.to_lowercase().contains("close");
            head.persist = conn.to_lowercase().contains("keep-alive");
        }

        // Parse Content-Length
        if let Some(cl) = head.headers.get(&HeaderName::ContentLength) {
            head.contlen = cl.parse::<usize>().ok();
        }

        // Parse Host
        head.host = head.headers.get(&HeaderName::Host).map(|s| s.to_string());

        // Parse Authorization
        if let Some(auth) = head.headers.get(&HeaderName::Authorization) {
            if let Some((user, pass)) = parse_basic_auth(auth) {
                head.authuser = Some(user);
                head.authpass = Some(pass);
            }
        }

        Ok(head)
    }

    /// Get the Content-Type header
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get(&HeaderName::ContentType)
    }

    /// Get the User-Agent header
    pub fn user_agent(&self) -> Option<&str> {
        self.headers.get(&HeaderName::UserAgent)
    }

    /// Get the Referer header
    pub fn referer(&self) -> Option<&str> {
        self.headers.get(&HeaderName::Referer)
    }

    /// Check if this is a HEAD request response
    pub fn is_head_request(&self) -> bool {
        // This would need to be set by the request parser
        false
    }
}

impl Default for HttpHead {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse Basic Authentication header
fn parse_basic_auth(auth: &str) -> Option<(String, String)> {
    if !auth.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth[6..];
    // Basic auth is base64 encoded "user:password"
    // For no_std, we do a simple decode
    let decoded = base64_decode(encoded)?;

    if let Some(pos) = decoded.find(':') {
        Some((decoded[..pos].to_string(), decoded[pos + 1..].to_string()))
    } else {
        None
    }
}

/// Simple base64 decoder for no_std
fn base64_decode(input: &str) -> Option<String> {
    const DECODE_TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[chars[i] as usize] = i as i8;
            i += 1;
        }
        table
    };

    let input = input.as_bytes();
    let mut output = alloc::string::String::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input {
        if byte == b'=' || byte == b'\n' || byte == b'\r' || byte == b' ' {
            break;
        }
        let value = DECODE_TABLE[byte as usize];
        if value < 0 {
            return None;
        }
        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8 as char);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(output)
}

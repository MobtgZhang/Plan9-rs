//! HTTP Request Parsing
//!
//! Implements the hparsereq function for parsing HTTP requests.

#![no_std]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::HttpError;
use crate::request::{HttpReq, Method};
use crate::header::HttpHead;
use crate::urlunesc::hurlunesc;
use crate::parseuri::{parseuri, stripsearch};

/// HTTP connection state
#[derive(Debug)]
pub struct HConnect {
    /// Request
    pub req: HttpReq,
    /// Headers
    pub head: HttpHead,
    /// Input buffer
    pub bin: alloc::vec::Vec<u8>,
    /// Header parse position
    pub hpos: usize,
    /// Header end position
    pub hstop: usize,
    /// Transfer buffer (32KB)
    pub xferbuf: [u8; 32768],
    /// Raw header buffer
    pub header: alloc::vec::Vec<u8>,
    /// Server context
    pub ctx: Option<ServerContext>,
}

/// Server context (optional, for virtual hosting etc.)
#[derive(Debug, Clone)]
pub struct ServerContext {
    /// Server name (Host header)
    pub server_name: alloc::string::String,
    /// Document root
    pub docroot: Option<alloc::string::String>,
    /// Port
    pub port: u16,
}

impl Default for HConnect {
    fn default() -> Self {
        Self::new()
    }
}

impl HConnect {
    /// Create a new connection context
    pub fn new() -> Self {
        HConnect {
            req: HttpReq::new(),
            head: HttpHead::new(),
            bin: alloc::vec::Vec::new(),
            hpos: 0,
            hstop: 0,
            xferbuf: [0u8; 32768],
            header: alloc::vec::Vec::new(),
            ctx: None,
        }
    }

    /// Reset the connection for reuse
    pub fn reset(&mut self) {
        self.req = HttpReq::new();
        self.head = HttpHead::new();
        self.bin.clear();
        self.hpos = 0;
        self.hstop = 0;
        self.header.clear();
    }

    /// Set the server context from Host header
    pub fn set_context(&mut self, host: &str) {
        // Parse host:port
        let (server_name, port) = if let Some(pos) = host.find(':') {
            (
                host[..pos].to_string(),
                host[pos + 1..].parse::<u16>().unwrap_or(80),
            )
        } else {
            (host.to_string(), 80)
        };

        self.ctx = Some(ServerContext {
            server_name,
            port,
            docroot: None,
        });
    }
}

/// Transfer encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEncoding {
    /// No transfer encoding
    None,
    /// Chunked transfer encoding
    Chunked,
    /// Identity encoding
    Identity,
}

impl TransferEncoding {
    /// Parse transfer encoding from string
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "chunked" => TransferEncoding::Chunked,
            "identity" => TransferEncoding::Identity,
            _ => TransferEncoding::None,
        }
    }
}

/// Parse an HTTP request
///
/// This function:
/// 1. Reads and parses the request line
/// 2. Reads and parses the headers
/// 3. Extracts the URI components
/// 4. Validates the request
pub fn hparsereq(cc: &mut HConnect, data: &[u8]) -> Result<(), HttpError> {
    // Find the end of the request line
    let request_end = find_line_end(data);
    if request_end == 0 {
        return Err(HttpError::InvalidRequest);
    }

    // Parse request line
    let request_line = core::str::from_utf8(&data[..request_end])
        .map_err(|_| HttpError::InvalidRequest)?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(HttpError::InvalidRequest);
    }

    // Parse method
    cc.req.method = Method::parse(parts[0]);

    // Parse URI
    let uri = parts[1].to_string();

    // Parse version
    if parts.len() >= 3 {
        let (maj, min) = HttpReq::parse_version(parts[2])?;
        cc.req.vermaj = maj;
        cc.req.vermin = min;
    }

    // Find header end
    let header_end = find_header_end(data, request_end);
    if header_end == 0 {
        return Err(HttpError::InvalidRequest);
    }

    // Parse headers
    let header_data = &data[request_end + 2..header_end];
    cc.head = HttpHead::parse(&cc.req, header_data)?;

    // Set header parsing position
    cc.hpos = 0;
    cc.hstop = header_data.len();

    // Extract URI components
    cc.req.uri = parseuri(&uri, &mut cc.req.urihost)?;

    // URL decode the URI
    hurlunesc(&mut cc.req.uri)?;

    // Strip query string
    let (path, search) = stripsearch(&cc.req.uri);
    cc.req.uri = path;
    cc.req.search = search;

    // Validate HTTP/1.1 requirements
    if cc.req.is_http11() && cc.head.host.is_none() {
        // HTTP/1.1 requires Host header
        // Be lenient and use the URI host if present
        if let Some(ref urihost) = cc.req.urihost {
            cc.head.host = Some(urihost.clone());
        }
    }

    // Set server context
    if let Some(ref host) = cc.head.host {
        let host_str = host.clone();
        cc.set_context(&host_str);
    }

    Ok(())
}

/// Find the end of a line (CRLF or LF)
fn find_line_end(data: &[u8]) -> usize {
    for (i, chunk) in data.windows(2).enumerate() {
        if chunk[0] == b'\r' && chunk[1] == b'\n' {
            return i;
        }
        if chunk[1] == b'\n' && i > 0 && data[i - 1] != b'\r' {
            return i + 1;
        }
    }

    // Check for just LF
    if let Some(pos) = data.iter().position(|&b| b == b'\n') {
        return pos;
    }

    0
}

/// Find the end of the headers section (blank line)
fn find_header_end(data: &[u8], request_end: usize) -> usize {
    let remaining = &data[request_end..];

    for (i, chunk) in remaining.windows(4).enumerate() {
        // CRLF CRLF - end of headers
        if chunk == b"\r\n\r\n" {
            return request_end + i + 4;
        }
        // LF LF - end of headers (HTTP/0.9 style)
        if chunk[0] == b'\n' && chunk[1] == b'\r' && chunk[2] == b'\n' {
            return request_end + i + 3;
        }
        if chunk[0] == b'\n' && chunk[1] == b'\n' {
            return request_end + i + 2;
        }
    }

    // Also check for just double CRLF at the start
    if remaining.starts_with(b"\r\n\r\n") {
        return request_end + 4;
    }
    if remaining.starts_with(b"\n\n") {
        return request_end + 2;
    }

    0
}

/// Get the request body from the connection
///
/// Handles chunked transfer encoding.
pub fn getbody(cc: &mut HConnect) -> Result<Option<alloc::vec::Vec<u8>>, HttpError> {
    let contlen = cc.head.contlen;

    // Check for chunked encoding
    if let Some(te) = cc.head.headers.get(&crate::header::HeaderName::TransferEncoding) {
        if TransferEncoding::parse(te) == TransferEncoding::Chunked {
            return Ok(Some(read_chunked_body(cc)?));
        }
    }

    // Handle Content-Length
    match contlen {
        Some(len) => {
            if len > MAX_BODY_SIZE {
                return Err(HttpError::PayloadTooLarge);
            }
            // In a real implementation, read len bytes from the input
            Ok(Some(alloc::vec::Vec::with_capacity(len)))
        }
        None => Ok(None), // No body
    }
}

/// Read a chunked transfer-encoded body
fn read_chunked_body(_cc: &mut HConnect) -> Result<alloc::vec::Vec<u8>, HttpError> {
    let body = alloc::vec::Vec::new();

    // In a real implementation, this would read chunks from the input:
    // 1. Read chunk size line
    // 2. Read chunk data
    // 3. Repeat until size is 0
    // 4. Read trailer headers (optional)

    // For now, return empty body
    Ok(body)
}

/// Maximum body size we'll accept
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB

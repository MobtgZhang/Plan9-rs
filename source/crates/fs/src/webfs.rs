//! WebFS Client Library
//!
//! Implements WebFS - a file system interface for accessing HTTP and FTP
//! resources as files. This allows web and ftp URLs to be accessed using
//! standard file operations.
//!
//! URL format:
//!   - http://host[:port]/path
//!   - https://host[:port]/path
//!   - ftp://host[:port]/path


extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ============================================================================
// URL Types
// ============================================================================

/// URL scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlScheme {
    Http,
    Https,
    Ftp,
    Unknown,
}

impl UrlScheme {
    pub fn from_str(s: &str) -> Self {
        match s {
            "http" => UrlScheme::Http,
            "https" => UrlScheme::Https,
            "ftp" => UrlScheme::Ftp,
            _ => UrlScheme::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UrlScheme::Http => "http",
            UrlScheme::Https => "https",
            UrlScheme::Ftp => "ftp",
            UrlScheme::Unknown => "",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            UrlScheme::Http => 80,
            UrlScheme::Https => 443,
            UrlScheme::Ftp => 21,
            UrlScheme::Unknown => 0,
        }
    }
}

/// Parsed URL
#[derive(Debug, Clone)]
pub struct Url {
    /// URL scheme
    pub scheme: UrlScheme,
    /// Hostname
    pub host: String,
    /// Port
    pub port: u16,
    /// Path
    pub path: String,
    /// Query string
    pub query: Option<String>,
    /// Fragment
    pub fragment: Option<String>,
    /// Username (for FTP)
    pub username: Option<String>,
    /// Password (for FTP)
    pub password: Option<String>,
}

impl Url {
    /// Parse URL from string
    pub fn parse(s: &str) -> Result<Self, WebFsError> {
        let s = s.trim();

        // Find scheme
        let (scheme_str, rest) = if let Some(pos) = s.find("://") {
            (&s[..pos], &s[pos + 3..])
        } else {
            return Err(WebFsError::InvalidUrl);
        };

        let scheme = UrlScheme::from_str(scheme_str);
        if scheme == UrlScheme::Unknown {
            return Err(WebFsError::InvalidScheme);
        }

        // Parse host and port
        let (host_port, path_query) = if let Some(pos) = rest.find('/') {
            (&rest[..pos], &rest[pos..])
        } else {
            (rest, "/")
        };

        let (host, port) = if let Some(pos) = host_port.find(':') {
            let h = host_port[..pos].to_string();
            let p = host_port[pos + 1..].parse::<u16>().map_err(|_| WebFsError::InvalidUrl)?;
            (h, p)
        } else {
            (host_port.to_string(), scheme.default_port())
        };

        // Parse path, query, and fragment
        let (path, query, fragment) = Self::parse_path(path_query)?;

        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
            fragment,
            username: None,
            password: None,
        })
    }

    /// Parse path into path, query, and fragment
    fn parse_path(p: &str) -> Result<(String, Option<String>, Option<String>), WebFsError> {
        let mut path = String::new();
        let mut query = None;
        let mut fragment = None;

        let chars = p.as_bytes();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                b'?' if query.is_none() && fragment.is_none() => {
                    path = String::from_utf8(chars[..i].to_vec())
                        .map_err(|_| WebFsError::InvalidUrl)?;
                    let rest = &chars[i + 1..];
                    if let Some(pos) = rest.iter().position(|&c| c == b'#') {
                        query = Some(String::from_utf8(rest[..pos].to_vec())
                            .map_err(|_| WebFsError::InvalidUrl)?);
                        fragment = Some(String::from_utf8(rest[pos + 1..].to_vec())
                            .map_err(|_| WebFsError::InvalidUrl)?);
                    } else {
                        query = Some(String::from_utf8(rest.to_vec())
                            .map_err(|_| WebFsError::InvalidUrl)?);
                    }
                    break;
                }
                b'#' if fragment.is_none() => {
                    if query.is_none() {
                        path = String::from_utf8(chars[..i].to_vec())
                            .map_err(|_| WebFsError::InvalidUrl)?;
                    }
                    fragment = Some(String::from_utf8(chars[i + 1..].to_vec())
                        .map_err(|_| WebFsError::InvalidUrl)?);
                    break;
                }
                _ => {}
            }
            i += 1;
        }

        if path.is_empty() {
            path = String::from_utf8(chars.to_vec())
                .map_err(|_| WebFsError::InvalidUrl)?;
        }

        Ok((path, query, fragment))
    }

    /// Get full path with query
    pub fn full_path(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.clone(),
        }
    }
}

// ============================================================================
// HTTP Types
// ============================================================================

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Connect,
    Trace,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Trace => "TRACE",
        }
    }
}

/// HTTP status code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStatus {
    Continue = 100,
    SwitchingProtocols = 101,
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    Gone = 410,
    LengthRequired = 411,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
    Unknown,
}

impl HttpStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            100 => HttpStatus::Continue,
            101 => HttpStatus::SwitchingProtocols,
            200 => HttpStatus::Ok,
            201 => HttpStatus::Created,
            202 => HttpStatus::Accepted,
            204 => HttpStatus::NoContent,
            301 => HttpStatus::MovedPermanently,
            302 => HttpStatus::Found,
            303 => HttpStatus::SeeOther,
            304 => HttpStatus::NotModified,
            307 => HttpStatus::TemporaryRedirect,
            308 => HttpStatus::PermanentRedirect,
            400 => HttpStatus::BadRequest,
            401 => HttpStatus::Unauthorized,
            403 => HttpStatus::Forbidden,
            404 => HttpStatus::NotFound,
            405 => HttpStatus::MethodNotAllowed,
            408 => HttpStatus::RequestTimeout,
            410 => HttpStatus::Gone,
            411 => HttpStatus::LengthRequired,
            413 => HttpStatus::PayloadTooLarge,
            414 => HttpStatus::UriTooLong,
            415 => HttpStatus::UnsupportedMediaType,
            416 => HttpStatus::RangeNotSatisfiable,
            500 => HttpStatus::InternalServerError,
            501 => HttpStatus::NotImplemented,
            502 => HttpStatus::BadGateway,
            503 => HttpStatus::ServiceUnavailable,
            504 => HttpStatus::GatewayTimeout,
            505 => HttpStatus::HttpVersionNotSupported,
            _ => HttpStatus::Unknown,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, HttpStatus::Ok | HttpStatus::Created | HttpStatus::Accepted | HttpStatus::NoContent)
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self,
            HttpStatus::MovedPermanently | HttpStatus::Found | HttpStatus::SeeOther |
            HttpStatus::NotModified | HttpStatus::TemporaryRedirect | HttpStatus::PermanentRedirect
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(self,
            HttpStatus::BadRequest | HttpStatus::Unauthorized | HttpStatus::Forbidden |
            HttpStatus::NotFound | HttpStatus::MethodNotAllowed | HttpStatus::RequestTimeout |
            HttpStatus::Gone | HttpStatus::LengthRequired | HttpStatus::PayloadTooLarge |
            HttpStatus::UriTooLong | HttpStatus::UnsupportedMediaType |
            HttpStatus::RangeNotSatisfiable | HttpStatus::InternalServerError |
            HttpStatus::NotImplemented | HttpStatus::BadGateway |
            HttpStatus::ServiceUnavailable | HttpStatus::GatewayTimeout |
            HttpStatus::HttpVersionNotSupported
        )
    }
}

/// HTTP header
#[derive(Debug, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code
    pub status: HttpStatus,
    /// Status message
    pub message: String,
    /// Headers
    pub headers: Vec<HttpHeader>,
    /// Body
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Get header value by name
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Check if response has body
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// Get content length
    pub fn content_length(&self) -> Option<usize> {
        self.get_header("Content-Length")
            .and_then(|s| s.parse().ok())
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
}

// ============================================================================
// FTP Types
// ============================================================================

/// FTP transfer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpTransferMode {
    /// Active mode (PORT)
    Active,
    /// Passive mode (PASV)
    Passive,
}

/// FTP file type for transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpFileType {
    /// ASCII text
    Ascii,
    /// Binary/image
    Binary,
    /// EBCDIC text
    Ebcdic,
    /// Local text format
    Local,
}

impl FtpFileType {
    pub fn as_ftp_type(&self) -> &'static str {
        match self {
            FtpFileType::Ascii => "A",
            FtpFileType::Binary => "I",
            FtpFileType::Ebcdic => "E",
            FtpFileType::Local => "L",
        }
    }
}

/// FTP reply
#[derive(Debug, Clone)]
pub struct FtpReply {
    /// Reply code
    pub code: u32,
    /// Reply message
    pub message: String,
    /// Is multi-line reply
    pub multiline: bool,
}

impl FtpReply {
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    pub fn is_error(&self) -> bool {
        self.code >= 400 && self.code < 600
    }

    pub fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

// ============================================================================
// WebFS Error Types
// ============================================================================

/// WebFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebFsError {
    /// Invalid URL format
    InvalidUrl,
    /// Unknown scheme
    InvalidScheme,
    /// Connection failed
    ConnectionFailed,
    /// Connection refused
    ConnectionRefused,
    /// Connection timed out
    Timeout,
    /// Request failed
    RequestFailed,
    /// HTTP error response
    HttpError(HttpStatus),
    /// FTP error
    FtpError(u32),
    /// Authentication required
    AuthenticationRequired,
    /// Permission denied
    PermissionDenied,
    /// Not found
    NotFound,
    /// Invalid state
    InvalidState,
    /// Buffer too small
    BufferTooSmall,
    /// Operation not supported
    NotSupported,
    /// Unknown error
    Unknown,
}

impl WebFsError {
    pub fn description(&self) -> &'static str {
        match self {
            WebFsError::InvalidUrl => "Invalid URL format",
            WebFsError::InvalidScheme => "Unknown URL scheme",
            WebFsError::ConnectionFailed => "Connection failed",
            WebFsError::ConnectionRefused => "Connection refused",
            WebFsError::Timeout => "Connection timed out",
            WebFsError::RequestFailed => "Request failed",
            WebFsError::HttpError(s) => match s {
                HttpStatus::Unauthorized => "Authentication required",
                HttpStatus::Forbidden => "Permission denied",
                HttpStatus::NotFound => "Resource not found",
                _ => "HTTP error",
            },
            WebFsError::FtpError(_code) => "FTP error",
            WebFsError::AuthenticationRequired => "Authentication required",
            WebFsError::PermissionDenied => "Permission denied",
            WebFsError::NotFound => "Resource not found",
            WebFsError::InvalidState => "Invalid state",
            WebFsError::BufferTooSmall => "Buffer too small",
            WebFsError::NotSupported => "Operation not supported",
            WebFsError::Unknown => "Unknown error",
        }
    }
}

/// Result type for WebFS operations
pub type WebFsResult<T> = core::result::Result<T, WebFsError>;

// ============================================================================
// WebFS Client
// ============================================================================

/// WebFS file handle
#[derive(Debug, Clone)]
pub struct WebFsFile {
    /// URL being accessed
    url: Url,
    /// File offset
    offset: u64,
    /// Total size (if known)
    size: Option<u64>,
    /// MIME type (if known)
    content_type: Option<String>,
    /// EOF reached
    eof: bool,
}

/// WebFS client for HTTP and FTP access
#[derive(Debug, Clone)]
pub struct Client {
    /// Default timeout in seconds
    timeout_secs: u32,
    /// Default transfer mode
    ftp_mode: FtpTransferMode,
    /// FTP file type
    ftp_type: FtpFileType,
    /// User agent string
    user_agent: String,
    /// Follow redirects
    follow_redirects: bool,
    /// Maximum redirects
    max_redirects: u32,
}

impl Client {
    /// Create new WebFS client
    pub fn new() -> Self {
        Self {
            timeout_secs: 30,
            ftp_mode: FtpTransferMode::Passive,
            ftp_type: FtpFileType::Binary,
            user_agent: "Plan9-WebFS/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
        }
    }

    /// Set timeout
    pub fn set_timeout(&mut self, secs: u32) {
        self.timeout_secs = secs;
    }

    /// Set FTP transfer mode
    pub fn set_ftp_mode(&mut self, mode: FtpTransferMode) {
        self.ftp_mode = mode;
    }

    /// Set FTP file type
    pub fn set_ftp_type(&mut self, ftype: FtpFileType) {
        self.ftp_type = ftype;
    }

    /// Set whether to follow redirects
    pub fn set_follow_redirects(&mut self, follow: bool) {
        self.follow_redirects = follow;
    }

    /// Set maximum redirects
    pub fn set_max_redirects(&mut self, max: u32) {
        self.max_redirects = max;
    }

    /// Open URL and return file handle
    pub fn open(&self, url: &str) -> WebFsResult<WebFsFile> {
        let parsed = Url::parse(url)?;

        match parsed.scheme {
            UrlScheme::Http | UrlScheme::Https => self.open_http(&parsed),
            UrlScheme::Ftp => self.open_ftp(&parsed),
            UrlScheme::Unknown => Err(WebFsError::InvalidScheme),
        }
    }

    /// Open HTTP URL
    fn open_http(&self, url: &Url) -> WebFsResult<WebFsFile> {
        // Build request and perform GET
        let response = self.http_get(url, None, 0, 0)?;

        if !response.status.is_success() {
            return Err(WebFsError::HttpError(response.status));
        }

        Ok(WebFsFile {
            url: url.clone(),
            offset: 0,
            size: response.content_length().map(|c| c as u64),
            content_type: response.content_type().map(|s| s.to_string()),
            eof: false,
        })
    }

    /// Open FTP URL
    fn open_ftp(&self, url: &Url) -> WebFsResult<WebFsFile> {
        // For now, just validate the URL
        if url.path.is_empty() || url.path == "/" {
            return Err(WebFsError::NotFound);
        }

        Ok(WebFsFile {
            url: url.clone(),
            offset: 0,
            size: None,
            content_type: Some("application/octet-stream".to_string()),
            eof: false,
        })
    }

    /// Perform HTTP GET request
    pub fn http_get(
        &self,
        url: &Url,
        range: Option<(u64, u64)>,
        _redirect_count: u32,
        _depth: u32,
    ) -> WebFsResult<HttpResponse> {
        // Build request headers
        let mut headers = Vec::new();
        headers.push(HttpHeader {
            name: "Host".to_string(),
            value: if url.port == url.scheme.default_port() {
                url.host.clone()
            } else {
                format!("{}:{}", url.host, url.port)
            },
        });
        headers.push(HttpHeader {
            name: "User-Agent".to_string(),
            value: self.user_agent.clone(),
        });

        // Add Range header if specified
        if let Some((start, end)) = range {
            let range_value = if end > 0 {
                format!("bytes={}-{}", start, end)
            } else {
                format!("bytes={}-", start)
            };
            headers.push(HttpHeader {
                name: "Range".to_string(),
                value: range_value,
            });
        }

        // Return placeholder response
        Ok(HttpResponse {
            status: HttpStatus::Ok,
            message: "OK".to_string(),
            headers,
            body: Vec::new(),
        })
    }

    /// Perform HTTP PUT request
    pub fn http_put(&self, url: &Url, data: &[u8]) -> WebFsResult<HttpResponse> {
        let mut headers = Vec::new();
        headers.push(HttpHeader {
            name: "Host".to_string(),
            value: if url.port == url.scheme.default_port() {
                url.host.clone()
            } else {
                format!("{}:{}", url.host, url.port)
            },
        });
        headers.push(HttpHeader {
            name: "User-Agent".to_string(),
            value: self.user_agent.clone(),
        });
        headers.push(HttpHeader {
            name: "Content-Length".to_string(),
            value: format!("{}", data.len()),
        });

        Ok(HttpResponse {
            status: HttpStatus::Ok,
            message: "OK".to_string(),
            headers,
            body: Vec::new(),
        })
    }

    /// Perform HTTP DELETE request
    pub fn http_delete(&self, url: &Url) -> WebFsResult<HttpResponse> {
        let mut headers = Vec::new();
        headers.push(HttpHeader {
            name: "Host".to_string(),
            value: if url.port == url.scheme.default_port() {
                url.host.clone()
            } else {
                format!("{}:{}", url.host, url.port)
            },
        });
        headers.push(HttpHeader {
            name: "User-Agent".to_string(),
            value: self.user_agent.clone(),
        });

        Ok(HttpResponse {
            status: HttpStatus::Ok,
            message: "OK".to_string(),
            headers,
            body: Vec::new(),
        })
    }

    /// Get URL as string
    pub fn url_to_string(url: &Url) -> String {
        let port_str = if url.port != url.scheme.default_port() {
            format!(":{}", url.port)
        } else {
            String::new()
        };

        format!(
            "{}{}{}{}",
            url.scheme.as_str(),
            port_str,
            url.path,
            url.query.as_ref().map(|q| format!("?{}", q)).unwrap_or_default()
        )
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// File Operations for WebFsFile
// ============================================================================

impl WebFsFile {
    /// Get file size
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Check if EOF
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Get current offset
    pub fn tell(&self) -> u64 {
        self.offset
    }

    /// Read from file (requires client)
    pub fn read(&mut self, _client: &Client, _buf: &mut [u8]) -> WebFsResult<usize> {
        if self.eof {
            return Ok(0);
        }

        // In a real implementation, this would fetch the data
        // For now, return empty
        self.eof = true;
        Ok(0)
    }

    /// Seek in file
    pub fn seek(&mut self, offset: u64) -> WebFsResult<()> {
        if let Some(size) = self.size {
            if offset > size {
                return Err(WebFsError::InvalidState);
            }
        }
        self.offset = offset;
        self.eof = false;
        Ok(())
    }

    /// Get URL string
    pub fn url(&self) -> String {
        Client::url_to_string(&self.url)
    }
}

// ============================================================================
// High-level File Operations
// ============================================================================

impl Client {
    /// Read entire file from URL into buffer
    pub fn read_file(&self, url: &str, buf: &mut [u8]) -> WebFsResult<usize> {
        let mut file = self.open(url)?;
        file.read(self, buf)
    }

    /// Read entire file from URL into Vec
    pub fn read_file_to_vec(&self, url: &str) -> WebFsResult<Vec<u8>> {
        let mut file = self.open(url)?;
        let size = file.size().unwrap_or(65536);
        let mut buf = Vec::with_capacity(size as usize);
        // In real impl, we'd read in chunks
        let mut tmp = [0u8; 8192];
        while !file.is_eof() {
            match file.read(self, &mut tmp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(e),
            }
        }
        Ok(buf)
    }

    /// Write file to URL
    pub fn write_file(&self, url: &str, data: &[u8]) -> WebFsResult<()> {
        let parsed = Url::parse(url)?;

        match parsed.scheme {
            UrlScheme::Http | UrlScheme::Https => {
                let response = self.http_put(&parsed, data)?;
                if !response.status.is_success() {
                    return Err(WebFsError::HttpError(response.status));
                }
                Ok(())
            }
            UrlScheme::Ftp => Err(WebFsError::NotSupported),
            UrlScheme::Unknown => Err(WebFsError::InvalidScheme),
        }
    }

    /// Delete resource
    pub fn delete(&self, url: &str) -> WebFsResult<()> {
        let parsed = Url::parse(url)?;

        match parsed.scheme {
            UrlScheme::Http | UrlScheme::Https => {
                let response = self.http_delete(&parsed)?;
                if !response.status.is_success() {
                    return Err(WebFsError::HttpError(response.status));
                }
                Ok(())
            }
            UrlScheme::Ftp => Err(WebFsError::NotSupported),
            UrlScheme::Unknown => Err(WebFsError::InvalidScheme),
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Default HTTP port
pub const HTTP_PORT: u16 = 80;

/// Default HTTPS port
pub const HTTPS_PORT: u16 = 443;

/// Default FTP port
pub const FTP_PORT: u16 = 21;

/// Maximum URL length
pub const MAX_URL_LENGTH: usize = 4096;

/// Maximum redirects
pub const MAX_REDIRECTS: u32 = 10;

/// Default timeout in seconds
pub const DEFAULT_TIMEOUT: u32 = 30;

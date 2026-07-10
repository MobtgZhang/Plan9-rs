//! HTTP Server Library
//!
//! Implements a simple HTTP server in Plan 9 style.

#![no_std]

extern crate alloc;


pub mod error;
pub mod request;
pub mod header;
pub mod urlunesc;
pub mod parseuri;
pub mod parsereq;
pub mod httpfmt;
pub mod auth;
pub mod log;
pub mod mime;
pub mod range;

// Re-exports
pub use error::HttpError;
pub use request::{HttpReq, Method};
pub use header::{HttpHead, Header, Headers, HeaderName};
pub use parsereq::HConnect;
pub use httpfmt::Response;
pub use urlunesc::{hurlunesc, htmlesc, hparsequery, UrlComponents};
pub use parseuri::{abspath, parseuri, stripsearch};
pub use auth::{AuthScheme, Credentials, UserDb};
pub use log::{AccessLog, CombinedLogEntry};
pub use mime::{ContentType, mime_from_ext, mime_from_path, is_text, is_compressible};
pub use range::{RangeSpec, ByteRange, parse_range, content_range, accept_ranges_header, is_range_satisfiable};

/// Result type for HTTP operations
pub type HttpResult<T> = core::result::Result<T, HttpError>;

/// HTTP status codes
pub mod status {
    /// Continue
    pub const CONTINUE: u16 = 100;
    /// Switching Protocols
    pub const SWITCHING_PROTOCOLS: u16 = 101;
    /// OK
    pub const OK: u16 = 200;
    /// Created
    pub const CREATED: u16 = 201;
    /// Accepted
    pub const ACCEPTED: u16 = 202;
    /// No Content
    pub const NO_CONTENT: u16 = 204;
    /// Partial Content
    pub const PARTIAL_CONTENT: u16 = 206;
    /// Moved Permanently
    pub const MOVED_PERMANENTLY: u16 = 301;
    /// Found
    pub const FOUND: u16 = 302;
    /// See Other
    pub const SEE_OTHER: u16 = 303;
    /// Not Modified
    pub const NOT_MODIFIED: u16 = 304;
    /// Temporary Redirect
    pub const TEMPORARY_REDIRECT: u16 = 307;
    /// Permanent Redirect
    pub const PERMANENT_REDIRECT: u16 = 308;
    /// Bad Request
    pub const BAD_REQUEST: u16 = 400;
    /// Unauthorized
    pub const UNAUTHORIZED: u16 = 401;
    /// Forbidden
    pub const FORBIDDEN: u16 = 403;
    /// Not Found
    pub const NOT_FOUND: u16 = 404;
    /// Method Not Allowed
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    /// Request Timeout
    pub const REQUEST_TIMEOUT: u16 = 408;
    /// Payload Too Large
    pub const PAYLOAD_TOO_LARGE: u16 = 413;
    /// URI Too Long
    pub const URI_TOO_LONG: u16 = 414;
    /// Unsupported Media Type
    pub const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
    /// Range Not Satisfiable
    pub const RANGE_NOT_SATISFIABLE: u16 = 416;
    /// Expectation Failed
    pub const EXPECTATION_FAILED: u16 = 417;
    /// Upgrade Required
    pub const UPGRADE_REQUIRED: u16 = 426;
    /// Internal Server Error
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    /// Not Implemented
    pub const NOT_IMPLEMENTED: u16 = 501;
    /// Bad Gateway
    pub const BAD_GATEWAY: u16 = 502;
    /// Service Unavailable
    pub const SERVICE_UNAVAILABLE: u16 = 503;
    /// Gateway Timeout
    pub const GATEWAY_TIMEOUT: u16 = 504;
    /// HTTP Version Not Supported
    pub const HTTP_VERSION_NOT_SUPPORTED: u16 = 505;
}

//! HTTP Error Types

use alloc::string::String;

/// HTTP error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Invalid request
    InvalidRequest,
    /// Bad request (syntax error)
    BadRequest(String),
    /// Not found
    NotFound,
    /// Forbidden
    Forbidden,
    /// Internal server error
    InternalError(String),
    /// I/O error
    IoError,
    /// Invalid URL
    InvalidUrl,
    /// URL escape error
    UrlEscapeError,
    /// Timeout
    Timeout,
    /// Connection closed
    ConnectionClosed,
    /// Unsupported HTTP version
    UnsupportedVersion(String),
    /// Method not allowed
    MethodNotAllowed,
    /// Payload too large
    PayloadTooLarge,
    /// Upgrade required
    UpgradeRequired,
    /// Range not satisfiable
    RangeNotSatisfiable,
    /// Parse error
    ParseError,
}

impl HttpError {
    /// Create a bad request error with a message
    pub fn bad_request(msg: impl Into<String>) -> Self {
        HttpError::BadRequest(msg.into())
    }

    /// Create an internal error with a message
    pub fn internal(msg: impl Into<String>) -> Self {
        HttpError::InternalError(msg.into())
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> u16 {
        match self {
            HttpError::InvalidRequest => 400,
            HttpError::BadRequest(_) => 400,
            HttpError::NotFound => 404,
            HttpError::Forbidden => 403,
            HttpError::InternalError(_) => 500,
            HttpError::IoError => 500,
            HttpError::InvalidUrl => 400,
            HttpError::UrlEscapeError => 400,
            HttpError::Timeout => 504,
            HttpError::ConnectionClosed => 499,
            HttpError::UnsupportedVersion(_) => 505,
            HttpError::MethodNotAllowed => 405,
            HttpError::PayloadTooLarge => 413,
            HttpError::UpgradeRequired => 426,
            HttpError::RangeNotSatisfiable => 416,
            HttpError::ParseError => 400,
        }
    }

    /// Get the reason phrase
    pub fn reason_phrase(&self) -> &'static str {
        match self {
            HttpError::InvalidRequest => "Invalid Request",
            HttpError::BadRequest(_) => "Bad Request",
            HttpError::NotFound => "Not Found",
            HttpError::Forbidden => "Forbidden",
            HttpError::InternalError(_) => "Internal Server Error",
            HttpError::IoError => "Internal Server Error",
            HttpError::InvalidUrl => "Bad Request",
            HttpError::UrlEscapeError => "Bad Request",
            HttpError::Timeout => "Gateway Timeout",
            HttpError::ConnectionClosed => "Client Closed Request",
            HttpError::UnsupportedVersion(_) => "HTTP Version Not Supported",
            HttpError::MethodNotAllowed => "Method Not Allowed",
            HttpError::PayloadTooLarge => "Payload Too Large",
            HttpError::UpgradeRequired => "Upgrade Required",
            HttpError::RangeNotSatisfiable => "Range Not Satisfiable",
            HttpError::ParseError => "Bad Request",
        }
    }
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HttpError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            HttpError::InternalError(msg) => write!(f, "Internal Server Error: {}", msg),
            HttpError::UnsupportedVersion(msg) => write!(f, "Unsupported Version: {}", msg),
            other => write!(f, "{}", other.reason_phrase()),
        }
    }
}

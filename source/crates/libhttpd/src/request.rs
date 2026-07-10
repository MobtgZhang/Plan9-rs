//! HTTP Request Structure
//!
//! Implements the HttpReq structure for parsing HTTP requests.

#![no_std]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::HttpError;

/// HTTP request method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Other(alloc::string::String),
}

impl Method {
    /// Parse a method from a string
    pub fn parse(s: &str) -> Self {
        match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "CONNECT" => Method::Connect,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
            "PATCH" => Method::Patch,
            other => Method::Other(other.to_string()),
        }
    }

    /// Check if this method has a body
    pub fn has_body(&self) -> bool {
        matches!(
            self,
            Method::Post | Method::Put | Method::Patch
        )
    }

    /// Check if this method is idempotent
    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Method::Get | Method::Head | Method::Put | Method::Delete | Method::Options | Method::Trace
        )
    }

    /// Convert to string
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
            Method::Other(s) => s,
        }
    }
}

impl Default for Method {
    fn default() -> Self {
        Method::Get
    }
}

/// HTTP request
#[derive(Debug, Clone)]
pub struct HttpReq {
    /// Request method
    pub method: Method,
    /// Original URI
    pub uri: alloc::string::String,
    /// URI host (extracted from absolute URI)
    pub urihost: Option<alloc::string::String>,
    /// Search/query string (after ?)
    pub search: Option<alloc::string::String>,
    /// HTTP version major
    pub vermaj: u8,
    /// HTTP version minor
    pub vermin: u8,
}

impl HttpReq {
    /// Create a new empty request
    pub fn new() -> Self {
        HttpReq {
            method: Method::Get,
            uri: alloc::string::String::new(),
            urihost: None,
            search: None,
            vermaj: 1,
            vermin: 1,
        }
    }

    /// Parse HTTP version string
    pub fn parse_version(s: &str) -> Result<(u8, u8), HttpError> {
        // Expect "HTTP/x.y"
        if !s.starts_with("HTTP/") {
            return Err(HttpError::UnsupportedVersion(s.to_string()));
        }

        let version = &s[5..];
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 2 {
            return Err(HttpError::UnsupportedVersion(s.to_string()));
        }

        let maj = parts[0]
            .parse::<u8>()
            .map_err(|_| HttpError::UnsupportedVersion(s.to_string()))?;
        let min = parts[1]
            .parse::<u8>()
            .map_err(|_| HttpError::UnsupportedVersion(s.to_string()))?;

        // Only support HTTP/1.0 and HTTP/1.1
        if maj != 1 || min > 1 {
            return Err(HttpError::UnsupportedVersion(s.to_string()));
        }

        Ok((maj, min))
    }

    /// Get the HTTP version as a string
    pub fn version_string(&self) -> alloc::string::String {
        alloc::format!("HTTP/{}.{}", self.vermaj, self.vermin)
    }

    /// Get the path portion of the URI
    pub fn path(&self) -> &str {
        // Find the path portion (before ? or #)
        if let Some(pos) = self.uri.find('?') {
            &self.uri[..pos]
        } else if let Some(pos) = self.uri.find('#') {
            &self.uri[..pos]
        } else {
            &self.uri
        }
    }

    /// Check if this is an HTTP/1.1 request
    pub fn is_http11(&self) -> bool {
        self.vermaj == 1 && self.vermin == 1
    }

    /// Check if this is an HTTP/1.0 request
    pub fn is_http10(&self) -> bool {
        self.vermaj == 1 && self.vermin == 0
    }

    /// Get the host from URI or Host header
    pub fn host(&self) -> Option<&str> {
        // First check if it's in the URI
        if let Some(ref host) = self.urihost {
            return Some(host);
        }
        None
    }
}

impl Default for HttpReq {
    fn default() -> Self {
        Self::new()
    }
}

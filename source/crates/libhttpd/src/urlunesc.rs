//! URL Encoding/Decoding
//!
//! Implements URL percent-encoding and decoding as per RFC 3986.

#![no_std]

extern crate alloc;

use alloc::string::ToString;

use crate::error::HttpError;

/// Maximum URL length we will process
pub const MAX_URL_LENGTH: usize = 8192;

/// Decode a percent-encoded URL string
///
/// Converts %XX sequences to their byte values.
/// Returns an error if the URL contains invalid percent sequences.
pub fn hurlunesc(s: &mut alloc::string::String) -> Result<(), HttpError> {
    // Check length
    if s.len() > MAX_URL_LENGTH {
        return Err(HttpError::BadRequest("URL too long".to_string()));
    }

    let mut result = alloc::string::String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                // Percent encoding
                if i + 2 >= bytes.len() {
                    // Not enough characters for encoding
                    result.push('%');
                    i += 1;
                    continue;
                }

                let hex1 = bytes[i + 1];
                let hex2 = bytes[i + 2];

                let d1 = hex_digit(hex1)?;
                let d2 = hex_digit(hex2)?;
                let value = (d1 << 4) | d2;

                // Check for invalid sequences
                if value == 0 {
                    // Null byte in URL is not allowed
                    return Err(HttpError::UrlEscapeError);
                }

                // For UTF-8, we need to decode properly
                // This is a simplified version - full UTF-8 validation
                // would require more sophisticated handling
                result.push(value as char);
                i += 3;
            }
            b'+' => {
                // Plus sign is space in query strings
                result.push(' ');
                i += 1;
            }
            b'\0' => {
                // Null byte not allowed
                return Err(HttpError::UrlEscapeError);
            }
            other => {
                // Check for control characters
                if other < 0x20 || other == 0x7F {
                    return Err(HttpError::UrlEscapeError);
                }
                result.push(other as char);
                i += 1;
            }
        }
    }

    // Validate UTF-8
    if core::str::from_utf8(result.as_bytes()).is_err() {
        return Err(HttpError::UrlEscapeError);
    }

    *s = result;
    Ok(())
}

/// Convert a hex digit to its numeric value
fn hex_digit(b: u8) -> Result<u8, HttpError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HttpError::UrlEscapeError),
    }
}

/// Encode a string for use in a URL
///
/// Percent-encodes special characters.
pub fn htmlesc(s: &str) -> alloc::string::String {
    let mut result = alloc::string::String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                result.push(hex_char(byte >> 4));
                result.push(hex_char(byte & 0x0F));
            }
        }
    }
    result
}

/// Convert a nibble to a hex character
fn hex_char(n: u8) -> char {
    (if n < 10 { b'0' + n } else { b'a' - 10 + n }) as char
}

/// Decode a query string into key-value pairs
///
/// The query string is in the format "key1=val1&key2=val2" or just "key" for flags.
pub fn hparsequery(query: &str) -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
    let mut result = alloc::vec::Vec::new();
    
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        
        let mut key = pair.to_string();
        let mut value = alloc::string::String::new();
        
        if let Some(pos) = key.find('=') {
            value = key[pos + 1..].to_string();
            key = key[..pos].to_string();
        }
        
        // Decode both key and value
        let _ = hurlunesc(&mut key);
        let _ = hurlunesc(&mut value);
        
        result.push((key, value));
    }
    
    result
}

/// URL parse result
#[derive(Debug)]
pub struct UrlComponents {
    /// Scheme (http, https)
    pub scheme: alloc::string::String,
    /// Host
    pub host: alloc::string::String,
    /// Port (optional)
    pub port: Option<u16>,
    /// Path
    pub path: alloc::string::String,
    /// Query string (optional)
    pub query: Option<alloc::string::String>,
    /// Fragment (optional)
    pub fragment: Option<alloc::string::String>,
}

impl UrlComponents {
    /// Parse a URL into components
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        let mut components = UrlComponents {
            scheme: alloc::string::String::new(),
            host: alloc::string::String::new(),
            port: None,
            path: alloc::string::String::new(),
            query: None,
            fragment: None,
        };

        let bytes = url.as_bytes();
        let mut i = 0;

        // Parse scheme
        if let Some(pos) = url.find("://") {
            components.scheme = url[..pos].to_ascii_lowercase();
            if components.scheme != "http" && components.scheme != "https" {
                return Err(HttpError::InvalidUrl);
            }
            i = pos + 3;
        }

        // Find end of host (next /, ?, or #)
        let host_end = bytes[i..]
            .iter()
            .position(|&b| b == b'/' || b == b'?' || b == b'#')
            .map(|p| i + p)
            .unwrap_or(bytes.len());

        // Parse host and port
        let host_part = &url[i..host_end];
        if let Some(pos) = host_part.find(':') {
            components.host = host_part[..pos].to_string();
            let port_str = &host_part[pos + 1..];
            components.port = port_str.parse::<u16>().ok();
        } else {
            components.host = host_part.to_string();
            components.port = if components.scheme == "https" { Some(443) } else { Some(80) };
        }

        i = host_end;

        // Parse path
        let path_end = bytes[i..]
            .iter()
            .position(|&b| b == b'?' || b == b'#')
            .map(|p| i + p)
            .unwrap_or(bytes.len());
        components.path = url[i..path_end].to_string();
        if components.path.is_empty() {
            components.path = "/".to_string();
        }
        i = path_end;

        // Parse query
        if i < bytes.len() && bytes[i] == b'?' {
            i += 1;
            let query_end = bytes[i..]
                .iter()
                .position(|&b| b == b'#')
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            components.query = Some(url[i..query_end].to_string());
            i = query_end;
        }

        // Parse fragment
        if i < bytes.len() && bytes[i] == b'#' {
            components.fragment = Some(url[i + 1..].to_string());
        }

        Ok(components)
    }
}

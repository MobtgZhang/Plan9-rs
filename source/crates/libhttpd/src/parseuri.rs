//! URI Parsing and Path Security
//!
//! Implements URI parsing with path security checks.

#![no_std]

extern crate alloc;

use alloc::string::ToString;

use crate::error::HttpError;

/// Reserved characters that should not appear in paths
const RESERVED_PATH_CHARS: &[u8] = b"`|\\";

/// Characters that are forbidden in URLs
const FORBIDDEN_CHARS: &[u8] = b"`;|\\";

/// Maximum path depth
const MAX_PATH_DEPTH: usize = 64;

/// Parse and validate a URI
///
/// Handles absolute and relative URIs.
/// Extracts host from absolute URIs.
pub fn parseuri(uri: &str, urihost: &mut Option<alloc::string::String>) -> Result<alloc::string::String, HttpError> {
    let bytes = uri.as_bytes();
    
    // Check for absolute URI
    if bytes.starts_with(b"http://") || bytes.starts_with(b"HTTP://") {
        // Extract host from absolute URI
        let after_scheme = if bytes.starts_with(b"http://") { 7 } else { 7 };
        if let Some(path_start) = uri[after_scheme..].find('/') {
            let host = &uri[after_scheme..after_scheme + path_start];
            *urihost = Some(host.to_string());
            return Ok(uri[after_scheme + path_start..].to_string());
        } else {
            let host = &uri[after_scheme..];
            *urihost = Some(host.to_string());
            return Ok("/".to_string());
        }
    }
    
    if bytes.starts_with(b"https://") || bytes.starts_with(b"HTTPS://") {
        let after_scheme = 8;
        if let Some(path_start) = uri[after_scheme..].find('/') {
            let host = &uri[after_scheme..after_scheme + path_start];
            *urihost = Some(host.to_string());
            return Ok(uri[after_scheme + path_start..].to_string());
        } else {
            let host = &uri[after_scheme..];
            *urihost = Some(host.to_string());
            return Ok("/".to_string());
        }
    }
    
    // Relative URI - use as-is
    *urihost = None;
    Ok(uri.to_string())
}

/// Strip the search portion (query string) from a URI
pub fn stripsearch(uri: &str) -> (alloc::string::String, Option<alloc::string::String>) {
    if let Some(pos) = uri.find('?') {
        let path = uri[..pos].to_string();
        let search = uri[pos + 1..].to_string();
        (path, Some(search))
    } else {
        (uri.to_string(), None)
    }
}

/// Convert a relative path to an absolute path
///
/// Note: This is a simplified version. A full implementation would
/// need the base URL to resolve relative paths properly.
pub fn absurl(base: &str, rel: &str) -> alloc::string::String {
    if rel.starts_with('/') {
        return rel.to_string();
    }
    
    // Simple relative URL handling
    if rel.starts_with("../") {
        // Strip one directory from base
        if let Some(pos) = base.rfind('/') {
            return absurl(&base[..pos], &rel[3..]);
        }
        return rel.to_string();
    }
    
    if rel.starts_with("./") {
        return absurl(base, &rel[2..]);
    }
    
    // Append to base path
    let base_path = if let Some(pos) = base.rfind('/') {
        &base[..pos + 1]
    } else {
        ""
    };
    
    alloc::format!("{}{}", base_path, rel)
}

/// Make a path absolute and secure
///
/// This function:
/// - Removes `.` and `..` components
/// - Prevents path traversal attacks (`../`)
/// - Rejects certain forbidden filenames
/// - Normalizes the path
pub fn abspath(wdir: &str, uri: &str) -> Result<alloc::string::String, HttpError> {
    let mut components: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    let mut depth = 0;
    
    // Split the URI into components
    for comp in uri.split('/') {
        match comp {
            "" => continue, // Skip empty components
            "." => continue, // Current directory - skip
            ".." => {
                // Parent directory - pop if not at root
                if !components.is_empty() && components.last() != Some(&"..") {
                    components.pop();
                    if depth > 0 {
                        depth -= 1;
                    }
                } else if wdir.is_empty() {
                    // At root, can't go higher
                    return Err(HttpError::Forbidden);
                }
            }
            other => {
                // Check for forbidden characters
                for &ch in FORBIDDEN_CHARS {
                    if other.contains(ch as char) {
                        return Err(HttpError::Forbidden);
                    }
                }
                
                // Check depth limit
                if depth >= MAX_PATH_DEPTH {
                    return Err(HttpError::Forbidden);
                }
                
                // Check for forbidden extensions (Plan 9 security)
                // Reject /bin/ paths for security
                if other == "bin" && components.is_empty() {
                    return Err(HttpError::Forbidden);
                }
                
                components.push(other);
                depth += 1;
            }
        }
    }
    
    // Build the final path
    let path = if components.is_empty() {
        "/".to_string()
    } else {
        "/".to_string() + &components.join("/")
    };
    
    // If there's a working directory, prepend it
    if !wdir.is_empty() {
        // Combine wdir and path
        let combined = if wdir.ends_with('/') {
            alloc::format!("{}{}", wdir, &path[1..])
        } else {
            alloc::format!("{}{}", wdir, path)
        };
        return Ok(combined);
    }
    
    Ok(path)
}

/// Validate that a path is safe to serve
pub fn validatesafepath(path: &str) -> Result<(), HttpError> {
    // Check for null bytes
    if path.contains('\0') {
        return Err(HttpError::Forbidden);
    }
    
    // Check for control characters
    for ch in path.chars() {
        if ch.is_control() {
            return Err(HttpError::Forbidden);
        }
    }
    
    // Check for forbidden characters
    for ch in path.bytes() {
        if FORBIDDEN_CHARS.contains(&ch) {
            return Err(HttpError::Forbidden);
        }
    }
    
    Ok(())
}

/// Get the file extension from a path
pub fn fileext(path: &str) -> Option<&str> {
    if let Some(pos) = path.rfind('.') {
        if pos > 0 && !path[..pos].contains('/') {
            return Some(&path[pos + 1..]);
        }
    }
    None
}

/// Check if a path looks like a directory
pub fn isdir(path: &str) -> bool {
    path.ends_with('/')
}

/// Normalize a path (remove trailing slashes except for root)
pub fn normalize(path: &str) -> alloc::string::String {
    if path == "/" {
        return "/".to_string();
    }
    
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    
    trimmed.to_string()
}

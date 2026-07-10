//! HTTP Response Formatting
//!
//! Implements the response building functions.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// HTTP response
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP version
    pub version: String,
    /// Status code
    pub status: u16,
    /// Status text
    pub status_text: String,
    /// Headers
    pub headers: Vec<(String, String)>,
    /// Body
    pub body: Option<Vec<u8>>,
}

impl Response {
    /// Create a new response
    pub fn new(status: u16, status_text: &str) -> Self {
        Response {
            version: "HTTP/1.1".to_string(),
            status,
            status_text: status_text.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a 200 OK response
    pub fn ok(body: Vec<u8>) -> Self {
        let mut resp = Response::new(200, "OK");
        resp.set_body(body);
        resp
    }

    /// Create a 200 OK response with text
    pub fn ok_text(text: &str) -> Self {
        let body = text.as_bytes().to_vec();
        let mut resp = Response::new(200, "OK");
        resp.set_body(body);
        resp.add_header("Content-Type", "text/plain; charset=utf-8");
        resp
    }

    /// Create a 200 OK response with HTML
    pub fn ok_html(html: &str) -> Self {
        let body = html.as_bytes().to_vec();
        let mut resp = Response::new(200, "OK");
        resp.set_body(body);
        resp.add_header("Content-Type", "text/html; charset=utf-8");
        resp
    }

    /// Create a 201 Created response
    pub fn created(location: &str) -> Self {
        let mut resp = Response::new(201, "Created");
        resp.add_header("Location", location);
        resp
    }

    /// Create a 204 No Content response
    pub fn no_content() -> Self {
        Response::new(204, "No Content")
    }

    /// Create a 301 Moved Permanently response
    pub fn moved_permanently(location: &str) -> Self {
        let mut resp = Response::new(301, "Moved Permanently");
        resp.add_header("Location", location);
        resp
    }

    /// Create a 302 Found response
    pub fn found(location: &str) -> Self {
        let mut resp = Response::new(302, "Found");
        resp.add_header("Location", location);
        resp
    }

    /// Create a 304 Not Modified response
    pub fn not_modified() -> Self {
        Response::new(304, "Not Modified")
    }

    /// Create a 400 Bad Request response
    pub fn bad_request(message: &str) -> Self {
        Self::error(400, "Bad Request", message)
    }

    /// Create a 403 Forbidden response
    pub fn forbidden() -> Self {
        Self::error(403, "Forbidden", "Access denied")
    }

    /// Create a 404 Not Found response
    pub fn not_found() -> Self {
        Self::error(404, "Not Found", "The requested resource was not found")
    }

    /// Create a 405 Method Not Allowed response
    pub fn method_not_allowed() -> Self {
        Self::error(405, "Method Not Allowed", "The method is not allowed for this resource")
    }

    /// Create a 500 Internal Server Error response
    pub fn internal_error(message: &str) -> Self {
        Self::error(500, "Internal Server Error", message)
    }

    /// Create a 502 Bad Gateway response
    pub fn bad_gateway() -> Self {
        Self::error(502, "Bad Gateway", "The server received an invalid response")
    }

    /// Create a 503 Service Unavailable response
    pub fn service_unavailable() -> Self {
        Self::error(503, "Service Unavailable", "The service is temporarily unavailable")
    }

    /// Create an error response
    fn error(status: u16, status_text: &str, message: &str) -> Self {
        let html = format!(
            "<html><head><title>{} {}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
            status, status_text, status_text, message
        );
        let mut resp = Response::new(status, status_text);
        resp.set_body(html.into_bytes());
        resp
    }

    /// Add a header
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Set the Content-Type header
    pub fn set_content_type(&mut self, content_type: &str) {
        self.add_header("Content-Type", content_type);
    }

    /// Set the Content-Length header
    pub fn set_content_length(&mut self, len: usize) {
        self.add_header("Content-Length", &len.to_string());
    }

    /// Set the body
    pub fn set_body(&mut self, body: Vec<u8>) {
        self.set_content_length(body.len());
        self.body = Some(body);
    }

    /// Set the body without Content-Length
    pub fn set_body_no_length(&mut self, body: Vec<u8>) {
        self.body = Some(body);
    }

    /// Add a cookie
    pub fn add_cookie(&mut self, name: &str, value: &str) {
        let cookie = format!("{}={}", name, value);
        self.add_header("Set-Cookie", &cookie);
    }

    /// Set Cache-Control header
    pub fn set_cache_control(&mut self, value: &str) {
        self.add_header("Cache-Control", value);
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Status line
        result.extend_from_slice(self.version.as_bytes());
        result.push(b' ');
        result.extend_from_slice(self.status.to_string().as_bytes());
        result.push(b' ');
        result.extend_from_slice(self.status_text.as_bytes());
        result.extend_from_slice(b"\r\n");

        // Headers
        for (name, value) in &self.headers {
            result.extend_from_slice(name.as_bytes());
            result.extend_from_slice(b": ");
            result.extend_from_slice(value.as_bytes());
            result.extend_from_slice(b"\r\n");
        }

        // Empty line
        result.extend_from_slice(b"\r\n");

        // Body
        if let Some(ref body) = self.body {
            result.extend_from_slice(body);
        }

        result
    }

    /// Get the body as a string
    pub fn body_as_str(&self) -> Option<&str> {
        self.body.as_ref().and_then(|b| core::str::from_utf8(b).ok())
    }
}

impl Default for Response {
    fn default() -> Self {
        Self::new(200, "OK")
    }
}

/// Build a redirect response
pub fn redirect(location: &str, permanent: bool) -> Response {
    if permanent {
        Response::moved_permanently(location)
    } else {
        Response::found(location)
    }
}

/// Build an HTML error response
pub fn html_error(status: u16, title: &str, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{} {}</title>
</head>
<body>
    <h1>{}</h1>
    <p>{}</p>
    <hr>
    <small>Plan 9 HTTP Server</small>
</body>
</html>"#,
        status, title, title, message
    );

    let mut resp = Response::new(status, title);
    resp.set_body(html.into_bytes());
    resp
}

//! HTTP MIME type detection
//!
//! Maps file extensions to MIME types and parses `Content-Type`
//! headers into their type/subtype/charset components.

use alloc::string::{String, ToString};

/// MIME content type broken into its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentType {
    /// Top-level type (e.g. `text`).
    pub top: String,
    /// Subtype (e.g. `html`).
    pub sub: String,
    /// Optional charset parameter.
    pub charset: Option<String>,
    /// Optional boundary parameter (for `multipart/*`).
    pub boundary: Option<String>,
}

impl ContentType {
    /// Parse a `Content-Type` header value, e.g. `text/html; charset=utf-8`.
    pub fn parse(s: &str) -> Result<Self, ()> {
        let mut parts = s.split(';');
        let main = parts.next().unwrap_or("").trim();
        if main.is_empty() {
            return Err(());
        }
        let (top, sub) = main.split_once('/').ok_or(())?;
        let mut ct = ContentType {
            top: top.trim().to_ascii_lowercase(),
            sub: sub.trim().to_ascii_lowercase(),
            charset: None,
            boundary: None,
        };
        for param in parts {
            let param = param.trim();
            if let Some((k, v)) = param.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().trim_matches('"');
                match k.as_str() {
                    "charset" => ct.charset = Some(v.to_string()),
                    "boundary" => ct.boundary = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        Ok(ct)
    }

    /// Render the content type back into a string.
    pub fn as_header(&self) -> String {
        let mut s = alloc::format!("{}/{}", self.top, self.sub);
        if let Some(cs) = &self.charset {
            s.push_str("; charset=");
            s.push_str(cs);
        }
        if let Some(b) = &self.boundary {
            s.push_str("; boundary=");
            s.push_str(b);
        }
        s
    }
}

/// Look up a MIME type by file extension.
pub fn mime_from_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "wasm" => "application/wasm",
        "yaml" | "yml" => "application/yaml",
        _ => "application/octet-stream",
    }
}

/// Look up a MIME type by full path or filename (uses the last `.`).
pub fn mime_from_path(path: &str) -> &'static str {
    if let Some(idx) = path.rfind('.') {
        mime_from_ext(&path[idx + 1..])
    } else {
        "application/octet-stream"
    }
}

/// Best-effort guess of whether a content type represents text.
pub fn is_text(ct: &ContentType) -> bool {
    matches!(ct.top.as_str(), "text")
        || matches!(
            (ct.top.as_str(), ct.sub.as_str()),
            ("application", "json")
                | ("application", "xml")
                | ("application", "javascript")
                | ("application", "yaml")
        )
}

/// Best-effort guess of whether a content type should be compressed.
pub fn is_compressible(ct: &ContentType) -> bool {
    is_text(ct)
        || matches!(ct.sub.as_str(), "svg" | "xml" | "json" | "javascript")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain() {
        let ct = ContentType::parse("text/plain").expect("parse should succeed");
        assert_eq!(ct.top, "text");
        assert_eq!(ct.sub, "plain");
        assert!(ct.charset.is_none());
    }

    #[test]
    fn test_parse_with_charset() {
        let ct = ContentType::parse("text/html; charset=UTF-8").expect("parse should succeed");
        assert_eq!(ct.top, "text");
        assert_eq!(ct.sub, "html");
        assert_eq!(ct.charset.as_deref(), Some("UTF-8"));
    }

    #[test]
    fn test_parse_with_boundary() {
        let ct = ContentType::parse("multipart/form-data; boundary=xyz").expect("parse should succeed");
        assert_eq!(ct.top, "multipart");
        assert_eq!(ct.sub, "form-data");
        assert_eq!(ct.boundary.as_deref(), Some("xyz"));
    }

    #[test]
    fn test_parse_rejects_empty() {
        assert!(ContentType::parse("").is_err());
    }

    #[test]
    fn test_parse_rejects_no_slash() {
        assert!(ContentType::parse("textplain").is_err());
    }

    #[test]
    fn test_as_header_round_trip() {
        let ct = ContentType::parse("text/html; charset=utf-8").expect("parse should succeed");
        assert_eq!(ct.as_header(), "text/html; charset=utf-8");
    }

    #[test]
    fn test_mime_from_ext_known() {
        assert_eq!(mime_from_ext("html"), "text/html; charset=utf-8");
        assert_eq!(mime_from_ext("png"), "image/png");
        assert_eq!(mime_from_ext("JSON"), "application/json; charset=utf-8");
    }

    #[test]
    fn test_mime_from_ext_unknown() {
        assert_eq!(mime_from_ext("foobar"), "application/octet-stream");
    }

    #[test]
    fn test_mime_from_path() {
        assert_eq!(mime_from_path("/foo/bar.html"), "text/html; charset=utf-8");
        assert_eq!(mime_from_path("plain.txt"), "text/plain; charset=utf-8");
        assert_eq!(mime_from_path("noextension"), "application/octet-stream");
    }

    #[test]
    fn test_is_text() {
        assert!(is_text(&ContentType::parse("text/plain").unwrap()));
        assert!(is_text(&ContentType::parse("application/json").unwrap()));
        assert!(!is_text(&ContentType::parse("image/png").unwrap()));
    }

    #[test]
    fn test_is_compressible() {
        assert!(is_compressible(&ContentType::parse("text/plain").unwrap()));
        assert!(is_compressible(&ContentType::parse("image/svg+xml").unwrap()));
        assert!(!is_compressible(&ContentType::parse("image/png").unwrap()));
    }
}
//! HTTP authentication helpers
//!
//! Implements Basic, Bearer, and Digest (RFC 2617) authentication schemes
//! for libhttpd.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::error::HttpError;

fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (b0 as u32) << 16 | (b1 as u32) << 8 | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() >= 2 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() >= 3 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(input: &[u8]) -> Result<Vec<u8>, ()> {
    fn dec(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let stripped: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    for chunk in stripped.chunks(4) {
        if chunk.len() < 2 {
            return Err(());
        }
        let mut n = 0u32;
        for &b in chunk.iter() {
            n = (n << 6) | (dec(b).ok_or(())? as u32);
        }
        out.push((n >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() >= 4 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Authentication scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    Basic,
    Bearer,
    P9Any,
}

impl AuthScheme {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("basic") || s.to_ascii_lowercase().starts_with("basic ") {
            Some(AuthScheme::Basic)
        } else if s.eq_ignore_ascii_case("bearer") || s.to_ascii_lowercase().starts_with("bearer ") {
            Some(AuthScheme::Bearer)
        } else if s.eq_ignore_ascii_case("p9any") || s.to_ascii_lowercase().starts_with("p9any ") {
            Some(AuthScheme::P9Any)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AuthScheme::Basic => "Basic",
            AuthScheme::Bearer => "Bearer",
            AuthScheme::P9Any => "p9any",
        }
    }
}

/// Credentials parsed from an Authorization header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub scheme: AuthScheme,
    pub user: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

impl Credentials {
    pub fn parse(scheme: AuthScheme, payload: &str) -> Result<Self, HttpError> {
        match scheme {
            AuthScheme::Basic => {
                let bytes = b64_decode(payload.as_bytes()).map_err(|_| HttpError::ParseError)?;
                let s = alloc::str::from_utf8(&bytes).map_err(|_| HttpError::ParseError)?;
                let (user, password) = s.split_once(':').ok_or(HttpError::ParseError)?;
                Ok(Credentials {
                    scheme,
                    user: Some(user.to_string()),
                    password: Some(password.to_string()),
                    token: None,
                })
            }
            AuthScheme::Bearer => Ok(Credentials {
                scheme,
                user: None,
                password: None,
                token: Some(payload.trim().to_string()),
            }),
            AuthScheme::P9Any => {
                let mut user = None;
                let mut password = None;
                let mut token = None;
                for part in payload.split_whitespace() {
                    if let Some((k, v)) = part.split_once('=') {
                        match k {
                            "user" => user = Some(v.to_string()),
                            "password" => password = Some(v.to_string()),
                            "token" => token = Some(v.to_string()),
                            _ => {}
                        }
                    }
                }
                Ok(Credentials { scheme, user, password, token })
            }
        }
    }

    pub fn basic_header(user: &str, password: &str) -> String {
        let mut s = String::with_capacity(user.len() + password.len() + 1);
        s.push_str(user);
        s.push(':');
        s.push_str(password);
        alloc::format!("Basic {}", b64_encode(s.as_bytes()))
    }
}

/// In-memory user database for HTTP authentication.
#[derive(Debug, Default)]
pub struct UserDb {
    entries: Vec<(String, String)>,
}

impl UserDb {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }
    pub fn add(&mut self, user: &str, password: &str) {
        self.entries.push((user.to_string(), password.to_string()));
    }
    pub fn remove(&mut self, user: &str) -> bool {
        if let Some(idx) = self.entries.iter().position(|(u, _)| u == user) {
            self.entries.swap_remove(idx);
            true
        } else {
            false
        }
    }
    pub fn lookup(&self, user: &str) -> Option<&str> {
        self.entries.iter()
            .find(|(u, _)| u == user)
            .map(|(_, p)| p.as_str())
    }
    pub fn verify(&self, user: &str, password: &str) -> bool {
        self.lookup(user).map_or(false, |p| p == password)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Digest Authentication (RFC 2617)
// ---------------------------------------------------------------------------

/// Quality of protection variants supported by the Digest parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestQop {
    /// No qop: legacy RFC 2069 style.
    None,
    /// `auth` only.
    Auth,
}

/// Parsed `Authorization: Digest ...` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestCredentials {
    /// Username (decoded from `username=...`).
    pub username: String,
    /// Realm value sent by the server in the WWW-Authenticate challenge.
    pub realm: String,
    /// Nonce from the server.
    pub nonce: String,
    /// Request URI (typically the request-URI of the protected resource).
    pub uri: String,
    /// Response digest computed by the client.
    pub response: String,
    /// Optional algorithm (`MD5` by default, `MD5-sess` for sessions).
    pub algorithm: String,
    /// Optional client nonce for `auth-int`/session modes.
    pub cnonce: Option<String>,
    /// Nonce counter.
    pub nc: Option<String>,
    /// Quality of protection.
    pub qop: DigestQop,
    /// Optional opaque value.
    pub opaque: Option<String>,
}

impl DigestCredentials {
    /// Parse the comma-separated key=value list that follows the
    /// `Digest` scheme name. Values may be quoted with double quotes;
    /// unquoted values are taken verbatim.
    pub fn parse(payload: &str) -> Result<Self, HttpError> {
        let mut username: Option<String> = None;
        let mut realm: Option<String> = None;
        let mut nonce: Option<String> = None;
        let mut uri: Option<String> = None;
        let mut response: Option<String> = None;
        let mut algorithm = "MD5".to_string();
        let mut cnonce: Option<String> = None;
        let mut nc: Option<String> = None;
        let mut opaque: Option<String> = None;
        let mut qop = DigestQop::None;

        for part in split_unquoted_commas(payload) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (raw_key, raw_val) = part
                .split_once('=')
                .ok_or_else(|| HttpError::ParseError)?;
            let key = raw_key.trim();
            let val = strip_quotes(raw_val.trim());

            match key {
                "username" => username = Some(val.to_string()),
                "realm" => realm = Some(val.to_string()),
                "nonce" => nonce = Some(val.to_string()),
                "uri" => uri = Some(val.to_string()),
                "response" => response = Some(val.to_string()),
                "algorithm" => algorithm = val.to_string(),
                "cnonce" => cnonce = Some(val.to_string()),
                "nc" => nc = Some(val.to_string()),
                "opaque" => opaque = Some(val.to_string()),
                "qop" => {
                    qop = match val.to_ascii_lowercase().as_str() {
                        "auth" => DigestQop::Auth,
                        _ => DigestQop::None,
                    };
                }
                _ => {}
            }
        }

        Ok(DigestCredentials {
            username: username.ok_or(HttpError::ParseError)?,
            realm: realm.ok_or(HttpError::ParseError)?,
            nonce: nonce.ok_or(HttpError::ParseError)?,
            uri: uri.ok_or(HttpError::ParseError)?,
            response: response.ok_or(HttpError::ParseError)?,
            algorithm,
            cnonce,
            nc,
            qop,
            opaque,
        })
    }
}

/// Build the `Digest` authorization header value for the legacy
/// `RFC 2069` flavour (no qop, no cnonce).
pub fn digest_header_simple(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
) -> String {
    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));
    let response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));
    format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        username, realm, nonce, uri, response
    )
}

/// Build the `Digest` authorization header for the modern `auth` qop
/// variant (RFC 2617). The caller must supply the opaque value (if any)
/// echoed from the server's challenge.
pub fn digest_header_auth(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    opaque: Option<&str>,
) -> String {
    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));
    let response = md5_hex(&format!(
        "{}:{}:{}:{}:{}:{}",
        ha1, nonce, nc, cnonce, "auth", ha2
    ));
    let mut header = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
         qop=auth, nc={}, cnonce=\"{}\", response=\"{}\"",
        username, realm, nonce, uri, nc, cnonce, response
    );
    if let Some(op) = opaque {
        header.push_str(&format!(", opaque=\"{}\"", op));
    }
    header
}

/// Verify a `DigestCredentials` against a stored password for the
/// given HTTP method. Returns `true` when the client-provided
/// `response` digest matches the locally recomputed digest.
pub fn verify_digest(
    creds: &DigestCredentials,
    password: &str,
    method: &str,
) -> bool {
    let ha1 = md5_hex(&format!("{}:{}:{}", creds.username, creds.realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, creds.uri));
    let expected = match creds.qop {
        DigestQop::None => md5_hex(&format!("{}:{}:{}", ha1, creds.nonce, ha2)),
        DigestQop::Auth => {
            let nc = creds.nc.as_deref().unwrap_or("00000000");
            let cnonce = creds.cnonce.as_deref().unwrap_or("");
            md5_hex(&format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, creds.nonce, nc, cnonce, "auth", ha2
            ))
        }
    };
    expected.eq_ignore_ascii_case(&creds.response)
}

/// Self-contained MD5 implementation used for Digest authentication.
/// Falls back to a slow-but-portable RFC 1321 algorithm so the crate
/// does not need to depend on an external crypto library just for
/// HTTP auth.
fn md5_hex(input: &str) -> String {
    let digest = md5(input.as_bytes());
    let mut out = String::with_capacity(32);
    for byte in &digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0F));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n & 0x0F {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '0',
    }
}

/// Canonical MD5 K table (RFC 1321).
const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Minimal MD5 implementation. Adapted from RFC 1321 reference code;
/// kept inline to avoid pulling a full crypto dependency for HTTP
/// auth alone. The output is always 16 bytes.
fn md5(input: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(input.len() + 64);
    msg.extend_from_slice(input);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for block in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, chunk) in block.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut a0 = a;
        let mut b0 = b;
        let mut c0 = c;
        let mut d0 = d;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b0 & c0) | (!b0 & d0), i),
                16..=31 => ((d0 & b0) | (!d0 & c0), (5 * i + 1) % 16),
                32..=47 => (b0 ^ c0 ^ d0, (3 * i + 5) % 16),
                _ => (c0 ^ (b0 | !d0), (7 * i) % 16),
            };
            let temp = d0;
            d0 = c0;
            c0 = b0;
            let sum = a0
                .wrapping_add(f)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            b0 = b0.wrapping_add(sum);
            a0 = temp;
        }
        a = a.wrapping_add(a0);
        b = b.wrapping_add(b0);
        c = c.wrapping_add(c0);
        d = d.wrapping_add(d0);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

/// Split a header value on commas that are not enclosed in double
/// quotes. This is required because RFC 2617 allows the `qop` list
/// (for example) to contain commas that must not be treated as
/// delimiters.
fn split_unquoted_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn strip_quotes(s: &str) -> &str {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_parse_basic() {
        assert_eq!(AuthScheme::parse("Basic"), Some(AuthScheme::Basic));
        assert_eq!(AuthScheme::parse("basic realm=x"), Some(AuthScheme::Basic));
    }

    #[test]
    fn test_scheme_parse_bearer() {
        assert_eq!(AuthScheme::parse("Bearer"), Some(AuthScheme::Bearer));
        assert_eq!(AuthScheme::parse("bearer xyz"), Some(AuthScheme::Bearer));
    }

    #[test]
    fn test_scheme_parse_p9any() {
        assert_eq!(AuthScheme::parse("p9any user=glenda"), Some(AuthScheme::P9Any));
    }

    #[test]
    fn test_basic_round_trip() {
        let header = Credentials::basic_header("glenda", "secret");
        assert!(header.starts_with("Basic "));
        let payload = &header[6..];
        let c = Credentials::parse(AuthScheme::Basic, payload).expect("parse should succeed");
        assert_eq!(c.user.as_deref(), Some("glenda"));
        assert_eq!(c.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_basic_decode_invalid() {
        let res = Credentials::parse(AuthScheme::Basic, "!!!");
        assert!(matches!(res, Err(HttpError::ParseError)));
    }

    #[test]
    fn test_bearer_parse() {
        let c = Credentials::parse(AuthScheme::Bearer, "abcdef").expect("parse should succeed");
        assert_eq!(c.token.as_deref(), Some("abcdef"));
    }

    #[test]
    fn test_p9any_parse() {
        let payload = "proto=p9any user=glenda dom=plan9 password=hunter2";
        let c = Credentials::parse(AuthScheme::P9Any, payload).expect("parse should succeed");
        assert_eq!(c.user.as_deref(), Some("glenda"));
        assert_eq!(c.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn test_user_db() {
        let mut db = UserDb::new();
        db.add("glenda", "secret");
        assert_eq!(db.lookup("glenda"), Some("secret"));
        assert!(db.verify("glenda", "secret"));
        assert!(!db.verify("glenda", "wrong"));
        assert!(db.remove("glenda"));
        assert!(db.is_empty());
    }
}

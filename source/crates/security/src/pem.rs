//! PEM Encoding and Decoding
//!
//! Implements PEM (Privacy-Enhanced Mail) format handling.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::SecurityError;

/// PEM block
#[derive(Debug, Clone)]
pub struct PemBlock {
    /// Label (e.g., "CERTIFICATE", "RSA PRIVATE KEY")
    pub label: String,
    /// Headers (key-value pairs)
    pub headers: Vec<(String, String)>,
    /// Decoded data
    pub data: Vec<u8>,
}

/// Check if data is PEM encoded
pub fn is_pem(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }
    // Check for PEM header
    let text = String::from_utf8_lossy(data);
    text.starts_with("-----BEGIN ")
}

/// Encode data as PEM
pub fn encode_pem(data: &[u8], label: &str) -> String {
    let mut result = String::new();
    
    // Header
    result.push_str("-----BEGIN ");
    result.push_str(label);
    result.push_str("-----\n");
    
    // Base64 encode
    let encoded = base64_encode(data);
    
    // Add lines of 64 characters
    for chunk in encoded.as_bytes().chunks(64) {
        result.push_str(&String::from_utf8_lossy(chunk).into_owned());
        result.push('\n');
    }
    
    // Footer
    result.push_str("-----END ");
    result.push_str(label);
    result.push_str("-----\n");
    
    result
}

/// Decode PEM string
pub fn decode_pem(pem: &str) -> Result<PemBlock, SecurityError> {
    let mut lines: Vec<&str> = pem.lines().collect();
    
    if lines.is_empty() {
        return Err(SecurityError::InvalidInputLength);
    }
    
    // Parse header line "-----BEGIN <label>-----"
    let first = lines.remove(0);
    if !first.starts_with("-----BEGIN ") || !first.ends_with("-----") {
        return Err(SecurityError::InvalidInputLength);
    }
    let label = first[11..first.len() - 5].to_string();
    
    // Parse footer line "-----END <label>-----"
    if lines.is_empty() {
        return Err(SecurityError::InvalidInputLength);
    }
    let last = lines.pop().unwrap();
    if !last.starts_with("-----END ") || !last.ends_with("-----") {
        return Err(SecurityError::InvalidInputLength);
    }
    
    // Parse headers and body
    let mut headers = Vec::new();
    let mut body_lines = Vec::new();
    
    for line in lines {
        if line.contains(':') && !line.starts_with(' ') {
            // Header line
            if let Some(pos) = line.find(':') {
                let key = String::from(&line[..pos]).trim().to_string();
                let value = String::from(&line[pos + 1..]).trim().to_string();
                headers.push((key, value));
            }
        } else if !line.is_empty() {
            body_lines.push(line);
        }
    }
    
    // Decode base64
    let body = body_lines.join("");
    let data = base64_decode(&body).map_err(|_| SecurityError::InvalidInputLength)?;
    
    Ok(PemBlock {
        label,
        headers,
        data,
    })
}

// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        
        result.push(TABLE[b0 >> 2] as char);
        result.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(TABLE[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}

// Simple base64 decoding
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    
    let input = input.as_bytes();
    let mut result = Vec::new();
    
    let mut i = 0;
    while i < input.len() {
        // Skip non-base64 characters
        while i < input.len() && decode_char(input[i]).is_none() {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        
        let a = decode_char(input[i]).ok_or(())?;
        i += 1;
        
        // Skip padding and whitespace
        while i < input.len() && (input[i] == b'=' || decode_char(input[i]).is_none()) {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        
        let b = decode_char(input[i]).ok_or(())?;
        i += 1;
        
        result.push((a << 2) | (b >> 4));
        
        // Skip padding
        while i < input.len() && input[i] == b'=' {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        
        let c = decode_char(input[i]).ok_or(())?;
        i += 1;
        
        result.push((b << 4) | (c >> 2));
        
        // Skip padding
        while i < input.len() && input[i] == b'=' {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        
        let d = decode_char(input[i]).ok_or(())?;
        i += 1;
        
        result.push((c << 6) | d);
    }
    
    Ok(result)
}

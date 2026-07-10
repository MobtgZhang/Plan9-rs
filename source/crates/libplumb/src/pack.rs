//! Plumb Message Packing
//!
//! Implements the plumbpack function for serializing Plumbmsg to wire format.

use alloc::boxed::Box;
use alloc::string::ToString;

use crate::attr::Plumbattr;
use crate::error::PlumbError;
use crate::message::Plumbmsg;

/// Pack an attribute list into a string
///
/// Format: `name=value name=value ...`
/// Values containing spaces or special characters are enclosed in single quotes.
fn pack_attr(attr: &Option<Box<Plumbattr>>) -> Result<alloc::string::String, PlumbError> {
    let mut result = alloc::string::String::new();
    
    let mut current = attr.as_deref();
    let mut first = true;
    
    while let Some(a) = current {
        if !first {
            result.push(' ');
        }
        first = false;
        
        // Add name
        result.push_str(&a.name);
        result.push('=');
        
        // Check if value needs quoting
        let needs_quote = a.value.contains(' ')
            || a.value.contains('\'')
            || a.value.contains('\n')
            || a.value.contains('\t')
            || a.value.contains('\0');
        
        if needs_quote {
            result.push('\'');
            // Escape single quotes by doubling them
            for ch in a.value.chars() {
                if ch == '\'' {
                    result.push('\'');
                }
                result.push(ch);
            }
            result.push('\'');
        } else {
            result.push_str(&a.value);
        }
        
        current = a.next.as_deref();
    }
    
    Ok(result)
}

/// Pack a Plumbmsg into wire format
///
/// The wire format is:
/// ```
/// src\ndst\nwdir\ntype\nattrs\nndata\n<data>
/// ```
///
/// Each field is terminated by a newline, and the data follows immediately.
pub fn plumbpack(msg: &Plumbmsg) -> Result<alloc::vec::Vec<u8>, PlumbError> {
    let mut buf = alloc::vec::Vec::new();
    
    // src\n
    buf.extend_from_slice(msg.src.as_bytes());
    buf.push(b'\n');
    
    // dst\n
    buf.extend_from_slice(msg.dst.as_bytes());
    buf.push(b'\n');
    
    // wdir\n (empty if not set)
    if let Some(ref wdir) = msg.wdir {
        buf.extend_from_slice(wdir.as_bytes());
    }
    buf.push(b'\n');
    
    // type\n
    buf.extend_from_slice(msg.mtype.as_bytes());
    buf.push(b'\n');
    
    // attrs\n
    let attr_str = pack_attr(&msg.attr)?;
    buf.extend_from_slice(attr_str.as_bytes());
    buf.push(b'\n');
    
    // ndata\n
    buf.extend_from_slice(msg.ndata.to_string().as_bytes());
    buf.push(b'\n');
    
    // data
    buf.extend_from_slice(&msg.data);
    
    Ok(buf)
}

/// Get the minimum number of bytes needed to unpack a message
pub const PLUMB_MIN_SIZE: usize = 6; // At least 6 newlines

/// Get the data offset in a packed message
/// Returns the offset where the data starts, or None if not enough bytes
pub fn get_data_offset(buf: &[u8]) -> Option<usize> {
    // Count newlines to find the 6th field (ndata value)
    let mut newlines = 0;
    let mut i = 0;
    
    while i < buf.len() && newlines < 5 {
        if buf[i] == b'\n' {
            newlines += 1;
        }
        i += 1;
    }
    
    if newlines < 5 {
        return None;
    }
    
    // Now find the 6th newline (end of ndata value)
    while i < buf.len() {
        if buf[i] == b'\n' {
            return Some(i + 1);
        }
        i += 1;
    }
    
    None
}

/// Get the expected data size from a packed message header
pub fn get_expected_size(buf: &[u8]) -> Option<usize> {
    // Find the 5th newline (end of attrs)
    let mut newlines = 0;
    let mut start = 0;
    let mut i = 0;
    
    while i < buf.len() && newlines < 5 {
        if buf[i] == b'\n' {
            newlines += 1;
            if newlines == 5 {
                start = i + 1;
            }
        }
        i += 1;
    }
    
    if newlines < 5 {
        return None;
    }
    
    // Find the 6th newline (end of ndata value)
    while i < buf.len() {
        if buf[i] == b'\n' {
            let ndata_str = core::str::from_utf8(&buf[start..i]).ok()?;
            return Some(ndata_str.parse::<usize>().ok()?);
        }
        i += 1;
    }
    
    None
}

/// Check if a packed message is complete
pub fn is_complete(buf: &[u8]) -> bool {
    if let Some(offset) = get_data_offset(buf) {
        if let Some(size) = get_expected_size(buf) {
            return buf.len() >= offset + size;
        }
    }
    false
}

/// Get the minimum bytes needed to determine message is complete
pub fn min_complete_size() -> usize {
    PLUMB_MIN_SIZE
}

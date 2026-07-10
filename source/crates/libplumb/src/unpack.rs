//! Plumb Message Unpacking
//!
//! Implements the plumbunpack and plumbunpackpartial functions.

use alloc::boxed::Box;
use alloc::string::ToString;

use crate::attr::Plumbattr;
use crate::error::PlumbError;
use crate::message::Plumbmsg;
use crate::pack::{get_data_offset, get_expected_size, is_complete};

/// Parse a single line from the buffer (up to newline, not including it)
fn parse_line(buf: &[u8], start: usize) -> Option<(&str, usize)> {
    let mut i = start;
    while i < buf.len() && buf[i] != b'\n' {
        i += 1;
    }
    
    if i >= buf.len() {
        return None; // No newline found
    }
    
    let line = core::str::from_utf8(&buf[start..i]).ok()?;
    Some((line, i + 1)) // Return line and position after newline
}

/// Unpack an attribute string into a Plumbattr list
///
/// Format: `name=value name=value ...`
/// Values enclosed in single quotes have escaped quotes handled.
fn unpack_attr(s: &str) -> Result<Option<Box<Plumbattr>>, PlumbError> {
    if s.is_empty() {
        return Ok(None);
    }
    
    let mut first: Option<Box<Plumbattr>> = None;
    let mut current: &mut Option<Box<Plumbattr>> = &mut first;
    
    let mut remaining = s;
    
    while !remaining.is_empty() {
        // Skip leading whitespace
        while remaining.starts_with(' ') {
            remaining = &remaining[1..];
        }
        
        if remaining.is_empty() {
            break;
        }
        
        // Parse name=value
        if let Some(eq_pos) = remaining.find('=') {
            let name = &remaining[..eq_pos];
            remaining = &remaining[eq_pos + 1..];
            
            // Parse value (may be quoted)
            let value: alloc::string::String;
            if remaining.starts_with('\'') {
                // Quoted value
                remaining = &remaining[1..];
                let mut value_bytes = alloc::vec::Vec::new();

                while !remaining.is_empty() {
                    if remaining.starts_with('\'') {
                        // Check for escaped quote
                        if remaining.starts_with("''") {
                            value_bytes.push(b'\'');
                            remaining = &remaining[2..];
                        } else {
                            remaining = &remaining[1..];
                            break;
                        }
                    } else {
                        value_bytes.push(remaining.as_bytes()[0]);
                        remaining = &remaining[1..];
                    }
                }

                value = alloc::string::String::from_utf8(value_bytes)
                    .map_err(|_| PlumbError::UnpackError)?;
            } else {
                // Unquoted value - ends at space or end
                let end = remaining.find(' ').unwrap_or(remaining.len());
                value = alloc::string::String::from_utf8(
                    remaining.as_bytes()[..end].to_vec()
                ).map_err(|_| PlumbError::UnpackError)?;
                remaining = &remaining[end..];
            }

            let attr = Box::new(Plumbattr::new(&name, &value));
            *current = Some(attr);
            if let Some(ref mut next) = *current {
                current = &mut next.next;
            }
        } else {
            // Malformed attribute, skip
            break;
        }
    }
    
    Ok(first)
}

/// Unpack a complete plumb message from wire format
pub fn plumbunpack(buf: &[u8]) -> Result<Plumbmsg, PlumbError> {
    let (msg, _) = plumbunpackpartial(buf, false)?;
    Ok(msg)
}

/// Unpack a plumb message, potentially partial
///
/// If `partial` is true, this will return as much of the message as possible
/// even if the data is incomplete. This is useful for streaming接收.
///
/// Returns `(message, bytes_consumed)` on success.
pub fn plumbunpackpartial(buf: &[u8], partial: bool) -> Result<(Plumbmsg, usize), PlumbError> {
    if buf.is_empty() {
        return Err(PlumbError::UnpackError);
    }
    
    let mut pos = 0;
    
    // Parse src
    let (src, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    
    // Parse dst
    let (dst, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    
    // Parse wdir
    let (wdir, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    let wdir = if wdir.is_empty() { None } else { Some(wdir.to_string()) };
    
    // Parse type
    let (mtype, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    
    // Parse attrs
    let (attrs_str, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    let attr = unpack_attr(attrs_str)?;
    
    // Parse ndata
    let (ndata_str, new_pos) = parse_line(buf, pos).ok_or(PlumbError::UnpackError)?;
    pos = new_pos;
    let ndata: usize = ndata_str
        .parse()
        .map_err(|_| PlumbError::UnpackError)?;
    
    // Get data
    if buf.len() < pos {
        return Err(PlumbError::UnpackError);
    }
    
    let data_available = buf.len() - pos;
    
    if data_available < ndata {
        if partial {
            // Return partial data
            let mut data = alloc::vec::Vec::new();
            data.extend_from_slice(&buf[pos..]);
            return Ok((
                Plumbmsg {
                    src: src.to_string(),
                    dst: dst.to_string(),
                    wdir,
                    mtype: mtype.to_string(),
                    attr,
                    ndata,
                    data,
                },
                buf.len(),
            ));
        } else {
            return Err(PlumbError::UnpackError);
        }
    }
    
    let data = buf[pos..pos + ndata].to_vec();
    let end_pos = pos + ndata;
    
    Ok((
        Plumbmsg {
            src: src.to_string(),
            dst: dst.to_string(),
            wdir,
            mtype: mtype.to_string(),
            attr,
            ndata,
            data,
        },
        end_pos,
    ))
}

/// Get the number of additional bytes needed to complete the message
pub fn plumbneedmore(buf: &[u8]) -> Option<usize> {
    if is_complete(buf) {
        return Some(0);
    }
    
    if let Some(offset) = get_data_offset(buf) {
        if let Some(size) = get_expected_size(buf) {
            if buf.len() >= offset {
                return Some(offset + size - buf.len());
            }
        }
    }
    
    // Not enough to determine, need more bytes
    None
}

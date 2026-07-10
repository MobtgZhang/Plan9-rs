//! Venti Protocol Message Types
//!
//! Venti uses a simple RPC protocol over TCP. Messages consist of:
//! - msgtype: 1 byte
//! - tag: 1 byte
//! - data: variable length depending on message type

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::VentiError;
use crate::score::Score;

/// Maximum data size for a single Venti message
pub const MAXDATA: usize = 1024 * 1024; // 1MB

/// Venti message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// Client hello
    Thello = 0,
    /// Server hello response
    Rhello = 1,
    /// Client read request
    Tread = 2,
    /// Server read response
    Rread = 3,
    /// Client write request
    Twrite = 4,
    /// Server write response
    Rwrite = 5,
    /// Client sync request
    Tsync = 6,
    /// Server sync response
    Rsync = 7,
    /// Client ping request
    Tping = 8,
    /// Server ping response
    Rping = 9,
    /// Client goodbye (close connection)
    Tgoodbye = 10,
    /// Server goodbye response
    Rgoodbye = 11,
    /// Error response
    Rerror = 127,
}

impl TryFrom<u8> for MsgType {
    type Error = VentiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MsgType::Thello),
            1 => Ok(MsgType::Rhello),
            2 => Ok(MsgType::Tread),
            3 => Ok(MsgType::Rread),
            4 => Ok(MsgType::Twrite),
            5 => Ok(MsgType::Rwrite),
            6 => Ok(MsgType::Tsync),
            7 => Ok(MsgType::Rsync),
            8 => Ok(MsgType::Tping),
            9 => Ok(MsgType::Rping),
            10 => Ok(MsgType::Tgoodbye),
            11 => Ok(MsgType::Rgoodbye),
            127 => Ok(MsgType::Rerror),
            _ => Err(VentiError::InvalidMessage),
        }
    }
}

impl MsgType {
    /// Check if this is a client (request) message type
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            MsgType::Thello
                | MsgType::Tread
                | MsgType::Twrite
                | MsgType::Tsync
                | MsgType::Tping
                | MsgType::Tgoodbye
        )
    }

    /// Get the corresponding response type for a request
    pub fn response(&self) -> Option<MsgType> {
        match self {
            MsgType::Thello => Some(MsgType::Rhello),
            MsgType::Tread => Some(MsgType::Rread),
            MsgType::Twrite => Some(MsgType::Rwrite),
            MsgType::Tsync => Some(MsgType::Rsync),
            MsgType::Tping => Some(MsgType::Rping),
            MsgType::Tgoodbye => Some(MsgType::Rgoodbye),
            _ => None,
        }
    }
}

/// Venti protocol message
#[derive(Debug, Clone)]
pub struct VtFcall {
    /// Message type
    pub msgtype: MsgType,
    /// Tag (0-255) for matching requests/responses
    pub tag: u8,
    /// Score (for read/write operations)
    pub score: Option<Score>,
    /// Block type (archival type)
    pub block_type: Option<u32>,
    /// Count (data size)
    pub count: Option<u32>,
    /// Data payload
    pub data: Option<alloc::vec::Vec<u8>>,
    /// Error message (for Rerror)
    pub error: Option<alloc::string::String>,
    /// Version string (for hello)
    pub version: Option<alloc::string::String>,
    /// Session ID (for hello)
    pub sid: Option<[u8; 16]>,
}

impl VtFcall {
    /// Create a new Thello (client hello) message
    pub fn hello_client(version: &str) -> Self {
        VtFcall {
            msgtype: MsgType::Thello,
            tag: 0, // No tag for initial hello
            score: None,
            block_type: None,
            count: None,
            data: None,
            error: None,
            version: Some(version.to_string()),
            sid: None,
        }
    }

    /// Create a new Tread (read) request
    pub fn read_request(tag: u8, score: Score, block_type: u32) -> Self {
        VtFcall {
            msgtype: MsgType::Tread,
            tag,
            score: Some(score),
            block_type: Some(block_type),
            count: None,
            data: None,
            error: None,
            version: None,
            sid: None,
        }
    }

    /// Create a new Twrite (write) request
    pub fn write_request(tag: u8, score: Score, block_type: u32, data: Vec<u8>) -> Self {
        VtFcall {
            msgtype: MsgType::Twrite,
            tag,
            score: Some(score),
            block_type: Some(block_type),
            count: Some(data.len() as u32),
            data: Some(data),
            error: None,
            version: None,
            sid: None,
        }
    }

    /// Create a new Tping request
    pub fn ping(tag: u8) -> Self {
        VtFcall {
            msgtype: MsgType::Tping,
            tag,
            score: None,
            block_type: None,
            count: None,
            data: None,
            error: None,
            version: None,
            sid: None,
        }
    }

    /// Create a new Tsync request
    pub fn sync(tag: u8) -> Self {
        VtFcall {
            msgtype: MsgType::Tsync,
            tag,
            score: None,
            block_type: None,
            count: None,
            data: None,
            error: None,
            version: None,
            sid: None,
        }
    }

    /// Create a new Tgoodbye request
    pub fn goodbye(tag: u8) -> Self {
        VtFcall {
            msgtype: MsgType::Tgoodbye,
            tag,
            score: None,
            block_type: None,
            count: None,
            data: None,
            error: None,
            version: None,
            sid: None,
        }
    }

    /// Pack the message into bytes for transmission
    pub fn pack(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();

        // Message type
        buf.push(self.msgtype as u8);
        // Tag
        buf.push(self.tag);

        match self.msgtype {
            MsgType::Thello => {
                // Version string
                if let Some(ref version) = self.version {
                    buf.extend_from_slice(version.as_bytes());
                }
                buf.push(0); // Null terminator
            }
            MsgType::Rhello => {
                // Version string
                if let Some(ref version) = self.version {
                    buf.extend_from_slice(version.as_bytes());
                    buf.push(0);
                } else {
                    buf.push(0);
                }
                // Session ID (16 bytes)
                if let Some(sid) = self.sid {
                    buf.extend_from_slice(&sid);
                } else {
                    buf.extend_from_slice(&[0u8; 16]);
                }
            }
            MsgType::Tread => {
                // Score (20 bytes)
                if let Some(ref score) = self.score {
                    buf.extend_from_slice(&score.0);
                } else {
                    buf.extend_from_slice(&[0u8; 20]);
                }
                // Block type (4 bytes, big-endian)
                let bt = self.block_type.unwrap_or(0);
                buf.extend_from_slice(&bt.to_be_bytes());
            }
            MsgType::Rread => {
                // Count (4 bytes, big-endian)
                let count = self.count.unwrap_or(0);
                buf.extend_from_slice(&count.to_be_bytes());
                // Data
                if let Some(ref data) = self.data {
                    buf.extend_from_slice(data);
                }
            }
            MsgType::Twrite => {
                // Score (20 bytes)
                if let Some(ref score) = self.score {
                    buf.extend_from_slice(&score.0);
                } else {
                    buf.extend_from_slice(&[0u8; 20]);
                }
                // Block type (4 bytes, big-endian)
                let bt = self.block_type.unwrap_or(0);
                buf.extend_from_slice(&bt.to_be_bytes());
                // Count (4 bytes, big-endian)
                let count = self.count.unwrap_or(0);
                buf.extend_from_slice(&count.to_be_bytes());
                // Data
                if let Some(ref data) = self.data {
                    buf.extend_from_slice(data);
                }
            }
            MsgType::Rwrite => {
                // Score (20 bytes) - the server returns the score it stored
                if let Some(ref score) = self.score {
                    buf.extend_from_slice(&score.0);
                } else {
                    buf.extend_from_slice(&[0u8; 20]);
                }
            }
            MsgType::Tsync | MsgType::Tping | MsgType::Tgoodbye => {
                // No additional data for these message types
            }
            MsgType::Rsync | MsgType::Rping | MsgType::Rgoodbye => {
                // No additional data for these response types
            }
            MsgType::Rerror => {
                // Error message
                if let Some(ref error) = self.error {
                    buf.extend_from_slice(error.as_bytes());
                }
                buf.push(0);
            }
        }

        buf
    }

    /// Unpack bytes into a VtFcall message
    pub fn unpack(buf: &[u8]) -> Result<(Self, usize), VentiError> {
        if buf.len() < 2 {
            return Err(VentiError::InvalidMessage);
        }

        let msgtype = MsgType::try_from(buf[0])?;
        let tag = buf[1];
        let mut pos = 2;

        let mut fcall = VtFcall {
            msgtype,
            tag,
            score: None,
            block_type: None,
            count: None,
            data: None,
            error: None,
            version: None,
            sid: None,
        };

        match msgtype {
            MsgType::Thello => {
                // Version string (null-terminated)
                if let Some(end) = buf[pos..].iter().position(|&b| b == 0) {
                    fcall.version = Some(
                        core::str::from_utf8(&buf[pos..pos + end])
                            .map_err(|_| VentiError::InvalidMessage)?
                            .to_string(),
                    );
                    pos += end + 1;
                }
            }
            MsgType::Rhello => {
                // Version string (null-terminated)
                if let Some(end) = buf[pos..].iter().position(|&b| b == 0) {
                    fcall.version = Some(
                        core::str::from_utf8(&buf[pos..pos + end])
                            .map_err(|_| VentiError::InvalidMessage)?
                            .to_string(),
                    );
                    pos += end + 1;
                } else {
                    pos += 1; // Skip null
                }
                // Session ID (16 bytes)
                if buf.len() >= pos + 16 {
                    let mut sid = [0u8; 16];
                    sid.copy_from_slice(&buf[pos..pos + 16]);
                    fcall.sid = Some(sid);
                    pos += 16;
                }
            }
            MsgType::Tread => {
                // Score (20 bytes)
                if buf.len() >= pos + 20 {
                    let mut score = [0u8; 20];
                    score.copy_from_slice(&buf[pos..pos + 20]);
                    fcall.score = Some(Score(score));
                    pos += 20;
                }
                // Block type (4 bytes, big-endian)
                if buf.len() >= pos + 4 {
                    fcall.block_type = Some(u32::from_be_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ]));
                    pos += 4;
                }
            }
            MsgType::Rread => {
                // Count (4 bytes, big-endian)
                if buf.len() >= pos + 4 {
                    fcall.count = Some(u32::from_be_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ]));
                    pos += 4;
                }
                // Data
                if let Some(count) = fcall.count {
                    if buf.len() >= pos + count as usize {
                        fcall.data = Some(buf[pos..pos + count as usize].to_vec());
                        pos += count as usize;
                    }
                }
            }
            MsgType::Twrite => {
                // Score (20 bytes)
                if buf.len() >= pos + 20 {
                    let mut score = [0u8; 20];
                    score.copy_from_slice(&buf[pos..pos + 20]);
                    fcall.score = Some(Score(score));
                    pos += 20;
                }
                // Block type (4 bytes, big-endian)
                if buf.len() >= pos + 4 {
                    fcall.block_type = Some(u32::from_be_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ]));
                    pos += 4;
                }
                // Count (4 bytes, big-endian)
                if buf.len() >= pos + 4 {
                    fcall.count = Some(u32::from_be_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ]));
                    pos += 4;
                }
                // Data
                if let Some(count) = fcall.count {
                    if buf.len() >= pos + count as usize {
                        fcall.data = Some(buf[pos..pos + count as usize].to_vec());
                        pos += count as usize;
                    }
                }
            }
            MsgType::Rwrite => {
                // Score (20 bytes)
                if buf.len() >= pos + 20 {
                    let mut score = [0u8; 20];
                    score.copy_from_slice(&buf[pos..pos + 20]);
                    fcall.score = Some(Score(score));
                    pos += 20;
                }
            }
            MsgType::Tsync | MsgType::Tping | MsgType::Tgoodbye => {
                // No additional data
            }
            MsgType::Rsync | MsgType::Rping | MsgType::Rgoodbye => {
                // No additional data
            }
            MsgType::Rerror => {
                // Error message (null-terminated)
                if let Some(end) = buf[pos..].iter().position(|&b| b == 0) {
                    fcall.error = Some(
                        core::str::from_utf8(&buf[pos..pos + end])
                            .map_err(|_| VentiError::InvalidMessage)?
                            .to_string(),
                    );
                    pos += end + 1;
                }
            }
        }

        Ok((fcall, pos))
    }
}

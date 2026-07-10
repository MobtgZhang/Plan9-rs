//! Authentication Header (AH)
//!
//! Implements AH protocol for IPsec.

use alloc::vec;
use alloc::vec::Vec;

/// AH header
#[derive(Debug, Clone)]
pub struct AhHeader {
    /// Next header
    pub next_header: u8,
    /// Payload length (in 32-bit words minus 2)
    pub payload_len: u8,
    /// Reserved
    pub reserved: u16,
    /// Security Parameters Index
    pub spi: u32,
    /// Sequence number
    pub seq: u32,
}

/// ICV (Integrity Check Value)
pub type AhIcv = Vec<u8>;

/// AH packet
#[derive(Debug, Clone)]
pub struct AhPacket {
    /// AH header
    pub header: AhHeader,
    /// Integrity Check Value (ICV)
    pub icv: Vec<u8>,
}

impl AhPacket {
    /// Parse AH header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        
        let next_header = data[0];
        let payload_len = data[1];
        let reserved = u16::from_be_bytes([data[2], data[3]]);
        let spi = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        
        Some(Self {
            header: AhHeader {
                next_header,
                payload_len,
                reserved,
                spi,
                seq,
            },
            icv: data[12..].to_vec(),
        })
    }

    /// Serialize AH header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.icv.len());
        buf.push(self.header.next_header);
        buf.push(self.header.payload_len);
        buf.extend_from_slice(&self.header.reserved.to_be_bytes());
        buf.extend_from_slice(&self.header.spi.to_be_bytes());
        buf.extend_from_slice(&self.header.seq.to_be_bytes());
        buf.extend_from_slice(&self.icv);
        buf
    }
}

/// AH protocol constants
pub mod protocol {
    /// AH protocol number
    pub const IPPROTO_AH: u8 = 51;
    
    /// ICV sizes for different algorithms
    pub const ICV_MD5_96: usize = 12;
    pub const ICV_SHA1_96: usize = 12;
    pub const ICV_SHA256_128: usize = 16;
    pub const ICV_SHA512_256: usize = 32;
}

/// AH authentication
pub mod auth {
    use super::*;
    
    /// Calculate HMAC-SHA1-96 ICV for AH
    pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
        // Simplified: return 12 zero bytes
        // Real implementation would compute HMAC-SHA1 and truncate to 96 bits
        let _ = key;
        let _ = data;
        vec![0u8; protocol::ICV_SHA1_96]
    }

    /// Verify ICV
    pub fn verify(key: &[u8], data: &[u8], icv: &[u8]) -> bool {
        let calc = hmac_sha1_96(key, data);
        calc == icv
    }
}

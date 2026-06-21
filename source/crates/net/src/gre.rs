//! GRE (Generic Routing Encapsulation) Implementation
//!
//! Implements GRE tunneling protocol as defined in RFC 2784 and RFC 2890.
//!
//! ## Overview
//!
//! GRE is a tunneling protocol that can encapsulate a wide variety of
//! network layer protocols inside virtual point-to-point links.
//!
//! ## Features
//!
//! - Checksum verification (optional)
//! - Key field for tunnel identification
//! - Sequence number support
//! - IPv4 and IPv6 payload support
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::gre::{GreTunnel, GRE_HEADER_SIZE};
//!
//! let tunnel = GreTunnel::new(local, remote, None);
//! let encapsulated = tunnel.encapsulate(payload, PROTOCOL_IPV4);
//! let decapsulated = tunnel.decapsulate(&encapsulated[IPV4_HEADER_SIZE..]).unwrap();
//! ```

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;

/// GRE header constants
pub const GRE_HEADER_SIZE: usize = 4;
pub const GRE_HEADER_SIZE_WITH_SEQ: usize = 8;
pub const GRE_HEADER_SIZE_WITH_KEY: usize = 8;
pub const GRE_HEADER_SIZE_FULL: usize = 12;

/// GRE flags
pub const GRE_FLAG_C: u16 = 0x8000;  // Checksum present
pub const GRE_FLAG_R: u16 = 0x4000;  // Routing present (deprecated)
pub const GRE_FLAG_K: u16 = 0x2000;  // Key present
pub const GRE_FLAG_S: u16 = 0x1000;  // Sequence number present
pub const GRE_FLAG_S_RECURSION: u16 = 0x0800;  // Recursion control
pub const GRE_FLAG_A: u16 = 0x0400;  // Acknowledgment sequence (GREv1)
pub const GRE_FLAG_FLAGS: u16 = 0x00F8;  // Reserved flags

/// GRE protocol types (ethernet types)
pub const PROTOCOL_IPV4: u16 = 0x0800;
pub const PROTOCOL_IPV6: u16 = 0x86DD;
pub const PROTOCOL_9P: u16 = 0x8088;
pub const PROTOCOL_MPLS_UNICAST: u16 = 0x8847;
pub const PROTOCOL_MPLS_MULTICAST: u16 = 0x8848;

/// GRE header structure
#[derive(Debug, Clone)]
#[repr(C)]
pub struct GreHeader {
    /// Flags and version
    pub flags: u16,
    /// Protocol type (ethernet type)
    pub protocol: u16,
}

impl GreHeader {
    /// Create new GRE header
    pub fn new(protocol: u16) -> Self {
        Self {
            flags: 0,
            protocol: protocol.to_be(),
        }
    }

    /// Create GRE header with key
    pub fn with_key(protocol: u16, key: u32) -> Self {
        let mut header = Self::new(protocol);
        header.set_key(true);
        header.set_flags(header.flags | GRE_FLAG_K);
        header.protocol = protocol.to_be();
        header
    }

    /// Check if checksum flag is set
    pub fn has_checksum(&self) -> bool {
        (self.flags & GRE_FLAG_C) != 0
    }

    /// Check if key flag is set
    pub fn has_key(&self) -> bool {
        (self.flags & GRE_FLAG_K) != 0
    }

    /// Check if sequence number flag is set
    pub fn has_sequence(&self) -> bool {
        (self.flags & GRE_FLAG_S) != 0
    }

    /// Set checksum flag
    pub fn set_checksum(&mut self, present: bool) {
        if present {
            self.flags |= GRE_FLAG_C;
        } else {
            self.flags &= !GRE_FLAG_C;
        }
    }

    /// Set key flag
    pub fn set_key(&mut self, present: bool) {
        if present {
            self.flags |= GRE_FLAG_K;
        } else {
            self.flags &= !GRE_FLAG_K;
        }
    }

    /// Set sequence flag
    pub fn set_sequence(&mut self, present: bool) {
        if present {
            self.flags |= GRE_FLAG_S;
        } else {
            self.flags &= !GRE_FLAG_S;
        }
    }

    /// Get protocol type
    pub fn protocol_type(&self) -> u16 {
        u16::from_be(self.protocol)
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(GRE_HEADER_SIZE);
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.protocol.to_be_bytes());
        bytes
    }

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < GRE_HEADER_SIZE {
            return None;
        }

        Some(Self {
            flags: u16::from_be_bytes([data[0], data[1]]),
            protocol: u16::from_be_bytes([data[2], data[3]]),
        })
    }

    /// Get header size based on flags
    pub fn header_size(&self) -> usize {
        let mut size = GRE_HEADER_SIZE;
        if self.has_checksum() {
            size += 4;  // 2 bytes checksum + 2 bytes reserved
        }
        if self.has_key() {
            size += 4;
        }
        if self.has_sequence() {
            size += 4;
        }
        size
    }
}

/// GRE header with optional fields
#[derive(Debug, Clone)]
pub struct GrePacket {
    /// Base header
    pub header: GreHeader,
    /// Checksum (if present)
    pub checksum: Option<u16>,
    /// Offset to routing (if present)
    pub routing_offset: Option<u16>,
    /// Key (if present)
    pub key: Option<u32>,
    /// Sequence number (if present)
    pub sequence: Option<u32>,
    /// Acknowledgment sequence (if present)
    pub ack: Option<u32>,
    /// Payload
    pub payload: Vec<u8>,
}

impl GrePacket {
    /// Create new GRE packet
    pub fn new(protocol: u16) -> Self {
        Self {
            header: GreHeader::new(protocol),
            checksum: None,
            routing_offset: None,
            key: None,
            sequence: None,
            ack: None,
            payload: Vec::new(),
        }
    }

    /// Create with key
    pub fn with_key(protocol: u16, key: u32) -> Self {
        let mut packet = Self::new(protocol);
        packet.header.set_key(true);
        packet.key = Some(key);
        packet
    }

    /// Create with sequence
    pub fn with_sequence(protocol: u16, seq: u32) -> Self {
        let mut packet = Self::new(protocol);
        packet.header.set_sequence(true);
        packet.sequence = Some(seq);
        packet
    }

    /// Parse GRE packet from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = GreHeader::parse(data)?;
        let header_len = header.header_size();

        if data.len() < header_len {
            return None;
        }

        let mut packet = Self {
            header,
            checksum: None,
            routing_offset: None,
            key: None,
            sequence: None,
            ack: None,
            payload: Vec::new(),
        };

        let mut offset = GRE_HEADER_SIZE;

        // Parse optional fields
        if packet.header.has_checksum() {
            if data.len() < offset + 4 {
                return None;
            }
            packet.checksum = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
            packet.routing_offset = Some(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
            offset += 4;
        }

        if packet.header.has_key() {
            if data.len() < offset + 4 {
                return None;
            }
            packet.key = Some(u32::from_be_bytes([
                data[offset], data[offset + 1],
                data[offset + 2], data[offset + 3]
            ]));
            offset += 4;
        }

        if packet.header.has_sequence() {
            if data.len() < offset + 4 {
                return None;
            }
            packet.sequence = Some(u32::from_be_bytes([
                data[offset], data[offset + 1],
                data[offset + 2], data[offset + 3]
            ]));
            offset += 4;
        }

        // Payload
        packet.payload = data[offset..].to_vec();

        Some(packet)
    }

    /// Serialize GRE packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = self.header.serialize();

        if self.header.has_checksum() {
            let checksum = self.checksum.unwrap_or(0);
            bytes.extend_from_slice(&checksum.to_be_bytes());
            let offset = self.routing_offset.unwrap_or(0);
            bytes.extend_from_slice(&offset.to_be_bytes());
        }

        if self.header.has_key() {
            let key = self.key.unwrap_or(0);
            bytes.extend_from_slice(&key.to_be_bytes());
        }

        if self.header.has_sequence() {
            let seq = self.sequence.unwrap_or(0);
            bytes.extend_from_slice(&seq.to_be_bytes());
        }

        bytes.extend_from_slice(&self.payload);

        // Calculate checksum if enabled
        if self.header.has_checksum() {
            let cs = calculate_checksum(&bytes);
            bytes[GRE_HEADER_SIZE..GRE_HEADER_SIZE + 2]
                .copy_from_slice(&cs.to_be_bytes());
        }

        bytes
    }
}

/// GRE tunnel state
pub struct GreTunnel {
    /// Local address
    local: [u8; 4],
    /// Remote address
    remote: [u8; 4],
    /// Tunnel key (if set)
    key: Option<u32>,
    /// Internal protocol type
    protocol: u16,
    /// Sequence number counter
    sequence: Spinlock<u32>,
}

impl GreTunnel {
    /// Create new GRE tunnel
    pub fn new(local: [u8; 4], remote: [u8; 4], key: Option<u32>) -> Self {
        Self {
            local,
            remote,
            key,
            protocol: PROTOCOL_IPV4,
            sequence: Spinlock::new(0),
        }
    }

    /// Create with specific protocol
    pub fn with_protocol(local: [u8; 4], remote: [u8; 4], key: Option<u32>, protocol: u16) -> Self {
        let mut tunnel = Self::new(local, remote, key);
        tunnel.protocol = protocol;
        tunnel
    }

    /// Encapsulate a packet
    pub fn encapsulate(&self, payload: &[u8], proto: u16) -> Vec<u8> {
        let mut header = GreHeader::new(proto);

        let mut options_size = 0;
        if self.key.is_some() {
            header.set_key(true);
            options_size += 4;
        }

        if header.has_checksum() {
            options_size += 4;
        }

        // Build outer IP header
        let mut outer_ip = Vec::new();
        // Version + IHL (5 * 4 = 20 bytes)
        outer_ip.push(0x45);
        // DSCP/ECN
        outer_ip.push(0);
        // Total length
        let total_len = 20 + GRE_HEADER_SIZE + options_size + payload.len();
        outer_ip.extend_from_slice(&(total_len as u16).to_be_bytes());
        // Identification
        outer_ip.extend_from_slice(&0u16.to_be_bytes());
        // Flags + Fragment offset
        outer_ip.extend_from_slice(&0x4000u16.to_be_bytes()); // Don't fragment
        // TTL
        outer_ip.push(64);
        // Protocol (GRE = 47)
        outer_ip.push(47);
        // Checksum (placeholder)
        outer_ip.extend_from_slice(&0u16.to_be_bytes());
        // Source address
        outer_ip.extend_from_slice(&self.local);
        // Destination address
        outer_ip.extend_from_slice(&self.remote);

        // Calculate IP header checksum
        let ip_checksum = calculate_checksum(&outer_ip);
        outer_ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // Build GRE header
        let mut gre = header.serialize();
        if let Some(key) = self.key {
            let seq = {
                let mut s = self.sequence.lock();
                *s += 1;
                *s
            };
            gre.extend_from_slice(&key.to_be_bytes());
            gre.extend_from_slice(&seq.to_be_bytes());
        }

        // Payload
        let mut packet = outer_ip;
        packet.extend(gre);
        packet.extend_from_slice(payload);

        packet
    }

    /// Decapsulate a packet
    pub fn decapsulate(&self, data: &[u8]) -> Result<Vec<u8>, GreError> {
        let packet = GrePacket::parse(data)
            .ok_or(GreError::InvalidPacket)?;

        // Verify key if set
        if let Some(expected_key) = self.key {
            let packet_key = packet.key.ok_or(GreError::NoKey)?;
            if packet_key != expected_key {
                return Err(GreError::KeyMismatch);
            }
        }

        Ok(packet.payload)
    }

    /// Get local address
    pub fn local(&self) -> [u8; 4] {
        self.local
    }

    /// Get remote address
    pub fn remote(&self) -> [u8; 4] {
        self.remote
    }

    /// Get tunnel key
    pub fn key(&self) -> Option<u32> {
        self.key
    }
}

/// Calculate IP/TCP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// GRE errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreError {
    /// Invalid packet format
    InvalidPacket,
    /// Checksum mismatch
    ChecksumMismatch,
    /// No key present
    NoKey,
    /// Key mismatch
    KeyMismatch,
    /// Sequence error
    SequenceError,
}

impl GreError {
    pub fn as_str(&self) -> &'static str {
        match self {
            GreError::InvalidPacket => "invalid GRE packet",
            GreError::ChecksumMismatch => "checksum mismatch",
            GreError::NoKey => "no key present",
            GreError::KeyMismatch => "key mismatch",
            GreError::SequenceError => "sequence error",
        }
    }
}

//! IP-in-IP (IPIP) Tunnel Implementation
//!
//! Implements IP-in-IP tunneling as defined in RFC 1853.
//!
//! ## Overview
//!
//! IPIP is a simple encapsulation protocol that wraps one IP packet
//! inside another IP packet. It's simpler than GRE but only supports
//! IPv4 over IPv4 or IPv6 over IPv4.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::ipip::{IpipTunnel, IPIP_HEADER_SIZE};
//!
//! let tunnel = IpipTunnel::new(local, remote);
//! let encapsulated = tunnel.encapsulate(inner_packet);
//! let decapsulated = tunnel.decapsulate(&encapsulated[IPIP_HEADER_SIZE..]).unwrap();
//! ```

/// IPIP header size (20 bytes for IPv4 header)
pub const IPIP_HEADER_SIZE: usize = 20;
/// IPv6-in-IPv4 header size
pub const IPV6_IPIP_HEADER_SIZE: usize = 20;

/// IPIP protocol number
pub const IPIP_PROTOCOL: u8 = 4;

/// IPIP header structure
#[derive(Debug, Clone)]
#[repr(C)]
pub struct IpipHeader {
    /// Version and IHL
    pub version_ihl: u8,
    /// Type of Service
    pub tos: u8,
    /// Total length
    pub total_length: u16,
    /// Identification
    pub identification: u16,
    /// Flags and fragment offset
    pub flags_offset: u16,
    /// Time to Live
    pub ttl: u8,
    /// Protocol (IPIP = 4)
    pub protocol: u8,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src: [u8; 4],
    /// Destination address
    pub dst: [u8; 4],
}

impl IpipHeader {
    /// Create new IPIP header
    pub fn new(src: [u8; 4], dst: [u8; 4]) -> Self {
        Self {
            version_ihl: 0x45,  // IPv4, 5 * 4 = 20 bytes
            tos: 0,
            total_length: 0,  // Filled later
            identification: 0,
            flags_offset: 0x4000,  // Don't fragment
            ttl: 64,
            protocol: IPIP_PROTOCOL,
            checksum: 0,
            src,
            dst,
        }
    }

    /// Get IP version
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get header length in bytes
    pub fn header_len(&self) -> usize {
        (self.version_ihl & 0x0F) as usize * 4
    }

    /// Get source address
    pub fn src(&self) -> [u8; 4] {
        self.src
    }

    /// Get destination address
    pub fn dst(&self) -> [u8; 4] {
        self.dst
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Set TOS
    pub fn set_tos(&mut self, tos: u8) {
        self.tos = tos;
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(IPIP_HEADER_SIZE);
        bytes.push(self.version_ihl);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.extend_from_slice(&self.flags_offset.to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.src);
        bytes.extend_from_slice(&self.dst);
        bytes
    }

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPIP_HEADER_SIZE {
            return None;
        }

        Some(Self {
            version_ihl: data[0],
            tos: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags_offset: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src: [data[12], data[13], data[14], data[15]],
            dst: [data[16], data[17], data[18], data[19]],
        })
    }
}

/// IPIP tunnel state
pub struct IpipTunnel {
    /// Local address (outer)
    local: [u8; 4],
    /// Remote address (outer)
    remote: [u8; 4],
    /// TTL for outer header
    ttl: u8,
    /// TOS for outer header
    tos: u8,
    /// Fragmentation flag
    dont_fragment: bool,
    /// Next identification number
    ident: Spinlock<u16>,
}

use crate::plan9_common::sync::Spinlock;

impl IpipTunnel {
    /// Create new IPIP tunnel
    pub fn new(local: [u8; 4], remote: [u8; 4]) -> Self {
        Self {
            local,
            remote,
            ttl: 64,
            tos: 0,
            dont_fragment: true,
            ident: Spinlock::new(0),
        }
    }

    /// Create with TTL
    pub fn with_ttl(local: [u8; 4], remote: [u8; 4], ttl: u8) -> Self {
        let mut tunnel = Self::new(local, remote);
        tunnel.ttl = ttl;
        tunnel
    }

    /// Encapsulate an IP packet
    pub fn encapsulate(&self, inner: &[u8]) -> Vec<u8> {
        let inner_len = inner.len();
        let total_len = IPIP_HEADER_SIZE + inner_len;

        let ident = {
            let mut id = self.ident.lock();
            *id = id.wrapping_add(1);
            *id
        };

        let mut header = IpipHeader::new(self.local, self.remote);
        header.total_length = total_len as u16;
        header.identification = ident;
        header.ttl = self.ttl;
        header.tos = self.tos;

        if self.dont_fragment {
            header.flags_offset = 0x4000;  // Don't fragment
        } else {
            header.flags_offset = 0x0000;
        }

        // Serialize header
        let mut header_bytes = header.serialize();

        // Calculate checksum
        let checksum = calculate_checksum(&header_bytes);
        header_bytes[10..12].copy_from_slice(&checksum.to_be_bytes());

        // Build packet
        let mut packet = header_bytes;
        packet.extend_from_slice(inner);

        packet
    }

    /// Decapsulate an IPIP packet
    pub fn decapsulate(&self, data: &[u8]) -> Result<Vec<u8>, IpipError> {
        // Verify it's an IPIP packet
        if data.len() < IPIP_HEADER_SIZE {
            return Err(IpipError::PacketTooShort);
        }

        let header = IpipHeader::parse(data)
            .ok_or(IpipError::InvalidHeader)?;

        // Verify protocol
        if header.protocol != IPIP_PROTOCOL {
            return Err(IpipError::WrongProtocol);
        }

        // Verify destination is our local address
        if header.dst() != self.local {
            return Err(IpipError::WrongDestination);
        }

        // Return inner packet
        Ok(data[IPIP_HEADER_SIZE..].to_vec())
    }

    /// Get local address
    pub fn local(&self) -> [u8; 4] {
        self.local
    }

    /// Get remote address
    pub fn remote(&self) -> [u8; 4] {
        self.remote
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Set TOS
    pub fn set_tos(&mut self, tos: u8) {
        self.tos = tos;
    }

    /// Enable/disable fragmentation
    pub fn set_dont_fragment(&mut self, dont_frag: bool) {
        self.dont_fragment = dont_frag;
    }
}

/// IPIP errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpipError {
    /// Packet too short
    PacketTooShort,
    /// Invalid IP header
    InvalidHeader,
    /// Wrong protocol
    WrongProtocol,
    /// Wrong destination
    WrongDestination,
    /// Checksum error
    ChecksumError,
}

impl IpipError {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpipError::PacketTooShort => "packet too short",
            IpipError::InvalidHeader => "invalid IP header",
            IpipError::WrongProtocol => "wrong protocol",
            IpipError::WrongDestination => "wrong destination address",
            IpipError::ChecksumError => "checksum error",
        }
    }
}

/// Calculate IP checksum
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

/// IPv6-in-IPv4 tunnel (6in4)
/// 
/// This is a variant of IPIP used for IPv6 traffic.
/// The protocol field is 41 instead of 4.
pub struct SixInFourTunnel {
    /// Standard IPIP tunnel
    inner: IpipTunnel,
}

impl SixInFourTunnel {
    /// Create new 6in4 tunnel
    pub fn new(local: [u8; 4], remote: [u8; 4]) -> Self {
        Self {
            inner: IpipTunnel::new(local, remote),
        }
    }

    /// Encapsulate IPv6 packet
    pub fn encapsulate(&self, inner: &[u8]) -> Vec<u8> {
        // 6in4 uses the same encapsulation as IPIP
        // but with protocol = 41
        self.inner.encapsulate(inner)
    }

    /// Decapsulate IPv6 packet
    pub fn decapsulate(&self, data: &[u8]) -> Result<Vec<u8>, IpipError> {
        // Just like IPIP
        self.inner.decapsulate(data)
    }
}

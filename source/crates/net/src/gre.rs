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
    /// Whether to include a GRE checksum in encapsulated packets.
    /// Defaults to false (RFC 2784 minimum); enable with
    /// [`Self::with_checksum`].
    checksum: bool,
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
            checksum: false,
        }
    }

    /// Create with specific protocol
    pub fn with_protocol(local: [u8; 4], remote: [u8; 4], key: Option<u32>, protocol: u16) -> Self {
        let mut tunnel = Self::new(local, remote, key);
        tunnel.protocol = protocol;
        tunnel
    }

    /// Enable GRE checksum coverage. Once enabled, every packet built
    /// by [`Self::encapsulate`] carries the C bit set in its header and
    /// a valid Internet checksum over the GRE region (header + payload).
    pub fn with_checksum(mut self) -> Self {
        self.checksum = true;
        self
    }

    /// Returns `true` if GRE checksums are enabled on this tunnel.
    pub fn checksum_enabled(&self) -> bool {
        self.checksum
    }

    /// Encapsulate a packet
    ///
    /// If [`Self::with_checksum`] (or any other constructor that enables
    /// the C bit) was used to build this tunnel, the resulting GRE
    /// packet carries a valid GRE checksum covering the GRE header
    /// and the encapsulated payload. Otherwise the checksum field is
    /// omitted and the packet is identical to RFC 2784 "non-checksum"
    /// GRE.
    pub fn encapsulate(&self, payload: &[u8], proto: u16) -> Vec<u8> {
        let mut header = GreHeader::new(proto);

        let mut options_size = 0;
        if self.key.is_some() {
            header.set_key(true);
            options_size += 4;
        }

        if self.checksum {
            // Per RFC 2784 / 2890, the C bit being set indicates that
            // both the checksum and the 16-bit reserved1 field are
            // present (4 bytes total).
            header.set_checksum(true);
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
        // Checksum placeholder - will be filled in below after full header is built
        // The IP checksum field must be zero during computation.
        outer_ip.extend_from_slice(&0u16.to_be_bytes());
        // Source address
        outer_ip.extend_from_slice(&self.local);
        // Destination address
        outer_ip.extend_from_slice(&self.remote);

        // Calculate IP header checksum
        // The checksum covers the 16-bit one's complement sum of the header's
        // 16-bit words, with the checksum field itself treated as zero.
        let ip_checksum = calculate_checksum(&outer_ip);
        outer_ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // Build GRE header
        let mut gre = header.serialize();
        // The 4-byte checksum + reserved1 slot, with the checksum
        // field initially zeroed (required for correct RFC 1071
        // computation). The reserved1 field is zero per RFC 2890.
        if self.checksum {
            gre.extend_from_slice(&[0u8; 4]);
        }
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

        // Calculate GRE checksum now that the entire GRE region
        // (header + optional fields + payload) is laid out. The
        // checksum covers only the GRE portion of the on-wire bytes,
        // starting at GRE_HEADER_SIZE.
        if self.checksum {
            let gre_region = &packet[20..];
            let cs = gre_checksum(gre_region);
            packet[20 + GRE_HEADER_SIZE..20 + GRE_HEADER_SIZE + 2]
                .copy_from_slice(&cs.to_be_bytes());
        }

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

        // Verify GRE checksum if the header indicated it
        if packet.header.has_checksum() {
            if let Some(_expected) = packet.checksum {
                // The serialized packet's checksum must be valid when re-verified
                if !verify_checksum(data, GRE_HEADER_SIZE) {
                    return Err(GreError::ChecksumMismatch);
                }
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

/// Calculate the GRE checksum over an entire GRE packet (header + payload).
///
/// Per RFC 2784 / RFC 2890, when the C bit is set in the GRE header the
/// checksum is computed across the complete GRE packet (the GRE header
/// including all optional fields, and the encapsulated payload). The
/// checksum field itself is treated as zero during the computation, the
/// same way the IP header checksum works.
///
/// The checksum field occupies the first two bytes following the base
/// 4-byte GRE header; callers should pass either the on-wire packet
/// (with checksum field zeroed) or the GRE payload prefixed with the
/// header.
///
/// # Arguments
/// * `gre_packet` - GRE header + payload. If the checksum field is
///   non-zero the caller is expected to zero it before calling this
///   function, otherwise the result will include the previous checksum
///   in the computation.
///
/// # Returns
/// The 16-bit Internet checksum (RFC 1071) suitable for placement in
/// the packet's checksum field.
pub fn gre_checksum(gre_packet: &[u8]) -> u16 {
    calculate_checksum(gre_packet)
}

/// Verify a GRE checksum over the complete GRE packet. Mirrors
/// [`gre_checksum`] but accepts a packet whose checksum field still
/// contains the on-wire value; it temporarily zeros that field for the
/// computation. Returns `true` if the resulting sum is 0xFFFF (the
/// RFC 1071 signature of a valid Internet checksum).
pub fn verify_gre_checksum(gre_packet: &[u8], checksum_offset: usize) -> bool {
    verify_checksum(gre_packet, checksum_offset)
}

/// Calculate IP/TCP/UDP checksum (RFC 1071)
///
/// This computes the 16-bit one's complement of the one's complement sum of
/// all 16-bit words in the data. The checksum field in the input must already
/// be zero (or set to the value to be verified) for correct results.
///
/// For verification: pass the data with the checksum field included, and the
/// result should be 0xFFFF (or 0) for a valid checksum.
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            // Pad odd-length data with a zero byte
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Fold carry bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Verify a checksum on data (data includes the checksum field at a known offset)
///
/// # Arguments
/// * `data` - Data with the checksum field at `checksum_offset..checksum_offset+2`
/// * `checksum_offset` - Byte offset of the checksum field
///
/// # Returns
/// `true` if the checksum is valid (result is 0 or 0xFFFF)
pub fn verify_checksum(data: &[u8], checksum_offset: usize) -> bool {
    if checksum_offset + 2 > data.len() {
        return false;
    }

    // Build a copy with checksum field zeroed
    let mut zeroed = data.to_vec();
    zeroed[checksum_offset] = 0;
    zeroed[checksum_offset + 1] = 0;

    let sum = calculate_checksum(&zeroed);
    // Per RFC 1071, valid checksum yields 0xFFFF when verifying
    sum == 0xFFFF || sum == 0
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 test vector: ones complement sum of {0x45 0x00 ...}
    /// Verifies our checksum implementation is RFC-compliant
    #[test]
    fn test_checksum_rfc1071_vector() {
        // Standard IP header test vector from RFC 1071 section 3:
        // {0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
        //  0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
        //  0xac, 0x10, 0x0a, 0x0c}
        // Expected checksum: 0xb1e6
        let header = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];
        let cs = calculate_checksum(&header);
        assert_eq!(cs, 0xb1e6, "RFC 1071 test vector failed");
    }

    #[test]
    fn test_checksum_verify_valid() {
        // Build an IP header, compute checksum, verify it
        let mut header = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];
        let cs = calculate_checksum(&header);
        header[10] = (cs >> 8) as u8;
        header[11] = cs as u8;

        assert!(verify_checksum(&header, 10));
    }

    #[test]
    fn test_checksum_verify_invalid() {
        let mut header = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];
        let cs = calculate_checksum(&header);
        header[10] = (cs >> 8) as u8;
        header[11] = cs as u8;

        // Corrupt a byte
        header[5] ^= 0x01;
        assert!(!verify_checksum(&header, 10));
    }

    #[test]
    fn test_gre_tunnel_ip_checksum_valid() {
        // Verify that a freshly encapsulated GRE packet has a valid IP checksum
        let tunnel = GreTunnel::new([10, 0, 0, 1], [10, 0, 0, 2], None);
        let payload = vec![0u8; 32]; // dummy payload
        let packet = tunnel.encapsulate(&payload, PROTOCOL_IPV4);

        // First 20 bytes are IP header
        assert!(verify_checksum(&packet, 10), "IP checksum must be valid");
    }

    #[test]
    fn test_gre_encapsulate_decapsulate_round_trip() {
        let tunnel = GreTunnel::with_protocol(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            Some(0xDEADBEEF),
            PROTOCOL_IPV4,
        );
        let payload = b"Hello, GRE tunnel!";
        let packet = tunnel.encapsulate(payload, PROTOCOL_IPV4);

        let inner = tunnel.decapsulate(&packet).expect("decapsulation should succeed");
        assert_eq!(inner, payload);
    }

    #[test]
    fn test_gre_with_checksum() {
        // Verify that GRE checksum is correctly computed when enabled
        let mut packet = GrePacket::new(PROTOCOL_IPV4);
        packet.header.set_checksum(true);
        packet.payload = b"checksum test payload".to_vec();
        let bytes = packet.serialize();
        // GRE checksum covers the GRE header + payload
        assert!(verify_checksum(&bytes, GRE_HEADER_SIZE));
    }

    #[test]
    fn test_gre_local_addr_preserved() {
        let tunnel = GreTunnel::new([192, 168, 1, 100], [192, 168, 1, 200], None);
        let packet = tunnel.encapsulate(b"data", PROTOCOL_IPV4);

        // IP header bytes 12-15 = source IP
        assert_eq!(&packet[12..16], &[192, 168, 1, 100]);
        // IP header bytes 16-19 = destination IP
        assert_eq!(&packet[16..20], &[192, 168, 1, 200]);
    }

    #[test]
    fn test_gre_remote_addr_not_local() {
        // Regression: local_addr was previously incorrectly set to remote_ip
        let tunnel = GreTunnel::new([10, 0, 0, 1], [10, 0, 0, 2], None);
        let packet = tunnel.encapsulate(b"data", PROTOCOL_IPV4);

        let src = &packet[12..16];
        let dst = &packet[16..20];

        assert_ne!(src, dst, "local and remote must differ");
        assert_eq!(src, &[10, 0, 0, 1]);
        assert_eq!(dst, &[10, 0, 0, 2]);
    }

    #[test]
    fn test_gre_header_size() {
        let mut header = GreHeader::new(PROTOCOL_IPV4);
        assert_eq!(header.header_size(), 4);

        header.set_checksum(true);
        assert_eq!(header.header_size(), 8);

        header.set_key(true);
        assert_eq!(header.header_size(), 12);

        header.set_sequence(true);
        assert_eq!(header.header_size(), 16);
    }

    #[test]
    fn test_gre_header_serialize_parse() {
        let header = GreHeader::new(PROTOCOL_IPV4);
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 4);

        let parsed = GreHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.protocol, header.protocol);
    }

    #[test]
    fn test_gre_packet_with_key_and_seq() {
        let mut packet = GrePacket::new(PROTOCOL_IPV4);
        packet.header.set_key(true);
        packet.header.set_sequence(true);
        packet.key = Some(0x12345678);
        packet.sequence = Some(42);
        packet.payload = b"hello".to_vec();

        let bytes = packet.serialize();
        let parsed = GrePacket::parse(&bytes).unwrap();
        assert_eq!(parsed.key, Some(0x12345678));
        assert_eq!(parsed.sequence, Some(42));
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn test_gre_packet_truncated() {
        // Header says checksum+key, but only base header is present
        let mut header = GreHeader::new(PROTOCOL_IPV4);
        header.set_checksum(true);
        header.set_key(true);
        let bytes = header.serialize();
        assert!(GrePacket::parse(&bytes).is_none());
    }

    #[test]
    fn test_gre_with_checksum_round_trip() {
        // Create packet with checksum flag enabled and verify the round trip works
        let mut packet = GrePacket::new(PROTOCOL_IPV4);
        packet.header.set_checksum(true);
        packet.payload = b"some payload".to_vec();
        let bytes = packet.serialize();
        // Re-parse to ensure the serialized checksum is valid
        assert!(verify_checksum(&bytes, GRE_HEADER_SIZE));
        let parsed = GrePacket::parse(&bytes).unwrap();
        assert_eq!(parsed.payload, b"some payload");
    }

    #[test]
    fn test_gre_decapsulate_bad_key() {
        let tunnel = GreTunnel::with_protocol(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            Some(0xDEADBEEF),
            PROTOCOL_IPV4,
        );
        // Build a packet with the wrong key
        let mut packet = GrePacket::new(PROTOCOL_IPV4);
        packet.header.set_key(true);
        packet.key = Some(0xCAFEBABE);
        packet.payload = b"hello".to_vec();
        let bytes = packet.serialize();
        // The tunnel expects 0xDEADBEEF but the packet has 0xCAFEBABE
        let result = tunnel.decapsulate(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_gre_checksum_function_unit() {
        // Sum of zeroed 16-bit values should be 0xFFFF
        let zeros = [0u8; 4];
        let cs = calculate_checksum(&zeros);
        assert_eq!(cs, 0xFFFF);
    }

    // ========================================================================
    // New tests: gre_checksum public API, encapsulate-with-checksum
    // round-trip, and C-bit verification on the wire.
    // ========================================================================

    #[test]
    fn test_gre_checksum_public_function_matches_calculate() {
        // gre_checksum is a thin alias over calculate_checksum for the
        // GRE region. They must agree exactly for any input.
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(gre_checksum(&data), calculate_checksum(&data));
    }

    #[test]
    fn test_gre_checksum_zero_input_yields_ones_complement() {
        // All-zero input is the "complement zero" RFC 1071 case; the
        // one's complement of zero is 0xFFFF.
        assert_eq!(gre_checksum(&[0u8; 16]), 0xFFFF);
    }

    #[test]
    fn test_gre_checksum_verifies_own_output() {
        // The signature property of Internet checksums: the verifier
        // yields 0xFFFF when the checksum field is correctly filled.
        let mut data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let cs = gre_checksum(&data);
        // Insert the checksum at the start of the buffer (the GRE
        // header position).
        data.insert(0, 0);
        data.insert(0, 0);
        data[0] = (cs >> 8) as u8;
        data[1] = cs as u8;
        assert!(verify_gre_checksum(&data, 0));
    }

    #[test]
    fn test_gre_checksum_detects_corrupted_packet() {
        // Flip a single byte; the verifier must reject the packet.
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        let mut packet = vec![0u8; 2];
        let cs = gre_checksum(&data);
        packet[0] = (cs >> 8) as u8;
        packet[1] = cs as u8;
        packet.extend_from_slice(&data);
        assert!(verify_gre_checksum(&packet, 0));
        // Corrupt one byte of the payload.
        packet[5] ^= 0xFF;
        assert!(!verify_gre_checksum(&packet, 0));
    }

    #[test]
    fn test_tunnel_with_checksum_emits_valid_c_bit() {
        let local = [10, 0, 0, 1];
        let remote = [10, 0, 0, 2];
        let tunnel = GreTunnel::new(local, remote, None).with_checksum();
        assert!(tunnel.checksum_enabled());

        let payload = b"GRE test payload";
        let packet = tunnel.encapsulate(payload, PROTOCOL_IPV4);

        // GRE header starts after the 20-byte outer IP header.
        // Bit 15 (C) must be set.
        let gre_word = u16::from_be_bytes([packet[20], packet[21]]);
        assert_eq!(gre_word & 0x8000, 0x8000, "C bit must be set");
        // Reserved1 (bits 12..15) must be zero per RFC 2890.
        assert_eq!(gre_word & 0x0FFF, 0);
    }

    #[test]
    fn test_tunnel_with_checksum_round_trip() {
        // Encapsulate, decapsulate, verify the payload survives and the
        // GRE checksum is correct on the wire.
        let local = [192, 168, 1, 1];
        let remote = [192, 168, 1, 2];
        let tunnel = GreTunnel::new(local, remote, None).with_checksum();
        let payload = b"hello GRE checksum world";

        let packet = tunnel.encapsulate(payload, PROTOCOL_IPV4);
        // Outer IP header is 20 bytes, then GRE header (4 bytes) +
        // 4 bytes for the checksum + reserved1 field = 28 bytes
        // before the payload.
        assert_eq!(&packet[48..], payload);

        // Verify the GRE checksum on the wire.
        let gre_region = &packet[20..];
        assert!(verify_gre_checksum(gre_region, GRE_HEADER_SIZE));

        // Decapsulate from the IP payload (skip the outer IP header).
        let recovered = tunnel.decapsulate(gre_region).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_tunnel_without_checksum_omits_c_bit() {
        // Sanity check the inverse of test_tunnel_with_checksum_emits_valid_c_bit.
        let tunnel = GreTunnel::new([10, 0, 0, 1], [10, 0, 0, 2], None);
        assert!(!tunnel.checksum_enabled());
        let packet = tunnel.encapsulate(b"plain", PROTOCOL_IPV4);
        let gre_word = u16::from_be_bytes([packet[20], packet[21]]);
        assert_eq!(gre_word & 0x8000, 0, "C bit must be clear");
    }

    #[test]
    fn test_gre_checksum_position_is_reserved1_zero() {
        // Per RFC 2890 the reserved1 field after the checksum must be
        // zero. Encapsulating twice with different payloads must give
        // identical reserved1 bytes (both 0).
        let tunnel = GreTunnel::new([10, 0, 0, 1], [10, 0, 0, 2], None)
            .with_checksum();
        let p1 = tunnel.encapsulate(b"alpha", PROTOCOL_IPV4);
        let p2 = tunnel.encapsulate(b"beta!!", PROTOCOL_IPV4);
        assert_eq!(p1[24], 0);
        assert_eq!(p2[24], 0);
    }
}

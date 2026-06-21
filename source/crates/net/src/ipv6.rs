//! IPv6 (Internet Protocol Version 6) Implementation
//!
//! Implements IPv6 as defined in RFC 8200 and related RFCs.
//!
//! ## Overview
//!
//! IPv6 is the successor to IPv4, providing a much larger address space
//! (128-bit addresses) and improved features including:
//! - Expanded address space
//! - Simplified header format
//! - Extension headers for options
//! - Flow labeling
//! - Neighbor Discovery Protocol (NDP)
//! - Stateless Address Autoconfiguration (SLAAC)
//!
//! ## Features
//!
//! - IPv6 header parsing and creation
//! - Extension headers (Hop-by-Hop, Routing, Fragment, Destination)
//! - Fragmentation and reassembly
//! - Address classification and manipulation
//! - EUI-64 interface identifier generation
//! - Solicited-node multicast address calculation
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::ipv6::{Ipv6Hdr, Ipv6Packet};
//!
//! // Parse incoming IPv6 packet
//! let packet = Ipv6Packet::parse(data).unwrap();
//! let src = packet.header.src_addr();
//! let dst = packet.header.dst_addr();
//! match packet.header.next_header() {
//!     6 => { /* TCP */ }
//!     17 => { /* UDP */ }
//!     58 => { /* ICMPv6 */ }
//!     _ => { /* other protocol */ }
//! }
//! ```

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;

use crate::common::sync::Spinlock;

/// IPv6 version constant
pub const IPV6_VERSION: u8 = 6;

/// IPv6 constants
pub const IPV6_HEADER_LEN: usize = 40;
pub const IPV6_MIN_MTU: usize = 1280;
pub const IPV6_MAX_PACKET: usize = 65535;
pub const IPV6_ADDR_LEN: usize = 16;
pub const IPV6_HOPS_MAX: u8 = 255;
pub const IPV6_MTU: usize = 1280;

/// IPv6 protocol numbers
pub mod proto {
    pub const HOPOPTS: u8 = 0; // Hop-by-Hop Options
    pub const TCP: u8 = 6; // TCP
    pub const UDP: u8 = 17; // UDP
    pub const ROUTING: u8 = 43; // Routing
    pub const FRAGMENT: u8 = 44; // Fragment
    pub const ICMPV6: u8 = 58; // ICMPv6
    pub const NONE: u8 = 59; // No Next Header
    pub const DESTOPTS: u8 = 60; // Destination Options
    pub const MOBILITY: u8 = 135; // Mobility
}

// ============================================================================
// IPv6 Address Types and Classification
// ============================================================================

/// IPv6 address classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6AddrType {
    /// Unspecified address (::/128)
    Unspecified,
    /// Loopback address (::1/128)
    Loopback,
    /// Multicast address (ff00::/8)
    Multicast,
    /// Link-local address (fe80::/10)
    LinkLocal,
    /// Unique local address (fc00::/7)
    UniqueLocal,
    /// Global unicast address
    GlobalUnicast,
}

impl Ipv6AddrType {
    /// Classify an IPv6 address
    pub fn classify(addr: &[u8; IPV6_ADDR_LEN]) -> Self {
        if addr.iter().all(|&b| b == 0) {
            return Ipv6AddrType::Unspecified;
        }

        if addr[0] == 0xFF {
            return Ipv6AddrType::Multicast;
        }

        if addr[0] == 0xFE {
            match addr[1] & 0xC0 {
                0x80 => return Ipv6AddrType::LinkLocal,
                _ => return Ipv6AddrType::GlobalUnicast,
            }
        }

        if addr[0] == 0xFC || addr[0] == 0xFD {
            return Ipv6AddrType::UniqueLocal;
        }

        // Check for loopback
        if addr[..15].iter().all(|&b| b == 0) && addr[15] == 1 {
            return Ipv6AddrType::Loopback;
        }

        Ipv6AddrType::GlobalUnicast
    }
}

/// IPv6 well-known addresses
pub mod addr {
    use super::*;

    /// Unspecified address (::)
    pub const UNSPECIFIED: [u8; IPV6_ADDR_LEN] = [0u8; IPV6_ADDR_LEN];

    /// Loopback address (::1)
    pub const LOOPBACK: [u8; IPV6_ADDR_LEN] = {
        let mut addr = [0u8; IPV6_ADDR_LEN];
        addr[15] = 1;
        addr
    };

    /// All-nodes multicast address (ff02::1)
    pub const ALL_NODES: [u8; IPV6_ADDR_LEN] = {
        let mut addr = [0u8; IPV6_ADDR_LEN];
        addr[0] = 0xFF;
        addr[1] = 0x02;
        addr[15] = 1;
        addr
    };

    /// All-routers multicast address (ff02::2)
    pub const ALL_ROUTERS: [u8; IPV6_ADDR_LEN] = {
        let mut addr = [0u8; IPV6_ADDR_LEN];
        addr[0] = 0xFF;
        addr[1] = 0x02;
        addr[15] = 2;
        addr
    };

    /// solicited-node multicast base (ff02::1:ff00:0000)
    pub const SOLICITED_NODE_BASE: [u8; IPV6_ADDR_LEN] = {
        let mut addr = [0u8; IPV6_ADDR_LEN];
        addr[0] = 0xFF;
        addr[1] = 0x02;
        addr[11] = 0x01;
        addr[12] = 0xFF;
        addr
    };

    /// Generate solicited-node multicast address from unicast address
    pub fn solicited_node_mcast(unicast: &[u8; IPV6_ADDR_LEN]) -> [u8; IPV6_ADDR_LEN] {
        let mut mcast = SOLICITED_NODE_BASE;
        mcast[13] = unicast[13];
        mcast[14] = unicast[14];
        mcast[15] = unicast[15];
        mcast
    }

    /// Check if address is unspecified (::)
    pub fn is_unspecified(addr: &[u8; IPV6_ADDR_LEN]) -> bool {
        addr.iter().all(|&b| b == 0)
    }

    /// Check if address is loopback (::1)
    pub fn is_loopback(addr: &[u8; IPV6_ADDR_LEN]) -> bool {
        addr[..15].iter().all(|&b| b == 0) && addr[15] == 1
    }

    /// Check if address is link-local (fe80::/10)
    pub fn is_link_local(addr: &[u8; IPV6_ADDR_LEN]) -> bool {
        addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
    }

    /// Check if address is multicast (ff00::/8)
    pub fn is_multicast(addr: &[u8; IPV6_ADDR_LEN]) -> bool {
        addr[0] == 0xFF
    }

    /// Check if address is in same subnet (same prefix)
    pub fn same_subnet(
        a: &[u8; IPV6_ADDR_LEN],
        b: &[u8; IPV6_ADDR_LEN],
        prefix_len: usize,
    ) -> bool {
        let full_bytes = prefix_len / 8;
        let remaining_bits = prefix_len % 8;

        // Compare full bytes
        if a[..full_bytes] != b[..full_bytes] {
            return false;
        }

        // Compare remaining bits
        if remaining_bits > 0 && full_bytes < IPV6_ADDR_LEN {
            let mask = !((1 << (8 - remaining_bits)) - 1);
            if (a[full_bytes] & mask as u8) != (b[full_bytes] & mask as u8) {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// IPv6 Header
// ============================================================================

/// IPv6 header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Ipv6Hdr {
    /// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    pub vcf: [u8; 4],
    /// Payload length (bytes after this header)
    pub payload_len: u16,
    /// Next header protocol number
    pub next_header: u8,
    /// Hop limit (replaces TTL)
    pub hop_limit: u8,
    /// Source address (128 bits)
    pub src: [u8; IPV6_ADDR_LEN],
    /// Destination address (128 bits)
    pub dst: [u8; IPV6_ADDR_LEN],
}

impl Ipv6Hdr {
    /// Create a new IPv6 header
    pub fn new() -> Self {
        Self {
            vcf: [(IPV6_VERSION << 4), 0, 0, 0],
            payload_len: 0u16.to_be(),
            next_header: 0,
            hop_limit: 64,
            src: [0u8; IPV6_ADDR_LEN],
            dst: [0u8; IPV6_ADDR_LEN],
        }
    }

    /// IPv6 version number
    pub const IPV6_VERSION: u8 = 6;

    /// Get IPv6 version
    pub fn version(&self) -> u8 {
        self.vcf[0] >> 4
    }

    /// Get traffic class
    pub fn traffic_class(&self) -> u8 {
        ((self.vcf[0] & 0xF) << 4) | (self.vcf[1] >> 4)
    }

    /// Set traffic class
    pub fn set_traffic_class(&mut self, tc: u8) {
        self.vcf[0] = (Self::IPV6_VERSION << 4) | (tc >> 4);
        self.vcf[1] = (tc << 4) | (self.vcf[1] & 0xF);
    }

    /// Get flow label
    pub fn flow_label(&self) -> u32 {
        let label =
            ((self.vcf[1] as u32) & 0xF) << 16 | (self.vcf[2] as u32) << 8 | (self.vcf[3] as u32);
        label
    }

    /// Set flow label
    pub fn set_flow_label(&mut self, label: u32) {
        self.vcf[1] = (self.vcf[1] & 0xF0) | ((label >> 16) as u8 & 0xF);
        self.vcf[2] = (label >> 8) as u8;
        self.vcf[3] = label as u8;
    }

    /// Get payload length
    pub fn payload_len(&self) -> u16 {
        u16::from_be(self.payload_len)
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: u16) {
        self.payload_len = len.to_be();
    }

    /// Get next header protocol
    pub fn next_header(&self) -> u8 {
        self.next_header
    }

    /// Set next header protocol
    pub fn set_next_header(&mut self, proto: u8) {
        self.next_header = proto;
    }

    /// Get hop limit
    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Set hop limit
    pub fn set_hop_limit(&mut self, hops: u8) {
        self.hop_limit = hops;
    }

    /// Decrement hop limit and check if expired
    pub fn dec_hop_limit(&mut self) -> bool {
        if self.hop_limit > 0 {
            self.hop_limit -= 1;
        }
        self.hop_limit == 0
    }

    /// Get source address
    pub fn src_addr(&self) -> [u8; IPV6_ADDR_LEN] {
        self.src
    }

    /// Set source address
    pub fn set_src_addr(&mut self, addr: &[u8; IPV6_ADDR_LEN]) {
        self.src.copy_from_slice(addr);
    }

    /// Get destination address
    pub fn dst_addr(&self) -> [u8; IPV6_ADDR_LEN] {
        self.dst
    }

    /// Set destination address
    pub fn set_dst_addr(&mut self, addr: &[u8; IPV6_ADDR_LEN]) {
        self.dst.copy_from_slice(addr);
    }

    /// Get total packet length (header + payload)
    pub fn total_len(&self) -> usize {
        IPV6_HEADER_LEN + (self.payload_len() as usize)
    }

    /// Get address type (source)
    pub fn src_type(&self) -> Ipv6AddrType {
        Ipv6AddrType::classify(&self.src)
    }

    /// Get address type (destination)
    pub fn dst_type(&self) -> Ipv6AddrType {
        Ipv6AddrType::classify(&self.dst)
    }

    /// Check if source is this host
    pub fn is_for_us(&self, our_addrs: &[[u8; IPV6_ADDR_LEN]]) -> bool {
        // Check if destination is one of our addresses
        for addr in our_addrs {
            if &self.dst == addr {
                return true;
            }
        }

        // Check for multicast
        if addr::is_multicast(&self.dst) {
            // All-nodes multicast
            if self.dst == addr::ALL_NODES {
                return true;
            }
            // Solicited-node multicast for our addresses
            for addr in our_addrs {
                if self.dst == addr::solicited_node_mcast(addr) {
                    return true;
                }
            }
        }

        false
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPV6_HEADER_LEN {
            return None;
        }

        // Verify version is 6
        if (bytes[0] >> 4) != Self::IPV6_VERSION {
            return None;
        }

        Some(Self {
            vcf: [bytes[0], bytes[1], bytes[2], bytes[3]],
            payload_len: u16::from_be_bytes([bytes[4], bytes[5]]),
            next_header: bytes[6],
            hop_limit: bytes[7],
            src: bytes[8..24].try_into().unwrap(),
            dst: bytes[24..40].try_into().unwrap(),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < IPV6_HEADER_LEN {
            return None;
        }

        bytes[0..4].copy_from_slice(&self.vcf);
        bytes[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        bytes[6] = self.next_header;
        bytes[7] = self.hop_limit;
        bytes[8..24].copy_from_slice(&self.src);
        bytes[24..40].copy_from_slice(&self.dst);
        Some(())
    }
}

// ============================================================================
// IPv6 Extension Headers
// ============================================================================

/// Extension header types
#[derive(Debug, Clone)]
pub enum ExtensionHeader {
    /// Hop-by-Hop Options (type 0)
    HopByHop(HopByHopOptions),
    /// Destination Options (type 60) - before routing
    DestinationOptions(DestOptions),
    /// Routing (type 43)
    Routing(RoutingHeader),
    /// Fragment (type 44)
    Fragment(FragmentHeader),
    /// Authentication (type 51) - AH
    Authentication,
    /// Encapsulating Security Payload (type 52) - ESP
    Esp,
    /// Destination Options (type 60) - after routing
    DestinationOptions2(DestOptions),
    /// Mobility (type 135)
    Mobility,
}

impl ExtensionHeader {
    /// Get the next header value
    pub fn next_header(&self) -> u8 {
        match self {
            ExtensionHeader::HopByHop(_) => proto::HOPOPTS,
            ExtensionHeader::DestinationOptions(_) => proto::DESTOPTS,
            ExtensionHeader::Routing(_) => proto::ROUTING,
            ExtensionHeader::Fragment(_) => proto::FRAGMENT,
            ExtensionHeader::Authentication => 51,
            ExtensionHeader::Esp => 52,
            ExtensionHeader::DestinationOptions2(_) => proto::DESTOPTS,
            ExtensionHeader::Mobility => 135,
        }
    }

    /// Get header length in bytes
    pub fn header_len(&self) -> usize {
        match self {
            ExtensionHeader::HopByHop(opts) => opts.total_len(),
            ExtensionHeader::DestinationOptions(opts) => opts.total_len(),
            ExtensionHeader::Routing(hdr) => hdr.total_len(),
            ExtensionHeader::Fragment(_) => 8,
            ExtensionHeader::Authentication => 8, // Variable, minimum 8
            ExtensionHeader::Esp => 8,            // Variable
            ExtensionHeader::DestinationOptions2(opts) => opts.total_len(),
            ExtensionHeader::Mobility => 8, // Variable
        }
    }
}

/// Hop-by-Hop Options
#[derive(Debug, Clone)]
pub struct HopByHopOptions {
    pub options: Vec<OptionTlv>,
}

/// Destination Options
#[derive(Debug, Clone)]
pub struct DestOptions {
    pub options: Vec<OptionTlv>,
}

impl HopByHopOptions {
    /// Get total length (must be multiple of 8 bytes)
    pub fn total_len(&self) -> usize {
        let mut len = 8; // Header takes 8 bytes minimum
        for opt in &self.options {
            len += opt.total_len();
        }
        // Pad to 8-byte alignment
        ((len + 7) / 8) * 8
    }
}

impl DestOptions {
    /// Get total length (must be multiple of 8 bytes)
    pub fn total_len(&self) -> usize {
        let mut len = 8; // Header takes 8 bytes minimum
        for opt in &self.options {
            len += opt.total_len();
        }
        // Pad to 8-byte alignment
        ((len + 7) / 8) * 8
    }
}

/// Option TLV structure
#[derive(Debug, Clone)]
pub struct OptionTlv {
    /// Option type
    pub option_type: u8,
    /// Option length
    pub length: u8,
    /// Option data
    pub data: Vec<u8>,
}

impl OptionTlv {
    /// Create a new option
    pub fn new(option_type: u8, data: Vec<u8>) -> Self {
        Self {
            option_type,
            length: data.len() as u8,
            data,
        }
    }

    /// Get total length of this option (including type and length bytes)
    pub fn total_len(&self) -> usize {
        2 + self.data.len()
    }
}

/// Routing header
#[derive(Debug, Clone)]
pub struct RoutingHeader {
    /// Routing type
    pub routing_type: u8,
    /// Segments left
    pub segments_left: u8,
    /// Type-specific data
    pub data: Vec<u8>,
}

impl RoutingHeader {
    /// Get total length
    pub fn total_len(&self) -> usize {
        // Header is 8 bytes minimum, plus data
        let len = 8 + self.data.len();
        ((len + 7) / 8) * 8
    }
}

/// Fragment header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FragmentHeader {
    /// Next header
    pub next_header: u8,
    /// Reserved
    pub reserved: u8,
    /// Fragment offset (13 bits) + flags
    pub offset_m: u16,
    /// Fragment identification
    pub identification: u32,
}

impl FragmentHeader {
    /// Create a new fragment header
    pub fn new(next_header: u8, identification: u32, offset: u16, more: bool) -> Self {
        let offset_m = ((offset & 0x1FFF) << 3) | if more { 0x0001 } else { 0 };
        Self {
            next_header,
            reserved: 0,
            offset_m: offset_m.to_be(),
            identification: identification.to_be(),
        }
    }

    /// Get fragment offset
    pub fn offset(&self) -> u16 {
        u16::from_be(self.offset_m) >> 3
    }

    /// Check if more fragments
    pub fn more_fragments(&self) -> bool {
        (u16::from_be(self.offset_m) & 0x0001) != 0
    }

    /// Get identification
    pub fn identification(&self) -> u32 {
        u32::from_be(self.identification)
    }
}

// ============================================================================
// IPv6 Fragmentation and Reassembly
// ============================================================================

/// Fragment cache key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentKey {
    /// Source address
    pub src: [u8; IPV6_ADDR_LEN],
    /// Destination address
    pub dst: [u8; IPV6_ADDR_LEN],
    /// Fragment identification
    pub identification: u32,
    /// Original next header
    pub next_header: u8,
}

impl FragmentKey {
    /// Create a new fragment key
    pub fn new(
        src: &[u8; IPV6_ADDR_LEN],
        dst: &[u8; IPV6_ADDR_LEN],
        identification: u32,
        next_header: u8,
    ) -> Self {
        Self {
            src: *src,
            dst: *dst,
            identification,
            next_header,
        }
    }
}

/// Fragment data
#[derive(Debug, Clone)]
pub struct FragmentData {
    /// Fragment offset
    pub offset: usize,
    /// More fragments flag
    pub more: bool,
    /// Fragment data
    pub data: Vec<u8>,
}

/// Fragment cache entry
#[derive(Debug, Clone)]
pub struct FragmentEntry {
    /// Fragment key
    pub key: FragmentKey,
    /// Received fragments
    pub fragments: Vec<FragmentData>,
    /// Original payload length
    pub total_len: Option<usize>,
    /// Creation time (for timeout)
    pub created_at: u64,
    /// Complete flag
    pub complete: bool,
}

impl FragmentEntry {
    /// Create a new fragment entry
    pub fn new(key: FragmentKey, created_at: u64) -> Self {
        Self {
            key,
            fragments: Vec::new(),
            total_len: None,
            created_at,
            complete: false,
        }
    }

    /// Add a fragment
    pub fn add_fragment(&mut self, offset: usize, more: bool, data: Vec<u8>) {
        // Check if we already have this fragment
        for frag in &mut self.fragments {
            if frag.offset == offset {
                return;
            }
        }

        self.fragments.push(FragmentData { offset, more, data });

        // Update total length from last fragment
        if !more {
            let last_offset = offset + data.len();
            if self.total_len.is_none() || self.total_len.unwrap() < last_offset {
                self.total_len = Some(last_offset);
            }
        }

        // Sort fragments by offset
        self.fragments.sort_by_key(|f| f.offset);
    }

    /// Check if all fragments are received
    pub fn is_complete(&self) -> bool {
        if self.fragments.is_empty() {
            return false;
        }

        // Check for holes
        let mut expected_offset = 0;
        for frag in &self.fragments {
            if frag.offset != expected_offset {
                return false;
            }
            expected_offset = frag.offset + frag.data.len();
            if !frag.more {
                // Last fragment, check if we have total length
                if let Some(total) = self.total_len {
                    if expected_offset != total {
                        return false;
                    }
                }
                return true;
            }
        }

        false
    }

    /// Reassemble the fragments
    pub fn reassemble(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for frag in &self.fragments {
            result.extend_from_slice(&frag.data);
        }
        result
    }
}

/// IPv6 fragment cache
pub struct FragmentCache {
    /// Fragment entries
    entries: BTreeMap<FragmentKey, FragmentEntry>,
    /// Maximum entries
    max_entries: usize,
    /// Fragment timeout (seconds)
    timeout_secs: u64,
    /// Lock
    lock: Spinlock<()>,
}

impl FragmentCache {
    /// Create a new fragment cache
    pub fn new(max_entries: usize, timeout_secs: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            timeout_secs,
            lock: Spinlock::new(()),
        }
    }

    /// Process an incoming fragment
    /// Returns Some(payload) if packet is complete, None if more fragments needed
    pub fn process_fragment(
        &mut self,
        header: &Ipv6Hdr,
        frag_hdr: &FragmentHeader,
        data: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        let _guard = self.lock.lock();

        let key = FragmentKey::new(
            &header.src,
            &header.dst,
            frag_hdr.identification(),
            frag_hdr.next_header,
        );
        let offset = frag_hdr.offset() as usize;
        let more = frag_hdr.more_fragments();

        // Get or create entry
        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| FragmentEntry::new(key.clone(), now));

        // Add fragment
        entry.add_fragment(offset, more, data.to_vec());

        // Check if complete
        if entry.is_complete() {
            let payload = entry.reassemble();
            self.entries.remove(&key);
            return Some(payload);
        }

        // Check for timeout
        if now - entry.created_at > self.timeout_secs {
            self.entries.remove(&key);
        }

        None
    }

    /// Clean up expired fragments
    pub fn cleanup(&mut self, now: u64) {
        let _guard = self.lock.lock();

        self.entries
            .retain(|_, entry| now - entry.created_at <= self.timeout_secs);
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// IPv6 Packet
// ============================================================================

/// IPv6 packet with header and payload
#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    /// IPv6 header
    pub header: Ipv6Hdr,
    /// Extension headers
    pub extension_headers: Vec<ExtensionHeader>,
    /// Transport layer payload
    pub payload: Vec<u8>,
}

impl Ipv6Packet {
    /// Create a new IPv6 packet
    pub fn new(src: &[u8; IPV6_ADDR_LEN], dst: &[u8; IPV6_ADDR_LEN], next_header: u8) -> Self {
        let mut hdr = Ipv6Hdr::new();
        hdr.set_src_addr(src);
        hdr.set_dst_addr(dst);
        hdr.set_next_header(next_header);

        Self {
            header: hdr,
            extension_headers: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Create packet with payload
    pub fn with_payload(
        src: &[u8; IPV6_ADDR_LEN],
        dst: &[u8; IPV6_ADDR_LEN],
        next_header: u8,
        payload: Vec<u8>,
    ) -> Self {
        let mut packet = Self::new(src, dst, next_header);
        packet.set_payload(payload);
        packet
    }

    /// Get total packet size
    pub fn total_len(&self) -> usize {
        let mut size = IPV6_HEADER_LEN;
        for ext in &self.extension_headers {
            size += ext.header_len();
        }
        size + self.payload.len()
    }

    /// Set payload and update header
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
        let mut ext_len = 0;
        for ext in &self.extension_headers {
            ext_len += ext.header_len();
        }
        self.header
            .set_payload_len((ext_len + self.payload.len()) as u16);
    }

    /// Get the effective next header (last extension or transport)
    pub fn effective_next_header(&self) -> u8 {
        if let Some(last) = self.extension_headers.last() {
            last.next_header()
        } else {
            self.header.next_header()
        }
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = Ipv6Hdr::from_bytes(bytes)?;

        let mut ext_headers = Vec::new();
        let mut offset = IPV6_HEADER_LEN;
        let mut current_next_header = header.next_header;

        // Parse extension headers
        while matches!(
            current_next_header,
            proto::HOPOPTS | proto::DESTOPTS | proto::ROUTING | proto::FRAGMENT | 51 | 52 | 135
        ) {
            if bytes.len() < offset + 8 {
                break;
            }

            let ext_type = current_next_header;
            current_next_header = bytes[offset];

            match ext_type {
                proto::HOPOPTS | proto::DESTOPTS => {
                    // Parse options header
                    let opt_len = ((bytes[offset + 1] as usize) + 1) * 8;
                    let mut options = Vec::new();
                    let mut opt_offset = offset + 2;

                    while opt_offset < offset + opt_len && opt_offset + 2 <= bytes.len() {
                        let opt_type = bytes[opt_offset];
                        let opt_len_byte = bytes[opt_offset + 1];

                        if opt_type == 0 {
                            // Pad1 option
                            opt_offset += 1;
                            continue;
                        }

                        if opt_len_byte == 0 {
                            // PadN option
                            opt_offset += 2;
                            continue;
                        }

                        let opt_data = if opt_len_byte as usize <= bytes.len() - opt_offset - 2 {
                            bytes[opt_offset + 2..opt_offset + 2 + opt_len_byte as usize].to_vec()
                        } else {
                            break;
                        };

                        options.push(OptionTlv {
                            option_type: opt_type,
                            length: opt_len_byte,
                            data: opt_data,
                        });

                        opt_offset += 2 + opt_len_byte as usize;
                    }

                    if ext_type == proto::HOPOPTS {
                        ext_headers.push(ExtensionHeader::HopByHop(HopByHopOptions { options }));
                    } else {
                        ext_headers
                            .push(ExtensionHeader::DestinationOptions(DestOptions { options }));
                    }

                    offset += opt_len;
                }
                proto::ROUTING => {
                    let routing_len = ((bytes[offset + 1] as usize) + 1) * 8;
                    ext_headers.push(ExtensionHeader::Routing(RoutingHeader {
                        routing_type: bytes[offset + 2],
                        segments_left: bytes[offset + 3],
                        data: bytes[offset + 4..offset + routing_len].to_vec(),
                    }));
                    offset += routing_len;
                }
                proto::FRAGMENT => {
                    if bytes.len() < offset + 8 {
                        break;
                    }
                    let frag_hdr = FragmentHeader {
                        next_header: bytes[offset],
                        reserved: bytes[offset + 1],
                        offset_m: u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
                        identification: u32::from_be_bytes([
                            bytes[offset + 4],
                            bytes[offset + 5],
                            bytes[offset + 6],
                            bytes[offset + 7],
                        ]),
                    };
                    ext_headers.push(ExtensionHeader::Fragment(frag_hdr));
                    offset += 8;
                }
                51 => {
                    // Authentication header - simplified
                    ext_headers.push(ExtensionHeader::Authentication);
                    offset += 8;
                }
                52 => {
                    // ESP - simplified
                    ext_headers.push(ExtensionHeader::Esp);
                    offset += 8;
                }
                135 => {
                    // Mobility - simplified
                    ext_headers.push(ExtensionHeader::Mobility);
                    offset += 8;
                }
                _ => break,
            }
        }

        // Get payload
        let payload = if bytes.len() > offset {
            bytes[offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            header,
            extension_headers: ext_headers,
            payload,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_len());

        // Write header
        let mut header_bytes = [0u8; IPV6_HEADER_LEN];
        self.header.to_bytes(&mut header_bytes);
        bytes.extend_from_slice(&header_bytes);

        // Write extension headers
        for ext in &self.extension_headers {
            match ext {
                ExtensionHeader::HopByHop(opts) => {
                    bytes.push(proto::HOPOPTS);
                    let opt_bytes = Self::serialize_options(opts);
                    bytes.push((opt_bytes.len() / 8 - 1) as u8);
                    bytes.extend_from_slice(&opt_bytes);
                }
                ExtensionHeader::DestinationOptions(opts) => {
                    bytes.push(proto::DESTOPTS);
                    let opt_bytes = Self::serialize_options(opts);
                    bytes.push((opt_bytes.len() / 8 - 1) as u8);
                    bytes.extend_from_slice(&opt_bytes);
                }
                ExtensionHeader::Routing(hdr) => {
                    bytes.push(proto::ROUTING);
                    bytes.push((hdr.total_len() / 8 - 1) as u8);
                    bytes.push(hdr.routing_type);
                    bytes.push(hdr.segments_left);
                    bytes.extend_from_slice(&hdr.data);
                }
                ExtensionHeader::Fragment(frag) => {
                    bytes.push(frag.next_header);
                    bytes.push(frag.reserved);
                    bytes.extend_from_slice(&frag.offset_m.to_be_bytes());
                    bytes.extend_from_slice(&frag.identification.to_be_bytes());
                }
                _ => {
                    // Simplified for other headers
                    bytes.push(ext.next_header());
                    bytes.push(0); // Length
                }
            }
        }

        // Write payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Serialize options
    fn serialize_options(opts: &HopByHopOptions) -> Vec<u8> {
        let mut bytes = Vec::new();

        for opt in &opts.options {
            if opt.option_type == 0 && opt.length == 0 {
                bytes.push(0); // Pad1
            } else {
                bytes.push(opt.option_type);
                bytes.push(opt.length);
                bytes.extend_from_slice(&opt.data);
            }
        }

        // Pad to 8-byte boundary
        while bytes.len() % 8 != 0 {
            if bytes.len() % 8 == 7 {
                bytes.push(1); // PadN with length 1
            } else {
                bytes.push(0); // Pad1
            }
        }

        bytes
    }
}

// ============================================================================
// IPv6 EUI-64 Address Generation
// ============================================================================

/// Generate EUI-64 interface identifier from MAC address
pub fn eui64_from_mac(mac: &[u8; 6]) -> [u8; 8] {
    let mut eui64 = [0u8; 8];
    // Flip the universal/local bit
    eui64[0] = mac[0] ^ 0x02;
    eui64[1] = mac[1];
    eui64[2] = mac[2];
    // Insert FF-FE
    eui64[3] = 0xFF;
    eui64[4] = 0xFE;
    eui64[5] = mac[3];
    eui64[6] = mac[4];
    eui64[7] = mac[5];
    eui64
}

/// Generate link-local address from MAC address
pub fn link_local_from_mac(mac: &[u8; 6]) -> [u8; IPV6_ADDR_LEN] {
    let eui64 = eui64_from_mac(mac);
    let mut addr = [0u8; IPV6_ADDR_LEN];
    addr[0] = 0xFE;
    addr[1] = 0x80;
    addr[8..].copy_from_slice(&eui64);
    addr
}

/// Generate interface identifier from MAC address (inverse operation)
pub fn mac_from_eui64(eui64: &[u8; 8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    // Flip the universal/local bit back
    mac[0] = eui64[0] ^ 0x02;
    mac[1] = eui64[1];
    mac[2] = eui64[2];
    mac[3] = eui64[5];
    mac[4] = eui64[6];
    mac[5] = eui64[7];
    mac
}

// ============================================================================
// IPv6 Statistics
// ============================================================================

/// IPv6 statistics
#[derive(Debug, Clone, Default)]
pub struct Ipv6Stats {
    /// Total packets received
    pub in_receives: u64,
    /// Packets delivered to upper layer
    pub in_delivers: u64,
    /// Received packets with invalid headers
    pub in_hdr_errors: u64,
    /// Received packets with invalid addresses
    pub in_addr_errors: u64,
    /// Packets with unknown protocols
    pub in_unknown_protos: u64,
    /// Received packets discarded
    pub in_discards: u64,
    /// Total packets transmitted
    pub out_requests: u64,
    /// Output packets discarded
    pub out_discards: u64,
    /// Fragments created
    pub frag_creates: u64,
    /// Fragments reassembled
    pub frag_ok: u64,
    /// Fragments failed
    pub frag_fail: u64,
}

// ============================================================================
// IPv6 Routing (Simplified)
// ============================================================================

/// IPv6 route entry
#[derive(Debug, Clone)]
pub struct Ipv6Route {
    /// Network prefix
    pub prefix: [u8; IPV6_ADDR_LEN],
    /// Prefix length
    pub prefix_len: u8,
    /// Gateway address (optional for direct)
    pub gateway: Option<[u8; IPV6_ADDR_LEN]>,
    /// Interface index
    pub iface: usize,
    /// Metric
    pub metric: u32,
}

impl Ipv6Route {
    /// Create a new route
    pub fn new(
        prefix: &[u8; IPV6_ADDR_LEN],
        prefix_len: u8,
        gateway: Option<[u8; IPV6_ADDR_LEN]>,
        iface: usize,
    ) -> Self {
        Self {
            prefix: *prefix,
            prefix_len,
            gateway,
            iface,
            metric: 1,
        }
    }

    /// Create a default route
    pub fn default_route(gateway: &[u8; IPV6_ADDR_LEN], iface: usize) -> Self {
        Self {
            prefix: [0u8; IPV6_ADDR_LEN],
            prefix_len: 0,
            gateway: Some(*gateway),
            iface,
            metric: 1,
        }
    }

    /// Create a direct route (no gateway)
    pub fn direct_route(prefix: &[u8; IPV6_ADDR_LEN], prefix_len: u8, iface: usize) -> Self {
        Self {
            prefix: *prefix,
            prefix_len,
            gateway: None,
            iface,
            metric: 1,
        }
    }

    /// Check if this route matches an address
    pub fn matches(&self, addr: &[u8; IPV6_ADDR_LEN]) -> bool {
        if self.prefix_len == 0 {
            return true; // Default route
        }

        let full_bytes = (self.prefix_len / 8) as usize;
        let remaining_bits = self.prefix_len % 8;

        // Compare full bytes
        if addr[..full_bytes] != self.prefix[..full_bytes] {
            return false;
        }

        // Compare remaining bits
        if remaining_bits > 0 && full_bytes < IPV6_ADDR_LEN {
            let mask = !((1 << (8 - remaining_bits)) - 1) as u8;
            if (addr[full_bytes] & mask) != (self.prefix[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

/// Simple IPv6 routing table
pub struct Ipv6RoutingTable {
    routes: Vec<Ipv6Route>,
}

impl Ipv6RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route
    pub fn add_route(&mut self, route: Ipv6Route) {
        self.routes.push(route);
        // Sort by prefix length (longest match first)
        self.routes.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Find route for destination
    pub fn find_route(&self, addr: &[u8; IPV6_ADDR_LEN]) -> Option<&Ipv6Route> {
        self.routes.iter().find(|r| r.matches(addr))
    }

    /// Remove a route
    pub fn remove_route(&mut self, prefix: &[u8; IPV6_ADDR_LEN], prefix_len: u8) {
        self.routes
            .retain(|r| &r.prefix != prefix || r.prefix_len != prefix_len);
    }
}

impl Default for Ipv6RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

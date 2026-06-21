//! ICMPv6 (Internet Control Message Protocol for IPv6) Implementation
//!
//! Implements ICMPv6 as defined in RFC 4443 for IPv6 networks, including
//! Neighbor Discovery Protocol (NDP) as defined in RFC 4861.
//!
//! ## Overview
//!
//! ICMPv6 is essential for IPv6 operation, providing:
//! - Error reporting (Destination Unreachable, Packet Too Big, Time Exceeded)
//! - Diagnostic functionality (Echo Request/Reply)
//! - Neighbor Discovery (NDP) for address resolution and router discovery
//!
//! ## Message Types
//!
//! ### Error Messages (Type 0-127)
//! - Destination Unreachable (Type 1)
//! - Packet Too Big (Type 2)
//! - Time Exceeded (Type 3)
//! - Parameter Problem (Type 4)
//!
//! ### Informational Messages (Type 128-255)
//! - Echo Request (Type 128)
//! - Echo Reply (Type 129)
//! - Router Solicitation (Type 133)
//! - Router Advertisement (Type 134)
//! - Neighbor Solicitation (Type 135)
//! - Neighbor Advertisement (Type 136)
//! - Redirect (Type 137)
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::icmpv6::{Icmpv6Hdr, Icmpv6Type, Icmpv6Packet};
//!
//! // Parse incoming ICMPv6 packet
//! let packet = Icmpv6Packet::parse(data).unwrap();
//! match packet.icmp_type() {
//!     Icmpv6Type::EchoRequest => { /* handle ping */ }
//!     Icmpv6Type::NbrSolicit => { /* handle neighbor solicitation */ }
//!     _ => { /* other ICMPv6 messages */ }
//! }
//! ```

#![no_std]

extern crate alloc;
use crate::common::sync::Spinlock;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// IPv6 address length
pub const IPV6_ADDR_LEN: usize = 16;

/// ICMPv6 constants
pub const ICMPV6_HEADER_SIZE: usize = 8;
pub const ICMPV6_MIN_SIZE: usize = 8;

/// ICMPv6 protocol number (for IPv6 next header)
pub const IPV6_ICMPV6_PROTO: u8 = 58;

/// Hop-by-Hop Options extension header number
pub const HBH: u8 = 0;

/// Neighbor Discovery constants
pub const MAX_MULTICAST_SOLICIT: u8 = 3;
pub const RETRANS_TIMER_MS: u32 = 1000;

/// ICMPv6 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    // Error messages
    EchoReply = 0,
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    // Informational messages
    EchoRequest = 128,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl Icmpv6Type {
    /// Convert from raw byte value
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Icmpv6Type::EchoReply),
            1 => Some(Icmpv6Type::DestinationUnreachable),
            2 => Some(Icmpv6Type::PacketTooBig),
            3 => Some(Icmpv6Type::TimeExceeded),
            4 => Some(Icmpv6Type::ParameterProblem),
            128 => Some(Icmpv6Type::EchoRequest),
            133 => Some(Icmpv6Type::RouterSolicitation),
            134 => Some(Icmpv6Type::RouterAdvertisement),
            135 => Some(Icmpv6Type::NeighborSolicitation),
            136 => Some(Icmpv6Type::NeighborAdvertisement),
            137 => Some(Icmpv6Type::Redirect),
            _ => None,
        }
    }

    /// Check if this is an error message
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Icmpv6Type::DestinationUnreachable
                | Icmpv6Type::PacketTooBig
                | Icmpv6Type::TimeExceeded
                | Icmpv6Type::ParameterProblem
        )
    }

    /// Check if this is an informational message
    pub fn is_info(&self) -> bool {
        !self.is_error() && *self != Icmpv6Type::EchoReply
    }
}

/// ICMPv6 unreachable codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnreachableCodeV6 {
    NoRoute = 0,
    AdministrativelyProhibited = 1,
    BeyondScope = 2,
    AddressUnreachable = 3,
    PortUnreachable = 4,
    SourceAddressFailed = 5,
    RejectRoute = 6,
}

impl UnreachableCodeV6 {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NoRoute),
            1 => Some(Self::AdministrativelyProhibited),
            2 => Some(Self::BeyondScope),
            3 => Some(Self::AddressUnreachable),
            4 => Some(Self::PortUnreachable),
            5 => Some(Self::SourceAddressFailed),
            6 => Some(Self::RejectRoute),
            _ => None,
        }
    }
}

/// ICMPv6 time exceeded codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeExceededCodeV6 {
    HopLimitExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
}

impl TimeExceededCodeV6 {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::HopLimitExceeded),
            1 => Some(Self::FragmentReassemblyTimeExceeded),
            _ => None,
        }
    }
}

/// ICMPv6 parameter problem codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ParameterProblemCode {
    ErroneousHeader = 0,
    UnrecognizedNextHeader = 1,
    UnrecognizedOption = 2,
}

impl ParameterProblemCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ErroneousHeader),
            1 => Some(Self::UnrecognizedNextHeader),
            2 => Some(Self::UnrecognizedOption),
            _ => None,
        }
    }
}

/// ICMPv6 Neighbor Discovery option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectedHeader = 4,
    Mtu = 5,
    /// RFC 5006: Router Advertisement DNS Search List
    RouteInformation = 24,
    /// RFC 5175: Default Router Preferences
    RouterAdv = 25,
    /// RFC 3810: Multicast Listener Discovery v2
    Mld = 31,
}

// ============================================================================
// ICMPv6 Header
// ============================================================================

/// ICMPv6 header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Icmpv6Hdr {
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Message body (varies by type)
    pub body: [u32; 1],
}

impl Icmpv6Hdr {
    /// Create a new ICMPv6 header
    pub fn new(icmp_type: Icmpv6Type) -> Self {
        Self {
            icmp_type: icmp_type as u8,
            code: 0,
            checksum: 0,
            body: [0u32; 1],
        }
    }

    /// Get ICMPv6 type as enum
    pub fn icmp_type(&self) -> Option<Icmpv6Type> {
        Icmpv6Type::from_u8(self.icmp_type)
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }

    /// Set checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be();
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ICMPV6_HEADER_SIZE {
            return None;
        }

        Some(Self {
            icmp_type: bytes[0],
            code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            body: [u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])],
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < ICMPV6_HEADER_SIZE {
            return None;
        }

        bytes[0] = self.icmp_type;
        bytes[1] = self.code;
        bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.body[0].to_be_bytes());
        Some(())
    }
}

// ============================================================================
// ICMPv6 Neighbor Discovery Structures
// ============================================================================

/// Neighbor Solicitation message
#[derive(Debug, Clone)]
pub struct NeighborSolicit {
    /// Reserved
    pub reserved: u32,
    /// Target address
    pub target: [u8; IPV6_ADDR_LEN],
    /// Options
    pub options: Vec<NdOption>,
}

impl NeighborSolicit {
    /// Create a new Neighbor Solicitation
    pub fn new(target: [u8; IPV6_ADDR_LEN]) -> Self {
        Self {
            reserved: 0,
            target,
            options: Vec::new(),
        }
    }

    /// Add source link-layer address option
    pub fn with_source_lladdr(mut self, lladdr: &[u8; 6]) -> Self {
        self.options
            .push(NdOption::SourceLinkLayerAddress(lladdr.clone()));
        self
    }

    /// Parse from bytes (after ICMPv6 header)
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            // 4 bytes reserved + 16 bytes target
            return None;
        }

        let reserved = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut target = [0u8; IPV6_ADDR_LEN];
        target.copy_from_slice(&bytes[4..20]);

        let mut options = Vec::new();
        let mut offset = 20;
        while offset + 8 <= bytes.len() {
            if let Some(opt) = NdOption::parse(&bytes[offset..]) {
                options.push(opt);
                let opt_len = opt.length() * 8;
                offset += opt_len;
            } else {
                break;
            }
        }

        Some(Self {
            reserved,
            target,
            options,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.reserved.to_be_bytes());
        bytes.extend_from_slice(&self.target);

        for opt in &self.options {
            bytes.extend_from_slice(&opt.to_bytes());
        }

        bytes
    }
}

/// Neighbor Advertisement message
#[derive(Debug, Clone)]
pub struct NeighborAdvert {
    /// Flags and reserved
    pub flags_reserved: u32,
    /// Target address
    pub target: [u8; IPV6_ADDR_LEN],
    /// Options
    pub options: Vec<NdOption>,
}

/// Neighbor Advertisement flags
pub const ND_NA_FLAG_ROUTER: u32 = 0x80000000;
pub const ND_NA_FLAG_SOLICITED: u32 = 0x40000000;
pub const ND_NA_FLAG_OVERRIDE: u32 = 0x20000000;

impl NeighborAdvert {
    /// Create a new Neighbor Advertisement
    pub fn new(target: [u8; IPV6_ADDR_LEN]) -> Self {
        Self {
            flags_reserved: 0,
            target,
            options: Vec::new(),
        }
    }

    /// Set router flag
    pub fn set_router(mut self, router: bool) -> Self {
        if router {
            self.flags_reserved |= ND_NA_FLAG_ROUTER;
        }
        self
    }

    /// Set solicited flag
    pub fn set_solicited(mut self, solicited: bool) -> Self {
        if solicited {
            self.flags_reserved |= ND_NA_FLAG_SOLICITED;
        }
        self
    }

    /// Set override flag
    pub fn set_override(mut self, override_flag: bool) -> Self {
        if override_flag {
            self.flags_reserved |= ND_NA_FLAG_OVERRIDE;
        }
        self
    }

    /// Add target link-layer address option
    pub fn with_target_lladdr(mut self, lladdr: &[u8; 6]) -> Self {
        self.options
            .push(NdOption::TargetLinkLayerAddress(lladdr.clone()));
        self
    }

    /// Check router flag
    pub fn is_router(&self) -> bool {
        (self.flags_reserved & ND_NA_FLAG_ROUTER) != 0
    }

    /// Check solicited flag
    pub fn is_solicited(&self) -> bool {
        (self.flags_reserved & ND_NA_FLAG_SOLICITED) != 0
    }

    /// Check override flag
    pub fn is_override(&self) -> bool {
        (self.flags_reserved & ND_NA_FLAG_OVERRIDE) != 0
    }

    /// Parse from bytes (after ICMPv6 header)
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }

        let flags_reserved = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut target = [0u8; IPV6_ADDR_LEN];
        target.copy_from_slice(&bytes[4..20]);

        let mut options = Vec::new();
        let mut offset = 20;
        while offset + 8 <= bytes.len() {
            if let Some(opt) = NdOption::parse(&bytes[offset..]) {
                options.push(opt);
                let opt_len = opt.length() * 8;
                offset += opt_len;
            } else {
                break;
            }
        }

        Some(Self {
            flags_reserved,
            target,
            options,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.flags_reserved.to_be_bytes());
        bytes.extend_from_slice(&self.target);

        for opt in &self.options {
            bytes.extend_from_slice(&opt.to_bytes());
        }

        bytes
    }
}

/// Router Solicitation message
#[derive(Debug, Clone)]
pub struct RouterSolicit {
    /// Reserved
    pub reserved: u32,
    /// Options
    pub options: Vec<NdOption>,
}

impl RouterSolicit {
    /// Create a new Router Solicitation
    pub fn new() -> Self {
        Self {
            reserved: 0,
            options: Vec::new(),
        }
    }

    /// Add source link-layer address option
    pub fn with_source_lladdr(mut self, lladdr: &[u8; 6]) -> Self {
        self.options
            .push(NdOption::SourceLinkLayerAddress(lladdr.clone()));
        self
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }

        let reserved = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let mut options = Vec::new();
        let mut offset = 4;
        while offset + 8 <= bytes.len() {
            if let Some(opt) = NdOption::parse(&bytes[offset..]) {
                options.push(opt);
                let opt_len = opt.length() * 8;
                offset += opt_len;
            } else {
                break;
            }
        }

        Some(Self { reserved, options })
    }
}

/// Router Advertisement message
#[derive(Debug, Clone)]
pub struct RouterAdvert {
    /// Hop limit
    pub hop_limit: u8,
    /// Flags
    pub flags: u8,
    /// Router lifetime (seconds)
    pub router_lifetime: u16,
    /// Reachable time (milliseconds)
    pub reachable_time: u32,
    /// Retransmit timer (milliseconds)
    pub retrans_timer: u32,
    /// Options
    pub options: Vec<NdOption>,
}

/// Router Advertisement flags
pub const ND_RA_FLAG_MANAGED: u8 = 0x80;
pub const ND_RA_FLAG_OTHER: u8 = 0x40;
pub const ND_RA_FLAG_HOME_AGENT: u8 = 0x20;

impl RouterAdvert {
    /// Create a new Router Advertisement
    pub fn new() -> Self {
        Self {
            hop_limit: 64,
            flags: 0,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: Vec::new(),
        }
    }

    /// Set managed address configuration flag
    pub fn set_managed(mut self, managed: bool) -> Self {
        if managed {
            self.flags |= ND_RA_FLAG_MANAGED;
        }
        self
    }

    /// Set other configuration flag
    pub fn set_other(mut self, other: bool) -> Self {
        if other {
            self.flags |= ND_RA_FLAG_OTHER;
        }
        self
    }

    /// Add source link-layer address option
    pub fn with_source_lladdr(mut self, lladdr: &[u8; 6]) -> Self {
        self.options
            .push(NdOption::SourceLinkLayerAddress(lladdr.clone()));
        self
    }

    /// Add prefix information option
    pub fn with_prefix(
        mut self,
        prefix: &[u8; 16],
        length: u8,
        valid: u32,
        preferred: u32,
    ) -> Self {
        self.options.push(NdOption::PrefixInformation(
            crate::icmpv6::PrefixInformation {
                prefix_length: length,
                flags: 0xC0, // L=1, A=1
                valid_lifetime: valid,
                preferred_lifetime: preferred,
                reserved: 0,
                prefix: *prefix,
            },
        ));
        self
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }

        let hop_limit = bytes[0];
        let flags = bytes[1];
        let router_lifetime = u16::from_be_bytes([bytes[2], bytes[3]]);
        let reachable_time = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let retrans_timer = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let mut options = Vec::new();
        let mut offset = 16;
        while offset + 8 <= bytes.len() {
            if let Some(opt) = NdOption::parse(&bytes[offset..]) {
                options.push(opt);
                let opt_len = opt.length() * 8;
                offset += opt_len;
            } else {
                break;
            }
        }

        Some(Self {
            hop_limit,
            flags,
            router_lifetime,
            reachable_time,
            retrans_timer,
            options,
        })
    }
}

// ============================================================================
// ICMPv6 Neighbor Discovery Options
// ============================================================================

/// Neighbor Discovery option
#[derive(Debug, Clone)]
pub enum NdOption {
    /// Source Link-Layer Address
    SourceLinkLayerAddress([u8; 6]),
    /// Target Link-Layer Address
    TargetLinkLayerAddress([u8; 6]),
    /// Prefix Information
    PrefixInformation(PrefixInformation),
    /// Redirected Header
    RedirectedHeader(Vec<u8>),
    /// MTU
    Mtu(MtuOption),
}

impl NdOption {
    /// Get option length in 8-byte units
    pub fn length(&self) -> u8 {
        match self {
            NdOption::SourceLinkLayerAddress(_) => 1,
            NdOption::TargetLinkLayerAddress(_) => 1,
            NdOption::PrefixInformation(_) => 4,
            NdOption::RedirectedHeader(data) => ((8 + data.len() + 7) / 8) as u8,
            NdOption::Mtu(_) => 1,
        }
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let option_type = bytes[0];
        let length = bytes[1];

        if length == 0 {
            return None; // Invalid, prevent infinite loop
        }

        let total_len = (length as usize) * 8;

        match option_type {
            1 => {
                // Source Link-Layer Address
                if total_len < 8 {
                    return None;
                }
                let mut lladdr = [0u8; 6];
                lladdr.copy_from_slice(&bytes[2..8]);
                Some(NdOption::SourceLinkLayerAddress(lladdr))
            }
            2 => {
                // Target Link-Layer Address
                if total_len < 8 {
                    return None;
                }
                let mut lladdr = [0u8; 6];
                lladdr.copy_from_slice(&bytes[2..8]);
                Some(NdOption::TargetLinkLayerAddress(lladdr))
            }
            3 => {
                // Prefix Information
                if total_len < 32 {
                    return None;
                }
                let prefix_length = bytes[2];
                let flags = bytes[3];
                let valid_lifetime = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                let preferred_lifetime =
                    u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
                let reserved = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&bytes[16..32]);
                Some(NdOption::PrefixInformation(PrefixInformation {
                    prefix_length,
                    flags,
                    valid_lifetime,
                    preferred_lifetime,
                    reserved,
                    prefix,
                }))
            }
            4 => {
                // Redirected Header
                let data_len = total_len - 8;
                Some(NdOption::RedirectedHeader(bytes[8..8 + data_len].to_vec()))
            }
            5 => {
                // MTU
                if total_len < 8 {
                    return None;
                }
                let mtu = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Some(NdOption::Mtu(MtuOption { mtu }))
            }
            _ => {
                // Unknown option, skip
                Some(NdOption::RedirectedHeader(bytes[2..total_len].to_vec()))
            }
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            NdOption::SourceLinkLayerAddress(lladdr) => {
                bytes.push(NdOptionType::SourceLinkLayerAddress as u8);
                bytes.push(1); // Length = 1 (8 bytes)
                bytes.extend_from_slice(lladdr);
                bytes.push(0); // Padding
                bytes.push(0); // Padding
            }
            NdOption::TargetLinkLayerAddress(lladdr) => {
                bytes.push(NdOptionType::TargetLinkLayerAddress as u8);
                bytes.push(1);
                bytes.extend_from_slice(lladdr);
                bytes.push(0);
                bytes.push(0);
            }
            NdOption::PrefixInformation(info) => {
                bytes.push(NdOptionType::PrefixInformation as u8);
                bytes.push(4);
                bytes.push(info.prefix_length);
                bytes.push(info.flags);
                bytes.extend_from_slice(&info.valid_lifetime.to_be_bytes());
                bytes.extend_from_slice(&info.preferred_lifetime.to_be_bytes());
                bytes.extend_from_slice(&info.reserved.to_be_bytes());
                bytes.extend_from_slice(&info.prefix);
            }
            NdOption::RedirectedHeader(data) => {
                bytes.push(NdOptionType::RedirectedHeader as u8);
                let padded_len = ((8 + data.len() + 7) / 8) as u8;
                bytes.push(padded_len);
                bytes.extend_from_slice(data);
                // Padding
                while bytes.len() % 8 != 0 {
                    bytes.push(0);
                }
            }
            NdOption::Mtu(mtu_opt) => {
                bytes.push(NdOptionType::Mtu as u8);
                bytes.push(1);
                bytes.push(0); // Reserved
                bytes.push(0);
                bytes.extend_from_slice(&mtu_opt.mtu.to_be_bytes());
            }
        }

        bytes
    }
}

/// Prefix Information option
#[derive(Debug, Clone)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved: u32,
    pub prefix: [u8; 16],
}

/// Prefix flags
pub const PREFIX_FLAG_ON_LINK: u8 = 0x80;
pub const PREFIX_FLAG_AUTO: u8 = 0x40;

/// MTU option
#[derive(Debug, Clone)]
pub struct MtuOption {
    pub mtu: u32,
}

// ============================================================================
// ICMPv6 Packet
// ============================================================================

/// ICMPv6 packet with payload
#[derive(Debug, Clone)]
pub struct Icmpv6Packet {
    /// ICMPv6 header
    pub header: Icmpv6Hdr,
    /// Message body (varies by type)
    pub body: Icmpv6Body,
    /// Raw data for checksum calculation
    pub raw_data: Vec<u8>,
}

/// ICMPv6 message body variants
#[derive(Debug, Clone)]
pub enum Icmpv6Body {
    /// Echo message
    Echo { id: u16, seq: u16, data: Vec<u8> },
    /// Destination Unreachable
    Unreachable { unused: u32, data: Vec<u8> },
    /// Packet Too Big
    PacketTooBig { mtu: u32, data: Vec<u8> },
    /// Time Exceeded
    TimeExceeded { unused: u32, data: Vec<u8> },
    /// Parameter Problem
    ParameterProblem { pointer: u32, data: Vec<u8> },
    /// Router Solicitation
    RouterSolicitation(RouterSolicit),
    /// Router Advertisement
    RouterAdvertisement(RouterAdvert),
    /// Neighbor Solicitation
    NeighborSolicitation(NeighborSolicit),
    /// Neighbor Advertisement
    NeighborAdvertisement(NeighborAdvert),
    /// Redirect
    Redirect {
        reserved: u32,
        target: [u8; 16],
        destination: [u8; 16],
        options: Vec<NdOption>,
    },
}

impl Icmpv6Packet {
    /// Create a new ICMPv6 packet
    pub fn new(icmp_type: Icmpv6Type) -> Self {
        Self {
            header: Icmpv6Hdr::new(icmp_type),
            body: Icmpv6Body::Echo {
                id: 0,
                seq: 0,
                data: Vec::new(),
            },
            raw_data: Vec::new(),
        }
    }

    /// Create an Echo Request packet
    pub fn echo_request(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::EchoRequest),
            body: Icmpv6Body::Echo { id, seq, data },
            raw_data: Vec::new(),
        }
    }

    /// Create an Echo Reply packet
    pub fn echo_reply(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::EchoReply),
            body: Icmpv6Body::Echo { id, seq, data },
            raw_data: Vec::new(),
        }
    }

    /// Create a Neighbor Solicitation packet
    pub fn neighbor_solicitation(target: [u8; 16], lladdr: Option<[u8; 6]>) -> Self {
        let body = NeighborSolicit::new(target);
        let body = if let Some(addr) = lladdr {
            NeighborSolicit::with_source_lladdr(body, &addr)
        } else {
            body
        };

        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::NeighborSolicitation),
            body: Icmpv6Body::NeighborSolicitation(body),
            raw_data: Vec::new(),
        }
    }

    /// Create a Neighbor Advertisement packet
    pub fn neighbor_advertisement(
        target: [u8; 16],
        lladdr: Option<[u8; 6]>,
        router: bool,
        solicited: bool,
        override_flag: bool,
    ) -> Self {
        let mut body = NeighborAdvert::new(target);
        body = body.set_router(router);
        body = body.set_solicited(solicited);
        body = body.set_override(override_flag);
        if let Some(addr) = lladdr {
            body = NeighborAdvert::with_target_lladdr(body, &addr);
        }

        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::NeighborAdvertisement),
            body: Icmpv6Body::NeighborAdvertisement(body),
            raw_data: Vec::new(),
        }
    }

    /// Create a Router Solicitation packet
    pub fn router_solicitation(lladdr: Option<[u8; 6]>) -> Self {
        let mut body = RouterSolicit::new();
        if let Some(addr) = lladdr {
            body = RouterSolicit::with_source_lladdr(body, &addr);
        }

        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::RouterSolicitation),
            body: Icmpv6Body::RouterSolicitation(body),
            raw_data: Vec::new(),
        }
    }

    /// Create a Router Advertisement packet
    pub fn router_advertisement(hop_limit: u8, lifetime: u16, lladdr: Option<[u8; 6]>) -> Self {
        let mut body = RouterAdvert::new();
        body.hop_limit = hop_limit;
        body.router_lifetime = lifetime;
        if let Some(addr) = lladdr {
            body = RouterAdvert::with_source_lladdr(body, &addr);
        }

        Self {
            header: Icmpv6Hdr::new(Icmpv6Type::RouterAdvertisement),
            body: Icmpv6Body::RouterAdvertisement(body),
            raw_data: Vec::new(),
        }
    }

    /// Get ICMPv6 type
    pub fn icmp_type(&self) -> Option<Icmpv6Type> {
        self.header.icmp_type()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut header_bytes = [0u8; ICMPV6_HEADER_SIZE];

        self.header.to_bytes(&mut header_bytes);

        // Add body
        match &self.body {
            Icmpv6Body::Echo { id, seq, data } => {
                header_bytes[4..6].copy_from_slice(&id.to_be_bytes());
                header_bytes[6..8].copy_from_slice(&seq.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(data);
            }
            Icmpv6Body::Unreachable { unused, data } => {
                header_bytes[4..8].copy_from_slice(&unused.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(data);
            }
            Icmpv6Body::PacketTooBig { mtu, data } => {
                header_bytes[4..8].copy_from_slice(&mtu.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(data);
            }
            Icmpv6Body::TimeExceeded { unused, data } => {
                header_bytes[4..8].copy_from_slice(&unused.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(data);
            }
            Icmpv6Body::ParameterProblem { pointer, data } => {
                header_bytes[4..8].copy_from_slice(&pointer.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(data);
            }
            Icmpv6Body::RouterSolicitation(rs) => {
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(&rs.to_bytes());
            }
            Icmpv6Body::RouterAdvertisement(ra) => {
                // RA has fixed header + options
                let mut ra_bytes = ra.to_bytes();
                header_bytes[4..8].copy_from_slice(&[
                    ra_bytes[0],
                    ra_bytes[1],
                    ra_bytes[2],
                    ra_bytes[3],
                ]);
                header_bytes[0] = Icmpv6Type::RouterAdvertisement as u8;
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(&ra_bytes[4..]);
            }
            Icmpv6Body::NeighborSolicitation(ns) => {
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(&ns.to_bytes());
            }
            Icmpv6Body::NeighborAdvertisement(na) => {
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(&na.to_bytes());
            }
            Icmpv6Body::Redirect {
                reserved,
                target,
                destination,
                options,
            } => {
                header_bytes[4..8].copy_from_slice(&reserved.to_be_bytes());
                bytes.extend_from_slice(&header_bytes);
                bytes.extend_from_slice(target);
                bytes.extend_from_slice(destination);
                for opt in options {
                    bytes.extend_from_slice(&opt.to_bytes());
                }
            }
        }

        bytes
    }
}

// ============================================================================
// ICMPv6 Checksum
// ============================================================================

/// Calculate ICMPv6 checksum
/// Uses IPv6 pseudo-header for checksum calculation
pub fn calculate_checksum(src: &[u8; 16], dst: &[u8; 16], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum source address (as 16-bit words)
    for chunk in src.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Sum destination address
    for chunk in dst.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Upper layer packet length (32 bits, upper 16 bits are 0)
    sum += ((data.len() as u32) >> 16) as u32;
    sum += (data.len() as u32) & 0xFFFF;

    // Next header (ICMPv6 = 58)
    sum += IPV6_ICMPV6_PROTO as u32;

    // Sum ICMPv6 data
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Add carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

// ============================================================================
// ICMPv6 Statistics
// ============================================================================

/// ICMPv6 statistics
#[derive(Debug, Clone, Default)]
pub struct Icmpv6Stats {
    /// Messages received
    pub in_msgs: u64,
    /// Messages sent
    pub out_msgs: u64,
    /// Input errors
    pub in_errors: u64,
    /// Checksum errors
    pub csum_errors: u64,
    /// Length errors
    pub len_errors: u64,
    /// Hop limit errors
    pub hoplim_errors: u64,
    /// Messages by type
    pub in_by_type: [u64; 256],
    pub out_by_type: [u64; 256],
}

impl Icmpv6Stats {
    /// Increment incoming message count
    pub fn inc_in(&mut self, icmp_type: u8) {
        self.in_msgs += 1;
        self.in_by_type[icmp_type as usize] += 1;
    }

    /// Increment outgoing message count
    pub fn inc_out(&mut self, icmp_type: u8) {
        self.out_msgs += 1;
        self.out_by_type[icmp_type as usize] += 1;
    }

    /// Increment checksum error count
    pub fn inc_csum_error(&mut self) {
        self.in_errors += 1;
        self.csum_errors += 1;
    }

    /// Increment length error count
    pub fn inc_len_error(&mut self) {
        self.in_errors += 1;
        self.len_errors += 1;
    }

    /// Increment hop limit error count
    pub fn inc_hoplim_error(&mut self) {
        self.in_errors += 1;
        self.hoplim_errors += 1;
    }
}

// ============================================================================
// ICMPv6 Handler (for integration with IPv6 stack)
// ============================================================================

/// ICMPv6 handler for the IPv6 stack
pub struct Icmpv6Handler {
    /// Statistics
    stats: Icmpv6Stats,
    /// Lock
    lock: Spinlock<()>,
}

impl Icmpv6Handler {
    /// Create a new ICMPv6 handler
    pub fn new() -> Self {
        Self {
            stats: Icmpv6Stats::default(),
            lock: Spinlock::new(()),
        }
    }

    /// Handle incoming ICMPv6 packet
    pub fn handle_packet(
        &mut self,
        src: &[u8; 16],
        dst: &[u8; 16],
        data: &[u8],
    ) -> Option<Icmpv6Packet> {
        let _guard = self.lock.lock();

        if data.len() < ICMPV6_MIN_SIZE {
            self.stats.inc_len_error();
            return None;
        }

        let icmp_type = data[0];
        self.stats.inc_in(icmp_type);

        // Create packet based on type
        match Icmpv6Type::from_u8(icmp_type) {
            Some(Icmpv6Type::EchoRequest) => {
                // Generate echo reply
                if data.len() >= 8 {
                    let id = u16::from_be_bytes([data[4], data[5]]);
                    let seq = u16::from_be_bytes([data[6], data[7]]);
                    let echo_data = if data.len() > 8 {
                        data[8..].to_vec()
                    } else {
                        Vec::new()
                    };
                    Some(Icmpv6Packet::echo_reply(id, seq, echo_data))
                } else {
                    None
                }
            }
            Some(Icmpv6Type::NeighborSolicitation) => {
                // Neighbor Solicitation requires special handling
                // Return None - caller should handle DAD and address resolution
                None
            }
            _ => None,
        }
    }

    /// Generate echo reply
    pub fn make_echo_reply(&self, request: &Icmpv6Packet) -> Option<Icmpv6Packet> {
        if request.icmp_type() != Some(Icmpv6Type::EchoRequest) {
            return None;
        }

        match &request.body {
            Icmpv6Body::Echo { id, seq, data } => {
                Some(Icmpv6Packet::echo_reply(*id, *seq, data.clone()))
            }
            _ => None,
        }
    }

    /// Send an ICMPv6 error message
    pub fn send_error(
        &mut self,
        _src: &[u8; 16],
        _dst: &[u8; 16],
        _packet: &Icmpv6Packet,
    ) -> Result<usize, Icmpv6Error> {
        let _guard = self.lock.lock();
        self.stats.inc_out(_packet.header.icmp_type);
        Ok(_packet.to_bytes().len())
    }

    /// Get statistics
    pub fn stats(&self) -> &Icmpv6Stats {
        &self.stats
    }
}

impl Default for Icmpv6Handler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ICMPv6 Error Types
// ============================================================================

/// ICMPv6 error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Error {
    /// Invalid argument
    InvalidArgument,
    /// No buffer space available
    NoBufferSpace,
    /// Operation not supported
    NotSupported,
    /// Operation would block
    WouldBlock,
}

impl Icmpv6Error {
    /// Get error description
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6Error::InvalidArgument => "invalid argument",
            Icmpv6Error::NoBufferSpace => "no buffer space available",
            Icmpv6Error::NotSupported => "operation not supported",
            Icmpv6Error::WouldBlock => "operation would block",
        }
    }
}

// ============================================================================
// IPv6 Address Utilities for ICMPv6
// ============================================================================

/// Generate solicited-node multicast address from unicast address
pub fn solicited_node_mcast(addr: &[u8; 16]) -> [u8; 16] {
    let mut mcast = [0u8; 16];
    mcast[0] = 0xFF;
    mcast[1] = 0x02;
    mcast[11] = 0x01;
    mcast[12] = 0xFF;
    mcast[13] = addr[13];
    mcast[14] = addr[14];
    mcast[15] = addr[15];
    mcast
}

/// Check if address is a solicited-node multicast address
pub fn is_solicited_node_mcast(addr: &[u8; 16]) -> bool {
    addr[0] == 0xFF && addr[1] == 0x02 && addr[11] == 0x01 && addr[12] == 0xFF
}

/// Get all-nodes multicast address (ff02::1)
pub fn all_nodes_mcast() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xFF;
    addr[1] = 0x02;
    addr[15] = 0x01;
    addr
}

/// Get all-routers multicast address (ff02::2)
pub fn all_routers_mcast() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xFF;
    addr[1] = 0x02;
    addr[15] = 0x02;
    addr
}

/// Check if address is unspecified (::)
pub fn is_unspecified(addr: &[u8; 16]) -> bool {
    addr.iter().all(|&b| b == 0)
}

/// Check if address is loopback (::1)
pub fn is_loopback(addr: &[u8; 16]) -> bool {
    addr[0..15].iter().all(|&b| b == 0) && addr[15] == 1
}

/// Check if address is link-local (fe80::/10)
pub fn is_link_local(addr: &[u8; 16]) -> bool {
    addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
}

/// Check if address is multicast (ff00::/8)
pub fn is_multicast(addr: &[u8; 16]) -> bool {
    addr[0] == 0xFF
}

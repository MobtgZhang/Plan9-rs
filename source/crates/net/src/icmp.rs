//! ICMPv4 (Internet Control Message Protocol) Implementation
//!
//! Implements ICMP as defined in RFC 792 for IPv4 networks.
//!
//! ## Overview
//!
//! ICMP is used by IP hosts and routers to send error messages and
//! operational information. This implementation supports the essential
//! ICMP message types required for proper network operation.
//!
//! ## Message Types
//!
//! - Echo Request/Reply (Type 0, 8): ping functionality
//! - Destination Unreachable (Type 3): error reporting
//! - Time Exceeded (Type 11): traceroute and loop detection
//! - Parameter Problem (Type 12): header error reporting
//! - Redirect (Type 5): routing optimization
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::icmp::{IcmpHdr, IcmpType, IcmpPacket};
//!
//! // Parse incoming ICMP packet
//! let packet = IcmpPacket::parse(data).unwrap();
//! match packet.icmp_type() {
//!     IcmpType::EchoRequest => { /* respond to ping */ }
//!     IcmpType::Unreachable => { /* handle unreachable error */ }
//!     _ => { /* other ICMP messages */ }
//! }
 //! ```
 

 extern crate alloc;

 use crate::common::sync::Spinlock;
 
 use alloc::vec::Vec;

 /// ICMPv4 constants
pub const ICMP_HEADER_SIZE: usize = 8;
pub const ICMP_MIN_SIZE: usize = 8;

/// ICMPv4 protocol number (for IP header)
pub const IP_ICMP_PROTO: u8 = 1;

/// ICMPv4 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    Unreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InfoRequest = 15,
    InfoReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
}

impl IcmpType {
    /// Convert from raw byte value
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::Unreachable),
            4 => Some(IcmpType::SourceQuench),
            5 => Some(IcmpType::Redirect),
            8 => Some(IcmpType::EchoRequest),
            11 => Some(IcmpType::TimeExceeded),
            12 => Some(IcmpType::ParameterProblem),
            13 => Some(IcmpType::TimestampRequest),
            14 => Some(IcmpType::TimestampReply),
            15 => Some(IcmpType::InfoRequest),
            16 => Some(IcmpType::InfoReply),
            17 => Some(IcmpType::AddressMaskRequest),
            18 => Some(IcmpType::AddressMaskReply),
            _ => None,
        }
    }

    /// Get the code range for this type
    pub fn code_range(&self) -> core::ops::RangeInclusive<u8> {
        match self {
            IcmpType::EchoReply => 0..=0,
            IcmpType::Unreachable => 0..=15,
            IcmpType::SourceQuench => 0..=0,
            IcmpType::Redirect => 0..=3,
            IcmpType::EchoRequest => 0..=0,
            IcmpType::TimeExceeded => 0..=1,
            IcmpType::ParameterProblem => 0..=2,
            IcmpType::TimestampRequest => 0..=0,
            IcmpType::TimestampReply => 0..=0,
            IcmpType::InfoRequest => 0..=0,
            IcmpType::InfoReply => 0..=0,
            IcmpType::AddressMaskRequest => 0..=0,
            IcmpType::AddressMaskReply => 0..=0,
        }
    }
}

/// ICMPv4 unreachable codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnreachableCode {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTos = 11,
    HostUnreachableForTos = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,
}

impl UnreachableCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NetworkUnreachable),
            1 => Some(Self::HostUnreachable),
            2 => Some(Self::ProtocolUnreachable),
            3 => Some(Self::PortUnreachable),
            4 => Some(Self::FragmentationNeeded),
            5 => Some(Self::SourceRouteFailed),
            6 => Some(Self::DestinationNetworkUnknown),
            7 => Some(Self::DestinationHostUnknown),
            8 => Some(Self::SourceHostIsolated),
            9 => Some(Self::NetworkAdministrativelyProhibited),
            10 => Some(Self::HostAdministrativelyProhibited),
            11 => Some(Self::NetworkUnreachableForTos),
            12 => Some(Self::HostUnreachableForTos),
            13 => Some(Self::CommunicationAdministrativelyProhibited),
            14 => Some(Self::HostPrecedenceViolation),
            15 => Some(Self::PrecedenceCutoffInEffect),
            _ => None,
        }
    }
}

/// ICMPv4 time exceeded codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeExceededCode {
    TTLExpired = 0,
    FragmentReassemblyTimeExceeded = 1,
}

impl TimeExceededCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::TTLExpired),
            1 => Some(Self::FragmentReassemblyTimeExceeded),
            _ => None,
        }
    }
}

/// ICMPv4 redirect codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedirectCode {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTosAndNetwork = 2,
    RedirectForTosAndHost = 3,
}

impl RedirectCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::RedirectForNetwork),
            1 => Some(Self::RedirectForHost),
            2 => Some(Self::RedirectForTosAndNetwork),
            3 => Some(Self::RedirectForTosAndHost),
            _ => None,
        }
    }
}

// ============================================================================
// ICMP Header
// ============================================================================

/// ICMPv4 header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IcmpHdr {
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Identifier (for Echo)
    pub icmp_id: u16,
    /// Sequence number (for Echo)
    pub seq: u16,
}

impl IcmpHdr {
    /// Create a new ICMP header
    pub fn new(icmp_type: IcmpType) -> Self {
        Self {
            icmp_type: icmp_type as u8,
            code: 0,
            checksum: 0,
            icmp_id: 0,
            seq: 0,
        }
    }

    /// Create an Echo Request header
    pub fn echo_request(id: u16, seq: u16) -> Self {
        Self {
            icmp_type: IcmpType::EchoRequest as u8,
            code: 0,
            checksum: 0,
            icmp_id: id.to_be(),
            seq: seq.to_be(),
        }
    }

    /// Create an Echo Reply header
    pub fn echo_reply(id: u16, seq: u16) -> Self {
        Self {
            icmp_type: IcmpType::EchoReply as u8,
            code: 0,
            checksum: 0,
            icmp_id: id.to_be(),
            seq: seq.to_be(),
        }
    }

    /// Get ICMP type as enum
    pub fn icmp_type(&self) -> Option<IcmpType> {
        IcmpType::from_u8(self.icmp_type)
    }

    /// Get identifier (host byte order)
    pub fn identifier(&self) -> u16 {
        u16::from_be(self.icmp_id)
    }

    /// Set identifier
    pub fn set_identifier(&mut self, id: u16) {
        self.icmp_id = id.to_be();
    }

    /// Get sequence number (host byte order)
    pub fn sequence(&self) -> u16 {
        u16::from_be(self.seq)
    }

    /// Set sequence number
    pub fn set_sequence(&mut self, seq: u16) {
        self.seq = seq.to_be();
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ICMP_HEADER_SIZE {
            return None;
        }

        Some(Self {
            icmp_type: bytes[0],
            code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            icmp_id: u16::from_be_bytes([bytes[4], bytes[5]]),
            seq: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < ICMP_HEADER_SIZE {
            return None;
        }

        bytes[0] = self.icmp_type;
        bytes[1] = self.code;
        bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.icmp_id.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.seq.to_be_bytes());
        Some(())
    }
}

// ============================================================================
// ICMP Packet
// ============================================================================

/// ICMP packet with payload
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    /// ICMP header
    pub header: IcmpHdr,
    /// ICMP payload (original IP header + first 8 bytes of original data for errors)
    pub payload: Vec<u8>,
    /// Original data (for echo requests/replies)
    pub data: Vec<u8>,
}

impl IcmpPacket {
    /// Create a new ICMP packet
    pub fn new(icmp_type: IcmpType) -> Self {
        Self {
            header: IcmpHdr::new(icmp_type),
            payload: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Create an Echo Request packet
    pub fn echo_request(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self {
            header: IcmpHdr::echo_request(id, seq),
            payload: Vec::new(),
            data,
        }
    }

    /// Create an Echo Reply packet
    pub fn echo_reply(id: u16, seq: u16, data: Vec<u8>) -> Self {
        Self {
            header: IcmpHdr::echo_reply(id, seq),
            payload: Vec::new(),
            data,
        }
    }

    /// Create a Destination Unreachable packet
    pub fn unreachable(code: UnreachableCode, original_packet: &[u8]) -> Self {
        let mut packet = Self::new(IcmpType::Unreachable);
        packet.header.code = code as u8;
        packet.payload = original_packet[..core::cmp::min(original_packet.len(), 576)].to_vec();
        packet
    }

    /// Create a Time Exceeded packet
    pub fn time_exceeded(code: TimeExceededCode, original_packet: &[u8]) -> Self {
        let mut packet = Self::new(IcmpType::TimeExceeded);
        packet.header.code = code as u8;
        packet.payload = original_packet[..core::cmp::min(original_packet.len(), 576)].to_vec();
        packet
    }

    /// Create a Parameter Problem packet
    pub fn parameter_problem(pointer: u8, original_packet: &[u8]) -> Self {
        let mut packet = Self::new(IcmpType::ParameterProblem);
        packet.header.code = pointer;
        packet.payload = original_packet[..core::cmp::min(original_packet.len(), 576)].to_vec();
        packet
    }

    /// Parse ICMP packet from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ICMP_MIN_SIZE {
            return None;
        }

        let header = IcmpHdr::from_bytes(bytes)?;

        // Data starts after header
        let data_start = ICMP_HEADER_SIZE;
        let data = if bytes.len() > data_start {
            bytes[data_start..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            header,
            payload: Vec::new(),
            data,
        })
    }

    /// Get ICMP type
    pub fn icmp_type(&self) -> Option<IcmpType> {
        self.header.icmp_type()
    }

    /// Get total packet size
    pub fn size(&self) -> usize {
        ICMP_HEADER_SIZE + self.payload.len() + self.data.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        let mut header_bytes = [0u8; ICMP_HEADER_SIZE];
        self.header.to_bytes(&mut header_bytes);

        // Calculate checksum
        let checksum = calculate_checksum(&header_bytes, &self.payload, &self.data);
        header_bytes[2] = (checksum >> 8) as u8;
        header_bytes[3] = checksum as u8;

        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Create echo reply from echo request
    pub fn make_echo_reply(&self) -> Option<Self> {
        if self.header.icmp_type != IcmpType::EchoRequest as u8 {
            return None;
        }

        Some(Self {
            header: IcmpHdr::echo_reply(self.header.identifier(), self.header.sequence()),
            payload: Vec::new(),
            data: self.data.clone(),
        })
    }
}

// ============================================================================
// ICMP Statistics
// ============================================================================

/// ICMP statistics
pub struct IcmpStats {
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
    /// Messages by type
    pub in_by_type: [u64; 256],
    pub out_by_type: [u64; 256],
}

impl Default for IcmpStats {
    fn default() -> Self {
        Self {
            in_msgs: 0,
            out_msgs: 0,
            in_errors: 0,
            csum_errors: 0,
            len_errors: 0,
            in_by_type: [0; 256],
            out_by_type: [0; 256],
        }
    }
}

impl core::fmt::Debug for IcmpStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IcmpStats")
            .field("in_msgs", &self.in_msgs)
            .field("out_msgs", &self.out_msgs)
            .field("in_errors", &self.in_errors)
            .finish()
    }
}

impl Clone for IcmpStats {
    fn clone(&self) -> Self {
        Self {
            in_msgs: self.in_msgs,
            out_msgs: self.out_msgs,
            in_errors: self.in_errors,
            csum_errors: self.csum_errors,
            len_errors: self.len_errors,
            in_by_type: self.in_by_type,
            out_by_type: self.out_by_type,
        }
    }
}

impl IcmpStats {
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
}

// ============================================================================
// ICMP Socket
// ============================================================================

/// ICMP socket for sending and receiving ICMP messages
pub struct IcmpSocket {
    /// Socket identifier (port-like)
    identifier: u16,
    /// Bound identifier
    bound: bool,
    /// Statistics
    stats: IcmpStats,
    /// Lock
    lock: Spinlock<()>,
}

impl IcmpSocket {
    /// Create a new ICMP socket
    pub fn new() -> Self {
        Self {
            identifier: 0,
            bound: false,
            stats: IcmpStats::default(),
            lock: Spinlock::new(()),
        }
    }

    /// Bind to an identifier (typically used for ICMP echo)
    pub fn bind(&mut self, identifier: u16) -> Result<(), IcmpError> {
        let _guard = self.lock.lock();
        if self.bound {
            return Err(IcmpError::AlreadyBound);
        }
        self.identifier = identifier;
        self.bound = true;
        Ok(())
    }

    /// Send an ICMP packet
    pub fn send(&mut self, packet: &IcmpPacket) -> Result<usize, IcmpError> {
        let _guard = self.lock.lock();

        let icmp_type = packet.header.icmp_type;
        self.stats.inc_out(icmp_type);

        Ok(packet.size())
    }

    /// Receive an ICMP packet
    pub fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, IcmpError> {
        let _guard = self.lock.lock();

        // In a real implementation, this would block waiting for data
        Err(IcmpError::WouldBlock)
    }

    /// Handle incoming ICMP packet
    pub fn handle_packet(&mut self, packet: &IcmpPacket) -> Option<IcmpPacket> {
        let _guard = self.lock.lock();

        let icmp_type = packet.header.icmp_type;
        self.stats.inc_in(icmp_type);

        match packet.icmp_type() {
            Some(IcmpType::EchoRequest) => {
                // Generate echo reply
                if self.bound {
                    // Only respond if identifier matches
                    if packet.header.identifier() == self.identifier {
                        packet.make_echo_reply()
                    } else {
                        None
                    }
                } else {
                    // Respond to all echo requests when not bound
                    packet.make_echo_reply()
                }
            }
            _ => None,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Get identifier
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Check if bound
    pub fn is_bound(&self) -> bool {
        self.bound
    }
}

impl Default for IcmpSocket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ICMP Port Table (for raw ICMP sockets)
// ============================================================================

/// ICMP port table for managing ICMP identifiers
pub struct IcmpPortTable {
    /// Sockets by identifier
    sockets: [Option<alloc::boxed::Box<IcmpSocket>>; 65536],
}

impl IcmpPortTable {
    /// Create a new port table
    pub fn new() -> Self {
        Self {
            sockets: [const { None }; 65536],
        }
    }

    /// Allocate a socket with identifier
    pub fn allocate(&mut self, identifier: u16) -> Result<&mut IcmpSocket, IcmpError> {
        if self.sockets[identifier as usize].is_some() {
            return Err(IcmpError::AddressInUse);
        }

        let socket = alloc::boxed::Box::new(IcmpSocket::new());
        self.sockets[identifier as usize] = Some(socket);

        // Get mutable reference
        let socket_ptr =
            &mut self.sockets[identifier as usize] as *mut Option<alloc::boxed::Box<IcmpSocket>>;
        let socket_ref = unsafe { &mut *socket_ptr }.as_mut().unwrap();

        Ok(socket_ref)
    }

    /// Get socket by identifier
    pub fn get(&self, identifier: u16) -> Option<&IcmpSocket> {
        self.sockets[identifier as usize].as_ref().map(|b| b.as_ref())
    }
    
    /// Get mutable socket by identifier
    pub fn get_mut(&mut self, identifier: u16) -> Option<&mut IcmpSocket> {
        self.sockets[identifier as usize].as_mut().map(|b| b.as_mut())
    }

    /// Release identifier
    pub fn release(&mut self, identifier: u16) {
        self.sockets[identifier as usize] = None;
    }
}

impl Default for IcmpPortTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ICMP Error Types
// ============================================================================

/// ICMP error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// Operation already in progress
    AlreadyBound,
    /// Address already in use
    AddressInUse,
    /// Operation would block
    WouldBlock,
    /// Invalid argument
    InvalidArgument,
    /// No buffer space available
    NoBufferSpace,
    /// Operation not supported
    NotSupported,
    /// Protocol not available
    ProtoNotAvailable,
}

impl IcmpError {
    /// Get error description
    pub fn as_str(&self) -> &'static str {
        match self {
            IcmpError::AlreadyBound => "ICMP socket already bound",
            IcmpError::AddressInUse => "ICMP identifier already in use",
            IcmpError::WouldBlock => "operation would block",
            IcmpError::InvalidArgument => "invalid argument",
            IcmpError::NoBufferSpace => "no buffer space available",
            IcmpError::NotSupported => "operation not supported",
            IcmpError::ProtoNotAvailable => "protocol not available",
        }
    }
}

// ============================================================================
// Checksum Calculation
// ============================================================================

/// Calculate ICMP checksum
pub fn calculate_checksum(header: &[u8; ICMP_HEADER_SIZE], payload: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum header words
    sum += u16::from_be_bytes([header[0], header[1]]) as u32;
    sum += u16::from_be_bytes([header[4], header[5]]) as u32;
    sum += u16::from_be_bytes([header[6], header[7]]) as u32;

    // Sum payload
    for chunk in payload.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Sum data
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

/// Verify ICMP checksum
pub fn verify_checksum(header: &IcmpHdr, payload: &[u8], data: &[u8]) -> bool {
    let mut header_bytes = [0u8; ICMP_HEADER_SIZE];
    header.to_bytes(&mut header_bytes);
    // Zero checksum for verification
    header_bytes[2] = 0;
    header_bytes[3] = 0;

    let computed = calculate_checksum(&header_bytes, payload, data);
    computed == 0 || computed == 0xFFFF
}

/// Calculate ICMP checksum from raw bytes
pub fn checksum_from_bytes(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

// ============================================================================
// ICMP Message Builder
// ============================================================================

/// Builder for constructing ICMP error messages
pub struct IcmpMessageBuilder {
    icmp_type: IcmpType,
    code: u8,
    pointer: Option<u8>,
    original_packet: Vec<u8>,
}

impl IcmpMessageBuilder {
    /// Create a new builder
    pub fn new(icmp_type: IcmpType) -> Self {
        Self {
            icmp_type,
            code: 0,
            pointer: None,
            original_packet: Vec::new(),
        }
    }

    /// Set the ICMP code
    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// Set pointer (for Parameter Problem)
    pub fn with_pointer(mut self, pointer: u8) -> Self {
        self.pointer = Some(pointer);
        self
    }

    /// Set original packet (included in error messages)
    pub fn with_original_packet(mut self, packet: &[u8]) -> Self {
        // RFC 792: include IP header + first 8 bytes of original data
        // but we include up to 576 bytes as per RFC 1122
        self.original_packet = packet[..core::cmp::min(packet.len(), 576)].to_vec();
        self
    }

    /// Build the ICMP packet
    pub fn build(self) -> IcmpPacket {
        let mut packet = IcmpPacket::new(self.icmp_type);
        packet.header.code = self.code;

        if let Some(ptr) = self.pointer {
            packet.payload.push(ptr);
        }

        packet.payload.extend_from_slice(&self.original_packet);
        packet
    }
}

// ============================================================================
// ICMP Protocol Handler (for integration with IP stack)
// ============================================================================

/// ICMP protocol handler for the IP stack
pub struct IcmpHandler {
    /// Statistics
    stats: IcmpStats,
    /// Port table
    port_table: IcmpPortTable,
    /// Lock
    lock: Spinlock<()>,
}

impl IcmpHandler {
    /// Create a new ICMP handler
    pub fn new() -> Self {
        Self {
            stats: IcmpStats::default(),
            port_table: IcmpPortTable::new(),
            lock: Spinlock::new(()),
        }
    }

    /// Handle incoming ICMP packet
    pub fn handle_packet(&mut self, data: &[u8]) -> Option<IcmpPacket> {
        let _guard = self.lock.lock();

        // Parse packet
        let packet = IcmpPacket::parse(data)?;

        // Update statistics
        let icmp_type = packet.header.icmp_type;
        self.stats.inc_in(icmp_type);

        // Check for valid checksum
        if !verify_checksum(&packet.header, &[], &packet.data) {
            self.stats.inc_csum_error();
            return None;
        }

        // Handle based on type
        match packet.icmp_type() {
            Some(IcmpType::EchoRequest) => {
                // Find matching socket or generate auto-reply
                if let Some(socket) = self.port_table.get_mut(packet.header.identifier()) {
                    socket.handle_packet(&packet)
                } else {
                    // Generate reply for unbound socket (ping response)
                    packet.make_echo_reply()
                }
            }
            Some(IcmpType::Unreachable) => {
                // Notify upper layer protocol (TCP/UDP) about unreachable destination
                self.notify_upper_protocol(&packet);
                None
            }
            Some(IcmpType::TimeExceeded) => {
                // Could trigger path MTU discovery or routing changes
                None
            }
            _ => None,
        }
    }

    /// Send an ICMP error message
    pub fn send_error(&mut self, _dest: u32, packet: &IcmpPacket) -> Result<usize, IcmpError> {
        let _guard = self.lock.lock();

        self.stats.inc_out(packet.header.icmp_type);
        Ok(packet.size())
    }

    /// Send ICMP echo request
    pub fn send_echo_request(&mut self, _dest: u32, id: u16, seq: u16, data: Vec<u8>) -> IcmpPacket {
        let packet = IcmpPacket::echo_request(id, seq, data);
        self.stats.inc_out(IcmpType::EchoRequest as u8);
        packet
    }

    /// Notify upper layer protocol about ICMP error
    fn notify_upper_protocol(&self, packet: &IcmpPacket) {
        // In a full implementation, this would look up the corresponding
        // TCP or UDP socket and notify it about the error
        match IcmpType::from_u8(packet.header.icmp_type) {
            Some(IcmpType::Unreachable) => {
                let code = UnreachableCode::from_u8(packet.header.code);
                match code {
                    Some(UnreachableCode::PortUnreachable) => {
                        // Notify UDP
                    }
                    Some(UnreachableCode::FragmentationNeeded) => {
                        // Trigger PMTU discovery
                    }
                    _ => {}
                }
            }
            Some(IcmpType::TimeExceeded) => {
                // Notify TCP about routing loop
            }
            _ => {}
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Get port table
    pub fn port_table(&mut self) -> &mut IcmpPortTable {
        &mut self.port_table
    }
}

impl Default for IcmpHandler {
    fn default() -> Self {
        Self::new()
    }
}

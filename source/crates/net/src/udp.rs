//! UDP Protocol Implementation
//!
//! Implements User Datagram Protocol for connectionless packet delivery.


extern crate alloc;

use crate::common::{Error, Result};
use crate::ipv4::proto;
use alloc::boxed::Box;
use alloc::vec::Vec;

// ============================================================================
// UDP Constants
// ============================================================================

/// UDP header length
pub const UDP_HEADER_LEN: usize = 8;

/// UDP port numbers
pub mod port {
    pub const DNS: u16 = 53;
    pub const BOOTPS: u16 = 67; // DHCP server
    pub const BOOTPC: u16 = 68; // DHCP client
    pub const NTP: u16 = 123;
    pub const MDNS: u16 = 5353;
}

// ============================================================================
// UDP Header
// ============================================================================

/// UDP header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UdpHdr {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// UDP length (header + data)
    pub length: u16,
    /// UDP checksum
    pub checksum: u16,
}

impl UdpHdr {
    /// Create new header
    pub fn new() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            length: (UDP_HEADER_LEN as u16).to_be(),
            checksum: 0,
        }
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < UDP_HEADER_LEN {
            return None;
        }

        Some(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < UDP_HEADER_LEN {
            return None;
        }

        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.length.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        Some(())
    }

    /// Get payload
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        if packet.len() < UDP_HEADER_LEN {
            None
        } else {
            Some(&packet[UDP_HEADER_LEN..])
        }
    }

    /// Get source port
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }

    /// Get destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }

    /// Get length
    pub fn length(&self) -> u16 {
        u16::from_be(self.length)
    }
}

// ============================================================================
// UDP Packet
// ============================================================================

/// UDP packet
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// UDP header
    pub header: UdpHdr,
    /// Payload data
    pub payload: Vec<u8>,
}

impl UdpPacket {
    /// Create new UDP packet
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        let mut hdr = UdpHdr::new();
        hdr.src_port = src_port.to_be();
        hdr.dst_port = dst_port.to_be();

        Self {
            header: hdr,
            payload: Vec::new(),
        }
    }

    /// Create packet with payload
    pub fn with_payload(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        let mut pkt = Self::new(src_port, dst_port);
        pkt.set_payload(payload);
        pkt
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = UdpHdr::from_bytes(bytes)?;
        let length = header.length() as usize;

        if bytes.len() < length {
            return None;
        }

        let payload = if UDP_HEADER_LEN < length {
            bytes[UDP_HEADER_LEN..length].to_vec()
        } else {
            Vec::new()
        };

        Some(Self { header, payload })
    }

    /// Set payload
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
        let length = (UDP_HEADER_LEN + self.payload.len()) as u16;
        self.header.length = length.to_be();
    }

    /// Get total size
    pub fn size(&self) -> usize {
        UDP_HEADER_LEN + self.payload.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.size();
        let mut bytes = Vec::with_capacity(size);
        bytes.resize(size, 0);
        self.header.to_bytes(&mut bytes).unwrap_or(());
        bytes[UDP_HEADER_LEN..].copy_from_slice(&self.payload);
        bytes
    }

    /// Calculate checksum
    pub fn calculate_checksum(&self, src_ip: [u8; 4], dst_ip: [u8; 4]) -> u16 {
        let len = self.size() as u16;
        let data = self.payload.as_slice();
        crate::ipv4::checksum_pseudo(data, src_ip, dst_ip, proto::UDP, len)
    }

    /// Finalize packet (set checksum)
    pub fn finalize(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4]) {
        let csum = self.calculate_checksum(src_ip, dst_ip);
        self.header.checksum = csum.to_be();
    }
}

// ============================================================================
// UDP Socket
// ============================================================================

/// UDP socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    Closed,
    Open,
}

/// UDP socket
pub struct UdpSocket {
    /// Local port
    local_port: u16,
    /// Remote port (0 if not connected)
    remote_port: u16,
    /// Remote IP (0 if not connected)
    remote_ip: u32,
    /// Socket state
    state: UdpState,
    /// Receive buffer
    recv_buf: Vec<u8>,
    /// Receive queue
    recv_queue: Vec<UdpPacket>,
}

impl UdpSocket {
    /// Create new UDP socket
    pub fn new() -> Self {
        Self {
            local_port: 0,
            remote_port: 0,
            remote_ip: 0,
            state: UdpState::Closed,
            recv_buf: Vec::new(),
            recv_queue: Vec::new(),
        }
    }

    /// Currently buffered bytes that have not yet been consumed by `recv`.
    pub fn recv_buf_len(&self) -> usize {
        self.recv_buf.len()
    }

    /// Append a chunk to the receive buffer (used by the demuxer).
    pub fn push_recv_buf(&mut self, chunk: &[u8]) {
        self.recv_buf.extend_from_slice(chunk);
    }

    /// Bind to local port
    pub fn bind(&mut self, port: u16) -> Result<()> {
        if self.state != UdpState::Closed {
            return Err(Error::Ealready);
        }
        self.local_port = port;
        self.state = UdpState::Open;
        Ok(())
    }

    /// Connect to remote address
    pub fn connect(&mut self, ip: u32, port: u16) -> Result<()> {
        if self.state != UdpState::Open {
            return Err(Error::Enotconn);
        }
        self.remote_ip = ip;
        self.remote_port = port;
        Ok(())
    }

    /// Send data
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != UdpState::Open {
            return Err(Error::Enotconn);
        }
        // In real implementation, would send to network stack
        Ok(data.len())
    }

    /// Receive data
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != UdpState::Open {
            return Err(Error::Enotconn);
        }

        if let Some(pkt) = self.recv_queue.pop() {
            let len = pkt.payload.len().min(buf.len());
            buf[..len].copy_from_slice(&pkt.payload[..len]);
            Ok(len)
        } else {
            Err(Error::Eagain)
        }
    }

    /// Handle incoming packet
    pub fn handle_packet(&mut self, packet: &UdpPacket) {
        if self.state == UdpState::Open {
            if self.local_port == 0 || packet.header.dst_port() == self.local_port {
                self.recv_queue.push(packet.clone());
            }
        }
    }

    /// Close socket
    pub fn close(&mut self) {
        self.state = UdpState::Closed;
        self.recv_queue.clear();
    }

    /// Get local port
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Check if socket is open
    pub fn is_open(&self) -> bool {
        self.state == UdpState::Open
    }
}

impl Default for UdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UDP Port Manager
// ============================================================================

/// UDP port allocation table
pub struct UdpPortTable {
    ports: [Option<Box<UdpSocket>>; 65536],
    next_port: u16,
}

impl UdpPortTable {
    /// Create new port table
    pub fn new() -> Self {
        Self {
            ports: [const { None }; 65536],
            next_port: 49152, // Start from dynamic ports
        }
    }

    /// Allocate a socket
    pub fn allocate(&mut self, port: Option<u16>) -> Result<(u16, &'static mut UdpSocket)> {
        let p = match port {
            Some(p) => {
                if self.ports[p as usize].is_some() {
                    return Err(Error::Eaddrinuse);
                }
                p
            }
            None => {
                // Find next available port
                let start = self.next_port;
                loop {
                    if self.ports[self.next_port as usize].is_none() {
                        break;
                    }
                    self.next_port = self.next_port.wrapping_add(1);
                    if self.next_port == start {
                        return Err(Error::Eaddrinuse);
                    }
                }
                self.next_port
            }
        };

        let socket = Box::new(UdpSocket::new());
        self.ports[p as usize] = Some(socket);

        // Get mutable reference
        let socket_ptr = &mut self.ports[p as usize] as *mut Option<Box<UdpSocket>>;
        let socket_ref = unsafe { &mut *socket_ptr }.as_mut().unwrap();

        Ok((p, socket_ref))
    }

    /// Get socket by port
    pub fn get(&self, port: u16) -> Option<&UdpSocket> {
        match &self.ports[port as usize] {
            Some(socket) => Some(socket),
            None => None,
        }
    }

    /// Release port
    pub fn release(&mut self, port: u16) {
        self.ports[port as usize] = None;
    }
}

impl Default for UdpPortTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UDP IPv6 Support
// ============================================================================

/// IPv6 address length
pub const IPV6_ADDR_LEN: usize = 16;

/// IPv6 pseudo-header for checksum calculation
#[derive(Debug, Clone, Copy)]
pub struct Udpv6PseudoHeader {
    /// Source address
    pub src: [u8; IPV6_ADDR_LEN],
    /// Destination address
    pub dst: [u8; IPV6_ADDR_LEN],
    /// UDP length
    pub length: u32,
}

impl Udpv6PseudoHeader {
    /// Create a new pseudo-header
    pub fn new(src: &[u8; IPV6_ADDR_LEN], dst: &[u8; IPV6_ADDR_LEN], length: u32) -> Self {
        Self {
            src: *src,
            dst: *dst,
            length,
        }
    }

    /// Calculate checksum over this pseudo-header and data
    pub fn checksum(&self, data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Sum source address (as 16-bit words)
        for chunk in self.src.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        // Sum destination address
        for chunk in self.dst.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        // Upper layer packet length
        sum += (self.length >> 16) as u32;
        sum += self.length & 0xFFFF;

        // Next header (UDP = 17)
        sum += 17u32;

        // Sum UDP data
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
}

/// IPv6-enabled UDP packet
#[derive(Debug, Clone)]
pub struct Udpv6Packet {
    /// IPv6 pseudo-header for checksum
    pub pseudo_header: Option<Udpv6PseudoHeader>,
    /// Base UDP packet
    pub base: UdpPacket,
}

impl Udpv6Packet {
    /// Create a new IPv6 UDP packet
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            pseudo_header: None,
            base: UdpPacket::new(src_port, dst_port),
        }
    }

    /// Create packet with payload
    pub fn with_payload(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        let mut pkt = Self::new(src_port, dst_port);
        pkt.base.set_payload(payload);
        pkt
    }

    /// Parse from bytes with IPv6 pseudo-header
    pub fn parse_ipv6(
        bytes: &[u8],
        src: &[u8; IPV6_ADDR_LEN],
        dst: &[u8; IPV6_ADDR_LEN],
    ) -> Option<Self> {
        let base = UdpPacket::parse(bytes)?;

        let pseudo_header = Udpv6PseudoHeader::new(src, dst, bytes.len() as u32);

        Some(Self {
            pseudo_header: Some(pseudo_header),
            base,
        })
    }

    /// Calculate IPv6 checksum
    pub fn calculate_checksum_ipv6(&self) -> u16 {
        if let Some(ph) = &self.pseudo_header {
            let data = self.base.to_bytes();
            ph.checksum(&data)
        } else {
            0
        }
    }

    /// Finalize packet with IPv6 checksum
    pub fn finalize_ipv6(&mut self, src: &[u8; IPV6_ADDR_LEN], dst: &[u8; IPV6_ADDR_LEN]) {
        let total_len = self.base.size() as u32;
        self.pseudo_header = Some(Udpv6PseudoHeader::new(src, dst, total_len));
        let csum = self.calculate_checksum_ipv6();
        self.base.header.checksum = csum.to_be();
    }

    /// Get header
    pub fn header(&self) -> &UdpHdr {
        &self.base.header
    }

    /// Get payload
    pub fn payload(&self) -> &[u8] {
        &self.base.payload
    }
}

// ============================================================================
// Dual-Stack UDP Socket
// ============================================================================

/// Dual-stack UDP socket supporting both IPv4 and IPv6
pub struct DualStackUdpSocket {
    /// Base socket
    base: UdpSocket,
    /// IPv6 mode
    is_ipv6: bool,
    /// IPv6 local address
    local_addr_v6: Option<[u8; IPV6_ADDR_LEN]>,
    /// IPv6 remote address
    remote_addr_v6: Option<[u8; IPV6_ADDR_LEN]>,
    /// Receive queue for IPv6 packets
    recv_queue_v6: Vec<Udpv6Packet>,
}

impl DualStackUdpSocket {
    /// Create new dual-stack socket
    pub fn new() -> Self {
        Self {
            base: UdpSocket::new(),
            is_ipv6: false,
            local_addr_v6: None,
            remote_addr_v6: None,
            recv_queue_v6: Vec::new(),
        }
    }

    /// Bind to IPv4 port
    pub fn bind_ipv4(&mut self, port: u16) -> Result<()> {
        self.base.bind(port)
    }

    /// Bind to IPv6 address and port
    pub fn bind_ipv6(&mut self, addr: &[u8; IPV6_ADDR_LEN], port: u16) -> Result<()> {
        self.is_ipv6 = true;
        self.local_addr_v6 = Some(*addr);
        self.base.bind(port)
    }

    /// Connect to IPv4 address
    pub fn connect_ipv4(&mut self, ip: u32, port: u16) -> Result<()> {
        self.is_ipv6 = false;
        self.base.connect(ip, port)
    }

    /// Connect to IPv6 address
    pub fn connect_ipv6(&mut self, addr: &[u8; IPV6_ADDR_LEN], port: u16) -> Result<()> {
        self.is_ipv6 = true;
        self.remote_addr_v6 = Some(*addr);
        self.base.connect(0, port) // IPv4 remote_ip is not used for IPv6
    }

    /// Send data (IPv4)
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        self.base.send(data)
    }

    /// Send data to IPv6 address
    pub fn send_to_ipv6(&mut self, addr: &[u8; IPV6_ADDR_LEN], data: &[u8]) -> Result<usize> {
        // In a real implementation, this would send to the IPv6 stack
        let _ = addr;
        Ok(data.len())
    }

    /// Receive IPv4 data
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.base.recv(buf)
    }

    /// Receive IPv6 data
    pub fn recv_ipv6(&mut self, buf: &mut [u8]) -> Result<(usize, Option<[u8; IPV6_ADDR_LEN]>)> {
        if let Some(pkt) = self.recv_queue_v6.pop() {
            let len = pkt.payload().len().min(buf.len());
            buf[..len].copy_from_slice(&pkt.payload()[..len]);
            let src = pkt.pseudo_header.map(|ph| ph.src);
            Ok((len, src))
        } else {
            Err(Error::Eagain)
        }
    }

    /// Handle incoming IPv6 packet
    pub fn handle_ipv6_packet(&mut self, packet: Udpv6Packet) {
        if self.is_ipv6 {
            self.recv_queue_v6.push(packet);
        }
    }

    /// Check if using IPv6
    pub fn is_ipv6(&self) -> bool {
        self.is_ipv6
    }

    /// Get local IPv6 address
    pub fn local_addr_v6(&self) -> Option<[u8; IPV6_ADDR_LEN]> {
        self.local_addr_v6
    }

    /// Close socket
    pub fn close(&mut self) {
        self.base.close();
        self.recv_queue_v6.clear();
    }

    /// Get local port
    pub fn local_port(&self) -> u16 {
        self.base.local_port()
    }
}

impl Default for DualStackUdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

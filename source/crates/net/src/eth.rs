//! Ethernet Frame Handling
//!
//! Implements Ethernet frame parsing and construction.


extern crate alloc;

// ============================================================================
// Ethernet Constants
// ============================================================================

/// Ethernet frame types
pub mod ether_type {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const RARP: u16 = 0x8035;
    pub const VLAN: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    pub const LLDP: u16 = 0x88CC;
    pub const EAPOL: u16 = 0x888E;
}

/// Maximum Ethernet frame size
pub const ETH_MTU: usize = 1500;

/// Minimum Ethernet frame size
pub const ETH_MIN_SIZE: usize = 64;

/// Ethernet header size
pub const ETH_HEADER_SIZE: usize = 14;

/// Ethernet address length
pub const ETH_ADDR_LEN: usize = 6;

/// Broadcast MAC address
pub const ETH_BROADCAST: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

// ============================================================================
// Ethernet Header
// ============================================================================

/// Ethernet header (packed)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct EthHdr {
    /// Destination MAC address
    pub dst: [u8; ETH_ADDR_LEN],
    /// Source MAC address
    pub src: [u8; ETH_ADDR_LEN],
    /// EtherType (network layer protocol)
    pub ether_type: u16,
}

impl EthHdr {
    /// Create a new Ethernet header
    pub fn new(dst: [u8; 6], src: [u8; 6], ether_type: u16) -> Self {
        Self {
            dst,
            src,
            ether_type: ether_type.to_be(),
        }
    }

    /// Parse header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ETH_HEADER_SIZE {
            return None;
        }

        let mut hdr = Self::default();
        hdr.dst.copy_from_slice(&bytes[0..6]);
        hdr.src.copy_from_slice(&bytes[6..12]);
        hdr.ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
        Some(hdr)
    }

    /// Write header to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < ETH_HEADER_SIZE {
            return None;
        }

        bytes[0..6].copy_from_slice(&self.dst);
        bytes[6..12].copy_from_slice(&self.src);
        bytes[12..14].copy_from_slice(&self.ether_type.to_be_bytes());
        Some(())
    }

    /// Get the payload as a slice
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let start = ETH_HEADER_SIZE;
        if start > packet.len() {
            None
        } else {
            Some(&packet[start..])
        }
    }

    /// Get the EtherType
    pub fn ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }
}

// ============================================================================
// Ethernet Frame
// ============================================================================

/// Complete Ethernet frame with header and payload
#[derive(Debug, Clone)]
pub struct EthFrame {
    /// Ethernet header
    pub header: EthHdr,
    /// Frame payload
    pub payload: alloc::vec::Vec<u8>,
}

impl EthFrame {
    /// Create a new frame
    pub fn new(dst: [u8; 6], src: [u8; 6], ether_type: u16) -> Self {
        Self {
            header: EthHdr::new(dst, src, ether_type),
            payload: alloc::vec::Vec::new(),
        }
    }

    /// Parse a frame from raw bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = EthHdr::from_bytes(bytes)?;
        let payload_start = ETH_HEADER_SIZE;
        let payload = if payload_start < bytes.len() {
            bytes[payload_start..].to_vec()
        } else {
            alloc::vec::Vec::new()
        };

        Some(Self { header, payload })
    }

    /// Get the total frame size
    pub fn frame_size(&self) -> usize {
        ETH_HEADER_SIZE + self.payload.len()
    }

    /// Convert frame to bytes (for transmission)
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let size = self.frame_size();
        let mut bytes = alloc::vec::Vec::with_capacity(size);
        bytes.resize(size, 0);
        self.header.to_bytes(&mut bytes).unwrap_or(());
        bytes[ETH_HEADER_SIZE..].copy_from_slice(&self.payload);
        bytes
    }

    /// Check if destination is broadcast
    pub fn is_broadcast(&self) -> bool {
        self.header.dst == ETH_BROADCAST
    }

    /// Check if destination matches MAC address
    pub fn is_for(&self, mac: [u8; 6]) -> bool {
        self.header.dst == mac || self.is_broadcast()
    }
}

// ============================================================================
// Ethernet Address Utilities
// ============================================================================

/// Ethernet address operations
pub mod addr {
    use super::*;

    /// Check if MAC address is broadcast
    pub fn is_broadcast(addr: [u8; 6]) -> bool {
        addr == ETH_BROADCAST
    }

    /// Check if MAC address is multicast
    pub fn is_multicast(addr: [u8; 6]) -> bool {
        (addr[0] & 1) != 0
    }

    /// Check if MAC address is unicast
    pub fn is_unicast(addr: [u8; 6]) -> bool {
        !is_multicast(addr) && !is_broadcast(addr)
    }

    /// Check if MAC address is null/zero
    pub fn is_null(addr: [u8; 6]) -> bool {
        addr == [0, 0, 0, 0, 0, 0]
    }

    /// Format MAC address as string
    pub fn format_mac(addr: [u8; 6]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        write!(
            s,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
        )
        .ok();
        s
    }

    /// Parse MAC address from string
    pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
        let parts: alloc::vec::Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut addr = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            addr[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(addr)
    }
}

// ============================================================================
// CRC32 for Ethernet
// ============================================================================

/// Calculate Ethernet CRC32
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;

    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Append CRC32 to data
pub fn append_crc(data: &mut alloc::vec::Vec<u8>) {
    let crc = crc32(data);
    data.extend_from_slice(&crc.to_le_bytes());
}

/// Verify CRC32 of received frame
pub fn verify_crc(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let received = u32::from_le_bytes([
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ]);
    let calculated = crc32(&data[..data.len() - 4]);
    received == calculated
}

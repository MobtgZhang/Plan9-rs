//! IPv4 Protocol Implementation
//!
//! Implements IPv4 packet handling, routing, and checksum calculation.


extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// IPv4 Constants
// ============================================================================

/// IPv4 version
pub const IPV4_VERSION: u8 = 4;

/// IPv4 header length (without options)
pub const IPV4_HEADER_LEN: usize = 20;

/// IPv4 maximum header length (with options)
pub const IPV4_MAX_HEADER_LEN: usize = 60;

/// IPv4 maximum packet size
pub const IPV4_MAX_PACKET: usize = 65535;

/// IPv4 MTU
pub const IPV4_MTU: usize = 1500;

/// Protocol numbers
pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

// ============================================================================
// IPv4 Header
// ============================================================================

/// IPv4 header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Ipv4Hdr {
    /// Version and header length
    pub ver_ihl: u8,
    /// Type of service
    pub tos: u8,
    /// Total length
    pub total_len: u16,
    /// Identification
    pub ident: u16,
    /// Flags and fragment offset
    pub flags_frag: u16,
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub proto: u8,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src: [u8; 4],
    /// Destination address
    pub dst: [u8; 4],
}

impl Ipv4Hdr {
    /// Create new header
    pub fn new() -> Self {
        Self {
            ver_ihl: (IPV4_VERSION << 4) | (IPV4_HEADER_LEN as u8 / 4),
            tos: 0,
            total_len: (IPV4_HEADER_LEN as u16).to_be(),
            ident: 0,
            flags_frag: 0,
            ttl: 64,
            proto: 0,
            checksum: 0,
            src: [0, 0, 0, 0],
            dst: [0, 0, 0, 0],
        }
    }

    /// Set version and IHL
    pub fn set_version_header_len(&mut self, ihl: u8) {
        self.ver_ihl = (IPV4_VERSION << 4) | (ihl & 0xF);
    }

    /// Get header length in bytes
    pub fn header_len(&self) -> usize {
        ((self.ver_ihl & 0xF) as usize) * 4
    }

    /// Get total length
    pub fn total_len(&self) -> u16 {
        u16::from_be(self.total_len)
    }

    /// Set total length
    pub fn set_total_len(&mut self, len: u16) {
        self.total_len = len.to_be();
    }

    /// Get protocol
    pub fn protocol(&self) -> u8 {
        self.proto
    }

    /// Set protocol
    pub fn set_protocol(&mut self, proto: u8) {
        self.proto = proto;
    }

    /// Get source IP as u32
    pub fn src_ip(&self) -> u32 {
        u32::from_be_bytes(self.src)
    }

    /// Set source IP
    pub fn set_src_ip(&mut self, ip: u32) {
        self.src = ip.to_be_bytes();
    }

    /// Get destination IP as u32
    pub fn dst_ip(&self) -> u32 {
        u32::from_be_bytes(self.dst)
    }

    /// Set destination IP
    pub fn set_dst_ip(&mut self, ip: u32) {
        self.dst = ip.to_be_bytes();
    }

    /// Get TTL
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Decrement TTL
    pub fn dec_ttl(&mut self) {
        if self.ttl > 0 {
            self.ttl -= 1;
        }
    }

    /// Check if TTL expired
    pub fn ttl_expired(&self) -> bool {
        self.ttl == 0
    }

    /// Get identification
    pub fn ident(&self) -> u16 {
        u16::from_be(self.ident)
    }

    /// Set identification
    pub fn set_ident(&mut self, id: u16) {
        self.ident = id.to_be();
    }

    /// Get fragment offset
    pub fn frag_offset(&self) -> u16 {
        u16::from_be(self.flags_frag) & 0x1FFF
    }

    /// Check if more fragments
    pub fn more_fragments(&self) -> bool {
        (u16::from_be(self.flags_frag) & 0x2000) != 0
    }

    /// Check if don't fragment
    pub fn dont_fragment(&self) -> bool {
        (u16::from_be(self.flags_frag) & 0x4000) != 0
    }

    /// Set fragment
    pub fn set_fragment(&mut self, offset: u16, mf: bool, df: bool) {
        let flags = (if df { 0x4000 } else { 0 }) | (if mf { 0x2000 } else { 0 });
        self.flags_frag = ((flags | (offset & 0x1FFF)) as u16).to_be();
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPV4_HEADER_LEN {
            return None;
        }

        let ver_ihl = bytes[0];
        if (ver_ihl >> 4) != IPV4_VERSION {
            return None;
        }

        let ihl = ((ver_ihl & 0xF) as usize) * 4;
        if bytes.len() < ihl {
            return None;
        }

        Some(Self {
            ver_ihl,
            tos: bytes[1],
            total_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            ident: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_frag: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl: bytes[8],
            proto: bytes[9],
            checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            src: [bytes[12], bytes[13], bytes[14], bytes[15]],
            dst: [bytes[16], bytes[17], bytes[18], bytes[19]],
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        let len = self.header_len();
        if bytes.len() < len {
            return None;
        }

        bytes[0] = self.ver_ihl;
        bytes[1] = self.tos;
        bytes[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.ident.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags_frag.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.proto;
        bytes[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.src);
        bytes[16..20].copy_from_slice(&self.dst);
        Some(())
    }

    /// Get payload
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let len = self.header_len();
        if packet.len() < len {
            None
        } else {
            Some(&packet[len..])
        }
    }

    /// Get payload mut
    pub fn payload_mut<'a>(&self, packet: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let len = self.header_len();
        if packet.len() < len {
            None
        } else {
            Some(&mut packet[len..])
        }
    }
}

// ============================================================================
// Checksum
// ============================================================================

/// Calculate IPv4 checksum
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else if chunk.len() == 1 {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }

    // Add carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate checksum with pseudo-header (for TCP/UDP)
pub fn checksum_pseudo(data: &[u8], src: [u8; 4], dst: [u8; 4], proto: u8, len: u16) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += len as u32;

    // Payload
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else if chunk.len() == 1 {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Verify IPv4 header checksum
pub fn verify_checksum(hdr: &Ipv4Hdr, data: &[u8]) -> bool {
    let computed = checksum(data);
    hdr.checksum == computed.to_be()
}

/// Set checksum in header
pub fn set_checksum(hdr: &mut Ipv4Hdr, data: &[u8]) {
    hdr.checksum = 0;
    let sum = checksum(data);
    hdr.checksum = sum.to_be();
}

// ============================================================================
// IPv4 Utilities
// ============================================================================

/// IPv4 address utilities
pub mod addr {
    use alloc::vec::Vec;

    /// Parse IPv4 address from bytes
    pub fn from_bytes(b: [u8; 4]) -> u32 {
        u32::from_be_bytes(b)
    }

    /// Format IPv4 address as string
    pub fn format_ip(ip: u32, buf: &mut [u8]) -> usize {
        let b = ip.to_be_bytes();
        let s = alloc::format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        if buf.len() < s.len() {
            return 0;
        }
        buf[..s.len()].copy_from_slice(s.as_bytes());
        s.len()
    }

    /// Parse IPv4 address string
    pub fn parse_ip(s: &[u8]) -> Option<u32> {
        if s.len() < 7 {
            return None;
        }

        let parts: Vec<&[u8]> = s.split(|&c| c == b'.').collect();
        if parts.len() != 4 {
            return None;
        }

        let mut ip: u32 = 0;
        for part in parts {
            if part.is_empty() {
                return None;
            }
            let mut val: u8 = 0;
            for &c in part {
                if !c.is_ascii_digit() {
                    return None;
                }
                val = val.wrapping_mul(10).wrapping_add(c.wrapping_sub(b'0'));
            }
            ip = (ip << 8) | (val as u32);
        }
        Some(ip)
    }

    /// Check if address is loopback
    pub fn is_loopback(ip: u32) -> bool {
        (ip & 0xFF000000) == 0x7F000000
    }

    /// Check if address is private
    pub fn is_private(ip: u32) -> bool {
        let b = (ip >> 24) as u8;
        let b1 = (ip >> 16) as u8;

        // 10.0.0.0/8
        if b == 10 {
            return true;
        }
        // 172.16.0.0/12
        if b == 172 && (b1 >= 16 && b1 <= 31) {
            return true;
        }
        // 192.168.0.0/16
        if b == 192 && b1 == 168 {
            return true;
        }
        false
    }

    /// Check if address is broadcast
    pub fn is_broadcast(ip: u32) -> bool {
        ip == 0xFFFFFFFF
    }

    /// Check if address is multicast
    pub fn is_multicast(ip: u32) -> bool {
        let b = (ip >> 24) as u8;
        b >= 224 && b <= 239
    }

    /// Check if address is link-local
    pub fn is_linklocal(ip: u32) -> bool {
        let b = (ip >> 24) as u8;
        let b1 = (ip >> 16) as u8;
        b == 169 && b1 == 254
    }

    /// Get broadcast address for network
    pub fn broadcast(ip: u32, mask: u32) -> u32 {
        ip | !mask
    }

    /// Get network address
    pub fn network(ip: u32, mask: u32) -> u32 {
        ip & mask
    }
}

// ============================================================================
// IP Packet
// ============================================================================

/// IPv4 packet
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    /// IP header
    pub header: Ipv4Hdr,
    /// Packet payload
    pub payload: alloc::vec::Vec<u8>,
}

impl Ipv4Packet {
    /// Create new packet
    pub fn new(src: u32, dst: u32, proto: u8) -> Self {
        let mut hdr = Ipv4Hdr::new();
        hdr.set_src_ip(src);
        hdr.set_dst_ip(dst);
        hdr.set_protocol(proto);

        Self {
            header: hdr,
            payload: alloc::vec::Vec::new(),
        }
    }

    /// Create packet with payload
    pub fn with_payload(src: u32, dst: u32, proto: u8, payload: alloc::vec::Vec<u8>) -> Self {
        let mut pkt = Self::new(src, dst, proto);
        pkt.set_payload(payload);
        pkt
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = Ipv4Hdr::from_bytes(bytes)?;
        let total_len = header.total_len() as usize;
        let header_len = header.header_len();

        if bytes.len() < total_len {
            return None;
        }

        let payload = if header_len < total_len {
            bytes[header_len..total_len].to_vec()
        } else {
            alloc::vec::Vec::new()
        };

        Some(Self { header, payload })
    }

    /// Get total packet size
    pub fn packet_len(&self) -> usize {
        self.header.header_len() + self.payload.len()
    }

    /// Set payload
    pub fn set_payload(&mut self, payload: alloc::vec::Vec<u8>) {
        self.payload = payload;
        self.header
            .set_total_len((self.packet_len() as u16).to_be());
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let size = self.packet_len();
        let mut bytes = alloc::vec::Vec::with_capacity(size);
        bytes.resize(size, 0);
        self.header.to_bytes(&mut bytes).unwrap_or(());
        bytes[self.header.header_len()..].copy_from_slice(&self.payload);
        // Calculate and set checksum in the bytes directly
        let checksum_offset = 10;
        let header_len = self.header.header_len();
        let mut checksum_data = bytes[..header_len].to_vec();
        // Set checksum field to 0 for calculation
        checksum_data[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);
        let sum = checksum(&checksum_data);
        bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&sum.to_be_bytes());
        bytes
    }

    /// Finalize packet (calculate checksums)
    pub fn finalize(&mut self) {
        let header_len = self.header.header_len();
        let mut header_bytes = alloc::vec::Vec::with_capacity(header_len);
        header_bytes.resize(header_len, 0);
        self.header.to_bytes(&mut header_bytes).unwrap_or(());
        // Set checksum field to 0 for calculation
        let checksum_offset = 10;
        header_bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);
        let sum = checksum(&header_bytes);
        self.header.checksum = sum.to_be();
    }
}

// ============================================================================
// Routing Table (Simple)
// ============================================================================

/// Route entry
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Network address
    pub network: u32,
    /// Subnet mask
    pub mask: u32,
    /// Gateway (0 if direct)
    pub gateway: u32,
    /// Interface (interface index)
    pub iface: usize,
    /// Metric
    pub metric: u32,
}

impl Route {
    pub fn new(network: u32, mask: u32, gateway: u32, iface: usize) -> Self {
        Self {
            network,
            mask,
            gateway,
            iface,
            metric: 1,
        }
    }

    /// Get prefix length
    pub fn prefix_len(&self) -> u8 {
        (!self.mask).leading_ones() as u8
    }

    /// Check if route matches IP
    pub fn matches(&self, ip: u32) -> bool {
        (ip & self.mask) == self.network
    }
}

/// Simple routing table
pub struct RoutingTable {
    routes: [Option<Route>; 16],
    count: usize,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: [const { None }; 16],
            count: 0,
        }
    }

    /// Add route
    pub fn add(&mut self, route: Route) {
        if self.count < 16 {
            self.routes[self.count] = Some(route);
            self.count += 1;
        }
    }

    /// Find route for destination
    pub fn find(&self, ip: u32) -> Option<&Route> {
        let mut best: Option<&Route> = None;
        let mut best_prefix = 0u8;

        for route in &self.routes {
            if let Some(r) = route {
                if r.matches(ip) {
                    if r.prefix_len() >= best_prefix {
                        best_prefix = r.prefix_len();
                        best = Some(r);
                    }
                }
            }
        }
        best
    }

    /// Add default route
    pub fn add_default(&mut self, gateway: u32, iface: usize) {
        self.add(Route::new(0, 0, gateway, iface));
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IPv4 Fragmentation and Reassembly
// ============================================================================

use crate::common::sync::Spinlock;
use alloc::collections::BTreeMap;

/// Fragment cache key
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct FragmentKey {
    /// Source address
    pub src: u32,
    /// Destination address
    pub dst: u32,
    /// Fragment identification
    pub ident: u16,
    /// Protocol
    pub proto: u8,
}

impl FragmentKey {
    pub fn new(src: u32, dst: u32, ident: u16, proto: u8) -> Self {
        Self {
            src,
            dst,
            ident,
            proto,
        }
    }
}

/// Fragment data
#[derive(Debug, Clone)]
pub struct FragmentData {
    /// Fragment offset in bytes
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
    /// Original total length (from last fragment)
    pub total_len: Option<usize>,
    /// Header length (for reconstructing original packet)
    pub header_len: usize,
    /// Original header (for reconstruction)
    pub original_header: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
    /// Complete flag
    pub complete: bool,
}

impl FragmentEntry {
    pub fn new(key: FragmentKey, header: &[u8], created_at: u64) -> Self {
        Self {
            key,
            fragments: Vec::new(),
            total_len: None,
            header_len: header.len(),
            original_header: header.to_vec(),
            created_at,
            complete: false,
        }
    }

    /// Add a fragment
    pub fn add_fragment(&mut self, offset: usize, more: bool, data: Vec<u8>) {
        // Check for duplicates
        if self.fragments.iter().any(|f| f.offset == offset) {
            return;
        }

        self.fragments.push(FragmentData { offset, more, data });

        // Update total length if this is the last fragment
        if !more {
            let last_offset = offset + self.fragments.last().map(|f| f.data.len()).unwrap_or(0);
            if self.total_len.is_none() || self.total_len.unwrap() < last_offset {
                self.total_len = Some(last_offset);
            }
        }

        // Sort fragments by offset
        self.fragments.sort_by_key(|f| f.offset);
    }

    /// Check if all fragments are received and contiguous
    pub fn is_complete(&self) -> bool {
        if self.fragments.is_empty() {
            return false;
        }

        let mut expected_offset = 0;

        for frag in &self.fragments {
            // Check for holes
            if frag.offset != expected_offset {
                return false;
            }
            expected_offset = frag.offset + frag.data.len();

            // If this is the last fragment, verify total length
            if !frag.more {
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

    /// Reassemble the fragments into a complete packet
    pub fn reassemble(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_len.unwrap_or(0));
        result.extend_from_slice(&self.original_header);

        for frag in &self.fragments {
            result.extend_from_slice(&frag.data);
        }

        // Update total length in header
        if result.len() >= 2 {
            let total_len = result.len() as u16;
            result[2] = (total_len >> 8) as u8;
            result[3] = total_len as u8;
        }

        result
    }
}

/// IPv4 fragment cache for reassembly
pub struct FragmentCache {
    /// Fragment entries (using BTreeMap for ordered key lookup)
    entries: BTreeMap<FragmentKey, FragmentEntry>,
    /// Maximum entries
    max_entries: usize,
    /// Fragment timeout in milliseconds
    timeout_ms: u64,
    /// Lock for thread safety
    lock: Spinlock<()>,
}

impl FragmentCache {
    /// Create a new fragment cache
    pub fn new(max_entries: usize, timeout_ms: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            timeout_ms,
            lock: Spinlock::new(()),
        }
    }

    /// Process an incoming fragment
    /// Returns Some(reassembled_packet) if complete, None if more fragments needed
    pub fn process_fragment(&mut self, header: &Ipv4Hdr, data: &[u8], now: u64) -> Option<Vec<u8>> {
        let _guard = self.lock.lock();

        let src = header.src_ip();
        let dst = header.dst_ip();
        let ident = header.ident();
        let proto = header.protocol();
        let offset = (header.frag_offset() as usize) * 8;
        let more = header.more_fragments();

        // If this is not a fragment, return directly
        if offset == 0 && !more {
            // Not fragmented, return the data as-is
            let mut header_bytes = vec![0u8; header.header_len()];
            header.to_bytes(&mut header_bytes)?;
            header_bytes.extend_from_slice(data);
            return Some(header_bytes);
        }

        let key = FragmentKey::new(src, dst, ident, proto);

        // Get or create entry
        let entry = self.entries.entry(key.clone()).or_insert_with(|| {
            // Store the original header (without fragment-related fields)
            let mut header_bytes = vec![0u8; IPV4_HEADER_LEN];
            let mut hdr_copy = *header;
            // Clear fragment-related fields for first fragment
            hdr_copy.set_fragment(0, false, false);
            hdr_copy.to_bytes(&mut header_bytes);
            FragmentEntry::new(key.clone(), &header_bytes, now)
        });

        // Add the fragment
        entry.add_fragment(offset, more, data.to_vec());

        // Check if complete
        if entry.is_complete() {
            let packet = entry.reassemble();
            self.entries.remove(&key);
            return Some(packet);
        }

        // Check timeout and cleanup
        if now - entry.created_at > self.timeout_ms {
            self.entries.remove(&key);
        }

        // Cleanup if too many entries
        if self.entries.len() > self.max_entries {
            // Get the first key to remove
            let oldest_key_to_remove = self.entries.keys().next().cloned();
            if let Some(key) = oldest_key_to_remove {
                self.entries.remove(&key);
            }
        }

        None
    }

    /// Clean up expired fragments
    pub fn cleanup(&mut self, now: u64) {
        let _guard = self.lock.lock();

        self.entries
            .retain(|_, entry| now - entry.created_at <= self.timeout_ms);
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

/// Fragment a packet into smaller pieces
pub struct Fragmenter {
    /// MTU for fragmentation
    mtu: usize,
    /// Identification counter
    ident: Spinlock<u16>,
}

impl Fragmenter {
    /// Create a new fragmenter
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu,
            ident: Spinlock::new(0),
        }
    }

    /// Set MTU
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Fragment a packet
    /// Returns a list of fragments, or None if fragmentation is not allowed (DF set)
    pub fn fragment(&self, packet: &[u8], ident: Option<u16>) -> Option<Vec<Vec<u8>>> {
        let header = Ipv4Hdr::from_bytes(packet)?;

        // Check if DF is set
        if header.dont_fragment() {
            return None;
        }

        let header_len = header.header_len();
        let max_data = self.mtu - header_len;

        if max_data < 8 {
            return None; // Minimum fragment size
        }

        let payload_len = packet.len() - header_len;
        let total_len = packet.len();

        if total_len <= self.mtu {
            return None; // No fragmentation needed
        }

        // Get or generate identification
        let id = ident.unwrap_or_else(|| {
            let mut id_lock = self.ident.lock();
            *id_lock = id_lock.wrapping_add(1);
            *id_lock
        });

        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < payload_len {
            let mut frag_len = max_data.min(payload_len - offset);

            // Align to 8-byte boundary (except for last fragment)
            if offset + frag_len < payload_len {
                frag_len = (frag_len / 8) * 8;
            }

            if frag_len == 0 {
                break;
            }

            // Create fragment header
            let mut frag_header = header;
            frag_header.set_ident(id);
            frag_header.set_fragment((offset / 8) as u16, offset + frag_len < payload_len, false);

            // Calculate fragment data length
            let frag_data_len = frag_len.min(payload_len - offset);
            let frag_total_len = header_len + frag_data_len;
            frag_header.set_total_len(frag_total_len as u16);

            // Build fragment
            let mut frag = vec![0u8; frag_total_len];
            frag_header.to_bytes(&mut frag)?;
            frag[header_len..]
                .copy_from_slice(&packet[header_len + offset..header_len + offset + frag_data_len]);

            // Calculate checksum
            let mut checksum_data = frag[..header_len].to_vec();
            checksum_data[10..12].copy_from_slice(&[0, 0]);
            let sum = checksum(&checksum_data);
            frag[10] = (sum >> 8) as u8;
            frag[11] = sum as u8;

            fragments.push(frag);
            offset += frag_data_len;
        }

        if fragments.is_empty() {
            return None;
        }

        Some(fragments)
    }
}

// ============================================================================
// IPv4 Options Support
// ============================================================================

/// IPv4 option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpOptionType {
    End = 0,           // End of option list
    NoOp = 1,          // No operation
    RecordRoute = 7,   // Record route
    Timestamp = 68,    // Timestamp
    LooseRoute = 131,  // Loose source route
    ExtendedSec = 133, // Extended security
    StreamId = 136,    // Stream identifier
    StrictRoute = 137, // Strict source route
}

/// IPv4 option structure
#[derive(Debug, Clone)]
pub struct IpOption {
    /// Option type
    pub option_type: IpOptionType,
    /// Option length (including type and length bytes)
    pub length: u8,
    /// Option data
    pub data: Vec<u8>,
}

/// Record route option state
#[derive(Debug, Clone)]
pub struct RecordRouteOption {
    /// Current pointer (1-indexed, pointing to next slot)
    pub pointer: u8,
    /// Recorded IP addresses
    pub addresses: [[u8; 4]; 9],
}

/// Timestamp option state
#[derive(Debug, Clone)]
pub struct TimestampOption {
    /// Current pointer
    pub pointer: u8,
    /// Overflow count
    pub overflow: u8,
    /// Timestamp entries
    pub entries: [(u32, u32); 9], // (IP, timestamp)
}

impl IpOption {
    /// Parse options from header bytes
    pub fn parse_options(header: &[u8], header_len: usize) -> Vec<IpOption> {
        let mut options = Vec::new();
        let mut offset = IPV4_HEADER_LEN;

        while offset < header_len {
            let opt_type = header[offset];

            match opt_type {
                0 => {
                    // End of option list
                    break;
                }
                1 => {
                    // No operation
                    options.push(IpOption {
                        option_type: IpOptionType::NoOp,
                        length: 1,
                        data: Vec::new(),
                    });
                    offset += 1;
                }
                _ => {
                    if offset + 1 >= header_len {
                        break;
                    }
                    let opt_len = header[offset + 1];

                    if opt_len < 2 || offset + opt_len as usize > header_len {
                        break;
                    }

                    let data = header[offset + 2..offset + opt_len as usize].to_vec();

                    let option_type = match opt_type {
                        7 => IpOptionType::RecordRoute,
                        68 => IpOptionType::Timestamp,
                        131 => IpOptionType::LooseRoute,
                        133 => IpOptionType::ExtendedSec,
                        136 => IpOptionType::StreamId,
                        137 => IpOptionType::StrictRoute,
                        _ => continue,
                    };

                    options.push(IpOption {
                        option_type,
                        length: opt_len,
                        data,
                    });

                    offset += opt_len as usize;
                }
            }
        }

        options
    }

    /// Process options (for source routing, etc.)
    /// Returns modified header and any additional actions needed
    pub fn process_options(
        options: &[IpOption],
        _header: &mut Ipv4Hdr,
        _our_ip: u32,
    ) -> IpOptionAction {
        let mut action = IpOptionAction::Continue;

        for opt in options {
            match opt.option_type {
                IpOptionType::RecordRoute => {
                    // Add our IP to the record route option
                    if opt.length >= 3 && opt.data.len() >= 3 {
                        let pointer = opt.data[0];
                        if pointer < opt.length - 3 {
                            let slots = (opt.length as usize - 3) / 4;
                            let current_slot = ((pointer - 1) as usize) / 4;
                            if current_slot < slots {
                                // Would need to modify the option data
                                // This is a simplified implementation
                            }
                        }
                    }
                }
                IpOptionType::LooseRoute | IpOptionType::StrictRoute => {
                    // Process source routing
                    // This is a simplified implementation
                    action = IpOptionAction::Continue;
                }
                IpOptionType::Timestamp => {
                    // Record timestamp
                }
                _ => {}
            }
        }

        action
    }
}

/// Action to take after processing options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpOptionAction {
    /// Continue normal processing
    Continue,
    /// Send ICMP error
    SendIcmpError,
    /// Drop packet
    Drop,
}

/// Parse IPv4 address from string
pub fn parse_ipv4_addr(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut ip: u32 = 0;
    for part in parts {
        let val: u8 = part.parse().ok()?;
        ip = (ip << 8) | (val as u32);
    }
    Some(ip)
}

/// Format IPv4 address to string
pub fn format_ipv4_addr(ip: u32) -> alloc::string::String {
    let b = ip.to_be_bytes();
    alloc::format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

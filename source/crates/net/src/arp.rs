//! Address Resolution Protocol (ARP)
//!
//! Implements ARP for mapping IPv4 addresses to MAC addresses.


extern crate alloc;

use crate::common::sync::Spinlock;
use crate::eth::ETH_ADDR_LEN;
use alloc::vec::Vec;

/// ARP operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    Request = 1,     // ARP request
    Reply = 2,       // ARP reply
    RarpRequest = 3, // RARP request
    RarpReply = 4,   // RARP reply
}

/// Hardware address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpHtype {
    Ethernet = 1,
}

/// Protocol address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpPtype {
    Ipv4 = 0x0800,
}

// ============================================================================
// ARP Header
// ============================================================================

/// ARP packet header
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ArpHdr {
    /// Hardware type
    pub htype: u16,
    /// Protocol type
    pub ptype: u16,
    /// Hardware address length
    pub hlen: u8,
    /// Protocol address length
    pub plen: u8,
    /// Operation (request/reply)
    pub oper: u16,
    /// Sender hardware address
    pub sha: [u8; ETH_ADDR_LEN],
    /// Sender protocol address
    pub spa: [u8; 4],
    /// Target hardware address
    pub tha: [u8; ETH_ADDR_LEN],
    /// Target protocol address
    pub tpa: [u8; 4],
}

impl ArpHdr {
    /// Create a new ARP header
    pub fn new(oper: ArpOpcode) -> Self {
        Self {
            htype: (ArpHtype::Ethernet as u16).to_be(),
            ptype: (ArpPtype::Ipv4 as u16).to_be(),
            hlen: ETH_ADDR_LEN as u8,
            plen: 4,
            oper: (oper as u16).to_be(),
            sha: [0; ETH_ADDR_LEN],
            spa: [0; 4],
            tha: [0; ETH_ADDR_LEN],
            tpa: [0; 4],
        }
    }

    /// Create ARP request
    pub fn request(sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Self {
        Self {
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: ETH_ADDR_LEN as u8,
            plen: 4,
            oper: (ArpOpcode::Request as u16).to_be(),
            sha,
            spa,
            tha: [0; ETH_ADDR_LEN],
            tpa,
        }
    }

    /// Create ARP reply
    pub fn reply(sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Self {
        Self {
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: ETH_ADDR_LEN as u8,
            plen: 4,
            oper: (ArpOpcode::Reply as u16).to_be(),
            sha,
            spa,
            tha,
            tpa,
        }
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }

        Some(Self {
            htype: u16::from_be_bytes([bytes[0], bytes[1]]),
            ptype: u16::from_be_bytes([bytes[2], bytes[3]]),
            hlen: bytes[4],
            plen: bytes[5],
            oper: u16::from_be_bytes([bytes[6], bytes[7]]),
            sha: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
            ],
            spa: [bytes[14], bytes[15], bytes[16], bytes[17]],
            tha: [
                bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
            ],
            tpa: [bytes[24], bytes[25], bytes[26], bytes[27]],
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() < 28 {
            return None;
        }

        bytes[0..2].copy_from_slice(&self.htype.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.ptype.to_be_bytes());
        bytes[4] = self.hlen;
        bytes[5] = self.plen;
        bytes[6..8].copy_from_slice(&self.oper.to_be_bytes());
        bytes[8..14].copy_from_slice(&self.sha);
        bytes[14..18].copy_from_slice(&self.spa);
        bytes[18..24].copy_from_slice(&self.tha);
        bytes[24..28].copy_from_slice(&self.tpa);
        Some(())
    }

    /// Get operation as enum
    pub fn opcode(&self) -> ArpOpcode {
        match u16::from_be(self.oper) as u16 {
            1 => ArpOpcode::Request,
            2 => ArpOpcode::Reply,
            3 => ArpOpcode::RarpRequest,
            4 => ArpOpcode::RarpReply,
            _ => ArpOpcode::Request,
        }
    }

    /// Get sender IP address as u32
    pub fn sender_ip(&self) -> u32 {
        u32::from_be_bytes(self.spa)
    }

    /// Get target IP address as u32
    pub fn target_ip(&self) -> u32 {
        u32::from_be_bytes(self.tpa)
    }
}

// ============================================================================
// ARP Cache
// ============================================================================

/// ARP cache entry
#[derive(Debug, Clone, Copy)]
pub struct ArpEntry {
    /// IP address
    pub ip: u32,
    /// MAC address
    pub mac: [u8; ETH_ADDR_LEN],
    /// Is valid
    pub valid: bool,
    /// Is static (doesn't expire)
    pub static_entry: bool,
    /// Timestamp (for expiry)
    pub timestamp: u64,
}

impl ArpEntry {
    pub fn new(ip: u32, mac: [u8; 6]) -> Self {
        Self {
            ip,
            mac,
            valid: true,
            static_entry: false,
            timestamp: 0,
        }
    }

    pub fn static_entry(ip: u32, mac: [u8; 6]) -> Self {
        Self {
            ip,
            mac,
            valid: true,
            static_entry: true,
            timestamp: 0,
        }
    }
}

/// ARP cache
pub struct ArpCache {
    /// Cache entries
    entries: [Option<ArpEntry>; 64],
    /// Number of entries
    count: usize,
    /// Lock
    lock: Spinlock<()>,
}

impl ArpCache {
    /// Create new ARP cache
    pub fn new() -> Self {
        Self {
            entries: [const { None }; 64],
            count: 0,
            lock: Spinlock::new(()),
        }
    }

    /// Look up MAC address for IP
    pub fn lookup(&self, ip: u32) -> Option<[u8; 6]> {
        let _guard = self.lock.lock();

        for entry in &self.entries {
            if let Some(e) = entry {
                if e.ip == ip && e.valid {
                    return Some(e.mac);
                }
            }
        }
        None
    }

    /// Add entry to cache
    pub fn add(&mut self, ip: u32, mac: [u8; 6]) {
        let _guard = self.lock.lock();

        // Check if entry already exists
        for entry in &mut self.entries {
            if let Some(e) = entry {
                if e.ip == ip {
                    e.mac = mac;
                    e.valid = true;
                    return;
                }
            }
        }

        // Find empty slot
        for entry in &mut self.entries {
            if entry.is_none() {
                *entry = Some(ArpEntry::new(ip, mac));
                self.count += 1;
                return;
            }
        }
    }

    /// Add static entry
    pub fn add_static(&mut self, ip: u32, mac: [u8; 6]) {
        let _guard = self.lock.lock();

        for entry in &mut self.entries {
            if let Some(e) = entry {
                if e.ip == ip {
                    e.mac = mac;
                    e.valid = true;
                    e.static_entry = true;
                    return;
                }
            }
        }

        for entry in &mut self.entries {
            if entry.is_none() {
                *entry = Some(ArpEntry::static_entry(ip, mac));
                self.count += 1;
                return;
            }
        }
    }

    /// Remove entry
    pub fn remove(&mut self, ip: u32) {
        let _guard = self.lock.lock();

        for entry in &mut self.entries {
            if let Some(e) = entry {
                if e.ip == ip {
                    *entry = None;
                    self.count -= 1;
                    return;
                }
            }
        }
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<ArpEntry> {
        let _guard = self.lock.lock();
        self.entries.iter().filter_map(|e| *e).collect()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ARP Table
// ============================================================================

/// ARP table for managing address resolution
pub struct ArpTable {
    cache: ArpCache,
    /// Lock for thread safety
    lock: Spinlock<()>,
    /// Our MAC address
    our_mac: [u8; 6],
    /// Our IP address
    our_ip: u32,
}

impl ArpTable {
    /// Create new ARP table
    pub fn new(our_mac: [u8; 6], our_ip: u32) -> Self {
        Self {
            cache: ArpCache::new(),
            lock: Spinlock::new(()),
            our_mac,
            our_ip,
        }
    }

    /// Set our MAC address
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.our_mac = mac;
    }

    /// Set our IP address
    pub fn set_ip(&mut self, ip: u32) {
        self.our_ip = ip;
    }

    /// Look up MAC address (may return None if not cached)
    pub fn lookup(&self, ip: u32) -> Option<[u8; 6]> {
        self.cache.lookup(ip)
    }

    /// Handle incoming ARP packet
    pub fn handle_packet(&mut self, hdr: &ArpHdr) -> Option<ArpHdr> {
        let _guard = self.lock.lock();
        let sender_ip = hdr.sender_ip();
        let target_ip = hdr.target_ip();

        // Update cache with sender
        self.cache.add(sender_ip, hdr.sha);

        match hdr.opcode() {
            ArpOpcode::Request => {
                // Is this a request for us?
                if target_ip == self.our_ip {
                    // Send ARP reply
                    return Some(ArpHdr::reply(
                        self.our_mac,
                        self.our_ip.to_be_bytes(),
                        hdr.sha,
                        hdr.spa,
                    ));
                }
                None
            }
            ArpOpcode::Reply => {
                // Update cache (already done above)
                // No pending waiters to wake in this simplified implementation
                None
            }
            _ => None,
        }
    }

    /// Create ARP request packet
    pub fn create_request(&self, target_ip: u32) -> ArpHdr {
        ArpHdr::request(
            self.our_mac,
            self.our_ip.to_be_bytes(),
            target_ip.to_be_bytes(),
        )
    }
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new([0; 6], 0)
    }
}

// ============================================================================
// ARP Enhancement: Retransmission and Proxy ARP
// ============================================================================

/// Ethernet address length constant (from eth module or define locally)
pub const ARP_ETH_ADDR_LEN: usize = 6;

/// Pending ARP request waiting for reply
#[derive(Debug, Clone)]
pub struct PendingArpRequest {
    /// Target IP address
    pub target_ip: u32,
    /// Time when request was first sent
    pub sent_at: u64,
    /// Number of retransmissions
    pub retrans_count: u8,
    /// Queued packets waiting for resolution
    pub pending_packets: Vec<ArpPendingPacket>,
}

/// Packet waiting for ARP resolution
#[derive(Debug, Clone)]
pub struct ArpPendingPacket {
    /// Destination MAC (original target)
    pub dst_mac: [u8; ARP_ETH_ADDR_LEN],
    /// Protocol (IPv4 = 0x0800)
    pub protocol: u16,
    /// Packet data
    pub data: Vec<u8>,
    /// Time when packet was queued
    pub queued_at: u64,
}

/// ARP configuration
#[derive(Debug, Clone, Copy)]
pub struct ArpConfig {
    /// Maximum retransmission attempts
    pub max_retrans: u8,
    /// Initial retransmission timeout (ms)
    pub retrans_timeout_ms: u64,
    /// Maximum retransmission timeout (ms)
    pub max_retrans_timeout_ms: u64,
    /// Entry lifetime (seconds)
    pub entry_lifetime_secs: u64,
    /// Proxy ARP enabled
    pub proxy_arp_enabled: bool,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            max_retrans: 3,
            retrans_timeout_ms: 1000,
            max_retrans_timeout_ms: 10000,
            entry_lifetime_secs: 900, // 15 minutes
            proxy_arp_enabled: false,
        }
    }
}

/// Proxy ARP rule
#[derive(Debug, Clone)]
pub struct ProxyArpRule {
    /// Network address
    pub network: u32,
    /// Network mask
    pub mask: u32,
    /// Allowed interface indices
    pub allowed_ifaces: alloc::vec::Vec<usize>,
}

impl ProxyArpRule {
    /// Check if an IP matches this rule
    pub fn matches(&self, ip: u32) -> bool {
        (ip & self.mask) == self.network
    }

    /// Create a new rule
    pub fn new(network: u32, mask: u32) -> Self {
        Self {
            network,
            mask,
            allowed_ifaces: alloc::vec::Vec::new(),
        }
    }

    /// Add an allowed interface
    pub fn allow_interface(&mut self, ifindex: usize) {
        if !self.allowed_ifaces.contains(&ifindex) {
            self.allowed_ifaces.push(ifindex);
        }
    }
}

/// Enhanced ARP table with retransmission and proxy support
pub struct EnhancedArpTable {
    /// Base ARP table
    base: ArpTable,
    /// Configuration
    config: ArpConfig,
    /// Pending ARP requests
    pending_requests: alloc::vec::Vec<PendingArpRequest>,
    /// Proxy ARP rules
    proxy_rules: alloc::vec::Vec<ProxyArpRule>,
    /// Current time (set by caller)
    current_time: Spinlock<u64>,
}

impl EnhancedArpTable {
    /// Create a new enhanced ARP table
    pub fn new(our_mac: [u8; 6], our_ip: u32) -> Self {
        Self {
            base: ArpTable::new(our_mac, our_ip),
            config: ArpConfig::default(),
            pending_requests: alloc::vec::Vec::new(),
            proxy_rules: alloc::vec::Vec::new(),
            current_time: Spinlock::new(0),
        }
    }

    /// Set current time (for testing)
    pub fn set_time(&self, time: u64) {
        let mut t = self.current_time.lock();
        *t = time;
    }

    /// Get current time
    fn now(&self) -> u64 {
        *self.current_time.lock()
    }

    /// Set configuration
    pub fn set_config(&mut self, config: ArpConfig) {
        self.config = config;
    }

    /// Get configuration
    pub fn config(&self) -> ArpConfig {
        self.config
    }

    /// Look up MAC address for IP
    pub fn lookup(&self, ip: u32) -> Option<[u8; 6]> {
        // First check cache
        if let Some(mac) = self.base.lookup(ip) {
            return Some(mac);
        }

        // Check proxy rules
        if self.config.proxy_arp_enabled {
            for rule in &self.proxy_rules {
                if rule.matches(ip) {
                    // Could return proxy MAC if configured
                    // For now, return None to trigger ARP request
                }
            }
        }

        None
    }

    /// Send ARP request for an IP
    pub fn send_request(&mut self, target_ip: u32) {
        let now = self.now();

        // Check if we already have a pending request for this IP
        if self
            .pending_requests
            .iter()
            .any(|r| r.target_ip == target_ip)
        {
            return;
        }

        // Create new pending request
        let request = PendingArpRequest {
            target_ip,
            sent_at: now,
            retrans_count: 0,
            pending_packets: alloc::vec::Vec::new(),
        };

        self.pending_requests.push(request);
    }

    /// Queue a packet for later transmission when ARP resolves
    pub fn queue_packet(&mut self, target_ip: u32, packet: ArpPendingPacket) {
        // Find or create pending request
        if let Some(req) = self
            .pending_requests
            .iter_mut()
            .find(|r| r.target_ip == target_ip)
        {
            req.pending_packets.push(packet);
        } else {
            // Create new pending request and queue packet
            let now = self.now();
            let mut request = PendingArpRequest {
                target_ip,
                sent_at: now,
                retrans_count: 0,
                pending_packets: alloc::vec::Vec::new(),
            };
            request.pending_packets.push(packet);
            self.pending_requests.push(request);
        }
    }

    /// Handle incoming ARP reply
    pub fn handle_reply(&mut self, hdr: &ArpHdr) -> alloc::vec::Vec<ArpPendingPacket> {
        let sender_ip = hdr.sender_ip();

        // Add to cache
        self.base.cache.add(sender_ip, hdr.sha);

        // Find and remove pending request
        if let Some(pos) = self
            .pending_requests
            .iter()
            .position(|r| r.target_ip == sender_ip)
        {
            let request = self.pending_requests.remove(pos);
            return request.pending_packets;
        }

        alloc::vec::Vec::new()
    }

    /// Handle timeout - process pending requests and cleanup
    /// Returns list of IPs that need ARP requests sent
    pub fn handle_timeout(&mut self) -> alloc::vec::Vec<u32> {
        let now = self.now();
        let mut requests_to_send = alloc::vec::Vec::new();

        // Collect requests to process and their timeouts
        let base_timeout = self.config.retrans_timeout_ms;
        let max_retrans = self.config.max_retrans;
        
        for req in &mut self.pending_requests {
            let elapsed = now.saturating_sub(req.sent_at);
            let retrans_count = req.retrans_count;
            
            // Calculate timeout: base * 2^retrans_count, capped
            let timeout = base_timeout << retrans_count as u64;
            let max_timeout = self.config.max_retrans_timeout_ms;
            let actual_timeout = if timeout > max_timeout { max_timeout } else { timeout };

            if elapsed >= actual_timeout {
                if retrans_count < max_retrans {
                    // Retransmit
                    req.retrans_count += 1;
                    req.sent_at = now;
                    requests_to_send.push(req.target_ip);
                } else {
                    // Give up - packets will be discarded
                    req.pending_packets.clear();
                }
            }
        }

        // Remove empty pending requests
        self.pending_requests
            .retain(|r| !r.pending_packets.is_empty());

        requests_to_send
    }

    /// Calculate timeout for retransmission (with exponential backoff)
    pub fn calculate_timeout(&self, retrans_count: u8) -> u64 {
        let base = self.config.retrans_timeout_ms;
        let max = self.config.max_retrans_timeout_ms;

        // Exponential backoff: base * 2^ retrans_count
        let timeout = base << retrans_count as u64;
        core::cmp::min(timeout, max)
    }

    /// Clean up expired cache entries
    pub fn cleanup(&mut self) {
        let now = self.now();
        let lifetime_ms = self.config.entry_lifetime_secs * 1000;

        // Note: ArpCache doesn't have timestamp in current implementation
        // This would need to be added for proper cleanup
        let _ = now;
        let _ = lifetime_ms;
    }

    /// Add a proxy ARP rule
    pub fn add_proxy_rule(&mut self, rule: ProxyArpRule) {
        self.proxy_rules.push(rule);
    }

    /// Remove a proxy ARP rule
    pub fn remove_proxy_rule(&mut self, network: u32, mask: u32) {
        self.proxy_rules
            .retain(|r| !(r.network == network && r.mask == mask));
    }

    /// Enable proxy ARP
    pub fn enable_proxy_arp(&mut self) {
        self.config.proxy_arp_enabled = true;
    }

    /// Disable proxy ARP
    pub fn disable_proxy_arp(&mut self) {
        self.config.proxy_arp_enabled = false;
    }

    /// Get pending request count
    pub fn pending_count(&self) -> usize {
        self.pending_requests
            .iter()
            .map(|r| r.pending_packets.len())
            .sum()
    }

    /// Check if there are pending requests
    pub fn has_pending(&self) -> bool {
        self.pending_requests
            .iter()
            .any(|r| !r.pending_packets.is_empty())
    }

    /// Get base ARP table
    pub fn base_table(&self) -> &ArpTable {
        &self.base
    }

    /// Get mutable base ARP table
    pub fn base_table_mut(&mut self) -> &mut ArpTable {
        &mut self.base
    }

    /// Set our MAC address
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.base.set_mac(mac);
    }

    /// Set our IP address
    pub fn set_ip(&mut self, ip: u32) {
        self.base.set_ip(ip);
    }

    /// Create ARP request
    pub fn create_request(&self, target_ip: u32) -> ArpHdr {
        self.base.create_request(target_ip)
    }
}

impl Default for EnhancedArpTable {
    fn default() -> Self {
        Self::new([0; 6], 0)
    }
}

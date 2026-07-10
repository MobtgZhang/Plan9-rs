//! DHCP Client Implementation
//!
//! Implements Dynamic Host Configuration Protocol (DHCP) client for automatic IP configuration.
//! Based on RFC 2131 and RFC 2132.

use alloc::vec::Vec;
use alloc::string::String;

// ============================================================================
// DHCP Constants
// ============================================================================

/// DHCP port numbers
pub mod port {
    /// Server port
    pub const SERVER: u16 = 67;
    /// Client port
    pub const CLIENT: u16 = 68;
}

/// DHCP operations
pub mod op {
    /// Boot request
    pub const BOOTREQUEST: u8 = 1;
    /// Boot reply
    pub const BOOTREPLY: u8 = 2;
}

/// DHCP message types (RFC 2132)
pub mod msg_type {
    pub const DHCPDISCOVER: u8 = 1;
    pub const DHCPOFFER: u8 = 2;
    pub const DHCPREQUEST: u8 = 3;
    pub const DHCPDECLINE: u8 = 4;
    pub const DHCPACK: u8 = 5;
    pub const DHCPNAK: u8 = 6;
    pub const DHCPRELEASE: u8 = 7;
    pub const DHCPINFORM: u8 = 8;
}

/// DHCP options (RFC 2132)
pub mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const HOST_NAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MSG_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST_LIST: u8 = 55;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const END: u8 = 255;
}

/// DHCP states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state
    Init,
    /// Selecting (waiting for offers)
    Selecting,
    /// Requesting (sent request, waiting for ack)
    Requesting,
    /// Bound (configuration received)
    Bound,
    /// Renewing (trying to renew)
    Renewing,
    /// Rebinding (trying to rebind)
    Rebinding,
    /// Failed
    Failed,
}

impl Default for DhcpState {
    fn default() -> Self {
        DhcpState::Init
    }
}

/// Maximum DHCP message size
pub const DHCP_MAX_SIZE: usize = 576;

/// DHCP header size
pub const DHCP_HEADER_SIZE: usize = 236;

// ============================================================================
// DHCP Packet Structure
// ============================================================================

/// DHCP packet structure
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// Operation code
    pub op: u8,
    /// Hardware address type
    pub htype: u8,
    /// Hardware address length
    pub hlen: u8,
    /// Hops
    pub hops: u8,
    /// Transaction ID
    pub xid: u32,
    /// Seconds elapsed since boot started
    pub secs: u16,
    /// Flags
    pub flags: u16,
    /// Client IP address (ciaddr)
    pub ciaddr: u32,
    /// Your IP address (yiaddr)
    pub yiaddr: u32,
    /// Server IP address (siaddr)
    pub siaddr: u32,
    /// Gateway IP address (giaddr)
    pub giaddr: u32,
    /// Client hardware address (chaddr)
    pub chaddr: [u8; 16],
    /// Magic cookie (0x63825363)
    pub magic: u32,
    /// Options
    pub options: Vec<u8>,
}

impl DhcpPacket {
    /// Create a new DHCP packet
    pub fn new() -> Self {
        Self {
            op: op::BOOTREQUEST,
            htype: 1,       // Ethernet
            hlen: 6,        // MAC address length
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0x8000, // Broadcast flag
            ciaddr: 0,
            yiaddr: 0,
            siaddr: 0,
            giaddr: 0,
            chaddr: [0; 16],
            magic: 0x6382_5363,
            options: Vec::new(),
        }
    }

    /// Set message type option
    pub fn set_message_type(&mut self, msg_type: u8) {
        self.add_option(option::MSG_TYPE, &[msg_type]);
    }

    /// Set requested IP address
    pub fn set_requested_ip(&mut self, ip: u32) {
        self.add_option(option::REQUESTED_IP, &ip.to_be_bytes());
    }

    /// Set server identifier
    pub fn set_server_id(&mut self, ip: u32) {
        self.add_option(option::SERVER_ID, &ip.to_be_bytes());
    }

    /// Set parameter request list
    pub fn set_parameter_list(&mut self, params: &[u8]) {
        self.add_option(option::PARAM_REQUEST_LIST, params);
    }

    /// Set client hardware address
    pub fn set_chaddr(&mut self, mac: &[u8]) {
        let len = mac.len().min(16);
        self.chaddr[..len].copy_from_slice(&mac[..len]);
    }

    /// Add an option
    pub fn add_option(&mut self, code: u8, data: &[u8]) {
        self.options.push(code);
        self.options.push(data.len() as u8);
        self.options.extend_from_slice(data);
    }

    /// Add end option
    pub fn add_end(&mut self) {
        self.options.push(option::END);
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DHCP_HEADER_SIZE + self.options.len());
        
        buf.push(self.op);
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.to_be_bytes());
        buf.extend_from_slice(&self.yiaddr.to_be_bytes());
        buf.extend_from_slice(&self.siaddr.to_be_bytes());
        buf.extend_from_slice(&self.giaddr.to_be_bytes());
        buf.extend_from_slice(&self.chaddr);
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.options);
        
        // Pad to minimum size
        while buf.len() < DHCP_HEADER_SIZE {
            buf.push(option::PAD);
        }
        
        buf
    }

    /// Parse from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < DHCP_HEADER_SIZE {
            return None;
        }
        
        let mut packet = Self::new();
        packet.op = buf[0];
        packet.htype = buf[1];
        packet.hlen = buf[2];
        packet.hops = buf[3];
        packet.xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        packet.secs = u16::from_be_bytes([buf[8], buf[9]]);
        packet.flags = u16::from_be_bytes([buf[10], buf[11]]);
        packet.ciaddr = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        packet.yiaddr = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        packet.siaddr = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        packet.giaddr = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        packet.chaddr.copy_from_slice(&buf[28..44]);
        packet.magic = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
        
        if packet.magic != 0x6382_5363 {
            return None; // Invalid magic cookie
        }
        
        // Parse options
        let opt_start = DHCP_HEADER_SIZE;
        let mut i = opt_start;
        while i < buf.len() {
            let code = buf[i];
            if code == option::END {
                break;
            }
            if code == option::PAD {
                i += 1;
                continue;
            }
            if i + 1 >= buf.len() {
                break;
            }
            let len = buf[i + 1] as usize;
            if i + 2 + len > buf.len() {
                break;
            }
            packet.options.push(code);
            packet.options.push(len as u8);
            packet.options.extend_from_slice(&buf[i + 2..i + 2 + len]);
            i += 2 + len;
        }
        
        Some(packet)
    }

    /// Get option by code
    pub fn get_option(&self, code: u8) -> Option<&[u8]> {
        let mut i = 0;
        while i < self.options.len() {
            if self.options[i] == code {
                let len = self.options[i + 1] as usize;
                return Some(&self.options[i + 2..i + 2 + len]);
            }
            if self.options[i] == option::END {
                break;
            }
            if self.options[i] == option::PAD {
                i += 1;
                continue;
            }
            if i + 1 >= self.options.len() {
                break;
            }
            let len = self.options[i + 1] as usize;
            i += 2 + len;
        }
        None
    }

    /// Get message type
    pub fn message_type(&self) -> Option<u8> {
        self.get_option(option::MSG_TYPE).map(|v| v[0])
    }

    /// Get server identifier
    pub fn server_id(&self) -> Option<u32> {
        self.get_option(option::SERVER_ID).map(|v| {
            u32::from_be_bytes([v[0], v[1], v[2], v[3]])
        })
    }

    /// Get offered IP address
    pub fn offered_ip(&self) -> u32 {
        self.yiaddr
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DHCP Configuration
// ============================================================================

/// DHCP configuration received from server
#[derive(Debug, Clone, Default)]
pub struct DhcpConfig {
    /// IP address
    pub ip: u32,
    /// Subnet mask
    pub subnet_mask: u32,
    /// Gateway/Router
    pub gateway: u32,
    /// DNS servers
    pub dns_servers: Vec<u32>,
    /// Lease time (seconds)
    pub lease_time: u32,
    /// Renewal time (T1) (seconds)
    pub renewal_time: u32,
    /// Rebinding time (T2) (seconds)
    pub rebinding_time: u32,
    /// Domain name
    pub domain_name: String,
    /// Server IP
    pub server_ip: u32,
}

impl DhcpConfig {
    /// Create from DHCP packet
    pub fn from_packet(packet: &DhcpPacket) -> Option<Self> {
        if packet.message_type()? != msg_type::DHCPACK {
            return None;
        }
        
        let server_ip = packet.server_id()?;
        
        let mut config = Self {
            ip: packet.yiaddr,
            subnet_mask: 0xFFFFFF00, // Default /24
            gateway: 0,
            dns_servers: Vec::new(),
            lease_time: 86400, // Default 24 hours
            renewal_time: 43200, // Default 12 hours
            rebinding_time: 75600, // Default 21 hours
            domain_name: String::new(),
            server_ip,
        };
        
        // Parse options
        if let Some(mask) = packet.get_option(option::SUBNET_MASK) {
            if mask.len() >= 4 {
                config.subnet_mask = u32::from_be_bytes([mask[0], mask[1], mask[2], mask[3]]);
            }
        }
        
        if let Some(router) = packet.get_option(option::ROUTER) {
            if router.len() >= 4 {
                config.gateway = u32::from_be_bytes([router[0], router[1], router[2], router[3]]);
            }
        }
        
        if let Some(dns) = packet.get_option(option::DNS) {
            for i in (0..dns.len()).step_by(4) {
                if i + 4 <= dns.len() {
                    let ip = u32::from_be_bytes([dns[i], dns[i+1], dns[i+2], dns[i+3]]);
                    config.dns_servers.push(ip);
                }
            }
        }
        
        if let Some(lease) = packet.get_option(option::LEASE_TIME) {
            if lease.len() >= 4 {
                config.lease_time = u32::from_be_bytes([lease[0], lease[1], lease[2], lease[3]]);
                config.renewal_time = config.lease_time / 2;
                config.rebinding_time = (config.lease_time * 7) / 8;
            }
        }
        
        if let Some(domain) = packet.get_option(option::DOMAIN_NAME) {
            let cow = core::str::from_utf8(domain).unwrap_or("");
            config.domain_name = alloc::string::String::from(cow);
        }
        
        Some(config)
    }
}

// ============================================================================
// DHCP Client
// ============================================================================

/// DHCP client state machine
pub struct DhcpClient {
    /// Current state
    state: DhcpState,
    /// Transaction ID (random)
    xid: u32,
    /// Client hardware address
    mac: [u8; 6],
    /// Received configuration
    config: Option<DhcpConfig>,
    /// Server IP from offer
    server_ip: Option<u32>,
    /// Requested IP
    requested_ip: Option<u32>,
    /// Retransmission count
    retransmit_count: u32,
    /// Initial timeout (seconds)
    timeout: u64,
}

impl DhcpClient {
    /// Create a new DHCP client
    pub fn new(mac: &[u8]) -> Self {
        let mut client = Self {
            state: DhcpState::Init,
            xid: 0,
            mac: [0; 6],
            config: None,
            server_ip: None,
            requested_ip: None,
            retransmit_count: 0,
            timeout: 1,
        };
        
        let len = mac.len().min(6);
        client.mac[..len].copy_from_slice(&mac[..len]);
        
        // Generate random transaction ID
        client.xid = Self::generate_xid();
        
        client
    }

    /// Generate random transaction ID
    fn generate_xid() -> u32 {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0x12345678);
        
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Mix with pointer address for some randomness
        let ptr_bits = (counter as *const u8) as u64;
        let val = counter.wrapping_add(ptr_bits.rotate_left(17).wrapping_mul(0x9E3779B97F4A7C15));
        val as u32
    }

    /// Start DHCP negotiation
    pub fn start(&mut self) {
        self.state = DhcpState::Init;
        self.xid = Self::generate_xid();
    }

    /// Build DHCPDISCOVER packet
    pub fn build_discover(&self) -> DhcpPacket {
        let mut packet = DhcpPacket::new();
        packet.xid = self.xid;
        packet.set_chaddr(&self.mac);
        packet.set_message_type(msg_type::DHCPDISCOVER);
        packet.set_parameter_list(&[
            option::SUBNET_MASK,
            option::ROUTER,
            option::DNS,
            option::DOMAIN_NAME,
            option::LEASE_TIME,
        ]);
        packet.add_end();
        packet
    }

    /// Build DHCPREQUEST packet
    pub fn build_request(&self) -> DhcpPacket {
        let mut packet = DhcpPacket::new();
        packet.xid = self.xid;
        packet.set_chaddr(&self.mac);
        packet.set_message_type(msg_type::DHCPREQUEST);
        
        if let Some(ip) = self.requested_ip {
            packet.set_requested_ip(ip);
        }
        
        if let Some(server) = self.server_ip {
            packet.set_server_id(server);
        }
        
        packet.set_parameter_list(&[
            option::SUBNET_MASK,
            option::ROUTER,
            option::DNS,
            option::DOMAIN_NAME,
            option::LEASE_TIME,
        ]);
        packet.add_end();
        packet
    }

    /// Process received packet
    pub fn process_packet(&mut self, packet: &DhcpPacket) -> Option<DhcpConfig> {
        // Check transaction ID matches
        if packet.xid != self.xid {
            return None;
        }
        
        match self.state {
            DhcpState::Selecting => {
                if let Some(msg_type) = packet.message_type() {
                    if msg_type == msg_type::DHCPOFFER {
                        // Store server IP and offered IP
                        self.server_ip = packet.server_id();
                        self.requested_ip = Some(packet.offered_ip());
                        
                        // Move to requesting state
                        self.state = DhcpState::Requesting;
                    }
                }
                None
            }
            DhcpState::Requesting | DhcpState::Renewing | DhcpState::Rebinding => {
                if let Some(msg_type) = packet.message_type() {
                    if msg_type == msg_type::DHCPACK {
                        // Got ACK - extract configuration
                        if let Some(config) = DhcpConfig::from_packet(packet) {
                            self.config = Some(config.clone());
                            self.state = DhcpState::Bound;
                            return Some(config);
                        }
                    } else if msg_type == msg_type::DHCPNAK {
                        // Got NAK - restart negotiation
                        self.state = DhcpState::Init;
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get current state
    pub fn state(&self) -> DhcpState {
        self.state
    }

    /// Get current configuration
    pub fn config(&self) -> Option<&DhcpConfig> {
        self.config.as_ref()
    }

    /// Transition to next state
    pub fn transition(&mut self) {
        match self.state {
            DhcpState::Init => {
                self.state = DhcpState::Selecting;
                self.retransmit_count = 0;
                self.timeout = 1;
            }
            DhcpState::Selecting | DhcpState::Requesting => {
                self.retransmit_count += 1;
                // Exponential backoff: 2, 4, 8, 16, 32, 64 seconds
                self.timeout = (self.timeout * 2).min(64);
                
                if self.retransmit_count >= 10 {
                    self.state = DhcpState::Failed;
                }
            }
            DhcpState::Bound => {
                // Would transition to Renewing after T1
            }
            _ => {}
        }
    }

    /// Check if should retransmit
    pub fn should_retransmit(&self) -> bool {
        matches!(self.state, DhcpState::Selecting | DhcpState::Requesting)
    }

    /// Get current timeout value
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
}

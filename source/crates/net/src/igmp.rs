//! IGMP (Internet Group Management Protocol) Implementation
//!
//! Implements IGMPv2 for IPv4 multicast group management.
//!
//! ## Overview
//!
//! IGMP is used by IP hosts to report their multicast group memberships
//! to adjacent routers. This implementation supports IGMPv2.
//!
//! ## Message Types
//!
//! - Membership Query (Type 0x11)
//! - Membership Report (Type 0x16)
//! - Leave Group (Type 0x17)
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::igmp::{IgmpSocket, IgmpMessage};
//!
//! let mut socket = IgmpSocket::new();
//! socket.join_group(Ipv4Addr::new(224, 0, 0, 1)).unwrap();
//! ```

use crate::plan9_common::sync::Spinlock;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

/// IGMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpType {
    /// Membership Query
    Query = 0x11,
    /// Membership Report (IGMPv2)
    Report = 0x16,
    /// Leave Group (IGMPv2)
    Leave = 0x17,
    /// Membership Report (IGMPv1) - deprecated
    ReportV1 = 0x12,
    /// IGMPv3 Membership Report
    ReportV3 = 0x22,
}

impl IgmpType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x11 => Some(IgmpType::Query),
            0x16 => Some(IgmpType::Report),
            0x17 => Some(IgmpType::Leave),
            0x12 => Some(IgmpType::ReportV1),
            0x22 => Some(IgmpType::ReportV3),
            _ => None,
        }
    }
}

/// IGMP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpVersion {
    V1,
    V2,
    V3,
}

/// IGMP group state
#[derive(Debug, Clone)]
pub struct IgmpGroupState {
    /// Group address
    pub group: [u8; 4],
    /// IGMP version to use
    version: IgmpVersion,
    /// Timer value (in units of 100ms)
    timer: u8,
    /// Whether we've sent a report
    reported: bool,
}

impl IgmpGroupState {
    /// Create new group state
    pub fn new(group: [u8; 4]) -> Self {
        Self {
            group,
            version: IgmpVersion::V2,
            timer: 0,
            reported: false,
        }
    }

    /// Set IGMP version
    pub fn set_version(&mut self, version: IgmpVersion) {
        self.version = version;
    }

    /// Get IGMP version
    pub fn version(&self) -> IgmpVersion {
        self.version
    }

    /// Start the timer
    pub fn start_timer(&mut self, value: u8) {
        self.timer = value;
    }

    /// Decrement timer
    pub fn tick_timer(&mut self) {
        if self.timer > 0 {
            self.timer -= 1;
        }
    }

    /// Check if timer expired
    pub fn timer_expired(&self) -> bool {
        self.timer == 0
    }
}

/// IGMP message
#[derive(Debug, Clone)]
pub enum IgmpMessage {
    /// Membership Query
    MembershipQuery {
        /// Maximum response time (in 100ms units)
        max_resp: u8,
        /// Group address (None for general query)
        group: Option<[u8; 4]>,
    },
    /// Membership Report
    MembershipReport {
        /// Group address
        group: [u8; 4],
    },
    /// Leave Group
    LeaveGroup {
        /// Group address
        group: [u8; 4],
    },
}

impl IgmpMessage {
    /// Parse IGMP message from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let msg_type = data[0];
        let max_resp = data[1];
        
        // Checksum (bytes 2-3)
        let _checksum = u16::from_be_bytes([data[2], data[3]]);
        
        // Group address
        let group = [data[4], data[5], data[6], data[7]];

        match IgmpType::from_u8(msg_type)? {
            IgmpType::Query => {
                if group == [0, 0, 0, 0] {
                    Some(IgmpMessage::MembershipQuery { max_resp, group: None })
                } else {
                    Some(IgmpMessage::MembershipQuery { max_resp, group: Some(group) })
                }
            }
            IgmpType::Report => {
                Some(IgmpMessage::MembershipReport { group })
            }
            IgmpType::Leave => {
                Some(IgmpMessage::LeaveGroup { group })
            }
            _ => None,
        }
    }

    /// Serialize IGMP message to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        
        match self {
            IgmpMessage::MembershipQuery { max_resp, group } => {
                data.push(IgmpType::Query as u8);
                data.push(*max_resp);
                // Checksum placeholder
                data.extend_from_slice(&[0, 0]);
                if let Some(g) = group {
                    data.extend_from_slice(g);
                } else {
                    data.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
            IgmpMessage::MembershipReport { group } => {
                data.push(IgmpType::Report as u8);
                data.push(0); // Max resp (not used in reports)
                data.extend_from_slice(&[0, 0]); // Checksum
                data.extend_from_slice(group);
            }
            IgmpMessage::LeaveGroup { group } => {
                data.push(IgmpType::Leave as u8);
                data.push(0);
                data.extend_from_slice(&[0, 0]); // Checksum
                data.extend_from_slice(group);
            }
        }

        // Calculate checksum
        let checksum = calculate_checksum(&data);
        data[2] = (checksum >> 8) as u8;
        data[3] = checksum as u8;

        data
    }
}

/// Calculate IGMP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Sum all 16-bit words
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
    }
    
    // Add carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

/// IGMP socket for group management
pub struct IgmpSocket {
    /// Joined groups
    groups: BTreeMap<u32, IgmpGroupState>,
    /// Last query received
    last_query: Option<([u8; 4], u8)>,
    /// Interface index
    ifindex: u32,
}

impl IgmpSocket {
    /// Create new IGMP socket
    pub fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            last_query: None,
            ifindex: 0,
        }
    }

    /// Create new IGMP socket with interface
    pub fn new_on_interface(ifindex: u32) -> Self {
        Self {
            groups: BTreeMap::new(),
            last_query: None,
            ifindex,
        }
    }

    /// Check if an address is a valid multicast address
    pub fn is_multicast(addr: &[u8; 4]) -> bool {
        addr[0] & 0xF0 == 0xE0
    }

    /// Join a multicast group
    pub fn join_group(&mut self, addr: &[u8; 4]) -> Result<(), IgmpError> {
        if !Self::is_multicast(addr) {
            return Err(IgmpError::InvalidAddress);
        }

        let key = u32::from_be_bytes(*addr);
        
        // Check if already joined
        if self.groups.contains_key(&key) {
            return Ok(());
        }

        // Add to groups
        self.groups.insert(key, IgmpGroupState::new(*addr));

        // TODO: Send IGMP Membership Report
        // In a real implementation, this would schedule the report
        // with a random delay (0-10 seconds) to avoid report storms

        Ok(())
    }

    /// Leave a multicast group
    pub fn leave_group(&mut self, addr: &[u8; 4]) -> Result<(), IgmpError> {
        if !Self::is_multicast(addr) {
            return Err(IgmpError::InvalidAddress);
        }

        let key = u32::from_be_bytes(*addr);
        
        if let Some(_state) = self.groups.remove(&key) {
            // TODO: Send IGMP Leave Group message
            // Only sent if this is the last host in the group
            return Ok(());
        }

        Err(IgmpError::NotMember)
    }

    /// Handle received IGMP message
    pub fn handle_message(&mut self, data: &[u8]) -> Result<(), IgmpError> {
        let msg = IgmpMessage::parse(data).ok_or(IgmpError::InvalidPacket)?;

        match msg {
            IgmpMessage::MembershipQuery { max_resp, group } => {
                self.handle_query(max_resp, group)?;
            }
            IgmpMessage::MembershipReport { group } => {
                self.handle_report(&group)?;
            }
            IgmpMessage::LeaveGroup { group } => {
                self.handle_leave(&group)?;
            }
        }

        Ok(())
    }

    /// Handle IGMP query
    fn handle_query(&mut self, max_resp: u8, group: Option<[u8; 4]>) -> Result<(), IgmpError> {
        self.last_query = group.map(|g| (g, max_resp));

        match group {
            Some(g) => {
                // Group-specific query
                let key = u32::from_be_bytes(g);
                if let Some(state) = self.groups.get_mut(&key) {
                    // Set timer to random value 0-max_resp
                    state.start_timer(max_resp);
                }
            }
            None => {
                // General query - respond for all groups
                for state in self.groups.values_mut() {
                    state.start_timer(max_resp);
                }
            }
        }

        Ok(())
    }

    /// Handle IGMP report
    fn handle_report(&mut self, group: &[u8; 4]) -> Result<(), IgmpError> {
        let key = u32::from_be_bytes(*group);

        if let Some(state) = self.groups.get_mut(&key) {
            // If we have a pending report, cancel it
            // The router doesn't need our report since another host reported
            state.reported = true;
            state.timer = 0;
        }

        Ok(())
    }

    /// Handle IGMP leave
    fn handle_leave(&mut self, group: &[u8; 4]) -> Result<(), IgmpError> {
        // Leave messages are processed by routers, not hosts
        // Hosts typically don't need to act on them
        let _ = group;
        Ok(())
    }

    /// Get list of joined groups
    pub fn get_groups(&self) -> Vec<[u8; 4]> {
        self.groups.keys().map(|k| k.to_be_bytes()).collect()
    }

    /// Check if joined to a group
    pub fn is_joined(&self, addr: &[u8; 4]) -> bool {
        let key = u32::from_be_bytes(*addr);
        self.groups.contains_key(&key)
    }

    /// Tick timers (call periodically)
    pub fn tick(&mut self) {
        for state in self.groups.values_mut() {
            state.tick_timer();
        }
    }

    /// Get groups with expired timers (need to send reports)
    pub fn expired_groups(&self) -> Vec<[u8; 4]> {
        self.groups
            .iter()
            .filter(|(_, s)| !s.reported && s.timer_expired())
            .map(|(k, _)| k.to_be_bytes())
            .collect()
    }
}

/// IGMP errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpError {
    /// Invalid multicast address
    InvalidAddress,
    /// Not a member of the group
    NotMember,
    /// Invalid packet format
    InvalidPacket,
    /// No space available
    NoSpace,
}

impl IgmpError {
    pub fn as_str(&self) -> &'static str {
        match self {
            IgmpError::InvalidAddress => "invalid multicast address",
            IgmpError::NotMember => "not a member of the group",
            IgmpError::InvalidPacket => "invalid IGMP packet",
            IgmpError::NoSpace => "no space for new group",
        }
    }
}

/// IGMP statistics
#[derive(Debug, Clone, Default)]
pub struct IgmpStats {
    /// Membership queries received
    pub queries_rx: u32,
    /// Membership reports sent
    pub reports_tx: u32,
    /// Membership reports received
    pub reports_rx: u32,
    /// Leave messages sent
    pub leaves_tx: u32,
    /// Leave messages received
    pub leaves_rx: u32,
    /// Invalid packets received
    pub invalid_rx: u32,
}

impl IgmpSocket {
    /// Get statistics
    pub fn stats(&self) -> IgmpStats {
        // In a real implementation, this would track statistics
        IgmpStats::default()
    }
}

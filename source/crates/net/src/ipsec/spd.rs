//! Security Policy Database (SPD)
//!
//! Manages IPsec security policies.

use alloc::vec::Vec;

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Discard the packet
    Discard,
    /// Apply IPsec
    Apply,
    /// Bypass IPsec (no protection)
    Bypass,
}

/// IP address with prefix length
#[derive(Debug, Clone)]
pub struct IpCidr {
    /// Address (IPv4 or IPv6)
    pub addr: [u8; 16],
    /// Prefix length
    pub prefix: u8,
    /// Address family (4 or 6)
    pub family: u8,
}

impl IpCidr {
    /// Create a new CIDR
    pub fn new(addr: [u8; 16], prefix: u8, family: u8) -> Self {
        Self { addr, prefix, family }
    }

    /// Check if address matches
    pub fn contains(&self, addr: &[u8]) -> bool {
        if addr.len() != self.addr.len() || addr.len() != (self.family as usize * 4) {
            return false;
        }
        
        let bytes = if self.family == 4 { 4 } else { 16 };
        let prefix_bytes = (self.prefix / 8) as usize;
        let prefix_bits = self.prefix % 8;
        
        // Compare full bytes
        for i in 0..prefix_bytes {
            if addr[i] != self.addr[i] {
                return false;
            }
        }
        
        // Compare partial byte
        if prefix_bits > 0 && prefix_bytes < bytes {
            let mask = 0xFF << (8 - prefix_bits);
            if addr[prefix_bytes] != (self.addr[prefix_bytes] & mask) {
                return false;
            }
        }
        
        true
    }
}

/// Security Policy
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Source address range
    pub src: IpCidr,
    /// Destination address range
    pub dst: IpCidr,
    /// Upper layer protocol
    pub proto: u8,
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Policy action
    pub action: PolicyAction,
    /// IPsec protocol (if action is Apply)
    pub ipsec_proto: Option<u8>,
    /// IPsec mode
    pub mode: super::sad::IpsecMode,
    /// Level (require, unique, etc.)
    pub level: u8,
}

impl SecurityPolicy {
    /// Create a new security policy
    pub fn new(src: IpCidr, dst: IpCidr, action: PolicyAction) -> Self {
        Self {
            src,
            dst,
            proto: 0,
            sport: 0,
            dport: 0,
            action,
            ipsec_proto: None,
            mode: super::sad::IpsecMode::Transport,
            level: 0,
        }
    }

    /// Check if a packet matches this policy
    pub fn matches(&self, src: &[u8], dst: &[u8], proto: u8, sport: u16, dport: u16) -> bool {
        // Check address match
        if !self.src.contains(src) || !self.dst.contains(dst) {
            return false;
        }
        
        // Check protocol (0 = any)
        if self.proto != 0 && self.proto != proto {
            return false;
        }
        
        // Check ports (0 = any)
        if self.sport != 0 && self.sport != sport {
            return false;
        }
        if self.dport != 0 && self.dport != dport {
            return false;
        }
        
        true
    }
}

/// SPD entry with policy
#[derive(Debug, Clone)]
pub struct SpdEntry {
    /// Entry index
    pub index: u32,
    /// Security policy
    pub policy: SecurityPolicy,
}

impl SpdEntry {
    /// Create a new SPD entry
    pub fn new(policy: SecurityPolicy) -> Self {
        static mut NEXT_INDEX: u32 = 1;
        unsafe {
            let idx = NEXT_INDEX;
            NEXT_INDEX += 1;
            Self { index: idx, policy }
        }
    }
}

/// Security Policy Database
pub struct SpdDatabase {
    /// Entries
    entries: Vec<SpdEntry>,
}

impl SpdDatabase {
    /// Create a new SPD database
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a security policy
    pub fn add(&mut self, entry: SpdEntry) {
        self.entries.push(entry);
    }

    /// Look up policy for a packet
    pub fn lookup(&self, src: &[u8], dst: &[u8], proto: u8, sport: u16, dport: u16) -> Option<&SecurityPolicy> {
        for entry in &self.entries {
            if entry.policy.matches(src, dst, proto, sport, dport) {
                return Some(&entry.policy);
            }
        }
        None
    }

    /// Remove an entry by index
    pub fn remove(&mut self, index: u32) {
        self.entries.retain(|e| e.index != index);
    }
}

impl Default for SpdDatabase {
    fn default() -> Self {
        Self::new()
    }
}

//! Network Interface Layer
//!
//! Implements the network protocol stack interface including:
//! - Network interface structures
//! - ARP cache
//! - Route table
//! - Protocol registration

use alloc::vec::Vec;
use crate::plan9_common::sync::Spinlock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum network interfaces
pub const NNETIF: usize = 4;

/// Maximum ARP cache entries
pub const ARP_SIZE: usize = 64;

/// Maximum routing table entries
pub const ROUTE_SIZE: usize = 32;

/// Maximum MTU
pub const MAX_MTU: usize = 65536;

/// Default MTU for Ethernet
pub const DEFAULT_MTU: usize = 1500;

// ============================================================================
// MAC Address
// ============================================================================

/// MAC (Ethernet) address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Broadcast address
    pub const BROADCAST: MacAddr = MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    
    /// Null address
    pub const NULL: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);

    /// Create from bytes
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Create from array reference
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&slice[..6]);
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Check if broadcast
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }

    /// Check if multicast
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Format as string
    pub fn format(&self) -> [u8; 18] {
        let mut s = [0u8; 18];
        for (i, b) in self.0.iter().enumerate() {
            let hex = b"0123456789abcdef";
            s[i * 3] = hex[(b >> 4) as usize];
            s[i * 3 + 1] = hex[(b & 0xf) as usize];
            if i < 5 {
                s[i * 3 + 2] = b':';
            }
        }
        s
    }
}

// ============================================================================
// IP Address
// ============================================================================

/// IPv4 address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub u32);

impl Ipv4Addr {
    /// Loopback address (127.0.0.1)
    pub const LOOPBACK: Ipv4Addr = Ipv4Addr(0x0100007f);
    
    /// Any address (0.0.0.0)
    pub const ANY: Ipv4Addr = Ipv4Addr(0);
    
    /// Broadcast address (255.255.255.255)
    pub const BROADCAST: Ipv4Addr = Ipv4Addr(0xffffffff);

    /// Create from octets
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self((d as u32) << 24 | (c as u32) << 16 | (b as u32) << 8 | a as u32)
    }

    /// Get octets
    pub fn octets(&self) -> [u8; 4] {
        [
            self.0 as u8,
            (self.0 >> 8) as u8,
            (self.0 >> 16) as u8,
            (self.0 >> 24) as u8,
        ]
    }

    /// Create from bytes (network byte order)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 4 {
            Some(Self(
                bytes[0] as u32
                | (bytes[1] as u32) << 8
                | (bytes[2] as u32) << 16
                | (bytes[3] as u32) << 24,
            ))
        } else {
            None
        }
    }

    /// Convert to bytes (network byte order)
    pub fn to_bytes(&self) -> [u8; 4] {
        self.octets()
    }

    /// Format as string
    pub fn format(&self) -> [u8; 16] {
        let octets = self.octets();
        let mut s = [0u8; 16];
        s[0] = b'0' + octets[0] / 100;
        s[1] = b'0' + (octets[0] / 10) % 10;
        s[2] = b'0' + octets[0] % 10;
        s[3] = b'.';
        s[4] = b'0' + octets[1] / 100;
        s[5] = b'0' + (octets[1] / 10) % 10;
        s[6] = b'0' + octets[1] % 10;
        s[7] = b'.';
        s[8] = b'0' + octets[2] / 100;
        s[9] = b'0' + (octets[2] / 10) % 10;
        s[10] = b'0' + octets[2] % 10;
        s[11] = b'.';
        s[12] = b'0' + octets[3] / 100;
        s[13] = b'0' + (octets[3] / 10) % 10;
        s[14] = b'0' + octets[3] % 10;
        s
    }
}

// ============================================================================
// Network Interface
// ============================================================================

/// Network interface state
#[derive(Debug, Clone, Copy)]
pub enum IfState {
    Down,
    Up,
    Testing,
}

/// Network interface
#[derive(Debug)]
pub struct NetIf {
    /// Interface name
    pub name: [u8; 16],
    /// Interface index
    pub index: usize,
    /// MAC address
    pub mac: MacAddr,
    /// IPv4 address
    pub ip: Ipv4Addr,
    /// Netmask
    pub netmask: Ipv4Addr,
    /// MTU
    pub mtu: u32,
    /// State
    pub state: IfState,
    /// Flags
    pub flags: u32,
    /// Reference count
    refcount: Spinlock<u32>,
}

impl NetIf {
    /// Create new network interface
    pub fn new(index: usize) -> Self {
        Self {
            name: [0; 16],
            index,
            mac: MacAddr::NULL,
            ip: Ipv4Addr::ANY,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: DEFAULT_MTU as u32,
            state: IfState::Down,
            flags: 0,
            refcount: Spinlock::new(1),
        }
    }

    /// Set interface name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Set MAC address
    pub fn set_mac(&mut self, mac: MacAddr) {
        self.mac = mac;
    }

    /// Set IP address
    pub fn set_ip(&mut self, ip: Ipv4Addr) {
        self.ip = ip;
    }

    /// Set netmask
    pub fn set_netmask(&mut self, mask: Ipv4Addr) {
        self.netmask = mask;
    }

    /// Check if interface is up
    pub fn is_up(&self) -> bool {
        matches!(self.state, IfState::Up)
    }

    /// Bring interface up
    pub fn up(&mut self) {
        self.state = IfState::Up;
        self.flags |= IFF_UP;
    }

    /// Take interface down
    pub fn down(&mut self) {
        self.state = IfState::Down;
        self.flags &= !IFF_UP;
    }

    /// Increment reference count
    pub fn incref(&self) {
        *self.refcount.lock() += 1;
    }

    /// Decrement reference count
    pub fn decref(&self) -> u32 {
        let mut count = self.refcount.lock();
        *count = count.saturating_sub(1);
        *count
    }
}

/// Interface flags
pub const IFF_UP: u32 = 0x1;         // Interface is up
pub const IFF_BROADCAST: u32 = 0x2;  // Broadcast address valid
pub const IFF_DEBUG: u32 = 0x4;       // Turn on debugging
pub const IFF_LOOPBACK: u32 = 0x8;   // Is a loopback interface
pub const IFF_POINTOPOINT: u32 = 0x10; // Point-to-point link
pub const IFF_RUNNING: u32 = 0x40;   // Interface is running
pub const IFF_NOARP: u32 = 0x80;     // No ARP protocol
pub const IFF_PROMISC: u32 = 0x100;   // Promiscuous mode
pub const IFF_ALLMULTI: u32 = 0x200;  // Receive all multicast

// ============================================================================
// ARP Cache
// ============================================================================

/// ARP cache entry
#[derive(Debug)]
pub struct ArpEntry {
    /// IP address
    pub ip: Ipv4Addr,
    /// MAC address
    pub mac: MacAddr,
    /// Interface
    pub ifindex: usize,
    /// State
    pub state: ArpState,
    /// Age (ticks since last update)
    pub age: u32,
}

impl ArpEntry {
    /// Create new entry
    pub fn new(ip: Ipv4Addr, mac: MacAddr, ifindex: usize) -> Self {
        Self {
            ip,
            mac,
            ifindex,
            state: ArpState::Static,
            age: 0,
        }
    }
}

/// ARP entry state
#[derive(Debug, Clone, Copy)]
pub enum ArpState {
    /// Pending resolution
    Pending,
    /// Resolution complete
    Resolved,
    /// Static entry (never expires)
    Static,
}

/// ARP cache
pub struct ArpCache {
    /// Entries
    entries: Spinlock<[Option<ArpEntry>; ARP_SIZE]>,
    /// Number of entries
    count: Spinlock<usize>,
}

impl ArpCache {
    /// Create new ARP cache
    pub fn new() -> Self {
        Self {
            entries: Spinlock::new([const { None }; ARP_SIZE]),
            count: Spinlock::new(0),
        }
    }

    /// Look up MAC address for IP
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        let entries = self.entries.lock();
        for entry in entries.iter() {
            if let Some(e) = entry {
                if e.ip == ip {
                    return Some(e.mac);
                }
            }
        }
        None
    }

    /// Add entry to cache
    pub fn insert(&self, ip: Ipv4Addr, mac: MacAddr, ifindex: usize) {
        let mut entries = self.entries.lock();
        let mut count = self.count.lock();

        // Find empty slot
        for entry in entries.iter_mut() {
            if entry.is_none() {
                *entry = Some(ArpEntry::new(ip, mac, ifindex));
                *count += 1;
                return;
            }
        }

        // Replace oldest entry if full
        if let Some(oldest) = entries.first_mut() {
            *oldest = Some(ArpEntry::new(ip, mac, ifindex));
        }
    }

    /// Remove entry
    pub fn remove(&self, ip: Ipv4Addr) {
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                if e.ip == ip {
                    *entry = None;
                    return;
                }
            }
        }
    }

    /// Age entries and remove old ones
    pub fn age(&self) {
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                e.age += 1;
                if e.age > 600 && !matches!(e.state, ArpState::Static) {
                    *entry = None; // Remove old entries
                }
            }
        }
    }
}

// ============================================================================
// Routing Table
// ============================================================================

/// Route entry
#[derive(Debug)]
pub struct RouteEntry {
    /// Destination network
    pub dest: Ipv4Addr,
    /// Netmask
    pub mask: Ipv4Addr,
    /// Gateway (0 for direct)
    pub gateway: Ipv4Addr,
    /// Interface index
    pub ifindex: usize,
    /// Metric (lower is better)
    pub metric: u32,
    /// Flags
    pub flags: u32,
}

impl RouteEntry {
    /// Create new route
    pub fn new(dest: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr, 
               ifindex: usize) -> Self {
        Self {
            dest,
            mask,
            gateway,
            ifindex,
            metric: 0,
            flags: 0,
        }
    }

    /// Check if route matches destination
    pub fn matches(&self, dest: Ipv4Addr) -> bool {
        (dest.0 & self.mask.0) == (self.dest.0 & self.mask.0)
    }

    /// Get gateway MAC (via ARP if needed)
    pub fn gateway_mac(&self) -> Option<MacAddr> {
        if self.gateway == Ipv4Addr::ANY {
            // Direct delivery
            None
        } else {
            // Need ARP lookup
            ARP.lock().lookup(self.gateway)
        }
    }
}

/// Route flags
pub const RTF_UP: u32 = 0x1;       // Route is up
pub const RTF_GATEWAY: u32 = 0x2;  // Gateway route
pub const RTF_HOST: u32 = 0x4;     // Host route
pub const RTF_DYNAMIC: u32 = 0x10; // Created dynamically

/// Routing table
pub struct RouteTable {
    /// Entries
    entries: Spinlock<[Option<RouteEntry>; ROUTE_SIZE]>,
    /// Number of entries
    count: Spinlock<usize>,
}

impl RouteTable {
    /// Create new routing table
    pub fn new() -> Self {
        Self {
            entries: Spinlock::new([const { None }; ROUTE_SIZE]),
            count: Spinlock::new(0),
        }
    }

    /// Add route
    pub fn add(&self, entry: RouteEntry) -> bool {
        let mut entries = self.entries.lock();
        let mut count = self.count.lock();

        for slot in entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                *count += 1;
                return true;
            }
        }
        false
    }

    /// Remove route
    pub fn remove(&self, dest: Ipv4Addr) -> bool {
        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                if e.dest == dest {
                    *entry = None;
                    return true;
                }
            }
        }
        false
    }

    /// Lookup route for destination
    pub fn lookup(&self, dest: Ipv4Addr) -> Option<&'static RouteEntry> {
        let entries = self.entries.lock();
        
        // Find most specific route (longest prefix match)
        let mut best: Option<&RouteEntry> = None;
        let mut best_prefix = 0u32;

        for entry in entries.iter() {
            if let Some(e) = entry {
                if e.flags & RTF_UP != 0 && e.matches(dest) {
                    // Count bits in mask to find prefix length
                    let prefix = (!e.mask.0).count_ones();
                    if prefix > best_prefix {
                        best_prefix = prefix;
                        best = Some(e);
                    }
                }
            }
        }
        best
    }

    /// Initialize default routes
    pub fn init_defaults(&self) {
        // Default route (0.0.0.0/0)
        self.add(RouteEntry::new(
            Ipv4Addr::ANY,
            Ipv4Addr::ANY,
            Ipv4Addr::ANY,
            0, // Default interface
        ));
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global network interface array
static NETIFS: Spinlock<[Option<NetIf>; NNETIF]> = 
    Spinlock::new([const { None }; NNETIF]);

/// Global ARP cache
pub static ARP: ArpCache = ArpCache::new();

/// Global routing table
pub static ROUTES: RouteTable = RouteTable::new();

/// Initialize network layer
pub fn init_net() {
    ROUTES.init_defaults();
}

/// Get network interface by index
pub fn get_if(index: usize) -> Option<SpinlockGuard<'static, Option<NetIf>>> {
    if index < NNETIF {
        Some(NETIFS.lock())
    } else {
        None
    }
}

/// Register network interface
pub fn register_if(iface: NetIf) -> Option<usize> {
    let mut netifs = NETIFS.lock();
    for (i, slot) in netifs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(iface);
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Packet Buffer
// ============================================================================

use core::sync::atomic::AtomicU64;

/// Packet buffer
pub struct Packet {
    /// Data buffer
    pub data: Vec<u8>,
    /// Length of valid data
    pub len: usize,
    /// Offset to data start
    pub offset: usize,
    /// Interface index received on
    pub ifindex: usize,
    /// Timestamp
    pub timestamp: u64,
}

impl Packet {
    /// Create new packet
    pub fn new(size: usize) -> Self {
        let mut data = Vec::with_capacity(size);
        data.resize(size, 0);
        Self {
            data,
            len: 0,
            offset: 0,
            ifindex: 0,
            timestamp: 0,
        }
    }

    /// Create from data
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            len: data.len(),
            offset: 0,
            data: data.to_vec(),
            ifindex: 0,
            timestamp: 0,
        }
    }

    /// Get packet data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.offset..self.offset + self.len]
    }

    /// Push data to front
    pub fn push_front(&mut self, data: &[u8]) {
        if self.offset >= data.len() {
            self.offset -= data.len();
            self.data[self.offset..self.offset + data.len()].copy_from_slice(data);
            self.len += data.len();
        }
    }

    /// Push data to back
    pub fn push_back(&mut self, data: &[u8]) {
        if self.data.len() >= self.offset + self.len + data.len() {
            self.data[self.offset + self.len..].copy_from_slice(data);
            self.len += data.len();
        }
    }
}

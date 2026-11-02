//! Network Stack
//!
//! Provides networking functionality including Ethernet, ARP, IPv4, IPv6, TCP, UDP,
//! ICMP, ICMPv6, and the 9P protocol for Plan 9 file system communication.
//!
//! ## Modules
//!
//! - `eth`: Ethernet frame handling
//! - `arp`: Address Resolution Protocol (IPv4)
//! - `ipv4`: Internet Protocol Version 4
//! - `ipv6`: Internet Protocol Version 6
//! - `tcp`: Transmission Control Protocol
//! - `udp`: User Datagram Protocol
//! - `icmp`: Internet Control Message Protocol (IPv4)
//! - `icmpv6`: ICMP for IPv6 (includes Neighbor Discovery)
//! - `protocol`: 9P protocol for Plan 9 file system communication
//!
//! ## Features
//!
//! - IPv4 fragmentation and reassembly
//! - IPv6 with extension headers and fragmentation
//! - TCP SYN cookies for SYN flood protection
//! - TCP Keep-Alive support
//! - TCP Window Scaling (RFC 1323)
//! - UDP dual-stack support (IPv4 and IPv6)
//! - ICMPv4 error reporting and ping
//! - ICMPv6 with full Neighbor Discovery Protocol (NDP)
//! - ARP with retransmission and proxy support
//!
//! ## Usage
//!
//! ```rust
//! use plan9_net::{ipv4::Ipv4Packet, tcp::TcpSocket, udp::UdpSocket};
//!
//! // Create IPv4 packet
//! let packet = Ipv4Packet::new(src_ip, dst_ip, 6); // Protocol 6 = TCP
//!
//! // Use TCP socket
//! let mut socket = TcpSocket::new();
//! socket.bind(8080).unwrap();
//! ```

#![no_std]
extern crate alloc;

pub mod common;

// Re-export alloc types for submodules
pub use alloc::vec;
pub use alloc::vec::Vec;
pub use alloc::string::String;
pub use alloc::boxed::Box;

pub mod arp;
pub mod eth;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod protocol;
pub mod tcp;
pub mod udp;
pub mod socket;
pub mod dhcp;
pub mod dns;
pub mod ipsec;
pub mod netstack;
#[path = "ssh/lib.rs"]
pub mod ssh;

// ============================================================================
// Re-exports from Ethernet
// ============================================================================
pub use eth::{EthFrame, EthHdr, ETH_HEADER_SIZE, ETH_MTU};

// ============================================================================
// Re-exports from ARP
// ============================================================================
pub use arp::{
    ArpCache,
    ArpConfig,
    ArpEntry,
    ArpHdr,
    ArpOpcode,
    ArpTable,
    // Enhanced ARP
    EnhancedArpTable,
    PendingArpRequest,
    ProxyArpRule,
};

// ============================================================================
// Re-exports from IPv4
// ============================================================================
pub use ipv4::{
    // Utilities
    checksum,
    checksum_pseudo,
    format_ipv4_addr,
    parse_ipv4_addr,
    set_checksum,
    verify_checksum,
    // Fragmentation
    FragmentCache,
    FragmentData,
    FragmentEntry,
    FragmentKey,
    Fragmenter,
    // Options
    IpOption,
    IpOptionAction,
    IpOptionType,
    Ipv4Hdr,
    Ipv4Packet,
    Route,
    RoutingTable,
};

// ============================================================================
// Re-exports from IPv6
// ============================================================================
pub use ipv6::{
    addr,
    // EUI-64
    eui64_from_mac,
    link_local_from_mac,
    mac_from_eui64,
    // Protocol numbers
    proto as ipv6_proto,
    // Fragmentation
    FragmentCache as Ipv6FragmentCache,
    FragmentEntry as Ipv6FragmentEntry,
    // Address utilities
    Ipv6AddrType,
    Ipv6Hdr,
    Ipv6Packet,
    Ipv6Route,
    // Routing
    Ipv6RoutingTable,
    IPV6_ADDR_LEN,
    // Constants
    IPV6_HEADER_LEN,
    IPV6_HOPS_MAX,
    IPV6_MTU,
};

// ============================================================================
// Re-exports from TCP
// ============================================================================
pub use tcp::{
    flag as tcp_flag,
    mss_option,
    timestamp_option,
    window_scale_option,
    // Congestion control
    CongState,
    // Keep-Alive
    KeepAliveConfig,
    KeepAliveState,
    LimboEntry,
    LimboQueue,
    // SYN Cookie
    SynCookie,
    TcpHdr,
    TcpInitialParams,
    // Options
    TcpOption,
    TcpOptionKind,
    TcpSegment,
    TcpSocket,
    TcpState,
    // Window Scaling
    WindowScaleConfig,
    // Constants
    TCP_HEADER_LEN,
    TCP_MSS,
};

// ============================================================================
// Re-exports from UDP
// ============================================================================
pub use udp::{
    port as udp_port,
    DualStackUdpSocket,
    UdpHdr,
    UdpPacket,
    UdpPortTable,
    UdpSocket,
    UdpState,
    // IPv6 support
    Udpv6Packet,
    Udpv6PseudoHeader,
    // Constants
    UDP_HEADER_LEN,
};

// ============================================================================
// Re-exports from ICMP
// ============================================================================
pub use icmp::{
    // Utilities
    calculate_checksum as icmp_checksum,
    verify_checksum as icmp_verify_checksum,
    // Error types
    IcmpError,
    IcmpHandler,
    IcmpHdr,
    IcmpPacket,
    IcmpSocket,
    // Statistics
    IcmpStats,
    IcmpType,
    RedirectCode,
    TimeExceededCode,
    // Error codes
    UnreachableCode,
    // Constants
    ICMP_HEADER_SIZE,
    ICMP_MIN_SIZE,
    IP_ICMP_PROTO,
};

// ============================================================================
// Re-exports from ICMPv6
// ============================================================================
pub use icmpv6::{
    all_nodes_mcast,
    all_routers_mcast,
    // Utilities
    calculate_checksum as icmpv6_checksum,
    is_link_local,
    is_loopback,
    is_multicast,
    is_solicited_node_mcast,
    is_unspecified,
    solicited_node_mcast,
    // Error types
    Icmpv6Error,
    Icmpv6Handler,
    Icmpv6Hdr,
    Icmpv6Packet,
    // Statistics
    Icmpv6Stats,
    Icmpv6Type,
    NdOption,
    NdOptionType,
    NeighborAdvert,
    // NDP types
    NeighborSolicit,
    ParameterProblemCode,
    PrefixInformation,
    RouterAdvert,
    RouterSolicit,
    TimeExceededCodeV6,
    // Error codes
    UnreachableCodeV6,
    // Constants
    ICMPV6_HEADER_SIZE,
    ICMPV6_MIN_SIZE,
    IPV6_ICMPV6_PROTO,
};

// ============================================================================
// Re-exports from 9P Protocol
// ============================================================================
pub use protocol::{P9Client, P9Codec, P9Msg, P9Server};

// ============================================================================
// Re-exports from Socket API
// ============================================================================
pub use socket::{
    // Socket functions
    socket,
    bind,
    listen,
    accept,
    connect,
    close,
    setsockopt,
    getsockopt,
    // Socket types
    Socket,
    SocketState,
    SocketError,
    SockAddr,
    SockAddrIn,
    SockAddrIn6,
    // Constants
    domain,
    sock_type,
    proto as sock_proto,
    flags,
    level,
    opt,
};

// ============================================================================
// Re-exports from DHCP
// ============================================================================
pub use dhcp::{
    DhcpClient,
    DhcpConfig,
    DhcpPacket,
    DhcpState,
    msg_type as dhcp_msg_type,
    op as dhcp_op,
    option as dhcp_option,
    port as dhcp_port,
};

// ============================================================================
// Re-exports from DNS
// ============================================================================
pub use dns::{
    DnsCache,
    DnsPacket,
    DnsQuestion,
    DnsRecord,
    DnsRecordType,
    DnsResolver,
    DnsRcode,
    DNS_MAX_SIZE,
    DNS_PORT,
};

// ============================================================================
// Re-exports from Common
// ============================================================================
pub use common::{Error, Mode, PhysAddr, Qid, Result, VirtAddr};

//! Socket API Implementation
//!
//! Provides Berkeley sockets-compatible API for network operations.
//! Supports TCP and UDP socket types.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use plan9_common::sync::{Spinlock, Mutex};

// ============================================================================
// Socket Constants
// ============================================================================

/// Socket domains (address families)
pub mod domain {
    /// Unix domain
    pub const AF_UNIX: i32 = 1;
    /// IPv4
    pub const AF_INET: i32 = 2;
    /// IPv6
    pub const AF_INET6: i32 = 10;
}

/// Socket types
pub mod sock_type {
    /// Stream socket (TCP)
    pub const SOCK_STREAM: i32 = 1;
    /// Datagram socket (UDP)
    pub const SOCK_DGRAM: i32 = 2;
    /// Raw socket
    pub const SOCK_RAW: i32 = 3;
}

/// Protocol numbers
pub mod proto {
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_ICMP: i32 = 1;
    pub const IPPROTO_TCP: i32 = 6;
    pub const IPPROTO_UDP: i32 = 17;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPPROTO_ICMPV6: i32 = 58;
}

/// Socket flags
pub mod flags {
    pub const SOCK_NONBLOCK: i32 = 0o4000;
    pub const SOCK_CLOEXEC: i32 = 0o2000000;
}

/// Socket level for setsockopt
pub mod level {
    pub const SOL_SOCKET: i32 = 1;
}

/// Socket options
pub mod opt {
    pub const SO_REUSEADDR: i32 = 2;
    pub const SO_KEEPALIVE: i32 = 9;
    pub const SO_LINGER: i32 = 13;
    pub const SO_RCVBUF: i32 = 8;
    pub const SO_SNDBUF: i32 = 7;
    pub const SO_RCVTIMEO: i32 = 20;
    pub const SO_SNDTIMEO: i32 = 21;
    pub const SO_ERROR: i32 = 4;
}

// ============================================================================
// Socket Address Structures
// ============================================================================

/// Generic socket address
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct SockAddr {
    /// Address family
    pub sa_family: u16,
    /// Address data (14 bytes for AF_INET)
    pub sa_data: [u8; 14],
}

impl SockAddr {
    /// Create a new AF_INET address
    pub fn inet(port: u16, ip: [u8; 4]) -> Self {
        let mut addr = Self::default();
        addr.sa_family = domain::AF_INET as u16;
        addr.sa_data[..2].copy_from_slice(&port.to_be_bytes());
        addr.sa_data[2..6].copy_from_slice(&ip);
        addr
    }

    /// Create a new AF_INET6 address
    pub fn inet6(port: u16, _flowinfo: u32, _ip: [u8; 16], _scope_id: u32) -> Self {
        let mut addr = Self::default();
        addr.sa_family = domain::AF_INET6 as u16;
        // For AF_INET6, we need a larger structure, but we use the same 14 bytes
        // This is a simplified version
        addr.sa_data[..2].copy_from_slice(&port.to_be_bytes());
        addr
    }
}

/// IPv4 socket address
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct SockAddrIn {
    /// Address family (AF_INET)
    pub sin_family: u16,
    /// Port in network byte order
    pub sin_port: u16,
    /// IPv4 address
    pub sin_addr: [u8; 4],
    /// Padding
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    /// Create a new IPv4 socket address
    pub fn new(port: u16, addr: [u8; 4]) -> Self {
        Self {
            sin_family: domain::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: addr,
            sin_zero: [0; 8],
        }
    }
}

/// IPv6 socket address
#[derive(Debug, Clone, Default)]
#[repr(C)]
#[repr(align(8))]
pub struct SockAddrIn6 {
    /// Address family (AF_INET6)
    pub sin6_family: u16,
    /// Port in network byte order
    pub sin6_port: u16,
    /// Flow label
    pub sin6_flowinfo: u32,
    /// IPv6 address
    pub sin6_addr: [u8; 16],
    /// Scope ID
    pub sin6_scope_id: u32,
}

impl SockAddrIn6 {
    /// Create a new IPv6 socket address
    pub fn new(port: u16, flowinfo: u32, addr: [u8; 16], scope_id: u32) -> Self {
        Self {
            sin6_family: domain::AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: flowinfo,
            sin6_addr: addr,
            sin6_scope_id: scope_id,
        }
    }
}

// ============================================================================
// Socket Errors
// ============================================================================

/// Socket operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// Invalid file descriptor
    InvalidFd,
    /// Invalid argument
    InvalidArgument,
    /// Address family not supported
    AddressFamilyNotSupported,
    /// Address already in use
    AddressInUse,
    /// Socket already bound
    AlreadyBound,
    /// Socket not bound
    NotBound,
    /// Socket not listening
    NotListening,
    /// Operation not supported
    NotSupported,
    /// Operation would block
    WouldBlock,
    /// Connection refused
    ConnectionRefused,
    /// Connection reset
    ConnectionReset,
    /// Connection timed out
    TimedOut,
    /// Out of memory
    OutOfMemory,
    /// Too many open files
    TooManyFiles,
}

impl SocketError {
    /// Get error code
    pub fn errno(&self) -> i32 {
        match self {
            SocketError::InvalidFd => 9,    // EBADF
            SocketError::InvalidArgument => 22, // EINVAL
            SocketError::AddressFamilyNotSupported => 47, // EAFNOSUPPORT
            SocketError::AddressInUse => 98, // EADDRINUSE
            SocketError::AlreadyBound => 22, // EINVAL
            SocketError::NotBound => 107, // ENOTCONN
            SocketError::NotListening => 22, // EINVAL
            SocketError::NotSupported => 95, // EOPNOTSUPP
            SocketError::WouldBlock => 11, // EAGAIN
            SocketError::ConnectionRefused => 111, // ECONNREFUSED
            SocketError::ConnectionReset => 104, // ECONNRESET
            SocketError::TimedOut => 110, // ETIMEDOUT
            SocketError::OutOfMemory => 12, // ENOMEM
            SocketError::TooManyFiles => 24, // EMFILE
        }
    }
}

/// Socket result type
pub type SocketResult<T> = core::result::Result<T, SocketError>;

// ============================================================================
// Socket Structure
// ============================================================================

/// Socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Socket is closed
    Closed,
    /// Socket is bound
    Bound,
    /// Socket is listening
    Listening,
    /// Socket is connected
    Connected,
}

/// Socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    /// Stream socket (TCP)
    Stream,
    /// Datagram socket (UDP)
    Datagram,
    /// Raw socket
    Raw,
}

/// Socket structure
pub struct Socket {
    /// File descriptor
    fd: i32,
    /// Socket domain (AF_INET, AF_INET6)
    domain: i32,
    /// Socket type
    kind: SocketKind,
    /// Protocol
    protocol: i32,
    /// Local address
    local_addr: Option<SockAddr>,
    /// Remote address
    peer_addr: Option<SockAddr>,
    /// Socket state
    state: SocketState,
    /// Receive buffer
    recv_buf: Vec<u8>,
    /// Send buffer
    send_buf: Vec<u8>,
}

impl Socket {
    /// Create a new socket
    pub fn new(domain: i32, sock_type: i32, protocol: i32) -> Self {
        let kind = match sock_type {
            sock_type::SOCK_STREAM => SocketKind::Stream,
            sock_type::SOCK_DGRAM => SocketKind::Datagram,
            _ => SocketKind::Raw,
        };

        // Allocate a file descriptor
        static FD_COUNTER: AtomicI32 = AtomicI32::new(100);
        let fd = FD_COUNTER.fetch_add(1, Ordering::SeqCst);

        Self {
            fd,
            domain,
            kind,
            protocol,
            local_addr: None,
            peer_addr: None,
            state: SocketState::Closed,
            recv_buf: Vec::new(),
            send_buf: Vec::new(),
        }
    }

    /// Get file descriptor
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Bind socket to address
    pub fn bind(&mut self, addr: &SockAddr) -> SocketResult<()> {
        if self.state != SocketState::Closed {
            return Err(SocketError::AlreadyBound);
        }

        self.local_addr = Some(addr.clone());
        self.state = SocketState::Bound;
        Ok(())
    }

    /// Listen for connections
    pub fn listen(&mut self, _backlog: i32) -> SocketResult<()> {
        if self.state != SocketState::Bound {
            return Err(SocketError::NotBound);
        }

        self.state = SocketState::Listening;
        Ok(())
    }

    /// Accept a connection
    pub fn accept(&mut self) -> SocketResult<Socket> {
        if self.state != SocketState::Listening {
            return Err(SocketError::NotListening);
        }

        // Create a new socket for the accepted connection
        let mut new_sock = Socket::new(self.domain, self.protocol, 0);
        new_sock.state = SocketState::Connected;
        new_sock.peer_addr = self.peer_addr.clone();
        Ok(new_sock)
    }

    /// Connect to address
    pub fn connect(&mut self, addr: &SockAddr) -> SocketResult<()> {
        self.peer_addr = Some(addr.clone());
        self.state = SocketState::Connected;
        Ok(())
    }

    /// Receive data
    pub fn recv(&mut self, buf: &mut [u8]) -> SocketResult<usize> {
        if self.recv_buf.is_empty() {
            return Err(SocketError::WouldBlock);
        }

        let len = core::cmp::min(buf.len(), self.recv_buf.len());
        buf[..len].copy_from_slice(&self.recv_buf[..len]);
        self.recv_buf.drain(..len);
        Ok(len)
    }

    /// Send data
    pub fn send(&mut self, buf: &[u8]) -> SocketResult<usize> {
        self.send_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Close socket
    pub fn close(&mut self) {
        self.state = SocketState::Closed;
        self.recv_buf.clear();
        self.send_buf.clear();
    }

    /// Get socket state
    pub fn state(&self) -> SocketState {
        self.state
    }
}

impl core::fmt::Debug for Socket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Socket")
            .field("fd", &self.fd)
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .field("state", &self.state)
            .finish()
    }
}

// ============================================================================
// Socket Table
// ============================================================================

/// Socket table for managing open sockets
pub struct SocketTable {
    /// Sockets by file descriptor
    sockets: alloc::collections::BTreeMap<i32, Socket>,
}

impl SocketTable {
    /// Create a new socket table
    pub fn new() -> Self {
        Self {
            sockets: alloc::collections::BTreeMap::new(),
        }
    }

    /// Add a socket to the table
    pub fn add(&mut self, sock: Socket) {
        self.sockets.insert(sock.fd(), sock);
    }

    /// Get a socket by file descriptor
    pub fn get(&self, fd: i32) -> Option<&Socket> {
        self.sockets.get(&fd)
    }

    /// Get a mutable socket by file descriptor
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut Socket> {
        self.sockets.get_mut(&fd)
    }

    /// Remove a socket by file descriptor
    pub fn remove(&mut self, fd: i32) -> Option<Socket> {
        self.sockets.remove(&fd)
    }

    /// Iterate over all sockets
    pub fn iter(&self) -> impl Iterator<Item = (&i32, &Socket)> {
        self.sockets.iter()
    }
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Socket API Functions
// ============================================================================

/// Global socket table
static SOCKET_TABLE_DATA: Mutex<Option<SocketTable>> = Mutex::new(None);
static SOCKET_TABLE_LOCK: Spinlock<()> = Spinlock::new(());

/// Initialize socket table
fn init_socket_table() {
    let mut guard = SOCKET_TABLE_DATA.lock();
    if guard.is_none() {
        *guard = Some(SocketTable::new());
    }
}

/// Get mutable reference to socket table
fn with_socket_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut SocketTable) -> R,
{
    let _lock = SOCKET_TABLE_LOCK.lock();
    init_socket_table();

    let mut guard = SOCKET_TABLE_DATA.lock();
    if let Some(ref mut table) = *guard {
        f(table)
    } else {
        panic!("Socket table not initialized")
    }
}

/// Create a new socket
pub fn socket(domain: i32, sock_type: i32, protocol: i32) -> SocketResult<i32> {
    // Validate domain
    if domain != domain::AF_INET && domain != domain::AF_INET6 {
        return Err(SocketError::AddressFamilyNotSupported);
    }

    // Create socket
    let sock = Socket::new(domain, sock_type, protocol);
    let fd = sock.fd();
    
    with_socket_table(|table| table.add(sock));
    Ok(fd)
}

/// Bind socket to address
pub fn bind(sockfd: i32, addr: *const SockAddr, _addrlen: u32) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    if addr.is_null() {
        return Err(SocketError::InvalidArgument);
    }

    let address = unsafe { &*addr };
    
    with_socket_table(|table| {
        if let Some(sock) = table.get_mut(sockfd) {
            sock.bind(address)?;
            Ok(0)
        } else {
            Err(SocketError::InvalidFd)
        }
    })
}

/// Start listening for connections
pub fn listen(sockfd: i32, backlog: i32) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    with_socket_table(|table| {
        if let Some(sock) = table.get_mut(sockfd) {
            sock.listen(backlog)?;
            Ok(0)
        } else {
            Err(SocketError::InvalidFd)
        }
    })
}

/// Accept a connection
pub fn accept(sockfd: i32, addr: *mut SockAddr, _addrlen: *mut u32) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    let new_fd = with_socket_table(|table| {
        if let Some(sock) = table.get_mut(sockfd) {
            match sock.accept() {
                Ok(new_sock) => {
                    let fd = new_sock.fd();
                    table.add(new_sock);
                    Ok(fd)
                }
                Err(e) => Err(e),
            }
        } else {
            Err(SocketError::InvalidFd)
        }
    })?;
    
    // Fill in address if provided
    if !addr.is_null() {
        let address = unsafe { &mut *addr };
        with_socket_table(|table| {
            if let Some(sock) = table.get(sockfd) {
                if let Some(peer) = &sock.peer_addr {
                    *address = peer.clone();
                }
            }
        });
    }
    
    Ok(new_fd)
}

/// Connect to address
pub fn connect(sockfd: i32, addr: *const SockAddr, _addrlen: u32) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    if addr.is_null() {
        return Err(SocketError::InvalidArgument);
    }

    let address = unsafe { &*addr };
    
    with_socket_table(|table| {
        if let Some(sock) = table.get_mut(sockfd) {
            sock.connect(address)?;
            Ok(0)
        } else {
            Err(SocketError::InvalidFd)
        }
    })
}

/// Close a socket
pub fn close(sockfd: i32) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    with_socket_table(|table| {
        if let Some(mut sock) = table.remove(sockfd) {
            sock.close();
            Ok(0)
        } else {
            Err(SocketError::InvalidFd)
        }
    })
}

/// Set socket option
pub fn setsockopt(
    sockfd: i32,
    _level: i32,
    _optname: i32,
    optval: *const u8,
    _optlen: u32,
) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    if optval.is_null() {
        return Err(SocketError::InvalidArgument);
    }

    // Just acknowledge the option for now
    with_socket_table(|_table| Ok(0))
}

/// Get socket option
pub fn getsockopt(
    sockfd: i32,
    _level: i32,
    _optname: i32,
    optval: *mut u8,
    optlen: *mut u32,
) -> SocketResult<i32> {
    if sockfd < 0 {
        return Err(SocketError::InvalidFd);
    }

    if optval.is_null() || optlen.is_null() {
        return Err(SocketError::InvalidArgument);
    }

    // Return default values for now
    with_socket_table(|_table| Ok(0))
}

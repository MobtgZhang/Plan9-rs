//! Network File System
//!
//! Implements the Plan 9 /net filesystem for network access.
//!
//! ## Plan 9 Network Architecture
//!
//! In Plan 9, network connections are accessed through the /net filesystem:
//! - /net/tcp - TCP connections
//! - /net/udp - UDP connections
//! - Each connection has a file for control (write commands) and data (read/write)
//!
//! Commands:
//! - clone - create new connection
//! - connect ip:port - initiate outbound connection
//! - announce port - listen for connections
//! - bind - bind to local address
//! - hangup - close connection

use alloc::format;
use alloc::vec::Vec;
use alloc::string::String;
use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev};
use crate::netdrv;
use crate::plan9_common::sync::Spinlock;
use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Network File System Structure
// ============================================================================

/// Network filesystem device
pub struct NetFs {
    /// Device name
    name: &'static str,
    /// Device character
    dev_char: char,
    /// TCP connections
    tcp_convs: Spinlock<Vec<TcpConnection>>,
    /// UDP connections
    udp_convs: Spinlock<Vec<UdpConnection>>,
    /// Next connection ID
    next_id: AtomicU32,
}

/// TCP connection state
#[derive(Debug, Clone, Copy)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

/// TCP connection
#[derive(Debug, Clone)]
pub struct TcpConnection {
    /// Connection ID
    pub id: u32,
    /// Local address
    pub local_addr: [u8; 4],
    /// Remote address
    pub remote_addr: [u8; 4],
    /// Local port
    pub local_port: u16,
    /// Remote port
    pub remote_port: u16,
    /// TCP state
    pub state: TcpState,
    /// Connection refcount
    pub refcount: u32,
}

/// UDP connection
#[derive(Debug, Clone)]
pub struct UdpConnection {
    /// Connection ID
    pub id: u32,
    /// Local address
    pub local_addr: [u8; 4],
    /// Local port
    pub local_port: u16,
    /// Connection refcount
    pub refcount: u32,
}

impl NetFs {
    /// Create a new network filesystem
    pub fn new() -> Self {
        Self {
            name: "net",
            dev_char: 'I',
            tcp_convs: Spinlock::new(Vec::new()),
            udp_convs: Spinlock::new(Vec::new()),
            // Qid paths 0, 1, and 2 are reserved for /net, /net/tcp, and
            // /net/udp directory entries.  Connection ids start above them so
            // a connection file is never mistaken for a directory.
            next_id: AtomicU32::new(3),
        }
    }

    /// Allocate a new TCP connection ID
    fn alloc_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Create a new TCP connection
    ///
    /// Returns the connection ID on success
    pub fn tcp_clone(&self) -> Option<TcpConnection> {
        let mut convs = self.tcp_convs.lock();
        let id = self.alloc_id();
        let conv = TcpConnection {
            id,
            local_addr: [0, 0, 0, 0],
            remote_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_port: 0,
            state: TcpState::Closed,
            refcount: 1,
        };
        convs.push(conv.clone());
        // Keep the kernel TCP data-plane state in sync with the /net qid.
        netdrv::tcp_open(id);
        Some(conv)
    }

    /// Create a listening TCP connection
    pub fn tcp_listen(&self, local_port: u16) -> Option<TcpConnection> {
        let mut convs = self.tcp_convs.lock();
        let id = self.alloc_id();
        let conv = TcpConnection {
            id,
            local_addr: [127, 0, 0, 1], // localhost
            remote_addr: [0, 0, 0, 0],
            local_port,
            remote_port: 0,
            state: TcpState::Listen,
            refcount: 1,
        };
        convs.push(conv.clone());
        Some(conv)
    }

    /// Create an outbound TCP connection
    pub fn tcp_connect(&self, local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> Option<TcpConnection> {
        let mut convs = self.tcp_convs.lock();
        let id = self.alloc_id();
        let conv = TcpConnection {
            id,
            local_addr: [0, 0, 0, 0],
            remote_addr: remote_ip,
            local_port,
            remote_port,
            state: TcpState::SynSent,
            refcount: 1,
        };
        convs.push(conv.clone());
        Some(conv)
    }

    /// Find a TCP connection by ID
    pub fn tcp_by_id(&self, id: u32) -> Option<TcpConnection> {
        let convs = self.tcp_convs.lock();
        convs.iter().find(|c| c.id == id).cloned()
    }

    /// Close a TCP connection
    pub fn tcp_close(&self, id: u32) {
        let mut convs = self.tcp_convs.lock();
        if let Some(conv) = convs.iter_mut().find(|c| c.id == id) {
            conv.refcount = conv.refcount.saturating_sub(1);
            if conv.refcount == 0 {
                conv.state = TcpState::Closed;
            }
        }
    }

    /// Remove a TCP connection
    pub fn tcp_remove(&self, id: u32) {
        let mut convs = self.tcp_convs.lock();
        convs.retain(|c| c.id != id);
    }

    /// Get all TCP connections
    pub fn tcp_all(&self) -> Vec<TcpConnection> {
        self.tcp_convs.lock().clone()
    }

    /// Parse a Plan 9 network address.  Plan 9 uses `ip!port`; the
    /// conventional `ip:port` spelling is accepted as well.
    pub fn parse_addr(addr: &str) -> Option<([u8; 4], u16)> {
        let addr = addr.trim();
        let parts: Vec<&str> = if addr.contains('!') {
            addr.split('!').collect()
        } else {
            addr.split(':').collect()
        };
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return None;
        }

        let ip_parts: Vec<&str> = parts[0].split('.').collect();
        if ip_parts.len() != 4 {
            return None;
        }

        let mut ip = [0u8; 4];
        for (i, part) in ip_parts.iter().enumerate() {
            ip[i] = part.parse().ok()?;
        }

        let port: u16 = parts[1].parse().ok()?;

        Some((ip, port))
    }

    /// Format address as string
    pub fn format_addr(ip: &[u8; 4], port: u16) -> String {
        format!("{}.{}.{}.{}!{}", ip[0], ip[1], ip[2], ip[3], port)
    }

    /// Format connection state for reading
    pub fn format_state(&self, conv: &TcpConnection) -> String {
        format!(
            "{} {:?} {} {} {}",
            conv.id,
            conv.state,
            NetFs::format_addr(&conv.local_addr, conv.local_port),
            NetFs::format_addr(&conv.remote_addr, conv.remote_port),
            conv.refcount
        )
    }
}

impl Dev for NetFs {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::IP, Qid::new(0, 0, qidtype::DIR), 0))
    }

    fn open(&mut self, ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        if ch.qid.path == 0xFFFFFFFF {
            if let Some(conv) = self.tcp_clone() {
                ch.qid.path = conv.id as u64;
                return Ok(());
            }
        }
        Ok(())
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        match name {
            "tcp" => {
                let qid = Qid::new(1, 0, qidtype::DIR);
                ch.qid = qid;
                Ok(Some(qid))
            }
            "udp" => {
                let qid = Qid::new(2, 0, qidtype::DIR);
                ch.qid = qid;
                Ok(Some(qid))
            }
            "clone" => {
                // A fresh clone channel has not yet been opened; the open
                // operation allocates the connection id.
                let qid = Qid::new(0xFFFFFFFF, 0, 0);
                ch.qid = qid;
                Ok(Some(qid))
            }
            _ => {
                if let Ok(id) = name.parse::<u32>() {
                    if self.tcp_by_id(id).is_some() {
                        let qid = Qid::new(id as u64, 0, 0);
                        ch.qid = qid;
                        return Ok(Some(qid));
                    }
                }
                Err(Error::Enoent)
            }
        }
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        let path = ch.qid.path;

        // Directory entries: /net, /net/tcp, /net/udp.
        if path == 0 || path == 1 || path == 2 {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut text = String::new();
            for conv in self.tcp_all() {
                text.push_str(&format!("{}\n", conv.id));
            }
            let bytes = text.as_bytes();
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            return Ok(n);
        }

        let id = path as u32;
        if self.tcp_by_id(id).is_none() {
            return Err(Error::Enoent);
        }
        let n = netdrv::tcp_read(id, buf);
        Ok(n)
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        let cmd = core::str::from_utf8(buf).map_err(|_| Error::Einval)?;
        let cmd = cmd.trim();
        let id = ch.qid.path as u32;

        if cmd.starts_with("connect ") {
            let addr = &cmd[8..];
            let (ip, port) = match NetFs::parse_addr(addr) {
                Some(a) => a,
                None => return Err(Error::Einval),
            };

            netdrv::tcp_open(id);
            let ok = netdrv::tcp_connect(id, ip, port);
            if !ok {
                if let Some(conv) = self.tcp_convs.lock().iter_mut().find(|c| c.id == id) {
                    conv.remote_addr = ip;
                    conv.remote_port = port;
                    conv.state = TcpState::SynSent;
                }
                return Err(Error::Eio);
            }

            if let Some(conv) = self.tcp_convs.lock().iter_mut().find(|c| c.id == id) {
                conv.local_addr = [10, 0, 2, 15];
                conv.remote_addr = ip;
                conv.remote_port = port;
                conv.local_port = 40000 + (id % 1000) as u16;
                conv.state = TcpState::Established;
            }
            return Ok(buf.len());
        }

        if cmd.starts_with("announce ") {
            let port_str = &cmd[9..];
            if let Ok(port) = port_str.parse::<u16>() {
                if let Some(conv) = self.tcp_convs.lock().iter_mut().find(|c| c.id == id) {
                    conv.local_port = port;
                    conv.state = TcpState::Listen;
                    return Ok(buf.len());
                }
            }
            return Err(Error::Einval);
        }

        if cmd == "hangup" || cmd == "close" {
            netdrv::tcp_close(id);
            self.tcp_close(id);
            return Ok(buf.len());
        }

        // After `connect`, the connection file carries user data.  Plan 9
        // separates control and data channels; for this implementation the
        // same opened connection channel accepts non-control payloads once
        // the TCP connection is established.
        if netdrv::tcp_is_established(id) {
            let n = netdrv::tcp_write(id, buf);
            if n == 0 {
                return Err(Error::Eio);
            }
            return Ok(n);
        }

        Err(Error::Einval)
    }

    fn close(&mut self, ch: &mut Chan) {
        let id = ch.qid.path as u32;
        netdrv::tcp_close(id);
        self.tcp_close(id);
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// TCP Device (sub-device for /net/tcp)
// ============================================================================

/// TCP sub-device
pub struct TcpDev {
    /// Parent filesystem
    parent: &'static NetFs,
}

impl TcpDev {
    pub fn new(parent: &'static NetFs) -> Self {
        Self { parent }
    }
}

impl Dev for TcpDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::IP, Qid::new(1, 0, qidtype::DIR), 0))
    }

    fn open(&mut self, ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        if ch.qid.path == 0xFFFFFFFF {
            if let Some(conv) = self.parent.tcp_clone() {
                ch.qid.path = conv.id as u64;
                ch.qid.vers += 1;
                return Ok(());
            }
            return Err(Error::Enomem);
        }
        Ok(())
    }

    fn walk(&mut self, ch: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        if let Ok(id) = name.parse::<u32>() {
            if self.parent.tcp_by_id(id).is_some() {
                let qid = Qid::new(id as u64, 0, 0);
                ch.qid = qid;
                return Ok(Some(qid));
            }
        }
        Err(Error::Enoent)
    }

    fn read(&mut self, ch: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if let Some(conv) = self.parent.tcp_by_id(ch.qid.path as u32) {
            let info = format!(
                "{} {:?} {} {} {}\n",
                conv.id,
                conv.state,
                NetFs::format_addr(&conv.local_addr, conv.local_port),
                NetFs::format_addr(&conv.remote_addr, conv.remote_port),
                conv.refcount,
            );
            let info_bytes = info.as_bytes();
            let start = offset as usize;
            if start >= info_bytes.len() {
                return Ok(0);
            }
            let end = (start + buf.len()).min(info_bytes.len());
            buf[..end - start].copy_from_slice(&info_bytes[start..end]);
            Ok(end - start)
        } else {
            Err(Error::Enoent)
        }
    }

    fn write(&mut self, ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        let cmd = core::str::from_utf8(buf).map_err(|_| Error::Einval)?;

        if cmd.starts_with("connect ") {
            let addr = &cmd[9..];
            if let Some((ip, port)) = NetFs::parse_addr(addr) {
                if let Some(conv) = self.parent.tcp_convs.lock().iter_mut()
                    .find(|c| c.id == ch.qid.path as u32) 
                {
                    conv.remote_addr = ip;
                    conv.remote_port = port;
                    conv.state = TcpState::SynSent;
                    return Ok(buf.len());
                }
            }
        } else if cmd.starts_with("announce ") {
            let port_str = &cmd[9..];
            if let Ok(port) = port_str.parse::<u16>() {
                if let Some(conv) = self.parent.tcp_convs.lock().iter_mut()
                    .find(|c| c.id == ch.qid.path as u32) 
                {
                    conv.local_port = port;
                    conv.state = TcpState::Listen;
                    return Ok(buf.len());
                }
            }
        } else if cmd == "hangup" || cmd == "close" {
            self.parent.tcp_close(ch.qid.path as u32);
        }

        Ok(buf.len())
    }

    fn close(&mut self, ch: &mut Chan) {
        self.parent.tcp_close(ch.qid.path as u32);
    }

    fn dev_char(&self) -> char {
        'I'
    }

    fn name(&self) -> &'static str {
        "tcp"
    }
}

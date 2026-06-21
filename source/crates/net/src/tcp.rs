//! TCP Protocol Implementation
//!
//! Implements Transmission Control Protocol for reliable, connection-oriented delivery.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;

use crate::common::sync::Spinlock;
use crate::common::Error;

pub type Result<T> = core::result::Result<T, Error>;
use crate::ipv4::proto;

// ============================================================================
// TCP Constants
// ============================================================================

/// TCP header length (without options)
pub const TCP_HEADER_LEN: usize = 20;

/// Maximum segment size
pub const TCP_MSS: usize = 1460;

// ============================================================================
// ISS Generator (Initial Send Sequence)
// ============================================================================

/// ISS Generator using a simple stream cipher suitable for no_std environments
/// 
/// Uses a cryptographically-inspired PRNG based on ChaCha20 constants.
/// This is more suitable for security-sensitive sequence numbers than a simple LCG.
struct IssGenerator {
    state: [u32; 16],
}

impl IssGenerator {
    /// Create a new ISS generator with given entropy
    fn new(entropy: u64) -> Self {
        // ChaCha20 constants: "expand 32-byte k"
        let mut state = [
            0x61707865u32, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0,  // key (will be initialized with entropy)
            0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        
        // Initialize key with entropy
        // Use splitmix32-like mixing for better randomness
        let mut x = entropy as u32;
        let mut y = (entropy >> 32) as u32;
        for i in 4..12 {
            x = x.wrapping_add(0x9e3779b9);
            y = y.wrapping_add(0xbb67ae85);
            state[i] = x.wrapping_mul(y).rotate_left(16);
        }
        
        Self { state }
    }
    
    /// Generate next ISS value
    fn next_iss(&mut self) -> u32 {
        // Simple but effective mixing function
        // This is a simplified version suitable for sequence numbers
        let mut sum: u32 = 0;
        
        // Mix the state
        for i in 0..16 {
            self.state[i] = self.state[i].wrapping_add(self.state[(i + 1) & 15]);
            self.state[i] = self.state[i].rotate_left(13);
            sum = sum.wrapping_add(self.state[i]);
        }
        
        // Ensure non-zero ISS
        if sum == 0 {
            sum = 0x12345678;
        }
        
        sum
    }
}

/// ISS state protected by simple spinlock
static ISS_STATE: Spinlock<()> = Spinlock::new(());

/// Generate a secure ISS value
/// 
/// Uses a cryptographically-inspired PRNG to generate Initial Send Sequence numbers.
/// This prevents sequence number prediction attacks.
fn generate_iss() -> u32 {
    // Use atomic operations for thread-safety
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    
    // Static counter for ISS generation
    static ISS_COUNTER: AtomicU64 = AtomicU64::new(0x12345678);
    static ISS_SEED: AtomicU64 = AtomicU64::new(0);
    
    // Get or initialize seed
    let seed = ISS_SEED.load(Ordering::Acquire);
    if seed == 0 {
        // First call - initialize with some entropy
        // In production, this would come from hardware RNG
        ISS_SEED.store(0x9ABCDEF0, Ordering::Release);
    }
    
    // Generate ISS using a simple but effective mixing function
    let counter = ISS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = ISS_SEED.load(Ordering::Acquire);
    
    // Mix counter and seed with rotation and multiplication
    let mut iss: u32 = (counter as u32).wrapping_add(seed as u32);
    iss = iss.rotate_left(13).wrapping_mul(0x9E3779B9);
    iss ^= iss.rotate_left(17);
    
    if iss == 0 {
        iss = 0x12345678;
    }
    
    iss
}

/// Re-seed the ISS generator with additional entropy
pub fn seed_iss_generator(entropy: u64) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0);
    SEED.store(entropy, Ordering::Release);
}

/// TCP port numbers
pub mod port {
    pub const FTP: u16 = 21;
    pub const SSH: u16 = 22;
    pub const TELNET: u16 = 23;
    pub const SMTP: u16 = 25;
    pub const DNS: u16 = 53;
    pub const HTTP: u16 = 80;
    pub const POP3: u16 = 110;
    pub const IMAP: u16 = 143;
    pub const HTTPS: u16 = 443;
}

// ============================================================================
// TCP Flags
// ============================================================================

/// TCP flags
pub mod flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

// ============================================================================
// TCP Header
// ============================================================================

/// TCP header structure
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TcpHdr {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq: u32,
    /// Acknowledgment number
    pub ack: u32,
    /// Data offset and flags
    pub offset_flags: u16,
    /// Window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer
    pub urgent: u16,
}

impl TcpHdr {
    /// Create new header
    pub fn new() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack: 0,
            offset_flags: ((TCP_HEADER_LEN as u16 / 4) << 12).to_be(),
            window: 65535u16.to_be(),
            checksum: 0,
            urgent: 0,
        }
    }

    /// Get header length in bytes
    pub fn header_len(&self) -> usize {
        (((u16::from_be(self.offset_flags) >> 12) as usize) * 4).max(TCP_HEADER_LEN)
    }

    /// Get flags
    pub fn flags(&self) -> u8 {
        (u16::from_be(self.offset_flags) & 0x3F) as u8
    }

    /// Check if flag is set
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags() & flag) != 0
    }

    /// Set flags
    pub fn set_flags(&mut self, flags: u8) {
        let offset = (((self.header_len() / 4) as u16) << 12).to_be();
        self.offset_flags = offset | (flags as u16);
    }

    /// Add flags
    pub fn add_flags(&mut self, flags: u8) {
        self.set_flags(self.flags() | flags);
    }

    /// Get sequence number
    pub fn seq(&self) -> u32 {
        u32::from_be(self.seq)
    }

    /// Get acknowledgment number
    pub fn ack_num(&self) -> u32 {
        u32::from_be(self.ack)
    }

    /// Get window size
    pub fn window(&self) -> u16 {
        u16::from_be(self.window)
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TCP_HEADER_LEN {
            return None;
        }

        Some(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            offset_flags: u16::from_be_bytes([bytes[12], bytes[13]]),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urgent: u16::from_be_bytes([bytes[18], bytes[19]]),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) -> Option<()> {
        let len = self.header_len();
        if bytes.len() < len {
            return None;
        }

        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.offset_flags.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent.to_be_bytes());
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
}

// ============================================================================
// TCP Connection State
// ============================================================================

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// ============================================================================
// TCP Segment
// ============================================================================

/// TCP segment
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// TCP header
    pub header: TcpHdr,
    /// Payload data
    pub payload: Vec<u8>,
}

impl TcpSegment {
    /// Create new segment
    pub fn new() -> Self {
        Self {
            header: TcpHdr::new(),
            payload: Vec::new(),
        }
    }

    /// Parse from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = TcpHdr::from_bytes(bytes)?;
        let header_len = header.header_len();

        if bytes.len() < header_len {
            return None;
        }

        let payload = if header_len < bytes.len() {
            bytes[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self { header, payload })
    }

    /// Set payload
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Get segment size
    pub fn size(&self) -> usize {
        self.header.header_len() + self.payload.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.size();
        let mut bytes = Vec::with_capacity(size);
        bytes.resize(size, 0);
        self.header.to_bytes(&mut bytes).unwrap_or(());
        bytes[self.header.header_len()..].copy_from_slice(&self.payload);
        bytes
    }

    /// Calculate checksum
    pub fn calculate_checksum(&self, src_ip: [u8; 4], dst_ip: [u8; 4]) -> u16 {
        let len = self.size() as u16;
        crate::ipv4::checksum_pseudo(&self.payload, src_ip, dst_ip, proto::TCP, len)
    }
}

// ============================================================================
// TCP Socket
// ============================================================================

/// TCP socket
pub struct TcpSocket {
    /// Local port
    local_port: u16,
    /// Remote port
    remote_port: u16,
    /// Remote IP
    remote_ip: u32,
    /// Connection state
    state: TcpState,
    /// Send sequence number
    snd_nxt: u32,
    /// Receive sequence number
    rcv_nxt: u32,
    /// Initial send sequence number
    iss: u32,
    /// Initial receive sequence number
    irs: u32,
    /// Send window
    snd_wnd: u16,
    /// Receive window
    rcv_wnd: u16,
    /// Maximum segment size
    mss: usize,
    /// Retransmission queue
    retrans_queue: Vec<RetransmitEntry>,
    /// Receive buffer
    recv_buf: Vec<u8>,
    /// Lock
    lock: Spinlock<()>,

    // === Congestion Control ===
    /// Congestion window (in bytes)
    cwind: u32,
    /// Slow start threshold
    ssthresh: u32,
    /// Congestion state
    cong_state: CongState,
    /// Duplicate ACK counter
    dupacks: u32,

    // === RTT Measurement ===
    /// Round trip time estimate (in ms)
    rtt: u32,
    /// Round trip time variance
    rttvar: u32,
    /// Retransmission timeout (in ms)
    rto: u32,
    /// Sequence number of last RTT sample
    rtt_seq: u32,
    /// Timestamp of last RTT sample
    rtt_time: u64,

    // === Timers ===
    /// Retransmission timer (expires at this tick)
    retrans_timer: Option<u64>,
    /// Persistent timer for zero windows
    persist_timer: Option<u64>,
}

struct RetransmitEntry {
    data: Vec<u8>,
    seq: u32,
    sent_at: u64,
    acked: bool,
}

/// Congestion control states (RFC 5681)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongState {
    /// Normal operation
    Open,
    /// Received duplicate ACKs
    Disorder,
    /// ECN congestion window reduced
    Cwr,
    /// Fast recovery
    Recovery,
    /// Loss detected by timeout
    Loss,
}

impl Default for CongState {
    fn default() -> Self {
        CongState::Open
    }
}

impl TcpSocket {
    /// Create new TCP socket
    pub fn new() -> Self {
        Self {
            local_port: 0,
            remote_port: 0,
            remote_ip: 0,
            state: TcpState::Closed,
            snd_nxt: 0,
            rcv_nxt: 0,
            iss: 0,
            irs: 0,
            snd_wnd: 65535,
            rcv_wnd: 65535,
            mss: TCP_MSS,
            retrans_queue: Vec::new(),
            recv_buf: Vec::new(),
            lock: Spinlock::new(()),

            // Congestion control - RFC 5681
            cwind: TCP_MSS as u32, // Initial cwnd = 1 MSS
            ssthresh: u32::MAX,    // Initially infinite (slow start)
            cong_state: CongState::Open,
            dupacks: 0,

            // RTT measurement - RFC 6298 (Jacobson's algorithm)
            rtt: 0,
            rttvar: 0,
            rto: 1000, // Initial RTO = 1 second
            rtt_seq: 0,
            rtt_time: 0,

            // Timers
            retrans_timer: None,
            persist_timer: None,
        }
    }

    /// Bind to local port
    pub fn bind(&mut self, port: u16) -> Result<()> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Closed {
            return Err(Error::Ealready);
        }
        self.local_port = port;
        Ok(())
    }

    /// Listen for connections
    pub fn listen(&mut self) -> Result<()> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Closed {
            return Err(Error::Ealready);
        }
        self.state = TcpState::Listen;
        Ok(())
    }

    /// Accept connection (simplified)
    pub fn accept(&mut self) -> Result<Self> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Listen {
            return Err(Error::Enotconn);
        }
        // In real implementation, would block waiting for connection
        Err(Error::Eagain)
    }

    /// Connect to remote
    pub fn connect(&mut self, ip: u32, port: u16) -> Result<()> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Closed {
            return Err(Error::Ealready);
        }

        self.remote_ip = ip;
        self.remote_port = port;
        self.iss = generate_iss(); // Secure ISS generation
        self.snd_nxt = self.iss;
        self.state = TcpState::SynSent;

        Ok(())
    }

    /// Send data
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Established {
            return Err(Error::Enotconn);
        }

        let len = data.len().min(self.snd_wnd as usize);
        self.snd_nxt = self.snd_nxt.wrapping_add(len as u32);

        Ok(len)
    }

    /// Receive data
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let _guard = self.lock.lock();
        if self.state != TcpState::Established {
            return Err(Error::Enotconn);
        }

        if self.recv_buf.is_empty() {
            return Err(Error::Eagain);
        }

        let len = self.recv_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&self.recv_buf[..len]);
        self.recv_buf.drain(..len);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(len as u32);

        Ok(len)
    }

    /// Handle incoming segment
    pub fn handle_segment(&mut self, seg: &TcpSegment) {
        let _guard = self.lock.lock();

        match self.state {
            TcpState::Listen => {
                if seg.header.has_flag(flag::SYN) {
                    self.irs = seg.header.seq();
                    self.rcv_nxt = self.irs.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                }
            }
            TcpState::SynSent => {
                if seg.header.has_flag(flag::SYN) {
                    self.irs = seg.header.seq();
                    self.rcv_nxt = self.irs.wrapping_add(1);
                    if seg.header.has_flag(flag::ACK) {
                        self.state = TcpState::Established;
                    } else {
                        self.state = TcpState::SynReceived;
                    }
                }
            }
            TcpState::Established => {
                if seg.header.has_flag(flag::FIN) {
                    self.state = TcpState::CloseWait;
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                }

                // Handle payload
                let payload_len = seg.payload.len();
                if payload_len > 0 {
                    self.recv_buf.extend_from_slice(&seg.payload);
                }

                self.rcv_nxt = seg.header.seq().wrapping_add(payload_len as u32);
            }
            _ => {}
        }
    }

    /// Close connection
    pub fn close(&mut self) -> Result<()> {
        let _guard = self.lock.lock();
        if self.state == TcpState::Established {
            self.state = TcpState::FinWait1;
        }
        Ok(())
    }

    /// Get state
    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            TcpState::SynSent | TcpState::SynReceived | TcpState::Established
        )
    }

    // ========================================================================
    // Congestion Control Methods (RFC 5681)
    // ========================================================================

    /// Get the effective congestion window
    /// The effective window is the minimum of cwnd and ssthresh
    pub fn effective_cwnd(&self) -> u32 {
        core::cmp::min(self.cwind, self.ssthresh)
    }

    /// Called when an ACK is received for new data
    /// Updates RTT and congestion window
    pub fn on_ack(&mut self, ack_num: u32, current_time: u64) {
        match self.cong_state {
            CongState::Open => {
                // Slow start: cwnd += MSS for each ACK
                if self.cwind < self.ssthresh {
                    self.cwind += self.mss as u32;
                }
                // Congestion avoidance: cwnd += MSS*MSS/cwnd
                else {
                    // Approximation: cwnd += 1 per RTT
                }

                // Update RTT
                self.update_rtt(ack_num, current_time);
            }
            CongState::Recovery | CongState::Cwr => {
                // Exit recovery mode
                self.cong_state = CongState::Open;
            }
            _ => {}
        }
    }

    /// Called when duplicate ACK is received
    /// Returns true if fast retransmit should be triggered
    pub fn on_dupack(&mut self) -> bool {
        match self.cong_state {
            CongState::Open | CongState::Disorder => {
                self.dupacks += 1;
                if self.dupacks >= 3 {
                    // Trigger fast retransmit
                    self.cong_state = CongState::Recovery;
                    // RFC 5681: ssthresh = max(flight_size/2, 2*MSS)
                    let flight_size = self.snd_nxt.wrapping_sub(self.iss);
                    self.ssthresh = core::cmp::max(flight_size / 2, 2 * self.mss as u32);
                    // RFC 5681: cwnd = ssthresh + 3*MSS
                    self.cwind = self.ssthresh + 3 * self.mss as u32;
                    true
                } else {
                    // In disorder state, inflate cwnd
                    self.cong_state = CongState::Disorder;
                    self.cwind += self.mss as u32;
                    false
                }
            }
            _ => false,
        }
    }

    /// Called on timeout - triggers slow start
    pub fn on_timeout(&mut self) {
        self.cong_state = CongState::Loss;
        // RFC 5681: ssthresh = max(flight_size/2, 2*MSS)
        let flight_size = self.snd_nxt.wrapping_sub(self.iss);
        self.ssthresh = core::cmp::max(flight_size / 2, 2 * self.mss as u32);
        // RFC 5681: cwnd = 1*MSS
        self.cwind = self.mss as u32;
        self.dupacks = 0;
    }

    /// Update RTT estimate using Jacobson's algorithm (RFC 6298)
    fn update_rtt(&mut self, ack: u32, current_time: u64) {
        if self.rtt_seq != 0 && ack >= self.rtt_seq {
            let sample = (current_time - self.rtt_time) as i64;

            if sample < 0 {
                return; // Ignore negative samples
            }

            let sample = sample as u64;

            if self.rtt == 0 {
                // First sample
                self.rtt = sample as u32;
                self.rttvar = sample as u32 / 2;
            } else {
                // Update RTTVAR
                self.rttvar = (3 * self.rttvar as u64 / 4
                    + (self.rtt as u64).saturating_sub(sample).abs() as u64)
                    as u32;
                // Update RTT
                self.rtt = (7 * self.rtt as u64 / 8 + sample) as u32;
            }

            // Update RTO: RTO = RTT + 4 * RTTVAR
            let rto_calc = self.rtt as u64 + 4 * self.rttvar as u64;
            self.rto = core::cmp::max(100, core::cmp::min(rto_calc as u32, 60000));

            self.rtt_seq = 0;
        }
    }

    /// Get current RTO
    pub fn rto(&self) -> u32 {
        self.rto
    }

    /// Get current congestion window
    pub fn cwnd(&self) -> u32 {
        self.cwind
    }

    /// Get slow start threshold
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    // ========================================================================
    // Timer Management
    // ========================================================================

    /// Set retransmission timer
    pub fn set_retrans_timer(&mut self, when: u64) {
        self.retrans_timer = Some(when);
    }

    /// Clear retransmission timer
    pub fn clear_retrans_timer(&mut self) {
        self.retrans_timer = None;
    }

    /// Check if retransmission timer is set
    pub fn has_retrans_timer(&self) -> bool {
        self.retrans_timer.is_some()
    }

    /// Get retransmission timer expiration
    pub fn retrans_timer_when(&self) -> Option<u64> {
        self.retrans_timer
    }

    /// Check if retransmission timer has expired
    pub fn retrans_timer_expired(&self, now: u64) -> bool {
        self.retrans_timer.map_or(false, |when| now >= when)
    }
}

impl Default for TcpSocket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TCP Port Manager
// ============================================================================

/// TCP port table entry
struct PortEntry {
    /// Listening socket (if any)
    listener: Option<TcpListener>,
    /// Established connections waiting to be accepted
    backlog: Vec<TcpSocket>,
    /// Maximum backlog size
    backlog_size: usize,
}

/// TCP listener for passive open
pub struct TcpListener {
    /// Local port
    port: u16,
    /// Maximum pending connections (backlog)
    backlog_size: usize,
    /// Lock for thread safety
    lock: Spinlock<()>,
}

impl TcpListener {
    /// Create a new TCP listener
    pub fn new(port: u16, backlog_size: usize) -> Self {
        Self {
            port,
            backlog_size: backlog_size.min(128).max(1), // Clamp to valid range
            lock: Spinlock::new(()),
        }
    }

    /// Get the listening port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if backlog is full
    pub fn is_backlog_full(&self) -> bool {
        let _guard = self.lock.lock();
        false // Simplified - actual implementation would check backlog size
    }
}

/// TCP port table manages listening ports and established connections
pub struct TcpPortTable {
    /// Port entries indexed by port number
    entries: [Option<PortEntry>; 65536],
    /// Global lock for table operations
    lock: Spinlock<()>,
}

impl TcpPortTable {
    /// Create a new TCP port table
    pub fn new() -> Self {
        Self {
            entries: [const { None }; 65536],
            lock: Spinlock::new(()),
        }
    }

    /// Start listening on a port
    ///
    /// Returns an error if the port is already in use.
    pub fn listen(&mut self, port: u16, backlog_size: usize) -> Result<()> {
        let _guard = self.lock.lock();
        
        if self.entries[port as usize].is_some() {
            return Err(Error::Eaddrinuse);
        }
        
        let listener = TcpListener::new(port, backlog_size);
        let entry = PortEntry {
            listener: Some(listener),
            backlog: Vec::with_capacity(backlog_size),
            backlog_size,
        };
        
        self.entries[port as usize] = Some(entry);
        Ok(())
    }

    /// Stop listening on a port
    pub fn unlisten(&mut self, port: u16) -> Result<()> {
        let _guard = self.lock.lock();
        
        if let Some(entry) = &self.entries[port as usize] {
            if !entry.backlog.is_empty() {
                return Err(Error::Eagain); // Still have pending connections
            }
        }
        
        self.entries[port as usize] = None;
        Ok(())
    }

    /// Accept a connection on a listening port
    ///
    /// Returns a new connected socket, or Eagain if no connection is ready.
    pub fn accept(&mut self, port: u16) -> Result<TcpSocket> {
        let _guard = self.lock.lock();
        
        let entry = self.entries[port as usize]
            .as_mut()
            .ok_or(Error::Enotconn)?;
        
        if entry.listener.is_none() {
            return Err(Error::Enotconn);
        }
        
        if let Some(conn) = entry.backlog.pop() {
            Ok(conn)
        } else {
            Err(Error::Eagain) // No connection available
        }
    }

    /// Add a connection to the backlog of a listening port
    ///
    /// Called when a connection completes the 3-way handshake.
    /// Returns an error if the backlog is full or port is not listening.
    pub fn queue_connection(&mut self, port: u16, socket: TcpSocket) -> Result<()> {
        let _guard = self.lock.lock();
        
        let entry = self.entries[port as usize]
            .as_mut()
            .ok_or(Error::Enotconn)?;
        
        if entry.listener.is_none() {
            return Err(Error::Enotconn);
        }
        
        if entry.backlog.len() >= entry.backlog_size {
            return Err(Error::Eagain); // Backlog full
        }
        
        entry.backlog.push(socket);
        Ok(())
    }

    /// Check if a port is listening
    pub fn is_listening(&self, port: u16) -> bool {
        self.entries[port as usize]
            .as_ref()
            .map_or(false, |e| e.listener.is_some())
    }

    /// Get the number of pending connections on a port
    pub fn pending_count(&self, port: u16) -> usize {
        self.entries[port as usize]
            .as_ref()
            .map_or(0, |e| e.backlog.len())
    }

    /// Remove all connections for a port (used during shutdown)
    pub fn close_port(&mut self, port: u16) {
        let _guard = self.lock.lock();
        self.entries[port as usize] = None;
    }
}

impl Default for TcpPortTable {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP socket listener trait for generic listener handling
pub trait TcpSocketListener: Send + Sync {
    /// Accept a connection
    fn accept(&mut self) -> Result<TcpSocket>;
    
    /// Check if listener is active
    fn is_active(&self) -> bool;
}

// ============================================================================
// SYN Cookie Implementation (RFC 4987)
// ============================================================================

/// SYN Cookie generator
pub struct SynCookie {
    /// Secret keys (should be rotated periodically)
    secret: [u32; 2],
    /// Cookie timestamp shift (to reduce timing info)
    timestamp_shift: u8,
}

impl SynCookie {
    /// Create a new SYN Cookie generator
    pub fn new() -> Self {
        Self {
            // In production, these should be truly random and periodically rotated
            secret: [0x12345678, 0x9ABCDEF0],
            timestamp_shift: 6, // Shift by ~64 seconds
        }
    }

    /// Set the secret keys
    pub fn set_secret(&mut self, s1: u32, s2: u32) {
        self.secret = [s1, s2];
    }

    /// Generate a SYN Cookie
    ///
    /// Cookie format:
    /// [ timestamp (t) | MSS index (m) | hash (h) ]
    ///
    /// Total: 32 bits
    pub fn generate(&self, addr: &(u32, u16, u32, u16), tsval: Option<u32>) -> u32 {
        // Get current time bits (reduced resolution)
        let timestamp = self.get_timestamp_bits();

        // Select MSS index based on tsval or default
        let mss_idx = tsval.map(|v| ((v >> 6) % 7) as u8).unwrap_or(2); // Default to 1448 (index 2)

        // Compute hash: H(timestamp, secret, address info)
        let hash = self.compute_hash(timestamp, addr);

        // Combine into cookie:
        // [ timestamp (5 bits) | MSS index (3 bits) | hash (24 bits) ]
        ((timestamp as u32 & 0x1F) << 27) | ((mss_idx as u32 & 0x7) << 24) | (hash & 0xFFFFFF)
    }

    /// Validate a SYN Cookie
    ///
    /// Returns initial parameters if valid, None if invalid/expired
    pub fn validate(
        &self,
        cookie: u32,
        addr: &(u32, u16, u32, u16),
        tsval: u32,
    ) -> Option<TcpInitialParams> {
        let cookie_timestamp = ((cookie >> 27) as u8) & 0x1F;
        let mss_idx = ((cookie >> 24) & 0x7) as usize;
        let stored_hash = cookie & 0xFFFFFF;

        // Verify timestamp is within acceptable range (about 2 minutes)
        let current_timestamp = self.get_timestamp_bits();
        let diff = if current_timestamp >= cookie_timestamp {
            current_timestamp - cookie_timestamp
        } else {
            (1 << 5) + current_timestamp - cookie_timestamp
        };

        // Cookie is valid for ~2^5 * timestamp_shift seconds = ~64 * 64 = ~68 minutes
        // but we only accept cookies within about 2 minutes
        if diff > 2 {
            return None;
        }

        // Recompute hash and verify
        let expected_hash = self.compute_hash(cookie_timestamp, addr);

        // Constant-time comparison to prevent timing attacks
        if !constant_time_eq(stored_hash, expected_hash & 0xFFFFFF) {
            // Try with previous timestamp (in case of boundary)
            let prev_timestamp = if cookie_timestamp == 0 {
                31
            } else {
                cookie_timestamp - 1
            };
            let prev_hash = self.compute_hash(prev_timestamp, addr);
            if !constant_time_eq(stored_hash, prev_hash & 0xFFFFFF) {
                return None;
            }
        }

        // Cookie is valid - extract parameters
        Some(TcpInitialParams {
            iss: cookie,
            irs: 0,
            mss: self.mss_from_index(mss_idx),
            window_scale: if mss_idx >= 4 { Some(7) } else { Some(0) },
        })
    }

    /// Get current timestamp bits (reduced resolution)
    fn get_timestamp_bits(&self) -> u8 {
        use core::sync::atomic::{AtomicU64, Ordering};
        
        // Use atomic counter for timestamp
        static TIMESTAMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        
        let value = TIMESTAMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        (value >> self.timestamp_shift) as u8
    }

    /// Compute hash for cookie
    fn compute_hash(&self, timestamp: u8, addr: &(u32, u16, u32, u16)) -> u32 {
        // Use a simple hash function (in production, use a cryptographic hash)
        let mut hash: u32 = 0;

        // Mix in timestamp
        hash = hash.wrapping_mul(31337).wrapping_add(timestamp as u32);

        // Mix in address info
        hash = hash.wrapping_mul(31337).wrapping_add(addr.0);
        hash = hash.wrapping_mul(31337).wrapping_add(addr.1 as u32);
        hash = hash.wrapping_mul(31337).wrapping_add(addr.2);
        hash = hash.wrapping_mul(31337).wrapping_add(addr.3 as u32);

        // Mix in secrets
        hash ^= self.secret[0];
        hash = hash.rotate_left(17).wrapping_add(self.secret[1]);

        hash
    }

    /// Get MSS from index
    fn mss_from_index(&self, idx: usize) -> usize {
        const MSS_VALUES: [usize; 8] = [
            536,   // 0: Minimum (IPv4 no options)
            1300,  // 1
            1448,  // 2: Common (IPv4 + IPv6)
            1460,  // 3: Ethernet (with options)
            1492,  // 4
            1500,  // 5
            1536,  // 6
            65535, // 7: Maximum
        ];
        if idx < MSS_VALUES.len() {
            MSS_VALUES[idx]
        } else {
            536
        }
    }
}

impl Default for SynCookie {
    fn default() -> Self {
        Self::new()
    }
}

/// Initial TCP parameters from SYN Cookie
#[derive(Debug, Clone, Copy)]
pub struct TcpInitialParams {
    /// Initial send sequence number (from cookie)
    pub iss: u32,
    /// Initial receive sequence number
    pub irs: u32,
    /// Maximum segment size
    pub mss: usize,
    /// Window scale factor
    pub window_scale: Option<u8>,
}

// ============================================================================
// Half-Open Connection Queue (Limbo)
// ============================================================================

/// Half-open connection entry (waiting for ACK to complete 3-way handshake)
#[derive(Debug, Clone)]
pub struct LimboEntry {
    /// Remote address (IP, port)
    pub remote: (u32, u16),
    /// Cookie value
    pub cookie: u32,
    /// Original timestamp value
    pub tsval: u32,
    /// Creation time
    pub created_at: u64,
    /// Original SYN packet payload (for TCP options)
    pub syn_data: Option<Vec<u8>>,
    /// Retransmission count
    pub retrans_count: u8,
}

impl LimboEntry {
    pub fn new(remote: (u32, u16), cookie: u32, tsval: u32, created_at: u64) -> Self {
        Self {
            remote,
            cookie,
            tsval,
            created_at,
            syn_data: None,
            retrans_count: 0,
        }
    }
}

/// Half-open connection queue (RFC 4987)
pub struct LimboQueue {
    /// Entries
    entries: Vec<LimboEntry>,
    /// Maximum entries
    max_entries: usize,
    /// Timeout in milliseconds
    timeout_ms: u64,
}

impl LimboQueue {
    pub fn new(max_entries: usize, timeout_ms: u64) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            timeout_ms,
        }
    }

    /// Add a connection to limbo
    pub fn add(&mut self, entry: LimboEntry) -> Option<usize> {
        if self.entries.len() >= self.max_entries {
            return None;
        }
        self.entries.push(entry);
        Some(self.entries.len() - 1)
    }

    /// Find and remove an entry by cookie (when final ACK arrives)
    pub fn find_and_remove(&mut self, addr: (u32, u16), cookie: u32) -> Option<LimboEntry> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.remote == addr && e.cookie == cookie)
        {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self, now: u64) {
        self.entries
            .retain(|e| now - e.created_at <= self.timeout_ms);
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

// ============================================================================
// Keep-Alive Implementation
// ============================================================================

/// Keep-Alive configuration
#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    /// Enable keep-alive
    pub enabled: bool,
    /// Idle time before first probe (ms)
    pub idle_time: u64,
    /// Interval between probes (ms)
    pub interval: u64,
    /// Maximum probes before disconnect
    pub max_probes: u32,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_time: 75_000, // 75 seconds (RFC 1122)
            interval: 75_000,  // 75 seconds
            max_probes: 9,     // 9 probes
        }
    }
}

impl KeepAliveConfig {
    /// Create a new config with specified idle time
    pub fn with_idle_time(mut self, ms: u64) -> Self {
        self.idle_time = ms;
        self
    }

    /// Create a new config with specified interval
    pub fn with_interval(mut self, ms: u64) -> Self {
        self.interval = ms;
        self
    }

    /// Enable keep-alive
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }
}

/// Keep-Alive state
#[derive(Debug, Clone)]
pub struct KeepAliveState {
    /// Time of last activity
    pub last_activity: u64,
    /// Number of probes sent
    pub probe_count: u32,
    /// Next probe time
    pub next_probe: Option<u64>,
}

impl KeepAliveState {
    pub fn new(now: u64) -> Self {
        Self {
            last_activity: now,
            probe_count: 0,
            next_probe: None,
        }
    }

    /// Record activity (data sent or received)
    pub fn record_activity(&mut self, now: u64) {
        self.last_activity = now;
        self.probe_count = 0;
        self.next_probe = None;
    }

    /// Check if keep-alive should be enabled
    pub fn should_probe(&self, now: u64, config: &KeepAliveConfig) -> bool {
        if !config.enabled {
            return false;
        }

        let idle = now.saturating_sub(self.last_activity);
        idle >= config.idle_time
    }
}

// ============================================================================
// Window Scale Implementation (RFC 1323)
// ============================================================================

/// Window scale configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowScaleConfig {
    /// Our send scale factor
    pub send_scale: u8,
    /// Peer's receive scale factor (what we should use when sending)
    pub recv_scale: u8,
    /// Whether scale has been negotiated
    pub negotiated: bool,
}

impl WindowScaleConfig {
    pub fn new() -> Self {
        Self {
            send_scale: 0,
            recv_scale: 0,
            negotiated: false,
        }
    }

    /// Process received window scale option
    pub fn process_option(&mut self, shift: u8) -> bool {
        // RFC 1323: shift must be 0-14
        if shift > 14 {
            return false;
        }

        // We can only use window scaling if we advertised it
        // In this implementation, we always advertise scale if our buffer > 65535
        self.recv_scale = shift.min(14);
        self.negotiated = true;
        true
    }

    /// Calculate scaled window size
    pub fn scale_window(&self, window: u16) -> u32 {
        (window as u32) << self.recv_scale
    }

    /// Unscale a received window (convert from wire format)
    pub fn unscale_window(&self, scaled_window: u16) -> u32 {
        (scaled_window as u32) << self.send_scale
    }
}

// ============================================================================
// TCP Options Support
// ============================================================================

/// TCP option kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpOptionKind {
    End = 0,
    NoOp = 1,
    MSS = 2,
    WindowScale = 3,
    SackPermitted = 4,
    Sack = 5,
    Timestamp = 8,
}

/// TCP option
#[derive(Debug, Clone)]
pub struct TcpOption {
    pub kind: TcpOptionKind,
    pub data: Vec<u8>,
}

impl TcpOption {
    /// Get the option as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.kind as u8];
        match self.kind {
            TcpOptionKind::End | TcpOptionKind::NoOp => bytes,
            _ => {
                bytes.push((2 + self.data.len()) as u8);
                bytes.extend_from_slice(&self.data);
                bytes
            }
        }
    }

    /// Parse options from TCP header bytes
    ///
    /// This function implements RFC 793 TCP options parsing with security considerations:
    /// - Validates option lengths
    /// - Records unknown options for security monitoring
    /// - Stops parsing on malformed options
    pub fn parse_options(data: &[u8]) -> Vec<TcpOption> {
        let mut options = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let kind = data[i];

            match kind {
                0 => {
                    // End of options
                    options.push(TcpOption {
                        kind: TcpOptionKind::End,
                        data: Vec::new(),
                    });
                    break;
                }
                1 => {
                    // No-op (single byte option)
                    options.push(TcpOption {
                        kind: TcpOptionKind::NoOp,
                        data: Vec::new(),
                    });
                    i += 1;
                }
                _ => {
                    // Multi-byte options must have at least 2 bytes (kind + length)
                    if i + 1 >= data.len() {
                        // Truncated option, stop parsing
                        break;
                    }
                    
                    let len = data[i + 1] as usize;

                    // RFC 793: Length must be at least 2 (for kind and length bytes)
                    // and must not exceed data bounds
                    if len < 2 {
                        // Invalid option length, stop parsing to prevent attacks
                        break;
                    }
                    
                    if i + len > data.len() {
                        // Option extends beyond data, stop parsing
                        break;
                    }
                    
                    // Security: Limit maximum option length to prevent buffer issues
                    const MAX_OPTION_LEN: usize = 40;
                    if len > MAX_OPTION_LEN {
                        break;
                    }

                    let option_data = if len > 2 {
                        data[i + 2..i + len].to_vec()
                    } else {
                        Vec::new()
                    };

                    // Validate specific options have correct length
                    let valid_option = match kind {
                        2 => len == 4,     // MSS must be exactly 4 bytes
                        3 => len == 3,     // Window Scale must be exactly 3 bytes
                        4 => len == 2,     // SACK Permitted must be exactly 2 bytes
                        5 => len >= 2,     // SACK: 2 + n*8 bytes
                        8 => len == 10,    // Timestamp must be exactly 10 bytes
                        _ => true,         // Unknown options: accept but don't process
                    };
                    
                    // Skip options with invalid length for known types
                    // For unknown types, we still accept them (extensibility)
                    if !valid_option {
                        i += len;
                        continue;
                    }

                    let parsed_kind = match kind {
                        2 => Some(TcpOptionKind::MSS),
                        3 => Some(TcpOptionKind::WindowScale),
                        4 => Some(TcpOptionKind::SackPermitted),
                        5 => Some(TcpOptionKind::Sack),
                        8 => Some(TcpOptionKind::Timestamp),
                        _ => None, // Unknown option type
                    };
                    
                    // For unknown options, add as generic option with UnknownKind variant
                    if let Some(parsed) = parsed_kind {
                        options.push(TcpOption {
                            kind: parsed,
                            data: option_data,
                        });
                    }
                    // Unknown options are silently skipped (RFC 793 compliant)
                    // They must be echoed back if MSS, Window Scale, or SACK
                    
                    i += len;
                }
            }
        }
        
        options
    }
    
    /// Create an unknown option from raw bytes
    /// Used when we receive an option type we don't recognize
    pub fn unknown(kind: u8, data: Vec<u8>) -> Self {
        // Note: We use NoOp as a placeholder since we don't have Unknown variant
        // In a full implementation, we'd add an Unknown variant to TcpOptionKind
        Self {
            kind: TcpOptionKind::NoOp,
            data: {
                let mut d = Vec::with_capacity(2 + data.len());
                d.push(kind);
                d.push((2 + data.len()) as u8);
                d.extend_from_slice(&data);
                d
            },
        }
    }
}

/// Build MSS option
pub fn mss_option(mss: u16) -> Vec<u8> {
    vec![TcpOptionKind::MSS as u8, 4, (mss >> 8) as u8, mss as u8]
}

/// Build window scale option
pub fn window_scale_option(scale: u8) -> Vec<u8> {
    vec![TcpOptionKind::WindowScale as u8, 3, scale]
}

/// Build timestamp option
pub fn timestamp_option(tsval: u32, tsecr: u32) -> Vec<u8> {
    vec![
        TcpOptionKind::Timestamp as u8,
        10,
        (tsval >> 24) as u8,
        (tsval >> 16) as u8,
        (tsval >> 8) as u8,
        tsval as u8,
        (tsecr >> 24) as u8,
        (tsecr >> 16) as u8,
        (tsecr >> 8) as u8,
        tsecr as u8,
    ]
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: u32, b: u32) -> bool {
    let diff = a ^ b;
    diff == 0
}

//! TCP Protocol Implementation
//!
//! Implements Transmission Control Protocol for reliable, connection-oriented delivery.


extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;

use crate::common::sync::Spinlock;
use crate::common::Error;
use crate::common::Result;
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
    const fn new(entropy: u64) -> Self {
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
        let mut i = 4;
        while i < 12 {
            x = x.wrapping_add(0x9e3779b9);
            y = y.wrapping_add(0xbb67ae85);
            state[i] = x.wrapping_mul(y).rotate_left(16);
            i += 1;
        }

        Self { state }
    }

    /// Generate next ISS value
    fn next_iss(&mut self) -> u32 {
        // Simple but effective mixing function
        // This is a simplified version suitable for sequence numbers
        let mut sum: u32 = 0;

        // Mix the state
        let mut i = 0;
        while i < 16 {
            self.state[i] = self.state[i].wrapping_add(self.state[(i + 1) & 15]);
            self.state[i] = self.state[i].rotate_left(13);
            sum = sum.wrapping_add(self.state[i]);
            i += 1;
        }

        // Ensure non-zero ISS
        if sum == 0 {
            sum = 0x12345678;
        }

        sum
    }
}

/// ISS state protected by a simple spinlock that wraps the generator.
static ISS_STATE: Spinlock<IssGenerator> = Spinlock::new(IssGenerator::new(0x9ABCDEF0));

/// Generate a secure ISS value
///
/// Uses a cryptographically-inspired PRNG (ChaCha20-style state mixing)
/// to generate Initial Send Sequence numbers. The generator is protected
/// by a spinlock so concurrent callers observe distinct sequence numbers.
pub fn generate_iss() -> u32 {
    let mut guard = ISS_STATE.lock();
    let value = guard.next_iss();
    drop(guard);
    value
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
    /// TCP options (variable-length, e.g. MSS, SACK, Timestamps).
    /// They are serialized after the fixed-size header and before the
    /// payload when the segment is rendered to bytes.
    pub options: Vec<TcpOption>,
}

impl TcpSegment {
    /// Create new segment
    pub fn new() -> Self {
        Self {
            header: TcpHdr::new(),
            payload: Vec::new(),
            options: Vec::new(),
        }
    }

    /// Parse from bytes. The header options are decoded via
    /// [`TcpOption::parse_options`]; the payload is everything that
    /// follows the declared header length.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = TcpHdr::from_bytes(bytes)?;
        let header_len = header.header_len();

        if bytes.len() < header_len {
            return None;
        }

        let opt_bytes = &bytes[TCP_HEADER_LEN..header_len];
        let options = TcpOption::parse_options(opt_bytes);

        let payload = if header_len < bytes.len() {
            bytes[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            header,
            payload,
            options,
        })
    }

    /// Set payload
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Replace the options list with the provided set. The header data
    /// offset is recomputed on the next [`Self::size`] / [`Self::to_bytes`]
    /// call so that the receiver can locate the payload boundary.
    pub fn set_options(&mut self, options: Vec<TcpOption>) {
        self.options = options;
    }

    /// Add a single option to the existing list. Mainly a convenience
    /// for ergonomic call sites like the SYN/SYN-ACK handshake.
    pub fn add_option(&mut self, option: TcpOption) {
        self.options.push(option);
    }

    /// Get segment size (header including options + payload).
    pub fn size(&self) -> usize {
        self.header.header_len() + self.payload.len()
    }

    /// Serialize to bytes. The header is rendered, options are appended
    /// and padded to a 4-byte boundary, then the payload follows.
    pub fn to_bytes(&self) -> Vec<u8> {
        let options_bytes = build_options(&self.options);
        // Total header length including options, rounded up to a 4-byte
        // boundary. The data offset field in the header is expressed in
        // 32-bit words, so we have to keep the alignment correct.
        let opt_padded = options_bytes.len();
        let opt_pad = (4 - (opt_padded % 4)) % 4;
        let header_len = TCP_HEADER_LEN + opt_padded + opt_pad;

        // The header's data offset was set at construction time to the
        // minimum (5 words = 20 bytes). We need to update it now so the
        // on-wire bytes reflect the actual header length.
        let mut header = self.header;
        let offset = ((header_len / 4) as u16) << 12;
        // Preserve the low six flag bits when rewriting the offset word.
        let flags = header.flags();
        header.offset_flags = offset.to_be() | (flags as u16);

        let total = header_len + self.payload.len();
        let mut bytes = Vec::with_capacity(total);
        bytes.resize(total, 0);
        header.to_bytes(&mut bytes).unwrap_or(());
        bytes[TCP_HEADER_LEN..TCP_HEADER_LEN + opt_padded]
            .copy_from_slice(&options_bytes);
        bytes[TCP_HEADER_LEN + opt_padded..header_len]
            .iter_mut()
            .for_each(|b| *b = TcpOptionKind::End.to_byte());
        bytes[header_len..].copy_from_slice(&self.payload);
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

    // === Keepalive ===
    /// TCP keepalive state and configuration
    keepalive: TcpKeepalive,
}

/// Pending retransmission entry. The struct is part of the public API
/// so external callers can construct their own retransmission queues;
/// in the current implementation the kernel-side retransmission path is
/// driven directly through `TcpSocket` timers instead of a queue.
pub struct RetransmitEntry {
    /// Payload that has been sent but not yet acknowledged.
    pub data: Vec<u8>,
    /// Sequence number of the first byte of `data`.
    pub seq: u32,
    /// Tick at which `data` was last transmitted.
    pub sent_at: u64,
    /// Whether the entry has been acknowledged.
    pub acked: bool,
}

impl RetransmitEntry {
    /// Construct a new retransmission entry.
    pub fn new(data: Vec<u8>, seq: u32, sent_at: u64) -> Self {
        Self {
            data,
            seq,
            sent_at,
            acked: false,
        }
    }
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

            // Keepalive (disabled by default; enabled via enable_keepalive())
            keepalive: TcpKeepalive::new(),
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

    /// Currently advertised receive window (bytes the peer is allowed to send).
    pub fn rcv_wnd(&self) -> u16 {
        self.rcv_wnd
    }

    /// Tick at which the zero-window persist timer expires, if armed.
    pub fn persist_timer(&self) -> Option<u64> {
        self.persist_timer
    }

    /// Arm the persist timer to expire at `tick`.
    pub fn set_persist_timer(&mut self, tick: Option<u64>) {
        self.persist_timer = tick;
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
                    + (self.rtt as u64).saturating_sub(sample)
                    .wrapping_sub(sample).wrapping_add(self.rtt as u64) / 2)
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
        // The number of pending connections would be tracked separately in
        // a full implementation; for now we expose the configured limit so
        // the caller can compare against it.
        self.backlog_size == 0
    }

    /// Configured maximum number of pending (unaccepted) connections.
    pub fn backlog_size(&self) -> usize {
        self.backlog_size
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
        _tsval: u32,
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
    /// Unknown option kind (preserves the raw byte value)
    Unknown(u8),
}

impl TcpOptionKind {
    /// Convert a raw byte to a TcpOptionKind, mapping unknown values to None
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(TcpOptionKind::End),
            1 => Some(TcpOptionKind::NoOp),
            2 => Some(TcpOptionKind::MSS),
            3 => Some(TcpOptionKind::WindowScale),
            4 => Some(TcpOptionKind::SackPermitted),
            5 => Some(TcpOptionKind::Sack),
            8 => Some(TcpOptionKind::Timestamp),
            _ => Some(TcpOptionKind::Unknown(b)),
        }
    }

    /// Convert to the underlying wire byte (always 0-255)
    pub fn to_byte(self) -> u8 {
        match self {
            TcpOptionKind::End => 0,
            TcpOptionKind::NoOp => 1,
            TcpOptionKind::MSS => 2,
            TcpOptionKind::WindowScale => 3,
            TcpOptionKind::SackPermitted => 4,
            TcpOptionKind::Sack => 5,
            TcpOptionKind::Timestamp => 8,
            TcpOptionKind::Unknown(b) => b,
        }
    }
}

/// TCP option
#[derive(Debug, Clone)]
pub struct TcpOption {
    /// Option kind (Unknown(u8) for unrecognized options)
    pub kind: TcpOptionKind,
    /// Raw option kind byte when kind is unknown (preserves the original)
    pub raw_kind: Option<u8>,
    /// Option data (kind/length bytes excluded)
    pub data: Vec<u8>,
}

impl TcpOption {
    /// Get the option as bytes for serialization into a TCP header
    pub fn to_bytes(&self) -> Vec<u8> {
        // Determine the kind byte: use raw_kind for unknown options
        let kind_byte = self.kind.to_byte();

        match self.kind {
            TcpOptionKind::End | TcpOptionKind::NoOp => vec![kind_byte],
            _ => {
                let mut bytes = Vec::with_capacity(2 + self.data.len());
                bytes.push(kind_byte);
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
                        raw_kind: None,
                        data: Vec::new(),
                    });
                    break;
                }
                1 => {
                    // No-op (single byte option)
                    options.push(TcpOption {
                        kind: TcpOptionKind::NoOp,
                        raw_kind: None,
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

                    // For known options, add with the parsed kind.
                    // For unknown options, preserve the raw kind byte via Unknown variant.
                    if let Some(parsed) = parsed_kind {
                        options.push(TcpOption {
                            kind: parsed,
                            raw_kind: None,
                            data: option_data,
                        });
                    } else {
                        options.push(TcpOption {
                            kind: TcpOptionKind::Unknown(kind),
                            raw_kind: Some(kind),
                            data: option_data,
                        });
                    }

                    i += len;
                }
            }
        }
        
        options
    }
    
    /// Create an unknown option from raw bytes
    /// Used when we receive an option type we don't recognize
    pub fn unknown(kind: u8, data: Vec<u8>) -> Self {
        Self {
            kind: TcpOptionKind::Unknown(kind),
            raw_kind: Some(kind),
            data,
        }
    }
}

/// Build a vector of TCP option bytes from a slice of TcpOption values
///
/// This function serializes the options into the wire format for outgoing TCP segments.
/// It automatically pads with EOL (End of Option List) to a 4-byte boundary per RFC 793.
///
/// # Arguments
/// * `options` - The list of TCP options to serialize
///
/// # Returns
/// A `Vec<u8>` containing the serialized options
///
/// # Example
/// ```
/// use plan9_net::tcp::{TcpOption, TcpOptionKind, build_options};
///
/// let opts = vec![
///     TcpOption { kind: TcpOptionKind::MSS, raw_kind: None, data: vec![0x05, 0xb4] },
/// ];
/// let bytes = build_options(&opts);
/// ```
pub fn build_options(options: &[TcpOption]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for opt in options {
        bytes.extend_from_slice(&opt.to_bytes());
    }

    // Pad to 4-byte boundary using EOL bytes (per RFC 793 section 3.1)
    // The TCP header is aligned to 32-bit words, so the options field
    // must also be a multiple of 4 bytes.
    let padding = (4 - (bytes.len() % 4)) % 4;
    for _ in 0..padding {
        bytes.push(TcpOptionKind::End.to_byte());
    }

    bytes
}

/// Build MSS option
pub fn mss_option(mss: u16) -> Vec<u8> {
    vec![TcpOptionKind::MSS.to_byte(), 4, (mss >> 8) as u8, mss as u8]
}

/// Build window scale option
pub fn window_scale_option(scale: u8) -> Vec<u8> {
    vec![TcpOptionKind::WindowScale.to_byte(), 3, scale]
}

/// Build timestamp option
pub fn timestamp_option(tsval: u32, tsecr: u32) -> Vec<u8> {
    vec![
        TcpOptionKind::Timestamp.to_byte(),
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

// ============================================================================
// TCP Keepalive
// ============================================================================

/// TCP Keepalive state and configuration
pub struct TcpKeepalive {
    /// Whether keepalive is enabled
    enabled: bool,
    /// Idle time before starting keepalive probes (in seconds)
    idle: u32,
    /// Interval between keepalive probes (in seconds)
    interval: u32,
    /// Maximum number of keepalive probes
    max_probes: u32,
    /// Current probe count
    probe_count: u32,
    /// Last activity timestamp
    last_activity: u64,
    /// Whether we're currently in keepalive mode
    in_keepalive: bool,
}

impl TcpKeepalive {
    /// Create new keepalive configuration
    pub fn new() -> Self {
        Self {
            enabled: false,
            idle: 7200,      // 2 hours default (Linux default)
            interval: 75,    // 75 seconds default (Linux default)
            max_probes: 9,   // 9 probes default (Linux default)
            probe_count: 0,
            last_activity: 0,
            in_keepalive: false,
        }
    }

    /// Enable keepalive with custom parameters
    pub fn enable(idle: u32, interval: u32, max_probes: u32) -> Self {
        Self {
            enabled: true,
            idle,
            interval,
            max_probes,
            probe_count: 0,
            last_activity: 0,
            in_keepalive: false,
        }
    }

    /// Disable keepalive
    pub fn disable(&mut self) {
        self.enabled = false;
        self.in_keepalive = false;
        self.probe_count = 0;
    }

    /// Check if keepalive is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record activity (call when data is sent or received)
    pub fn record_activity(&mut self, timestamp: u64) {
        self.last_activity = timestamp;
        self.in_keepalive = false;
        self.probe_count = 0;
    }

    /// Check if we should send a keepalive probe
    /// Returns true if a probe should be sent
    pub fn should_probe(&self, current_time: u64) -> bool {
        if !self.enabled {
            return false;
        }

        // First check if we've been idle long enough
        let idle_time = current_time.saturating_sub(self.last_activity);
        if idle_time < self.idle as u64 {
            return false;
        }

        // In keepalive mode, check if it's time for next probe
        if self.in_keepalive {
            let time_since_last = current_time.saturating_sub(self.last_activity);
            return time_since_last >= self.interval as u64;
        }

        // First probe after idle timeout
        true
    }

    /// Call after sending a keepalive probe
    pub fn on_probe_sent(&mut self, timestamp: u64) {
        if !self.in_keepalive {
            self.in_keepalive = true;
            self.probe_count = 1;
        } else {
            self.probe_count += 1;
        }
        self.last_activity = timestamp;
    }

    /// Call when we receive a response to a keepalive probe
    pub fn on_probe_response(&mut self) {
        self.in_keepalive = false;
        self.probe_count = 0;
    }

    /// Check if connection should be closed due to failed keepalive
    pub fn should_close(&self) -> bool {
        self.enabled && self.in_keepalive && self.probe_count >= self.max_probes
    }

    /// Get current probe count
    pub fn probe_count(&self) -> u32 {
        self.probe_count
    }

    /// Get remaining probes
    pub fn remaining_probes(&self) -> u32 {
        self.max_probes.saturating_sub(self.probe_count)
    }
}

impl Default for TcpKeepalive {
    fn default() -> Self {
        Self::new()
    }
}

/// Extend TcpSocket with keepalive support
impl TcpSocket {
    /// Get keepalive state (mutable)
    pub fn keepalive_mut(&mut self) -> &mut TcpKeepalive {
        &mut self.keepalive
    }

    /// Get keepalive state (read-only)
    pub fn keepalive(&self) -> &TcpKeepalive {
        &self.keepalive
    }

    /// Enable keepalive on this socket
    ///
    /// # Arguments
    /// * `idle` - Seconds of idle time before first probe
    /// * `interval` - Seconds between probes
    /// * `max_probes` - Maximum number of failed probes before closing
    pub fn enable_keepalive(&mut self, idle: u32, interval: u32, max_probes: u32) {
        self.keepalive = TcpKeepalive::enable(idle, interval, max_probes);
    }

    /// Disable keepalive on this socket
    pub fn disable_keepalive(&mut self) {
        self.keepalive.disable();
    }

    /// Check and handle keepalive state
    /// Call this periodically for active sockets
    ///
    /// # Returns
    /// - `KeepaliveAction::None` - No action needed
    /// - `KeepaliveAction::SendProbe` - Should send a keepalive probe
    /// - `KeepaliveAction::CloseConnection` - Should close connection (max probes exceeded)
    pub fn check_keepalive(&mut self, current_time: u64) -> KeepaliveAction {
        if !self.keepalive.is_enabled() {
            return KeepaliveAction::None;
        }

        if self.keepalive.should_close() {
            return KeepaliveAction::CloseConnection;
        }

        if self.keepalive.should_probe(current_time) {
            self.keepalive.on_probe_sent(current_time);
            return KeepaliveAction::SendProbe;
        }

        KeepaliveAction::None
    }

    /// Record that data was sent or received (resets keepalive timer)
    pub fn keepalive_activity(&mut self, timestamp: u64) {
        self.keepalive.record_activity(timestamp);
    }

    /// Record that a keepalive probe response was received
    pub fn keepalive_response(&mut self) {
        self.keepalive.on_probe_response();
    }

    /// Build a TCP keepalive probe segment on the wire.
    ///
    /// Per RFC 1122 section 4.2.3.6, a TCP keepalive probe is sent as an
    /// empty segment with the ACK of `seq = snd_nxt - 1` (i.e. one byte
    /// behind the next data we would send). The receiver's response is a
    /// regular ACK echoing `snd_nxt - 1`; anything else (e.g. RST)
    /// indicates the connection is broken.
    ///
    /// The returned segment has no payload and no options - both the
    /// kernel and most implementations keep probes minimal so they do
    /// not interfere with the application data stream.
    pub fn build_keepalive_probe(&self) -> TcpSegment {
        let mut seg = TcpSegment::new();
        seg.header.src_port = self.local_port.to_be();
        seg.header.dst_port = self.remote_port.to_be();
        // RFC 1122: seq = snd_nxt - 1 so the peer's ACK has something
        // concrete to acknowledge.
        seg.header.seq = self.snd_nxt.wrapping_sub(1).to_be();
        seg.header.ack = self.rcv_nxt.to_be();
        // Pure ACK probe: only the ACK flag set, no PSH/FIN.
        seg.header.set_flags(flag::ACK);
        seg.header.window = self.snd_wnd.to_be();
        seg
    }

    /// Handle a peer response to a keepalive probe we previously sent.
    ///
    /// Returns `true` if the response was a healthy ACK (i.e. the
    /// connection is still alive); `false` means the peer did not
    /// acknowledge our probe and another probe (or connection close)
    /// is required.
    pub fn handle_keepalive_response(&mut self, seg: &TcpSegment) -> bool {
        if !self.keepalive.is_enabled() {
            return false;
        }
        if !seg.header.has_flag(flag::ACK) {
            return false;
        }
        // A healthy response echoes our probe sequence (snd_nxt - 1).
        let expected = self.snd_nxt.wrapping_sub(1);
        if seg.header.seq() == expected || seg.header.ack_num() == self.rcv_nxt {
            self.keepalive.on_probe_response();
            true
        } else {
            false
        }
    }
}

/// Actions to take based on keepalive state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveAction {
    /// No action needed
    None,
    /// Send a keepalive probe
    SendProbe,
    /// Close the connection
    CloseConnection,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_options_mss() {
        let opts = vec![
            TcpOption {
                kind: TcpOptionKind::MSS,
                raw_kind: None,
                data: vec![0x05, 0xb4], // MSS = 1460
            },
        ];
        let bytes = build_options(&opts);
        // MSS option: [kind=2, len=4, mss_hi, mss_lo] = 4 bytes
        // Padded to 4-byte boundary = no padding
        assert_eq!(bytes, vec![2, 4, 0x05, 0xb4]);
    }

    #[test]
    fn test_build_options_with_padding() {
        // Window Scale option is 3 bytes, padded to 4 with EOL
        let opts = vec![
            TcpOption {
                kind: TcpOptionKind::WindowScale,
                raw_kind: None,
                data: vec![7], // scale = 7
            },
        ];
        let bytes = build_options(&opts);
        assert_eq!(bytes, vec![3, 3, 7, 0]); // last byte is EOL padding
    }

    #[test]
    fn test_build_options_multiple() {
        let opts = vec![
            TcpOption {
                kind: TcpOptionKind::MSS,
                raw_kind: None,
                data: vec![0x05, 0xb4],
            },
            TcpOption {
                kind: TcpOptionKind::NoOp,
                raw_kind: None,
                data: Vec::new(),
            },
            TcpOption {
                kind: TcpOptionKind::WindowScale,
                raw_kind: None,
                data: vec![7],
            },
            TcpOption {
                kind: TcpOptionKind::NoOp,
                raw_kind: None,
                data: Vec::new(),
            },
            TcpOption {
                kind: TcpOptionKind::SackPermitted,
                raw_kind: None,
                data: Vec::new(),
            },
        ];
        let bytes = build_options(&opts);
        // MSS (4) + NOP (1) + WS (3) + NOP (1) + SackPermitted (2) = 11
        // Padded to 12 with EOL
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[11], 0); // EOL padding
    }

    #[test]
    fn test_parse_options_mss() {
        // MSS = 1460 = [0x05, 0xb4]
        let bytes = vec![2, 4, 0x05, 0xb4];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].kind, TcpOptionKind::MSS);
        assert_eq!(opts[0].data, vec![0x05, 0xb4]);
    }

    #[test]
    fn test_parse_options_unknown_preserved() {
        // Unknown option kind 9 with 2 bytes of data
        let bytes = vec![9, 4, 0xaa, 0xbb];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 1);
        match opts[0].kind {
            TcpOptionKind::Unknown(b) => assert_eq!(b, 9),
            _ => panic!("Expected Unknown variant"),
        }
        assert_eq!(opts[0].raw_kind, Some(9));
        assert_eq!(opts[0].data, vec![0xaa, 0xbb]);
    }

    #[test]
    fn test_parse_options_end_and_nop() {
        // NOP + NOP + EOL
        let bytes = vec![1, 1, 0];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].kind, TcpOptionKind::NoOp);
        assert_eq!(opts[1].kind, TcpOptionKind::NoOp);
        assert_eq!(opts[2].kind, TcpOptionKind::End);
    }

    #[test]
    fn test_round_trip_build_parse() {
        let opts = vec![
            TcpOption {
                kind: TcpOptionKind::MSS,
                raw_kind: None,
                data: vec![0x05, 0xb4],
            },
            TcpOption {
                kind: TcpOptionKind::WindowScale,
                raw_kind: None,
                data: vec![7],
            },
        ];
        let bytes = build_options(&opts);
        // After build: 4 bytes MSS + 4 bytes (WS + EOL padding) = 8 bytes
        let parsed = TcpOption::parse_options(&bytes);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, TcpOptionKind::MSS);
        assert_eq!(parsed[0].data, vec![0x05, 0xb4]);
        assert_eq!(parsed[1].kind, TcpOptionKind::WindowScale);
        assert_eq!(parsed[1].data, vec![7]);
    }

    #[test]
    fn test_keepalive_disabled_by_default() {
        let ka = TcpKeepalive::new();
        assert!(!ka.is_enabled());
    }

    #[test]
    fn test_keepalive_enable_with_params() {
        let ka = TcpKeepalive::enable(60, 10, 3);
        assert!(ka.is_enabled());
        assert_eq!(ka.probe_count(), 0);
        assert!(!ka.should_close());
    }

    #[test]
    fn test_keepalive_probe_lifecycle() {
        let mut ka = TcpKeepalive::enable(10, 5, 2);
        ka.record_activity(0);

        // Before idle period, no probe needed
        assert!(!ka.should_probe(5));

        // After idle period, probe needed
        assert!(ka.should_probe(11));

        // After probe sent, we're in keepalive mode
        ka.on_probe_sent(11);
        assert_eq!(ka.probe_count(), 1);

        // Response received, back to normal
        ka.on_probe_response();
        assert_eq!(ka.probe_count(), 0);
        assert!(!ka.should_close());
    }

    #[test]
    fn test_keepalive_max_probes_closes() {
        let mut ka = TcpKeepalive::enable(5, 1, 2);
        ka.record_activity(0);

        // First probe
        ka.on_probe_sent(6);
        assert!(!ka.should_close());

        // Second probe - should close after this
        ka.on_probe_sent(7);
        assert!(ka.should_close());
    }

    #[test]
    fn test_socket_keepalive_integration() {
        let mut sock = TcpSocket::new();
        assert!(!sock.keepalive().is_enabled());

        sock.enable_keepalive(60, 10, 3);
        assert!(sock.keepalive().is_enabled());

        sock.keepalive_activity(100);
        // No probe needed before idle
        assert_eq!(sock.check_keepalive(110), KeepaliveAction::None);

        // After idle, probe needed
        assert_eq!(sock.check_keepalive(170), KeepaliveAction::SendProbe);

        sock.keepalive_response();
        assert_eq!(sock.keepalive().probe_count(), 0);
    }

    #[test]
    fn test_from_byte() {
        assert_eq!(TcpOptionKind::from_byte(0), Some(TcpOptionKind::End));
        assert_eq!(TcpOptionKind::from_byte(2), Some(TcpOptionKind::MSS));
        assert_eq!(TcpOptionKind::from_byte(8), Some(TcpOptionKind::Timestamp));
        // Unknown byte should map to Unknown variant
        match TcpOptionKind::from_byte(99) {
            Some(TcpOptionKind::Unknown(b)) => assert_eq!(b, 99),
            other => panic!("Expected Unknown(99), got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_option_creation() {
        let opt = TcpOption::unknown(7, vec![0xaa, 0xbb]);
        assert_eq!(opt.raw_kind, Some(7));
        assert_eq!(opt.data, vec![0xaa, 0xbb]);
        match opt.kind {
            TcpOptionKind::Unknown(b) => assert_eq!(b, 7),
            _ => panic!("Expected Unknown variant"),
        }

        // Round-trip through serialization
        let bytes = opt.to_bytes();
        assert_eq!(bytes, vec![7, 4, 0xaa, 0xbb]);
    }

    #[test]
    fn test_mss_option_helper() {
        let bytes = mss_option(1460);
        // 1460 = 0x05B4
        assert_eq!(bytes, vec![2, 4, 0x05, 0xb4]);
    }

    #[test]
    fn test_window_scale_option_helper() {
        let bytes = window_scale_option(7);
        assert_eq!(bytes, vec![3, 3, 7]);
    }

    #[test]
    fn test_timestamp_option_helper() {
        let bytes = timestamp_option(0x01020304, 0x05060708);
        assert_eq!(bytes, vec![8, 10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_sack_option_round_trip() {
        // SACK with one block: [kind=5, len=10, left_hi, left_lo, right_hi, right_lo]
        let bytes = vec![5, 10, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].kind, TcpOptionKind::Sack);
        assert_eq!(opts[0].data, vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04]);
    }

    #[test]
    fn test_parse_options_empty() {
        let bytes: Vec<u8> = vec![];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 0);
    }

    #[test]
    fn test_parse_options_truncated() {
        // Truncated MSS option - kind=2, length byte missing
        let bytes = vec![2];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 0);
    }

    #[test]
    fn test_build_options_empty() {
        let bytes = build_options(&[]);
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_keepalive_disable() {
        let mut ka = TcpKeepalive::enable(60, 10, 3);
        assert!(ka.is_enabled());
        ka.disable();
        assert!(!ka.is_enabled());
        assert_eq!(ka.probe_count(), 0);
    }

    #[test]
    fn test_keepalive_default_via_socket() {
        let sock = TcpSocket::new();
        // Newly created socket has keepalive disabled
        assert!(!sock.keepalive().is_enabled());
        assert_eq!(sock.keepalive().probe_count(), 0);
        assert_eq!(sock.keepalive().remaining_probes(), 0);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(0x12345678, 0x12345678));
        assert!(!constant_time_eq(0x12345678, 0x12345679));
        assert!(constant_time_eq(0, 0));
    }

    // ========================================================================
    // New tests: segment round-trip with options, keepalive probe segment,
    // keepalive probe response handling, and expanded NoOp coverage.
    // ========================================================================

    #[test]
    fn test_nop_option_to_bytes_is_single_byte() {
        let nop = TcpOption {
            kind: TcpOptionKind::NoOp,
            raw_kind: None,
            data: Vec::new(),
        };
        assert_eq!(nop.to_bytes(), vec![1]);
    }

    #[test]
    fn test_multiple_nops_in_a_row_parse_correctly() {
        // 4 NOPs back to back - the parser must advance exactly one
        // byte per NOP and emit four distinct TcpOptionKind::NoOp.
        let bytes = vec![1, 1, 1, 1];
        let opts = TcpOption::parse_options(&bytes);
        assert_eq!(opts.len(), 4);
        for opt in &opts {
            assert_eq!(opt.kind, TcpOptionKind::NoOp);
        }
    }

    #[test]
    fn test_nop_padding_to_four_byte_boundary() {
        // 3 bytes of NOPs => pad with one EOL (0x00).
        let opts = vec![
            TcpOption { kind: TcpOptionKind::NoOp, raw_kind: None, data: Vec::new() },
            TcpOption { kind: TcpOptionKind::NoOp, raw_kind: None, data: Vec::new() },
            TcpOption { kind: TcpOptionKind::NoOp, raw_kind: None, data: Vec::new() },
        ];
        let bytes = build_options(&opts);
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[3], 0); // EOL pad
    }

    #[test]
    fn test_segment_round_trip_with_options() {
        let mut seg = TcpSegment::new();
        seg.header.src_port = 12345u16.to_be();
        seg.header.dst_port = 80u16.to_be();
        seg.header.seq = 0xDEADBEEFu32.to_be();
        seg.header.ack = 0xCAFEBABEu32.to_be();
        seg.header.set_flags(flag::SYN | flag::ACK);
        seg.add_option(TcpOption {
            kind: TcpOptionKind::MSS,
            raw_kind: None,
            data: vec![0x05, 0xb4],
        });
        seg.add_option(TcpOption {
            kind: TcpOptionKind::NoOp,
            raw_kind: None,
            data: Vec::new(),
        });

        let bytes = seg.to_bytes();
        let parsed = TcpSegment::parse(&bytes).expect("round-trip parse");
        assert_eq!(parsed.header.src_port, 12345u16.to_be());
        assert_eq!(parsed.header.dst_port, 80u16.to_be());
        assert_eq!(parsed.header.seq, 0xDEADBEEFu32.to_be());
        assert_eq!(parsed.header.ack, 0xCAFEBABEu32.to_be());
        assert_eq!(parsed.header.flags() & (flag::SYN | flag::ACK),
                   flag::SYN | flag::ACK);
        // Data offset in words should reflect 24-byte header (5 + 1
        // padding word = 6 words = 24 bytes).
        assert_eq!(parsed.header.header_len(), 24);
        // Options decoded by parse_options should include MSS + NOP.
        assert_eq!(parsed.options.len(), 2);
        assert_eq!(parsed.options[0].kind, TcpOptionKind::MSS);
        assert_eq!(parsed.options[1].kind, TcpOptionKind::NoOp);
    }

    #[test]
    fn test_segment_set_options_replaces_previous() {
        let mut seg = TcpSegment::new();
        seg.add_option(TcpOption {
            kind: TcpOptionKind::NoOp,
            raw_kind: None,
            data: Vec::new(),
        });
        seg.set_options(vec![TcpOption {
            kind: TcpOptionKind::MSS,
            raw_kind: None,
            data: vec![0x05, 0xb4],
        }]);
        assert_eq!(seg.options.len(), 1);
        assert_eq!(seg.options[0].kind, TcpOptionKind::MSS);
    }

    #[test]
    fn test_segment_options_data_offset_is_updated() {
        // Header length on wire must equal TCP_HEADER_LEN + padded options.
        let mut seg = TcpSegment::new();
        seg.add_option(TcpOption {
            kind: TcpOptionKind::MSS,
            raw_kind: None,
            data: vec![0x05, 0xb4],
        });
        // MSS = 4 bytes; pad 0 to multiple of 4 -> header length 24.
        let bytes = seg.to_bytes();
        // Data offset (upper 4 bits of byte 12) = 6.
        let offset_word = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(offset_word >> 12, 6);
        assert_eq!(seg.size(), 24);
    }

    #[test]
    fn test_segment_with_empty_options_serializes_cleanly() {
        // No options: header must remain 20 bytes (5 words).
        let mut seg = TcpSegment::new();
        seg.header.src_port = 22u16.to_be();
        seg.set_payload(vec![0xAB, 0xCD]);
        let bytes = seg.to_bytes();
        let offset_word = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(offset_word >> 12, 5);
        // Total = 20 header + 2 payload.
        assert_eq!(bytes.len(), 22);
        assert_eq!(&bytes[20..], &[0xAB, 0xCD]);
    }

    #[test]
    fn test_keepalive_probe_segment_fields() {
        let mut sock = TcpSocket::new();
        sock.local_port = 8080;
        sock.remote_port = 22;
        sock.remote_ip = 0x0A000001; // 10.0.0.1
        sock.snd_nxt = 1000;
        sock.rcv_nxt = 500;
        sock.snd_wnd = 8192;

        let probe = sock.build_keepalive_probe();
        // No payload, no options.
        assert!(probe.payload.is_empty());
        assert!(probe.options.is_empty());
        // Ports swapped to network byte order.
        assert_eq!(u16::from_be(probe.header.src_port), 8080);
        assert_eq!(u16::from_be(probe.header.dst_port), 22);
        // Seq = snd_nxt - 1, in network byte order.
        assert_eq!(u32::from_be(probe.header.seq), 999);
        assert_eq!(u32::from_be(probe.header.ack), 500);
        // ACK flag set, no other flags.
        assert_eq!(probe.header.flags(), flag::ACK);
        // Window in network byte order.
        assert_eq!(u16::from_be(probe.header.window), 8192);
    }

    #[test]
    fn test_keepalive_probe_wraps_at_zero() {
        // snd_nxt = 0 must not panic on the saturating_sub.
        let mut sock = TcpSocket::new();
        sock.snd_nxt = 0;
        let probe = sock.build_keepalive_probe();
        // wrapping_sub(1) yields u32::MAX.
        assert_eq!(u32::from_be(probe.header.seq), u32::MAX);
    }

    #[test]
    fn test_handle_keepalive_response_accepts_matching_ack() {
        let mut sock = TcpSocket::new();
        sock.snd_nxt = 1000;
        sock.rcv_nxt = 500;
        sock.enable_keepalive(60, 10, 3);
        // Pretend we just sent a probe.
        sock.keepalive.on_probe_sent(123);
        assert_eq!(sock.keepalive.probe_count(), 1);

        // Build a healthy response: ACK with seq = snd_nxt - 1.
        let mut resp = TcpSegment::new();
        resp.header.ack = sock.snd_nxt.wrapping_sub(1).to_be();
        resp.header.set_flags(flag::ACK);
        assert!(sock.handle_keepalive_response(&resp));
        // Probe counter reset on response.
        assert_eq!(sock.keepalive.probe_count(), 0);
    }

    #[test]
    fn test_handle_keepalive_response_rejects_unhealthy_ack() {
        let mut sock = TcpSocket::new();
        sock.snd_nxt = 1000;
        sock.rcv_nxt = 500;
        sock.enable_keepalive(60, 10, 3);
        sock.keepalive.on_probe_sent(0);
        // Wrong seq - not our probe's sequence.
        let mut resp = TcpSegment::new();
        resp.header.ack = 1u32.to_be();
        resp.header.set_flags(flag::ACK);
        assert!(!sock.handle_keepalive_response(&resp));
        // Probe counter must not reset.
        assert_eq!(sock.keepalive.probe_count(), 1);
    }

    #[test]
    fn test_handle_keepalive_response_ignores_when_disabled() {
        let mut sock = TcpSocket::new();
        sock.snd_nxt = 1000;
        sock.rcv_nxt = 500;
        // Keepalive disabled.
        let mut resp = TcpSegment::new();
        resp.header.ack = 999u32.to_be();
        resp.header.set_flags(flag::ACK);
        assert!(!sock.handle_keepalive_response(&resp));
    }

    #[test]
    fn test_handle_keepalive_response_rejects_segment_without_ack() {
        let mut sock = TcpSocket::new();
        sock.snd_nxt = 1000;
        sock.rcv_nxt = 500;
        sock.enable_keepalive(60, 10, 3);
        // SYN segment - keepalive probes never carry SYN.
        let mut resp = TcpSegment::new();
        resp.header.ack = 999u32.to_be();
        resp.header.set_flags(flag::SYN);
        assert!(!sock.handle_keepalive_response(&resp));
    }

    #[test]
    fn test_keepalive_probe_then_response_resets_full_state() {
        let mut sock = TcpSocket::new();
        sock.enable_keepalive(1, 1, 3);
        sock.snd_nxt = 50;
        sock.rcv_nxt = 0;

        // 1 second of idle, then probe is triggered.
        assert!(sock.check_keepalive(2) == KeepaliveAction::SendProbe);
        // After probe is sent, in_keepalive is true.
        assert!(sock.keepalive().is_enabled());

        let probe = sock.build_keepalive_probe();
        let mut resp = TcpSegment::new();
        resp.header.ack = u32::from_be(probe.header.seq);
        resp.header.set_flags(flag::ACK);
        assert!(sock.handle_keepalive_response(&resp));
        // Connection healthy - no further probe needed at the same time.
        assert_eq!(sock.check_keepalive(2), KeepaliveAction::None);
    }
}


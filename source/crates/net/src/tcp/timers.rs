//! TCP Timer and Congestion Control
//!
//! Implements TCP timers, retransmission, RTT measurement, and
//! congestion control algorithms.

use crate::common::sync::Spinlock;
use core::cmp::{min, max};
use core::collections::BTreeMap;

// ============================================================================
// TCP Timer Types
// ============================================================================

/// TCP timer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpTimerType {
    /// Retransmission timer
    Retransmit,
    /// Delayed ACK timer
    DelayedAck,
    /// RTT measurement timer
    Rtt,
    /// Keep-alive timer
    KeepAlive,
    /// FIN_WAIT_2 timer
    FinWait2,
    /// TIME_WAIT timer
    TimeWait,
    /// Persist timer (zero window probe)
    Persist,
}

/// TCP timer entry
#[derive(Debug)]
pub struct TcpTimerEntry {
    /// Connection ID
    pub conv_id: u32,
    /// Timer type
    pub timer_type: TcpTimerType,
    /// When the timer expires (in ticks)
    pub expires: u64,
    /// Timer data
    pub data: u64,
}

impl TcpTimerEntry {
    pub fn new(conv_id: u32, timer_type: TcpTimerType, expires: u64, data: u64) -> Self {
        Self {
            conv_id,
            timer_type,
            expires,
            data,
        }
    }
}

// ============================================================================
// TCP Timer Manager
// ============================================================================

/// Timer wheel for TCP timers
pub struct TcpTimerManager {
    /// Pending timers (sorted by expiration time)
    timers: BTreeMap<u64, Vec<TcpTimerEntry>>,
    /// Current time in ticks
    current_time: u64,
}

impl TcpTimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            timers: BTreeMap::new(),
            current_time: 0,
        }
    }

    /// Add a timer
    pub fn add(&mut self, entry: TcpTimerEntry) {
        let expires = entry.expires;
        self.timers
            .entry(expires)
            .or_insert_with(Vec::new)
            .push(entry);
    }

    /// Remove timers for a connection
    pub fn remove_connection(&mut self, conv_id: u32) {
        for timers in self.timers.values_mut() {
            timers.retain(|t| t.conv_id != conv_id);
        }
    }

    /// Process expired timers
    /// Returns timers that have expired
    pub fn process_expired(&mut self) -> Vec<TcpTimerEntry> {
        let mut expired = Vec::new();
        
        while let Some((time, mut entries)) = self.timers.pop_first() {
            if time > self.current_time {
                // Not expired yet, put back
                self.timers.insert(time, entries);
                break;
            }
            
            self.current_time = time;
            expired.append(&mut entries);
        }
        
        expired
    }

    /// Get next timer expiration
    pub fn next_expiration(&self) -> Option<u64> {
        self.timers.keys().next().copied()
    }

    /// Advance time
    pub fn advance(&mut self, ticks: u64) {
        self.current_time += ticks;
    }

    /// Get current time
    pub fn current_time(&self) -> u64 {
        self.current_time
    }
}

impl Default for TcpTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Congestion Control State
// ============================================================================

/// Congestion control state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Open (normal operation)
    Open,
    /// Disorder (duplicate ACKs received)
    Disorder,
    /// CWR (congestion window reduced, waiting for ACK)
    Cwr,
    /// Recovery (in fast recovery)
    Recovery,
    /// Loss (timeout detected)
    Loss,
}

/// TCP congestion control
#[derive(Debug)]
pub struct CongestionControl {
    /// Congestion window
    pub cwind: u64,
    /// Slow start threshold
    pub ssthresh: u64,
    /// Number of duplicate ACKs received
    pub dupacks: u32,
    /// Flight size (bytes in flight)
    pub flight: u64,
    /// Recovery point (highest sequence sent)
    pub recovery_point: u64,
    /// Current state
    pub state: CongestionState,
    /// Partial ACK handling
    pub partial_ack: bool,
}

impl CongestionControl {
    /// Create new congestion control
    pub fn new(mss: u64) -> Self {
        Self {
            cwind: mss.min(2 * mss), // Initial window = 2 * MSS
            ssthresh: u64::MAX,
            dupacks: 0,
            flight: 0,
            recovery_point: 0,
            state: CongestionState::Open,
            partial_ack: false,
        }
    }

    /// Handle incoming ACK
    pub fn on_ack(&mut self, acked: u64, mss: u64) {
        match self.state {
            CongestionState::Open => {
                if self.cwind < self.ssthresh {
                    // Slow start: increase cwnd by MSS for each ACK
                    self.cwind += mss * acked / self.cwind;
                } else {
                    // Congestion avoidance: increase cwnd by MSS^2 / cwnd
                    self.cwind += mss * mss / self.cwind;
                }
                self.dupacks = 0;
            }
            CongestionState::Disorder => {
                // Stay in disorder until recovery point
                if acked >= self.recovery_point {
                    self.state = CongestionState::Open;
                    self.dupacks = 0;
                }
            }
            CongestionState::Cwr | CongestionState::Recovery => {
                // In recovery, reduce cwnd
                if acked >= self.recovery_point {
                    self.state = CongestionState::Open;
                    self.cwind = self.ssthresh;
                    self.dupacks = 0;
                }
            }
            CongestionState::Loss => {
                // After loss, restart slow start
                if acked >= self.recovery_point {
                    self.state = CongestionState::Open;
                }
            }
        }
    }

    /// Handle duplicate ACK
    pub fn on_dupack(&mut self, mss: u64) -> bool {
        self.dupacks += 1;
        
        match self.state {
            CongestionState::Open => {
                if self.dupacks == 3 {
                    // Fast retransmit
                    self.ssthresh = max(2 * mss, self.cwind / 2);
                    self.cwind = self.ssthresh + 3 * mss;
                    self.recovery_point = self.flight;
                    self.state = CongestionState::Recovery;
                    true // Trigger fast retransmit
                } else {
                    self.cwind += mss; // Stretch ACK
                    false
                }
            }
            CongestionState::Recovery | CongestionState::Cwr => {
                self.cwind += mss;
                false
            }
            _ => false,
        }
    }

    /// Handle timeout
    pub fn on_timeout(&mut self, mss: u64) {
        // Save current flight as loss point
        self.ssthresh = max(2 * mss, self.flight / 2);
        self.cwind = mss;
        self.recovery_point = 0;
        self.state = CongestionState::Loss;
        self.dupacks = 0;
    }

    /// Handle ECN (Explicit Congestion Notification)
    pub fn on_ecn(&mut self, mss: u64) {
        self.ssthresh = max(2 * mss, self.cwind / 2);
        self.cwind = self.ssthresh;
        self.recovery_point = self.flight;
        self.state = CongestionState::Cwr;
    }

    /// Update flight size
    pub fn update_flight(&mut self, sent: u64, acked: u64, lost: u64) {
        self.flight = self.flight + sent - acked - lost;
    }

    /// Get usable window
    pub fn usable_window(&self) -> u64 {
        min(self.cwind, self.flight)
    }
}

// ============================================================================
// RTT (Round-Trip Time) Measurement
// ============================================================================

/// RTT state
#[derive(Debug)]
pub struct RttState {
    /// Round-trip time estimate (in ms)
    pub srtt: u32,
    /// RTT variance
    pub rttvar: u32,
    /// RTO (Retransmission Timeout)
    pub rto: u64,
    /// Sample count
    pub nsamples: u32,
    /// Minimum RTT observed
    pub min_rtt: u32,
    /// Maximum RTT observed
    pub max_rtt: u32,
}

impl RttState {
    /// Create new RTT state
    pub fn new() -> Self {
        Self {
            srtt: 0,
            rttvar: 0,
            rto: 1000, // 1 second default
            nsamples: 0,
            min_rtt: u32::MAX,
            max_rtt: 0,
        }
    }

    /// Add an RTT sample (in ms)
    pub fn add_sample(&mut self, sample: u32) {
        self.nsamples += 1;
        
        // Update min/max
        self.min_rtt = min(self.min_rtt, sample);
        self.max_rtt = max(self.max_rtt, sample);
        
        if self.nsamples == 1 {
            // First sample
            self.srtt = sample;
            self.rttvar = sample / 2;
        } else {
            // Jacobson's algorithm
            let delta = if sample > self.srtt {
                sample - self.srtt
            } else {
                self.srtt - sample
            };
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + sample) / 8;
        }
        
        // Calculate RTO: srtt + 4 * rttvar
        // With clock granularity adjustment
        self.rto = (self.srtt as u64 + max(100, 4 * self.rttvar as u64))
            .max(200) // Minimum RTO = 200ms
            .min(60000); // Maximum RTO = 60s
    }

    /// Backoff RTO (exponential backoff on timeout)
    pub fn backoff(&mut self) {
        self.rto = min(self.rto * 2, 60000);
    }

    /// Reset RTO after successful ACK
    pub fn reset_rto(&mut self) {
        // RTO is already calculated from smoothed RTT
        // Just ensure it's within bounds
        self.rto = (self.srtt as u64 + max(100, 4 * self.rttvar as u64))
            .max(200)
            .min(60000);
    }
}

impl Default for RttState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TCP Retransmission Queue
// ============================================================================

/// Segment in the retransmission queue
#[derive(Debug)]
pub struct RetransSegment {
    /// Sequence number
    pub seq: u32,
    /// End sequence number
    pub end_seq: u32,
    /// Number of transmissions
    pub ntransmit: u32,
    /// When segment was first sent
    pub first_send: u64,
    /// When segment was last sent
    pub last_send: u64,
}

impl RetransSegment {
    pub fn new(seq: u32, len: u32) -> Self {
        Self {
            seq,
            end_seq: seq.wrapping_add(len),
            ntransmit: 1,
            first_send: 0,
            last_send: 0,
        }
    }
}

/// Retransmission queue
#[derive(Debug)]
pub struct RetransQueue {
    /// Segments waiting for ACK
    segments: Vec<RetransSegment>,
    /// Highest sequence sent
    pub snd_nxt: u32,
    /// Highest sequence acknowledged
    pub snd_una: u32,
}

impl RetransQueue {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            snd_nxt: 0,
            snd_una: 0,
        }
    }

    /// Add a segment to the queue
    pub fn push(&mut self, seg: RetransSegment) {
        self.segments.push(seg);
    }

    /// Check if a segment needs retransmission
    pub fn check_retrans(&self, rto: u64, now: u64) -> Option<usize> {
        for (i, seg) in self.segments.iter().enumerate() {
            let elapsed = now - seg.last_send;
            if elapsed >= rto {
                return Some(i);
            }
        }
        None
    }

    /// Remove acknowledged segments
    pub fn remove_acked(&mut self, ack: u32) {
        self.segments.retain(|seg| seg.end_seq > ack);
        self.snd_una = ack;
    }

    /// Get number of unacknowledged bytes
    pub fn unacked(&self) -> u32 {
        self.segments
            .iter()
            .map(|s| s.end_seq.wrapping_sub(s.seq))
            .sum()
    }

    /// Get first segment
    pub fn first(&self) -> Option<&RetransSegment> {
        self.segments.first()
    }

    /// Get segment by index
    pub fn get(&self, index: usize) -> Option<&RetransSegment> {
        self.segments.get(index).copied()
    }

    /// Increment transmission count
    pub fn inc_transmit(&mut self, index: usize) {
        if let Some(seg) = self.segments.get_mut(index) {
            seg.ntransmit += 1;
        }
    }
}

impl Default for RetransQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TCP Output Queue
// ============================================================================

/// Outgoing TCP segment
#[derive(Debug)]
pub struct TcpOutput {
    /// Sequence number
    pub seq: u32,
    /// End sequence number
    pub end_seq: u32,
    /// Flags
    pub flags: TcpFlags,
    /// Data
    pub data: Vec<u8>,
    /// Whether this is a retransmit
    pub retransmit: bool,
    /// Timestamp option
    pub ts_val: Option<u32>,
    pub ts_ecr: Option<u32>,
}

/// TCP flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_ack(mut self) -> Self {
        self.0 |= Self::ACK;
        self
    }

    pub fn with_fin(mut self) -> Self {
        self.0 |= Self::FIN;
        self
    }

    pub fn with_syn(mut self) -> Self {
        self.0 |= Self::SYN;
        self
    }

    pub fn with_rst(mut self) -> Self {
        self.0 |= Self::RST;
        self
    }

    pub fn with_psh(mut self) -> Self {
        self.0 |= Self::PSH;
        self
    }

    pub fn has_ack(&self) -> bool {
        (self.0 & Self::ACK) != 0
    }

    pub fn has_fin(&self) -> bool {
        (self.0 & Self::FIN) != 0
    }

    pub fn has_syn(&self) -> bool {
        (self.0 & Self::SYN) != 0
    }

    pub fn has_rst(&self) -> bool {
        (self.0 & Self::RST) != 0
    }
}

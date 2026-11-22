use alloc::{vec, vec::Vec};
use core::net::Ipv4Addr;
use smoltcp::{phy::ChecksumCapabilities, time::{Duration, Instant}, wire::{IpProtocol, Ipv4Packet, Ipv4Repr}};

pub const PROTOCOL: IpProtocol = IpProtocol::Unknown(254);
const HEADER: usize = 24;
pub const MAX_PAYLOAD: usize = 1500 - 20 - HEADER;
const RETRY: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: u8 = 10;
const HANGUP: u32 = u32::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Ipv4Addr,
    pub port: u16,
}

pub struct Message<'a> {
    pub source: Endpoint,
    pub destination: Endpoint,
    sequence: u32,
    generation: u32,
    ack: u32,
    ack_generation: u32,
    pub payload: &'a [u8],
}

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let packet = Ipv4Packet::new_checked(bytes).ok()?;
        let payload = packet.payload();
        let header = payload.get(..HEADER)?;
        let length = usize::from(u16::from_be_bytes(header[4..6].try_into().ok()?));
        if length != payload.len() || packet.next_header() != PROTOCOL {
            return None;
        }
        let source = Endpoint { address: packet.src_addr(), port: u16::from_be_bytes(header[0..2].try_into().ok()?) };
        let destination = Endpoint { address: packet.dst_addr(), port: u16::from_be_bytes(header[2..4].try_into().ok()?) };
        if source.port == 0 || destination.port == 0 || source.address.is_unspecified()
            || source.address.is_broadcast() || source.address.is_multicast()
            || (header[6..8] != [0, 0] && packet_checksum(source.address, destination.address, payload) != 0)
        {
            return None;
        }
        let message = Self {
            source, destination,
            sequence: u32::from_be_bytes(header[8..12].try_into().ok()?),
            generation: u32::from_be_bytes(header[12..16].try_into().ok()?),
            ack: u32::from_be_bytes(header[16..20].try_into().ok()?),
            ack_generation: u32::from_be_bytes(header[20..24].try_into().ok()?),
            payload: &payload[HEADER..],
        };
        (message.generation != 0 && (message.sequence != 0 || message.payload.is_empty())).then_some(message)
    }
}

fn packet_checksum(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> u16 {
    let mut header = [0; 12];
    header[..4].copy_from_slice(&source.octets());
    header[4..8].copy_from_slice(&destination.octets());
    header[9] = PROTOCOL.into();
    header[10..12].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    crate::netstack::internet_checksum(&[&header, payload])
}

fn next(sequence: u32) -> u32 {
    sequence.wrapping_add(1).max(1)
}

struct Pending {
    data: Vec<u8>,
    due: Instant,
    attempts: u8,
}

pub struct Flow {
    pub local: Endpoint,
    pub peer: Endpoint,
    pub interface: usize,
    generation: u32,
    sequence: u32,
    received_generation: u32,
    received_sequence: u32,
    pending: Option<Pending>,
    ack_due: bool,
    pub closed: bool,
}

impl Flow {
    pub fn new(local: Endpoint, peer: Endpoint, interface: usize, generation: u32) -> Self {
        Self {
            local, peer, interface, generation, sequence: 0,
            received_generation: 0, received_sequence: 0, pending: None, ack_due: false, closed: false,
        }
    }

    pub fn queue(&mut self, payload: &[u8], now: Instant) -> bool {
        if self.pending.is_some() { return false; }
        self.sequence = next(self.sequence);
        self.pending = Some(Pending { data: payload.to_vec(), due: now, attempts: 0 });
        true
    }

    pub fn receive(&mut self, incoming: &Message<'_>, space: bool) -> bool {
        if incoming.ack != 0 && incoming.ack_generation != self.generation {
            return false;
        }
        if incoming.generation == HANGUP {
            self.closed |= incoming.ack_generation == self.generation;
            return false;
        }
        if incoming.generation != self.received_generation {
            if incoming.sequence > 1 || self.received_generation != 0 { return false; }
            self.received_generation = incoming.generation;
        }
        if incoming.ack != 0 && incoming.ack == self.sequence {
            self.pending = None;
        }
        if incoming.sequence == 0 { return false; }
        if incoming.sequence != next(self.received_sequence) {
            self.ack_due = true;
            return false;
        }
        if !space { return false; }
        self.received_sequence = incoming.sequence;
        self.ack_due = true;
        true
    }

    pub fn poll(&mut self, time: Instant, mut output: impl FnMut(&[u8]) -> bool) {
        if self.closed { return; }
        if let Some(pending) = self.pending.as_ref().filter(|pending| pending.due <= time) {
            if pending.attempts >= MAX_ATTEMPTS {
                self.closed = true;
                return;
            }
            if output(&self.packet(self.sequence, self.generation, &pending.data)) {
                if let Some(pending) = self.pending.as_mut() {
                    pending.due = time + RETRY;
                    pending.attempts += 1;
                }
                self.ack_due = false;
            }
        } else if self.ack_due && output(&self.packet(0, self.generation, &[])) {
            self.ack_due = false;
        }
    }

    pub fn hangup(&self) -> Option<Vec<u8>> {
        (self.received_generation != 0 && !self.closed).then(|| self.packet(0, HANGUP, &[]))
    }

    fn packet(&self, sequence: u32, generation: u32, data: &[u8]) -> Vec<u8> {
        let length = HEADER + data.len();
        let repr = Ipv4Repr { src_addr: self.local.address, dst_addr: self.peer.address, next_header: PROTOCOL, payload_len: length, hop_limit: 64 };
        let mut bytes = vec![0; repr.buffer_len() + length];
        let mut packet = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        repr.emit(&mut packet, &ChecksumCapabilities::default());
        let payload = packet.payload_mut();
        payload[0..2].copy_from_slice(&self.local.port.to_be_bytes());
        payload[2..4].copy_from_slice(&self.peer.port.to_be_bytes());
        payload[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        payload[8..12].copy_from_slice(&sequence.to_be_bytes());
        payload[12..16].copy_from_slice(&generation.to_be_bytes());
        payload[16..20].copy_from_slice(&self.received_sequence.to_be_bytes());
        payload[20..24].copy_from_slice(&self.received_generation.to_be_bytes());
        payload[24..].copy_from_slice(data);
        let checksum = packet_checksum(self.local.address, self.peer.address, payload);
        payload[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
        bytes
    }
}

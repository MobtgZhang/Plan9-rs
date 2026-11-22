use alloc::{boxed::Box, collections::VecDeque, format, string::String, sync::{Arc, Weak}, vec::Vec};
use core::{fmt::Write, net::{IpAddr, Ipv4Addr}};
use smoltcp::{
    phy::{ChecksumCapabilities, Medium},
    wire::{HardwareAddress, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Packet, NdiscNeighborFlags, NdiscRepr},
};

use crate::dev::Error;

pub const MAX_TAPS: usize = 8;
const QUEUE_SIZE: usize = 16;
const ARP_SIZE: usize = 32;
const ARP_AGE: u64 = 120_000;

struct Tap {
    active: Weak<()>,
    kind: Option<i32>,
    promiscuous: bool,
    frames: VecDeque<Arc<[u8]>>,
}

struct Neighbor {
    ip: IpAddr,
    mac: [u8; 6],
    seen: u64,
}

pub struct EtherPort {
    mac: [u8; 6],
    taps: [Option<Tap>; MAX_TAPS],
    neighbors: Vec<Neighbor>,
    fixed: Vec<(Ipv4Addr, [u8; 6])>,
    replies: VecDeque<[u8; 42]>,
    received: u64,
    transmitted: u64,
    input_bytes: u64,
    output_bytes: u64,
    dropped: u64,
}

impl EtherPort {
    pub fn new(mac: [u8; 6]) -> Box<Self> {
        Box::new(Self {
            mac, taps: core::array::from_fn(|_| None), neighbors: Vec::new(),
            fixed: Vec::new(), replies: VecDeque::new(),
            received: 0, transmitted: 0, input_bytes: 0, output_bytes: 0, dropped: 0,
        })
    }

    pub fn reap(&mut self) {
        for tap in &mut self.taps {
            if tap.as_ref().is_some_and(|tap| tap.active.strong_count() == 0) {
                *tap = None;
            }
        }
    }

    pub fn ids(&self) -> impl Iterator<Item = usize> + '_ {
        self.taps.iter().enumerate().filter_map(|(id, tap)| {
            tap.as_ref().is_some_and(|tap| tap.active.strong_count() != 0).then_some(id)
        })
    }

    fn tap(&mut self, id: usize) -> Result<&mut Tap, Error> {
        self.taps.get_mut(id).and_then(Option::as_mut)
            .filter(|tap| tap.active.strong_count() != 0).ok_or(Error::Enoent)
    }

    pub fn clone_tap(&mut self) -> Result<(usize, Arc<()>), Error> {
        self.reap();
        let id = self.taps.iter().position(Option::is_none).ok_or(Error::Enospace)?;
        let active = Arc::new(());
        self.taps[id] = Some(Tap { active: Arc::downgrade(&active), kind: None, promiscuous: false, frames: VecDeque::new() });
        Ok((id, active))
    }

    pub fn reference(&mut self, id: usize) -> Result<Arc<()>, Error> {
        self.tap(id)?.active.upgrade().ok_or(Error::Enoent)
    }

    pub fn kind(&mut self, id: usize) -> Result<i32, Error> {
        Ok(self.tap(id)?.kind.unwrap_or(0))
    }

    pub fn connect(&mut self, id: usize, kind: i32) -> Result<(), Error> {
        if !(-2..=65535).contains(&kind) { return Err(Error::Einval); }
        let tap = self.tap(id)?;
        tap.kind = Some(kind);
        tap.frames.clear();
        Ok(())
    }

    pub fn promiscuous(&mut self, id: usize, enabled: bool) -> Result<(), Error> {
        self.tap(id)?.promiscuous = enabled;
        Ok(())
    }

    pub fn wants_promiscuous(&self) -> bool {
        self.taps.iter().flatten().any(|tap| tap.promiscuous && tap.active.strong_count() != 0)
    }

    pub fn pop(&mut self, id: usize, buffer: &mut [u8]) -> Result<Option<usize>, Error> {
        let Some(frame) = self.tap(id)?.frames.pop_front() else { return Ok(None); };
        let length = buffer.len().min(frame.len());
        buffer[..length].copy_from_slice(&frame[..length]);
        Ok(Some(length))
    }

    pub fn mac(&self) -> [u8; 6] { self.mac }

    pub fn set_neighbor(&mut self, ip: Ipv4Addr, mac: [u8; 6]) -> Result<(), Error> {
        if let Some(entry) = self.fixed.iter_mut().find(|entry| entry.0 == ip) {
            entry.1 = mac;
        } else if self.fixed.len() < ARP_SIZE {
            self.fixed.push((ip, mac));
        } else {
            return Err(Error::Enospace);
        }
        self.neighbors.retain(|entry| entry.ip != IpAddr::V4(ip));
        self.replies.retain(|reply| reply[28..32] != ip.octets());
        Ok(())
    }

    pub fn clear_neighbors(&mut self, ip: Option<Ipv4Addr>) {
        self.fixed.retain(|entry| ip.is_some_and(|ip| entry.0 != ip));
        self.neighbors.retain(|entry| ip.is_some_and(|ip| entry.ip != IpAddr::V4(ip)));
        self.replies.retain(|reply| ip.is_some_and(|ip| reply[28..32] != ip.octets()));
    }

    pub fn answer_arp(&mut self, request: &[u8]) -> bool {
        if request.len() < 42 || request[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 1]
            || request[6..12] != self.mac || request[28..32] == request[38..42]
        {
            return false;
        }
        let Some((_, mac)) = self.fixed.iter().find(|(ip, _)| request[38..42] == ip.octets()) else {
            return false;
        };
        if self.replies.len() < QUEUE_SIZE {
            let mut reply = [0; 42];
            reply[..6].copy_from_slice(&self.mac);
            reply[6..12].copy_from_slice(mac);
            reply[12..21].copy_from_slice(&request[12..21]);
            reply[21] = 2;
            reply[22..28].copy_from_slice(mac);
            reply[28..32].copy_from_slice(&request[38..42]);
            reply[32..42].copy_from_slice(&request[22..32]);
            self.replies.push_back(reply);
        }
        true
    }

    pub fn local_arp_reply(&mut self) -> Option<[u8; 42]> {
        self.replies.pop_front()
    }

    pub fn neighbor(&self, ip: IpAddr) -> Option<[u8; 6]> {
        self.fixed.iter().find(|entry| IpAddr::V4(entry.0) == ip).map(|entry| entry.1).or_else(|| {
            let now = crate::netstack::now();
            self.neighbors.iter().find(|entry| entry.ip == ip && now.saturating_sub(entry.seen) < ARP_AGE)
                .map(|entry| entry.mac)
        })
    }

    pub fn enforce_arp(&self, frame: &mut [u8]) {
        if frame.len() < 42 || frame[12..20] != [8, 6, 0, 1, 8, 0, 6, 4]
            || frame[6..12] != frame[22..28]
        {
            return;
        }
        if let Some((_, mac)) = self.fixed.iter().find(|(ip, _)| frame[28..32] == ip.octets()) {
            frame[6..12].copy_from_slice(mac);
            frame[22..28].copy_from_slice(mac);
        }
    }

    pub fn addr(&self) -> String {
        let mut text = String::new();
        for byte in self.mac { let _ = write!(text, "{byte:02x}"); }
        text
    }

    pub fn stats(&self) -> String {
        format!("in: {}\nout: {}\ninbytes: {}\noutbytes: {}\noverflows: {}\naddr: {}\n",
            self.received, self.transmitted, self.input_bytes, self.output_bytes, self.dropped, self.addr())
    }

    pub fn observe(&mut self, frame: &[u8], incoming: bool) -> bool {
        if frame.len() < 14 { return false; }
        let for_us = !incoming || frame[..6] == self.mac || frame[0] & 1 != 0;
        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        if incoming {
            self.received = self.received.saturating_add(1);
            self.input_bytes = self.input_bytes.saturating_add(frame.len() as u64);
            if for_us && ether_type == 0x0806 { self.observe_arp(frame); }
            if frame[..6] == self.mac && ether_type == 0x86dd { self.observe_neighbor_advert(frame); }
        } else {
            self.transmitted = self.transmitted.saturating_add(1);
            self.output_bytes = self.output_bytes.saturating_add(frame.len() as u64);
        }
        let (mut header, mut full) = (None, None);
        for tap in self.taps.iter_mut().flatten().filter(|tap| tap.active.strong_count() != 0) {
            let target = match tap.kind {
                Some(-2) if for_us || tap.promiscuous => (&mut header, &frame[..frame.len().min(64)]),
                Some(-1) if for_us || tap.promiscuous => (&mut full, frame),
                Some(kind) if for_us && kind == i32::from(ether_type) => (&mut full, frame),
                _ => continue,
            };
            if tap.frames.len() == QUEUE_SIZE {
                self.dropped = self.dropped.saturating_add(1);
            } else {
                tap.frames.push_back(Arc::clone(target.0.get_or_insert_with(|| Arc::from(target.1))));
            }
        }
        for_us
    }

    fn observe_arp(&mut self, frame: &[u8]) {
        if frame.len() < 42 || frame[14..20] != [0, 1, 8, 0, 6, 4] || !matches!(frame[20..22], [0, 1 | 2]) { return; }
        let Ok(mac) = <[u8; 6]>::try_from(&frame[22..28]) else { return; };
        if mac[0] & 1 != 0 || mac == [0; 6] || mac != frame[6..12] { return; }
        let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() { return; }
        if self.fixed.iter().any(|entry| entry.0 == ip) { return; }
        self.learn_neighbor(ip.into(), mac);
    }

    fn observe_neighbor_advert(&mut self, frame: &[u8]) {
        let Ok(packet) = Ipv6Packet::new_checked(&frame[14..]) else { return; };
        if packet.version() != 6 || packet.hop_limit() != 255 || packet.next_header() != IpProtocol::Icmpv6
            || packet.src_addr().is_unspecified() || packet.src_addr().is_multicast()
            || packet.dst_addr().is_multicast()
        {
            return;
        }
        let Ok(message) = Icmpv6Packet::new_checked(packet.payload()) else { return; };
        let Ok(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert { flags, target_addr, lladdr: Some(address) })) =
            Icmpv6Repr::parse(&packet.src_addr(), &packet.dst_addr(), &message, &ChecksumCapabilities::default())
        else { return; };
        let Ok(HardwareAddress::Ethernet(mac)) = address.parse(Medium::Ethernet) else { return; };
        if !flags.contains(NdiscNeighborFlags::SOLICITED) || target_addr.is_multicast()
            || target_addr.is_unspecified() || target_addr.is_loopback()
            || mac.0[0] & 1 != 0 || mac.0 == [0; 6] || mac.0 != frame[6..12]
        {
            return;
        }
        self.learn_neighbor(target_addr.into(), mac.0);
    }

    fn learn_neighbor(&mut self, ip: IpAddr, mac: [u8; 6]) {
        let neighbor = Neighbor { ip, mac, seen: crate::netstack::now() };
        self.neighbors.retain(|entry| entry.ip != ip);
        if self.neighbors.len() == ARP_SIZE { self.neighbors.remove(0); }
        self.neighbors.push(neighbor);
    }

    pub fn arp(&self, output: &mut String) {
        let now = crate::netstack::now();
        for (ip, mac) in &self.fixed {
            let _ = write!(output, "ether OK {ip} ");
            for byte in mac { let _ = write!(output, "{byte:02x}"); }
            output.push('\n');
        }
        for entry in self.neighbors.iter().filter(|entry| now.saturating_sub(entry.seen) < ARP_AGE) {
            let _ = write!(output, "ether OK {} ", entry.ip);
            for byte in entry.mac { let _ = write!(output, "{byte:02x}"); }
            output.push('\n');
        }
    }
}

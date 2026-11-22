//! Shared IPv4/IPv6 interfaces and transport conversations for #I.

use alloc::{
    collections::VecDeque,
    format,
    string::String,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use plan9_common::sync::Spinlock;
use smoltcp::{
    iface::{Config, Interface, PollIngressSingleResult, Route, SocketHandle, SocketSet},
    socket::{dhcpv4, dns, icmp, raw, tcp, udp},
    time::Instant,
    wire::{
        DnsQueryType, EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint,
        IpListenEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Cidr, Ipv6Packet, Ipv6Repr,
    },
};

use crate::{dev::Error, esp, netdrv::Link, netmux::Filter, rudp};

const MAX_CONVERSATIONS: usize = 64;
const TCP_BUFFER: usize = 8192;
const PACKET_BUFFER: usize = 4096;
const PACKET_SLOTS: usize = 8;
const CLOSE_TIMEOUT: u64 = 10_000;
pub const IO_TIMEOUT: u64 = 5_000;
const UDP_HEADER: usize = 52;
const GRE_PROTOCOL: IpProtocol = IpProtocol::Unknown(47);
pub const LOOPBACK: usize = 1;

pub fn nic_interface(nic: usize) -> usize {
    if nic == 0 { 0 } else { nic + 1 }
}

fn nic_index(interface: usize) -> Option<usize> {
    match interface {
        0 => Some(0),
        LOOPBACK => None,
        _ => Some(interface - 1),
    }
}

static NETWORK: Spinlock<Option<Network>> = Spinlock::new(None);

pub fn now() -> u64 {
    plan9_arch::hal::timer::ms_since_boot()
}

fn timestamp() -> Instant {
    Instant::from_millis(now() as i64)
}

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    plan9_arch::hal::timer::init_timer();
    let ethernet = Link::ethernet().into_iter().map(|(mac, link)| {
        let mut medium = Medium::new(HardwareAddress::Ethernet(EthernetAddress(mac)), link);
        medium.dhcp = Some(medium.sockets.add(dhcpv4::Socket::new()));
        medium
    }).collect();
    let mut local = Medium::new(HardwareAddress::Ip, Link::loopback());
    local.iface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(Ipv4Addr::LOCALHOST.into(), 8));
        let _ = addresses.push(IpCidr::new(Ipv6Addr::LOCALHOST.into(), 128));
    });
    *NETWORK.lock() = Some(Network {
        ethernet,
        local,
        conversations: Vec::new(),
        next_id: 0,
        next_port: 49152 + (plan9_arch::hal::timer::counter() % 16384) as u16,
        stats: [Traffic::default(); 8],
        next_spi: 256,
        next_generation: (plan9_arch::hal::timer::counter() as u32).clamp(1, u32::MAX - 1),
        forwarding: false,
        forwarded: 0,
        transit: VecDeque::new(),
        last_forward_error: None,
    });
    poll();
}

pub fn poll() {
    if let Some(mut slot) = NETWORK.try_lock() {
        if let Some(network) = slot.as_mut() {
            network.poll();
        }
    }
}

pub fn with_network<T>(
    operation: impl FnOnce(&mut Network) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut slot = NETWORK.lock();
    let network = slot.as_mut().ok_or(Error::Eio)?;
    network.poll();
    network.reap();
    operation(network)
}

pub fn wait<T>(
    operation: impl FnMut(&mut Network) -> Result<Option<T>, Error>,
) -> Result<T, Error> {
    wait_io(operation, false)
}

pub fn wait_io<T>(
    mut operation: impl FnMut(&mut Network) -> Result<Option<T>, Error>,
    interruptible: bool,
) -> Result<T, Error> {
    let start = now();
    loop {
        if let Some(value) = with_network(&mut operation)? {
            return Ok(value);
        }
        if interruptible && crate::syscall::user_io_interrupted() {
            return Err(Error::Eintr);
        }
        if now().saturating_sub(start) >= IO_TIMEOUT {
            return Err(Error::Eio);
        }
        core::hint::spin_loop();
    }
}

pub fn resolve_dns(name: &str, query_type: DnsQueryType) -> Result<Vec<IpAddress>, Error> {
    let configured = crate::netlookup::name_servers();
    let (interface, socket, query) = with_network(|network| {
        let (interface, servers) = if configured.is_empty() {
            let index = network.ethernet.iter().position(|medium| medium.enabled && medium.dns.iter().any(Option::is_some))
                .ok_or(Error::Enoent)?;
            let servers = network.ethernet[index].dns.iter().flatten().copied().map(IpAddress::from).collect();
            (nic_interface(index), servers)
        } else {
            let mut selected = None;
            let mut servers = Vec::new();
            for address in configured.iter().copied().map(IpAddress::from) {
                if let Some(interface) = network.select_interface(None, Some(address))? {
                    if *selected.get_or_insert(interface) == interface { servers.push(address); }
                }
            }
            (selected.ok_or(Error::Enoent)?, servers)
        };
        let medium = network.medium(interface)?;
        let mut resolver = dns::Socket::new(&servers, vec![None]);
        let query = resolver
            .start_query(medium.iface.context(), name, query_type)
            .map_err(|_| Error::Einval)?;
        Ok((interface, medium.sockets.add(resolver), query))
    })?;
    let result = wait(|network| {
        let medium = network.medium(interface)?;
        match medium.sockets.get_mut::<dns::Socket>(socket).get_query_result(query) {
            Ok(addresses) => Ok(Some(addresses.into_iter().collect())),
            Err(dns::GetQueryResultError::Pending) => Ok(None),
            Err(dns::GetQueryResultError::Failed) => Err(Error::Enoent),
        }
    });
    with_network(|network| {
        network.medium_even_disabled(interface).ok_or(Error::Eio)?.sockets.remove(socket);
        Ok(())
    })?;
    result
}

pub fn trace(destination: IpAddr, ttl: u8) -> Result<Option<(&'static str, IpAddr)>, Error> {
    let remote = IpAddress::from(destination);
    let (protocol, next_header, request) = if destination.is_ipv6() {
        (Protocol::Icmp6, IpProtocol::Icmpv6, 128)
    } else {
        (Protocol::Icmp, IpProtocol::Icmp, 8)
    };
    let (binding, reader, probe, _reference) = with_network(|network| {
        let (id, reference) = network.allocate(protocol)?;
        if !network.start(protocol, id, IpListenEndpoint::default(), Some(IpEndpoint::new(remote, 0)))? {
            return Err(Error::Enoent);
        }
        let binding = network.binding(protocol, id)?;
        let medium = network.medium(binding.interface)?;
        let reader = medium.sockets.add(raw::Socket::new(
            Some(remote.version()), Some(next_header),
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
            raw::PacketBuffer::new([], []),
        ));
        let sequence = (id as u16 ^ (now() as u16)).to_be_bytes();
        let mut probe = [0; 8];
        probe[0] = request;
        probe[4..6].copy_from_slice(&binding.local.port.to_be_bytes());
        probe[6..8].copy_from_slice(&sequence);
        let socket = medium.sockets.get_mut::<icmp::Socket>(binding.handle);
        socket.set_hop_limit(Some(ttl));
        if socket.send_slice(&probe, remote).is_err() {
            medium.sockets.remove(reader);
            return Err(Error::Eio);
        }
        Ok((binding, reader, probe, reference))
    })?;
    let local = binding.local.addr.ok_or(Error::Eio)?;
    let deadline = now().saturating_add(1_000);
    let result = loop {
        let received = with_network(|network| {
            let socket = network.medium(binding.interface)?.sockets.get_mut::<raw::Socket>(reader);
            while let Ok(packet) = socket.recv() {
                if let Some(reply) = crate::nettrace::reply(packet, local.into(), destination, &probe) {
                    return Ok(Some(reply));
                }
            }
            Ok(None)
        });
        match received {
            Ok(None) if now() < deadline => core::hint::spin_loop(),
            _ => break received,
        }
    };
    with_network(|network| {
        network.medium_even_disabled(binding.interface).ok_or(Error::Eio)?.sockets.remove(reader);
        Ok(())
    })?;
    result
}

struct Medium {
    iface: Interface,
    sockets: SocketSet<'static>,
    raw_output: SocketSet<'static>,
    raw_sender: Option<SocketHandle>,
    link: Link,
    dhcp: Option<SocketHandle>,
    lease: Option<IpCidr>,
    dns: [Option<Ipv4Addr>; 3],
    enabled: bool,
    claim: Weak<()>,
}

impl Medium {
    fn new(address: HardwareAddress, mut link: Link) -> Self {
        Self {
            iface: Self::interface(address, &mut link),
            sockets: SocketSet::new(Vec::new()),
            raw_output: SocketSet::new(Vec::new()),
            raw_sender: None,
            link,
            dhcp: None,
            lease: None,
            dns: [None; 3],
            enabled: true,
            claim: Weak::new(),
        }
    }

    fn interface(address: HardwareAddress, link: &mut Link) -> Interface {
        let mut config = Config::new(address);
        config.random_seed = plan9_arch::hal::timer::counter();
        config.slaac = matches!(address, HardwareAddress::Ethernet(_));
        let mut iface = Interface::new(config, link, timestamp());
        if let HardwareAddress::Ethernet(mac) = address {
            let prefix = Ipv6Cidr::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64);
            iface.update_ip_addrs(|addresses| {
                if let Some(link_local) = Ipv6Cidr::from_link_prefix(&prefix, mac.into()) {
                    let _ = addresses.push(IpCidr::Ipv6(link_local));
                }
            });
        }
        iface
    }

    fn poll(&mut self, time: Instant, conversations: &mut [Conversation], mut transit: Option<(&mut Vec<(usize, Vec<u8>)>, usize)>) {
        if !self.enabled {
            self.link.drain_ethernet();
            return;
        }
        self.iface.poll_maintenance(time);
        for _ in 0..16 {
            if !self.link.stage_ingress() {
                break;
            }
            if self.multiplex(conversations) {
                self.link.discard_ingress();
                continue;
            }
            if let Some((packets, index)) = transit.as_mut() {
                if let Some(packet) = self.transit_packet() {
                    packets.push((*index, packet));
                    self.link.discard_ingress();
                    continue;
                }
            }
            if matches!(
                self.iface
                    .poll_ingress_single(time, &mut self.link, &mut self.sockets),
                PollIngressSingleResult::None
            ) {
                break;
            }
        }
        self.iface
            .poll_egress(time, &mut self.link, &mut self.sockets);
        if self.raw_sender.is_some() {
            self.iface.poll_egress(time, &mut self.link, &mut self.raw_output);
        }
        if let Some(handle) = self.dhcp {
            match self.sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
                Some(dhcpv4::Event::Configured(config)) => {
                    let address = IpCidr::Ipv4(config.address);
                    let former = self.lease.replace(address);
                    self.iface.update_ip_addrs(|addresses| {
                        addresses.retain(|entry| Some(*entry) != former);
                        if !addresses.contains(&address) { let _ = addresses.insert(0, address); }
                    });
                    self.iface.routes_mut().remove_default_ipv4_route();
                    if let Some(router) = config.router {
                        let _ = self.iface.routes_mut().add_default_ipv4_route(router);
                    }
                    self.dns.fill(None);
                    for (slot, server) in self.dns.iter_mut().zip(config.dns_servers) {
                        *slot = Some(server);
                    }
                }
                Some(dhcpv4::Event::Deconfigured) => {
                    let former = self.lease.take();
                    self.iface.update_ip_addrs(|addresses| {
                        addresses.retain(|entry| Some(*entry) != former);
                    });
                    self.iface.routes_mut().remove_default_ipv4_route();
                    self.dns.fill(None);
                }
                None => {}
            }
        }
    }

    fn transit_packet(&self) -> Option<Vec<u8>> {
        if !self.link.staged_unicast() { return None; }
        let bytes = self.link.staged_ip()?;
        if IpVersion::of_packet(bytes).ok()? == IpVersion::Ipv6 {
            let packet = Ipv6Packet::new_checked(bytes).ok()?;
            if !forwardable_ipv6(packet.src_addr()) || !forwardable_ipv6(packet.dst_addr())
                || self.iface.has_ip_addr(packet.dst_addr())
            {
                return None;
            }
            return Some(bytes[..40 + usize::from(packet.payload_len())].to_vec());
        }
        let packet = Ipv4Packet::new_checked(bytes).ok()?;
        let destination = packet.dst_addr();
        if packet.version() != 4 || !packet.verify_checksum() || !forwardable(destination)
            || !forwardable(packet.src_addr())
            || self.iface.ip_addrs().iter().any(|cidr| match cidr {
                IpCidr::Ipv4(subnet) => subnet.address() == destination || subnet.broadcast() == Some(destination),
                _ => false,
            })
        {
            return None;
        }
        Some(bytes[..usize::from(packet.total_len())].to_vec())
    }

    fn multiplex(&self, conversations: &mut [Conversation]) -> bool {
        let Some(bytes) = self.link.staged_ip() else { return false; };
        let Ok(packet) = Ipv4Packet::new_checked(bytes) else { return false; };
        if packet.version() != 4 || !packet.verify_checksum() {
            return false;
        }
        let Some(address) = self.iface.ip_addrs().iter().find_map(|entry| match entry {
            IpCidr::Ipv4(address) => Some(address.address()),
            _ => None,
        }) else {
            return false;
        };
        let mut chosen: Option<(usize, &Filter)> = None;
        let header = &bytes[..usize::from(packet.header_len())];
        for (index, conversation) in conversations.iter().enumerate() {
            let Some(filter) = conversation.filter.as_ref() else { continue; };
            if conversation.use_count.strong_count() == 0 { continue; }
            if filter.matches(header, packet.payload(), address.octets())
                && chosen.is_none_or(|(candidate, previous)| {
                    filter.precedes(previous) || (!previous.precedes(filter) && conversation.id < conversations[candidate].id)
                })
            {
                chosen = Some((index, filter));
            }
        }
        let Some((index, _)) = chosen else { return false; };
        let queue = &mut conversations[index].packets;
        if queue.len() < PACKET_SLOTS {
            let mut message = Vec::with_capacity(16 + usize::from(packet.total_len()));
            message.extend_from_slice(&address.to_ipv6_mapped().octets());
            message.extend_from_slice(&bytes[..usize::from(packet.total_len())]);
            queue.push_back(message);
        }
        true
    }

    fn send_raw(&mut self, bytes: &[u8]) -> Result<Option<usize>, Error> {
        let handle = *self.raw_sender.get_or_insert_with(|| {
            self.raw_output.add(raw::Socket::new(
                None,
                None,
                raw::PacketBuffer::new(vec![], vec![]),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
            ))
        });
        let socket = self.raw_output.get_mut::<raw::Socket>(handle);
        if !socket.can_send() { return Ok(None); }
        socket.send_slice(bytes).map_err(|_| Error::Eio)?;
        Ok(Some(bytes.len()))
    }

    fn add_socket(&mut self, protocol: Protocol) -> SocketHandle {
        match protocol {
            Protocol::Tcp => self.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            )),
            Protocol::Udp => self.sockets.add(udp::Socket::new(
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
                    vec![0; PACKET_BUFFER],
                ),
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
                    vec![0; PACKET_BUFFER],
                ),
            )),
            Protocol::Icmp | Protocol::Icmp6 => self.sockets.add(icmp::Socket::new(
                icmp::PacketBuffer::new(
                    vec![icmp::PacketMetadata::EMPTY; PACKET_SLOTS],
                    vec![0; PACKET_BUFFER],
                ),
                icmp::PacketBuffer::new(
                    vec![icmp::PacketMetadata::EMPTY; PACKET_SLOTS],
                    vec![0; PACKET_BUFFER],
                ),
            )),
            Protocol::Gre | Protocol::Rudp => self.sockets.add(raw::Socket::new(
                Some(IpVersion::Ipv4),
                Some(if protocol == Protocol::Gre { GRE_PROTOCOL } else { rudp::PROTOCOL }),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
            )),
            Protocol::Esp => self.sockets.add(raw::Socket::new(
                None,
                Some(esp::PROTOCOL),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; PACKET_SLOTS], vec![0; PACKET_BUFFER]),
            )),
            Protocol::Ipmux => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Gre,
    Ipmux,
    Rudp,
    Esp,
}

#[derive(Clone, Copy)]
struct Binding {
    handle: SocketHandle,
    interface: usize,
    local: IpListenEndpoint,
    remote: Option<IpEndpoint>,
    announced: bool,
    udp_headers: bool,
}

struct Conversation {
    id: u32,
    protocol: Protocol,
    use_count: Weak<()>,
    binding: Option<Binding>,
    listeners: Vec<Binding>,
    closing: Option<u64>,
    error: Option<&'static str>,
    reserved: Option<IpListenEndpoint>,
    udp_parent: Option<Arc<()>>,
    datagrams: VecDeque<Datagram>,
    filter: Option<Filter>,
    packets: VecDeque<Vec<u8>>,
    rudp: Option<rudp::Flow>,
    esp: Option<esp::Association>,
    owner: u32,
}

struct Datagram {
    interface: usize,
    remote: IpEndpoint,
    local: Option<IpAddress>,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct Traffic {
    reads: u64,
    writes: u64,
    read_bytes: u64,
    written_bytes: u64,
    errors: u64,
}

fn header_ip(address: IpAddress) -> [u8; 16] {
    match address {
        IpAddress::Ipv4(address) => address.to_ipv6_mapped().octets(),
        IpAddress::Ipv6(address) => address.octets(),
    }
}

fn read_header_ip(bytes: [u8; 16]) -> IpAddress {
    let address = Ipv6Addr::from(bytes);
    address.to_ipv4_mapped().map_or(IpAddress::Ipv6(address), IpAddress::Ipv4)
}

pub struct Network {
    ethernet: Vec<Medium>,
    local: Medium,
    conversations: Vec<Conversation>,
    next_id: u32,
    next_port: u16,
    stats: [Traffic; 8],
    next_spi: u32,
    next_generation: u32,
    forwarding: bool,
    forwarded: u64,
    transit: VecDeque<Transit>,
    last_forward_error: Option<Instant>,
}

struct Transit {
    interface: usize,
    next_hop: IpAddress,
    source: IpAddress,
    expires: Instant,
    probe: Instant,
    bytes: Vec<u8>,
    kind: TransitKind,
}

const TRANSIT_LIMIT: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransitKind {
    Forwarded,
    ForwardingError,
    RawOutput,
}

impl Network {
    fn poll(&mut self) {
        let time = timestamp();
        let mut packets = Vec::new();
        for (index, ethernet) in self.ethernet.iter_mut().enumerate() {
            ethernet.poll(time, &mut self.conversations, self.forwarding.then_some((&mut packets, index)));
        }
        self.local.poll(time, &mut self.conversations, None);
        for (input, packet) in packets {
            self.route_transit(input, packet, time);
        }
        self.poll_transit(time);
        self.deliver_udp();
        self.poll_rudp(time);
    }

    fn poll_rudp(&mut self, time: Instant) {
        let (ethernet, local, conversations) = (&mut self.ethernet, &mut self.local, &mut self.conversations);
        for conversation in conversations.iter_mut().filter(|conv| conv.protocol == Protocol::Rudp && conv.use_count.strong_count() != 0) {
            let Some(primary) = conversation.binding else { continue; };
            for binding in core::iter::once(primary).chain(conversation.listeners.iter().copied()) {
                let medium = match nic_index(binding.interface) {
                    Some(index) => &mut ethernet[index],
                    None => &mut *local,
                };
                let socket = medium.sockets.get_mut::<raw::Socket>(binding.handle);
                for _ in 0..PACKET_SLOTS {
                    let Ok(bytes) = socket.recv() else { break; };
                    let Some(message) = rudp::Message::parse(bytes) else { continue; };
                    if message.destination.port != binding.local.port
                        || binding.local.addr.is_some_and(|address| address != message.destination.address.into())
                        || !medium.iface.has_ip_addr(message.destination.address)
                    {
                        continue;
                    }
                    if conversation.rudp.is_none() {
                        let generation = take_generation(&mut self.next_generation);
                        let mut flow = rudp::Flow::new(message.destination, message.source, binding.interface, generation);
                        if flow.receive(&message, true) {
                            conversation.rudp = Some(flow);
                            conversation.packets.push_back(message.payload.to_vec());
                        }
                    } else if let Some(flow) = conversation.rudp.as_mut() {
                        if !flow.closed && flow.interface == binding.interface && flow.local == message.destination
                            && flow.peer == message.source && flow.receive(&message, conversation.packets.len() < PACKET_SLOTS)
                        {
                            conversation.packets.push_back(message.payload.to_vec());
                        }
                    }
                }
                if let Some(flow) = conversation.rudp.as_mut().filter(|flow| flow.interface == binding.interface) {
                    flow.poll(time, |packet| socket.can_send() && socket.send_slice(packet).is_ok());
                    if flow.closed { conversation.error = Some("RUDP connection closed or acknowledgement timed out"); }
                }
            }
        }
    }

    pub fn set_forwarding(&mut self, enabled: bool) {
        self.forwarding = enabled;
        if !enabled {
            self.transit.retain(|packet| packet.kind == TransitKind::RawOutput);
        }
    }

    pub fn interface_stats(&self) -> String {
        format!("Forwarding: {}\nDefaultTTL: 64\nForwDatagrams: {}\n", u8::from(self.forwarding), self.forwarded)
    }

    fn transit_route(&mut self, address: IpAddress, time: Instant) -> Option<(usize, IpAddress, IpAddress)> {
        let interface = self.select_interface(None, Some(address)).ok().flatten().and_then(nic_index)?;
        let medium = &mut self.ethernet[interface];
        let direct = medium.iface.ip_addrs().iter().filter(|cidr| cidr.contains_addr(&address))
            .map(IpCidr::prefix_len).max();
        let mut gateway = None;
        medium.iface.routes_mut().update(|routes| {
            gateway = routes.iter().filter(|route| {
                route.via_router.version() == address.version() && route.cidr.contains_addr(&address)
                    && route.expires_at.is_none_or(|expires| expires >= time)
                    && direct.is_none_or(|prefix| route.cidr.prefix_len() > prefix)
            }).max_by_key(|route| route.cidr.prefix_len()).map(|route| route.via_router);
        });
        let next_hop = gateway.unwrap_or(address);
        let source = match next_hop {
            IpAddress::Ipv4(hop) => medium.iface.ip_addrs().iter().find_map(|cidr| match cidr {
                IpCidr::Ipv4(subnet) if subnet.contains_addr(&hop) && subnet.broadcast() != Some(hop) => Some(subnet.address().into()),
                _ => None,
            })?,
            IpAddress::Ipv6(_) => medium.iface.get_source_address(&address)
                .filter(|source| !source.is_unspecified())?,
        };
        Some((interface, next_hop, source))
    }

    fn route_transit(&mut self, input: usize, mut bytes: Vec<u8>, time: Instant) {
        if bytes[0] >> 4 == 6 {
            self.route_transit_ipv6(input, bytes, time);
            return;
        }
        let packet = Ipv4Packet::new_unchecked(bytes.as_slice());
        let destination = packet.dst_addr();
        if self.ethernet.iter().filter(|medium| medium.enabled).any(|medium| {
            medium.iface.ip_addrs().iter().any(|cidr| match cidr {
                IpCidr::Ipv4(subnet) => subnet.address() == destination || subnet.broadcast() == Some(destination),
                _ => false,
            })
        }) {
            return;
        }
        let ttl = packet.hop_limit();
        let route = self.transit_route(destination.into(), time);
        match route {
            Some((output, next_hop, source)) if output != input && ttl > 1 => {
                let mut outgoing = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
                outgoing.set_hop_limit(ttl - 1);
                outgoing.fill_checksum();
                self.queue_transit(output, next_hop, source, bytes, TransitKind::Forwarded, time);
            }
            Some((output, _, _)) if output == input => {}
            _ => self.transit_error(packet, time, ttl <= 1),
        }
    }

    fn transit_error(&mut self, packet: Ipv4Packet<&[u8]>, time: Instant, expired: bool) {
        if packet.frag_offset() != 0 || (packet.next_header() == IpProtocol::Icmp
            && matches!(packet.payload().first(), Some(3 | 4 | 5 | 11 | 12)))
            || self.last_forward_error.is_some_and(|last| time.total_millis() - last.total_millis() < 100)
        {
            return;
        }
        let destination = packet.src_addr();
        let Some((interface, next_hop, IpAddress::Ipv4(source))) = self.transit_route(destination.into(), time) else { return; };
        let quote_len = (usize::from(packet.header_len()) + 8).min(usize::from(packet.total_len()));
        let repr = Ipv4Repr { src_addr: source, dst_addr: destination, next_header: IpProtocol::Icmp, payload_len: 8 + quote_len, hop_limit: 64 };
        let mut bytes = vec![0; repr.buffer_len() + repr.payload_len];
        let mut response = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        repr.emit(&mut response, &smoltcp::phy::ChecksumCapabilities::default());
        let icmp = response.payload_mut();
        icmp[0] = if expired { 11 } else { 3 };
        icmp[8..].copy_from_slice(&packet.into_inner()[..quote_len]);
        let checksum = internet_checksum(&[icmp]);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        self.last_forward_error = Some(time);
        self.queue_transit(interface, next_hop, source.into(), bytes, TransitKind::ForwardingError, time);
    }

    fn route_transit_ipv6(&mut self, input: usize, mut bytes: Vec<u8>, time: Instant) {
        let packet = Ipv6Packet::new_unchecked(bytes.as_slice());
        let destination = packet.dst_addr();
        if self.ethernet.iter().any(|medium| medium.enabled && medium.iface.has_ip_addr(destination)) {
            return;
        }
        let hop_limit = packet.hop_limit();
        if let Some((output, next_hop, source)) = self.transit_route(destination.into(), time) {
            if output == input { return; }
            if hop_limit > 1 {
                Ipv6Packet::new_unchecked(bytes.as_mut_slice()).set_hop_limit(hop_limit - 1);
                self.queue_transit(output, next_hop, source, bytes, TransitKind::Forwarded, time);
                return;
            }
        }
        self.transit_error_ipv6(packet, time, hop_limit <= 1);
    }

    fn transit_error_ipv6(&mut self, packet: Ipv6Packet<&[u8]>, time: Instant, expired: bool) {
        if matches!(packet.next_header(), IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Frag
            | IpProtocol::Ipv6Opts | IpProtocol::IpSecAh)
            || (packet.next_header() == IpProtocol::Icmpv6 && packet.payload().first().is_none_or(|kind| *kind < 128))
            || self.last_forward_error.is_some_and(|last| time.total_millis() - last.total_millis() < 100)
        {
            return;
        }
        let destination = packet.src_addr();
        let Some((interface, next_hop, IpAddress::Ipv6(source))) = self.transit_route(destination.into(), time) else { return; };
        let original = packet.into_inner();
        let quote = &original[..original.len().min(1280 - 40 - 8)];
        let repr = Ipv6Repr {
            src_addr: source, dst_addr: destination, next_header: IpProtocol::Icmpv6,
            payload_len: 8 + quote.len(), hop_limit: 64,
        };
        let mut bytes = vec![0; repr.buffer_len() + repr.payload_len];
        let mut response = Ipv6Packet::new_unchecked(bytes.as_mut_slice());
        repr.emit(&mut response);
        let icmp = response.payload_mut();
        icmp[0] = if expired { 3 } else { 1 };
        icmp[8..].copy_from_slice(quote);
        let checksum = internet_checksum(&[&source.octets(), &destination.octets(),
            &(repr.payload_len as u32).to_be_bytes(), &[0, 0, 0, 58], icmp]);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        self.last_forward_error = Some(time);
        self.queue_transit(interface, next_hop, source.into(), bytes, TransitKind::ForwardingError, time);
    }

    fn queue_transit(&mut self, interface: usize, next_hop: IpAddress, source: IpAddress, bytes: Vec<u8>, kind: TransitKind, time: Instant) {
        if self.transit.len() >= TRANSIT_LIMIT { return; }
        self.transit.push_back(Transit {
            interface, next_hop, source, bytes, kind, probe: time,
            expires: time + smoltcp::time::Duration::from_secs(3),
        });
    }

    fn poll_transit(&mut self, time: Instant) {
        for _ in 0..self.transit.len() {
            let Some(mut packet) = self.transit.pop_front() else { break; };
            let medium = &mut self.ethernet[packet.interface];
            if !medium.enabled || time >= packet.expires { continue; }
            match medium.link.forward_ip(packet.next_hop, &packet.bytes, time) {
                Some(true) => {
                    if packet.kind == TransitKind::Forwarded {
                        self.forwarded = self.forwarded.saturating_add(1);
                    }
                    continue;
                }
                None if time >= packet.probe => {
                    match (packet.source, packet.next_hop) {
                        (IpAddress::Ipv4(source), IpAddress::Ipv4(target)) => medium.link.request_arp(source, target, time),
                        (IpAddress::Ipv6(source), IpAddress::Ipv6(target)) => medium.link.request_ndp(source, target, time),
                        _ => continue,
                    }
                    packet.probe = time + smoltcp::time::Duration::from_secs(1);
                    for queued in &mut self.transit {
                        if queued.interface == packet.interface && queued.next_hop == packet.next_hop {
                            queued.probe = packet.probe;
                        }
                    }
                }
                _ => {}
            }
            self.transit.push_back(packet);
        }
    }

    fn deliver_udp(&mut self) {
        let (ethernet, local, conversations) = (&mut self.ethernet, &mut self.local, &mut self.conversations);
        for index in 0..conversations.len() {
            let listener = &conversations[index];
            let Some(binding) = listener.binding else { continue; };
            if listener.protocol != Protocol::Udp || !binding.announced || binding.udp_headers { continue; }
            let bindings = core::array::from_fn::<_, 5, _>(|slot| {
                if slot == 0 { Some(binding) } else { listener.listeners.get(slot - 1).copied() }
            });
            for binding in bindings.into_iter().flatten() {
                let medium = match nic_index(binding.interface) {
                    Some(nic) => &mut ethernet[nic],
                    None => &mut *local,
                };
                let socket = medium.sockets.get_mut::<udp::Socket>(binding.handle);
                for _ in 0..PACKET_SLOTS {
                    let Ok((packet, metadata)) = socket.recv() else { break; };
                    let destination = metadata.local_address.or(binding.local.addr);
                    let peer = conversations.iter().position(|conv| {
                        conv.udp_parent.is_some() && conv.use_count.strong_count() != 0 && conv.binding.is_some_and(|child| {
                            child.interface == binding.interface && child.handle == binding.handle
                                && child.remote == Some(metadata.endpoint) && child.local.addr == destination
                        })
                    }).unwrap_or(index);
                    let queue = &mut conversations[peer].datagrams;
                    if queue.len() < PACKET_SLOTS {
                        queue.push_back(Datagram { interface: binding.interface, remote: metadata.endpoint, local: destination, data: packet.to_vec() });
                    }
                }
            }
        }
    }

    fn medium(&mut self, interface: usize) -> Result<&mut Medium, Error> {
        self.medium_even_disabled(interface).filter(|medium| medium.enabled).ok_or(Error::Eio)
    }

    fn medium_even_disabled(&mut self, interface: usize) -> Option<&mut Medium> {
        match nic_index(interface) {
            Some(index) => self.ethernet.get_mut(index),
            None => Some(&mut self.local),
        }
    }

    fn select_interface(&mut self, local: Option<IpAddress>, remote: Option<IpAddress>) -> Result<Option<usize>, Error> {
        if local.or(remote).is_some_and(|address| IpAddr::from(address).is_loopback()) {
            return if remote.is_none_or(|address| IpAddr::from(address).is_loopback()) {
                Ok(Some(LOOPBACK))
            } else { Err(Error::Einval) };
        }
        let mut best = None;
        let time = timestamp();
        for (index, medium) in self.ethernet.iter_mut().enumerate().filter(|(_, medium)| medium.enabled) {
            if local.is_some_and(|address| !medium.iface.has_ip_addr(address)) { continue; }
            let mut score = 0;
            if let Some(address) = remote {
                if medium.iface.get_source_address(&address).is_none_or(|source| source.is_unspecified()) { continue; }
                for cidr in medium.iface.ip_addrs() {
                    if cidr.contains_addr(&address) { score = score.max(2 * u16::from(cidr.prefix_len()) + 2); }
                }
                medium.iface.routes_mut().update(|routes| {
                    for route in routes {
                        if route.cidr.contains_addr(&address) && route.expires_at.is_none_or(|until| until >= time) {
                            score = score.max(2 * u16::from(route.cidr.prefix_len()) + 1);
                        }
                    }
                });
                if score == 0 { continue; }
            }
            if best.is_none_or(|(previous, _)| score > previous) { best = Some((score, nic_interface(index))); }
        }
        match best {
            Some((_, interface)) => Ok(Some(interface)),
            None if local.is_some() => Err(Error::Einval),
            None if remote.is_some() => Ok(None),
            None => Ok(Some(LOOPBACK)),
        }
    }

    fn reap(&mut self) {
        let time = now();
        let mut index = 0;
        while index < self.conversations.len() {
            let conversation = &self.conversations[index];
            if conversation.use_count.strong_count() != 0 {
                index += 1;
                continue;
            }
            if conversation.protocol == Protocol::Rudp {
                self.finish_rudp(index);
            }
            let conversation = &self.conversations[index];
            if let Some(binding) = conversation.binding.filter(|_| conversation.udp_parent.is_none()) {
                let closing = conversation.closing;
                let protocol = conversation.protocol;
                if let Some(medium) = self.medium_even_disabled(binding.interface) {
                    if protocol == Protocol::Tcp && !binding.announced {
                        let socket = medium.sockets.get_mut::<tcp::Socket>(binding.handle);
                        if closing.is_none() {
                            socket.close();
                        }
                        if socket.is_open() && closing.is_none_or(|until| time < until) {
                            self.conversations[index]
                                .closing
                                .get_or_insert(time + CLOSE_TIMEOUT);
                            index += 1;
                            continue;
                        }
                    }
                    medium.sockets.remove(binding.handle);
                }
            }
            let removed = self.conversations.swap_remove(index);
            for binding in removed.listeners {
                if let Some(medium) = self.medium_even_disabled(binding.interface) {
                    medium.sockets.remove(binding.handle);
                }
            }
        }
    }

    pub fn allocate(&mut self, protocol: Protocol) -> Result<(u32, Arc<()>), Error> {
        if self.conversations.len() >= MAX_CONVERSATIONS {
            return Err(Error::Enospace);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::Enospace)?;
        let reference = Arc::new(());
        self.conversations.push(Conversation {
            id,
            protocol,
            use_count: Arc::downgrade(&reference),
            binding: None,
            listeners: Vec::new(),
            closing: None,
            error: None,
            reserved: None,
            udp_parent: None,
            datagrams: VecDeque::new(),
            filter: None,
            packets: VecDeque::new(),
            rudp: None,
            esp: None,
            owner: crate::proc::curproc().map_or(0, |process| process.uid),
        });
        Ok((id, reference))
    }

    fn index(&self, protocol: Protocol, id: u32) -> Result<usize, Error> {
        let index = self.conversations
            .iter()
            .position(|conv| {
                conv.id == id && conv.protocol == protocol && conv.use_count.strong_count() != 0
            })
            .ok_or(Error::Enoent)?;
        if crate::proc::curproc().is_some_and(|process| process.uid != 0 && process.uid != self.conversations[index].owner) {
            return Err(Error::Eperm);
        }
        Ok(index)
    }

    pub fn reference(&self, protocol: Protocol, id: u32) -> Result<Arc<()>, Error> {
        self.conversations[self.index(protocol, id)?]
            .use_count
            .upgrade()
            .ok_or(Error::Enoent)
    }

    pub fn ids(&self, protocol: Protocol) -> impl Iterator<Item = u32> + '_ {
        self.conversations.iter().filter_map(move |conv| {
            (conv.protocol == protocol && conv.use_count.strong_count() != 0).then_some(conv.id)
        })
    }

    fn port_used(&self, protocol: Protocol, id: u32, interface: usize, local: IpListenEndpoint) -> bool {
        self.conversations
            .iter()
            .filter(|conv| conv.protocol == protocol && conv.id != id)
            .any(|conv| {
                conv.reserved.is_some_and(|reserved| {
                    reserved.port != 0 && reserved.port == local.port
                        && (reserved.addr.is_none() || local.addr.is_none() || reserved.addr == local.addr)
                })
                    || conv.binding.iter().chain(&conv.listeners).any(|binding| {
                    binding.interface == interface
                        && binding.local.port == local.port
                        && (binding.local.addr.is_none()
                            || local.addr.is_none()
                            || binding.local.addr == local.addr)
                })
            })
    }

    pub fn bind(&mut self, protocol: Protocol, id: u32, local: IpListenEndpoint) -> Result<(), Error> {
        let index = self.index(protocol, id)?;
        if !matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Rudp) {
            return Err(Error::Einval);
        }
        if local.addr.is_some() { self.select_interface(local.addr, None)?; }
        if self.conversations[index].binding.is_some() || self.conversations[index].reserved.is_some()
            || (local.port != 0 && self.interface_ids().any(|interface| self.port_used(protocol, id, interface, local))) {
            return Err(Error::Eexists);
        }
        self.conversations[index].reserved = Some(local);
        Ok(())
    }

    pub fn start(
        &mut self,
        protocol: Protocol,
        id: u32,
        mut local: IpListenEndpoint,
        remote: Option<IpEndpoint>,
    ) -> Result<bool, Error> {
        if matches!(protocol, Protocol::Ipmux | Protocol::Esp) { return Err(Error::Einval); }
        let index = self.index(protocol, id)?;
        if self.conversations[index].binding.is_some() {
            return Err(Error::Eexists);
        }
        if let Some(reserved) = self.conversations[index].reserved {
            if local.port == 0 { local.port = reserved.port; }
            if reserved.port != 0 && reserved.port != local.port { return Err(Error::Einval); }
            if local.addr.is_none() { local.addr = reserved.addr; }
            if reserved.addr.is_some() && reserved.addr != local.addr { return Err(Error::Einval); }
        }
        if let Some(remote) = remote {
            if remote.addr.is_unspecified()
                || (remote.port == 0 && matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Rudp))
            {
                return Err(Error::Einval);
            }
        }
        if protocol == Protocol::Gre && remote.is_none_or(|peer| {
            peer.port == 0 || !matches!(peer.addr, IpAddress::Ipv4(_)) || !peer.addr.is_unicast()
        }) {
            return Err(Error::Einval);
        }
        if protocol == Protocol::Rudp && (local.addr.is_some_and(|address| !matches!(address, IpAddress::Ipv4(_)))
            || remote.is_some_and(|peer| !matches!(peer.addr, IpAddress::Ipv4(_)) || !peer.addr.is_unicast()))
        {
            return Err(Error::Einval);
        }
        let Some(interface) = self.select_interface(local.addr, remote.map(|endpoint| endpoint.addr))? else {
            return Ok(false);
        };
        let medium = self.medium(interface)?;
        if let Some(remote) = remote {
            if local.addr.is_none() {
                local.addr = medium.iface.get_source_address(&remote.addr);
                if local.addr.is_none_or(|address| address.is_unspecified()) {
                    return Ok(false);
                }
            }
            if local
                .addr
                .is_some_and(|source| source.version() != remote.addr.version())
            {
                return Err(Error::Einval);
            }
        }
        if local
            .addr
            .is_some_and(|address| !medium.iface.has_ip_addr(address))
        {
            return Err(Error::Einval);
        }
        if protocol == Protocol::Gre && self.conversations.iter().any(|conversation| {
            conversation.protocol == Protocol::Gre && conversation.binding.is_some_and(|binding| {
                binding.interface == interface && binding.local.addr == local.addr && binding.remote == remote
            })
        }) {
            return Err(Error::Eexists);
        }
        let mut additional = Vec::new();
        if remote.is_none() && local.addr.is_none() && matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Rudp) {
            for candidate in self.interface_ids().collect::<Vec<_>>() {
                if candidate != interface && self.medium(candidate).is_ok() {
                    additional.push(candidate);
                }
            }
        }
        if local.port == 0 {
            for _ in 0..=MAX_CONVERSATIONS {
                local.port = self.next_port;
                self.next_port = if self.next_port == u16::MAX {
                    49152
                } else {
                    self.next_port + 1
                };
                if !core::iter::once(interface).chain(additional.iter().copied())
                    .any(|candidate| self.port_used(protocol, id, candidate, local)) {
                    break;
                }
            }
        }
        if core::iter::once(interface).chain(additional.iter().copied())
            .any(|candidate| self.port_used(protocol, id, candidate, local)) {
            return Err(Error::Eexists);
        }

        let medium = self.medium(interface)?;
        let handle = medium.add_socket(protocol);
        let result = match (protocol, remote) {
            (Protocol::Tcp, Some(remote)) => medium
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(medium.iface.context(), remote, local)
                .map_err(|_| Error::Eio),
            (Protocol::Tcp, None) => medium
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .listen(local)
                .map_err(|_| Error::Einval),
            (Protocol::Udp, _) => medium
                .sockets
                .get_mut::<udp::Socket>(handle)
                .bind(local)
                .map_err(|_| Error::Einval),
            (Protocol::Gre, Some(_)) => Ok(()),
            (Protocol::Rudp, _) => Ok(()),
            (Protocol::Icmp | Protocol::Icmp6, Some(remote))
                if matches!(remote.addr, IpAddress::Ipv6(_)) == (protocol == Protocol::Icmp6) =>
            {
                medium
                    .sockets
                    .get_mut::<icmp::Socket>(handle)
                    .bind(icmp::Endpoint::Ident(local.port))
                    .map_err(|_| Error::Einval)
            }
            _ => Err(Error::Enotsup),
        };
        if result.is_err() {
            medium.sockets.remove(handle);
        }
        result?;
        let binding = Binding {
            handle,
            interface,
            local,
            remote,
            announced: remote.is_none(),
            udp_headers: false,
        };
        let mut listeners: Vec<Binding> = Vec::new();
        for candidate in additional {
            let medium = self.medium(candidate)?;
            let handle = medium.add_socket(protocol);
            let attached = if protocol == Protocol::Tcp {
                medium.sockets.get_mut::<tcp::Socket>(handle).listen(local).is_ok()
            } else if protocol == Protocol::Udp {
                medium.sockets.get_mut::<udp::Socket>(handle).bind(local).is_ok()
            } else {
                true
            };
            if !attached {
                medium.sockets.remove(handle);
                for entry in listeners.into_iter().chain(core::iter::once(binding)) {
                    self.medium(entry.interface)?.sockets.remove(entry.handle);
                }
                return Err(Error::Eio);
            }
            listeners.push(Binding { interface: candidate, handle, ..binding });
        }
        self.conversations[index].binding = Some(binding);
        self.conversations[index].listeners = listeners;
        self.conversations[index].reserved = None;
        if protocol == Protocol::Rudp {
            if let (Some(IpAddress::Ipv4(source)), Some(IpEndpoint { addr: IpAddress::Ipv4(peer), port })) = (local.addr, remote) {
                let local = rudp::Endpoint { address: source, port: local.port };
                let peer = rudp::Endpoint { address: peer, port };
                let generation = take_generation(&mut self.next_generation);
                self.conversations[index].rudp = Some(rudp::Flow::new(local, peer, interface, generation));
            }
        }
        Ok(true)
    }

    pub fn udp_headers(&mut self, id: u32, enabled: bool) -> Result<(), Error> {
        let index = self.index(Protocol::Udp, id)?;
        let binding = self.binding(Protocol::Udp, id)?;
        if !binding.announced {
            return Err(Error::Einval);
        }
        if self.udp_children(index) { return Err(Error::Eexists); }
        self.conversations[index].binding = Some(Binding { udp_headers: enabled, ..binding });
        for listener in &mut self.conversations[index].listeners { listener.udp_headers = enabled; }
        self.conversations[index].datagrams.clear();
        Ok(())
    }

    fn udp_children(&self, index: usize) -> bool {
        let listener = &self.conversations[index];
        self.conversations.iter().any(|conv| conv.udp_parent.is_some() && conv.binding.is_some_and(|child| {
            listener.binding.iter().chain(&listener.listeners).any(|binding| {
                child.interface == binding.interface && child.handle == binding.handle
            })
        }))
    }

    fn accept_udp(&mut self, id: u32) -> Result<Option<(u32, Arc<()>)>, Error> {
        let index = self.index(Protocol::Udp, id)?;
        let binding = self.binding(Protocol::Udp, id)?;
        if !binding.announced || binding.udp_headers { return Err(Error::Einval); }
        let Some(first) = self.conversations[index].datagrams.front() else { return Ok(None); };
        let (interface, remote, local) = (first.interface, first.remote, first.local);
        let binding = self.conversations[index].binding.iter().chain(&self.conversations[index].listeners)
            .find(|binding| binding.interface == interface).copied().ok_or(Error::Eio)?;
        let parent = self.reference(Protocol::Udp, id)?;
        let accepted = self.allocate(Protocol::Udp)?;
        let child = self.index(Protocol::Udp, accepted.0)?;
        let mut matched = VecDeque::new();
        let queue = &mut self.conversations[index].datagrams;
        for _ in 0..queue.len() {
            let packet = queue.pop_front().ok_or(Error::Eio)?;
            if packet.interface == interface && packet.remote == remote && packet.local == local { matched.push_back(packet); }
            else { queue.push_back(packet); }
        }
        self.conversations[child].udp_parent = Some(parent);
        self.conversations[child].datagrams = matched;
        self.conversations[child].binding = Some(Binding {
            remote: Some(remote), local: IpListenEndpoint { addr: local, port: binding.local.port }, announced: false, ..binding
        });
        Ok(Some(accepted))
    }

    pub fn account(&mut self, protocol: Protocol, id: u32, reading: bool, result: &Result<usize, Error>) {
        let stats = &mut self.stats[protocol as usize];
        match result {
            Ok(count) if reading => {
                stats.reads = stats.reads.saturating_add(1);
                stats.read_bytes = stats.read_bytes.saturating_add(*count as u64);
            }
            Ok(count) => {
                stats.writes = stats.writes.saturating_add(1);
                stats.written_bytes = stats.written_bytes.saturating_add(*count as u64);
            }
            Err(error) => {
                stats.errors = stats.errors.saturating_add(1);
                if let Ok(index) = self.index(protocol, id) {
                    self.conversations[index].error = Some(match error {
                        Error::Eio => "I/O error or timeout",
                        Error::Eclosed => "connection closed",
                        Error::Einval => "invalid I/O request",
                        _ => "network operation failed",
                    });
                }
            }
        }
    }

    pub fn protocol_stats(&self, protocol: Protocol) -> String {
        let stats = self.stats[protocol as usize];
        format!("Reads: {}\nWrites: {}\nReadBytes: {}\nWrittenBytes: {}\nErrors: {}\n",
            stats.reads, stats.writes, stats.read_bytes, stats.written_bytes, stats.errors)
    }

    pub fn error(&self, protocol: Protocol, id: u32) -> Result<&'static str, Error> {
        Ok(self.conversations[self.index(protocol, id)?].error.unwrap_or(""))
    }

    fn binding(&self, protocol: Protocol, id: u32) -> Result<Binding, Error> {
        self.conversations[self.index(protocol, id)?]
            .binding
            .ok_or(Error::Eclosed)
    }

    pub fn connected(&mut self, id: u32) -> Result<Option<()>, Error> {
        let binding = self.binding(Protocol::Tcp, id)?;
        match self
            .medium(binding.interface)?
            .sockets
            .get::<tcp::Socket>(binding.handle)
            .state()
        {
            tcp::State::Established | tcp::State::CloseWait => Ok(Some(())),
            tcp::State::SynSent | tcp::State::SynReceived => Ok(None),
            _ => Err(Error::Eclosed),
        }
    }

    pub fn accept(&mut self, protocol: Protocol, id: u32) -> Result<Option<(u32, Arc<()>)>, Error> {
        if protocol == Protocol::Udp { return self.accept_udp(id); }
        let index = self.index(Protocol::Tcp, id)?;
        let binding = self.binding(Protocol::Tcp, id)?;
        if !binding.announced {
            return Err(Error::Einval);
        }
        let listeners = self.conversations[index].listeners.clone();
        let mut connection = None;
        for (slot, listener) in core::iter::once(binding).chain(listeners).enumerate() {
            let medium = self.medium(listener.interface)?;
            let socket = medium.sockets.get_mut::<tcp::Socket>(listener.handle);
            match socket.state() {
                tcp::State::Established | tcp::State::CloseWait => {
                    let local = socket.local_endpoint().ok_or(Error::Eio)?;
                    let remote = socket.remote_endpoint().ok_or(Error::Eio)?;
                    connection = Some((slot, listener, local, remote));
                    break;
                }
                tcp::State::Closed => socket.listen(listener.local).map_err(|_| Error::Eio)?,
                _ => {}
            }
        }
        let Some((slot, binding, local, remote)) = connection else {
            return Ok(None);
        };
        let accepted = self.allocate(Protocol::Tcp)?;
        let medium = self.medium(binding.interface)?;
        let listener = medium.add_socket(Protocol::Tcp);
        if medium
            .sockets
            .get_mut::<tcp::Socket>(listener)
            .listen(binding.local)
            .is_err()
        {
            medium.sockets.remove(listener);
            return Err(Error::Eio);
        }
        let replacement = Binding { handle: listener, ..binding };
        if slot == 0 { self.conversations[index].binding = Some(replacement); }
        else { self.conversations[index].listeners[slot - 1] = replacement; }
        let child = self.index(Protocol::Tcp, accepted.0)?;
        self.conversations[child].binding = Some(Binding {
            remote: Some(remote),
            local: IpListenEndpoint {
                addr: Some(local.addr),
                port: local.port,
            },
            announced: false,
            ..binding
        });
        Ok(Some(accepted))
    }

    pub fn hangup(&mut self, protocol: Protocol, id: u32) -> Result<(), Error> {
        let index = self.index(protocol, id)?;
        self.finish_rudp(index);
        self.conversations[index].filter = None;
        self.conversations[index].esp = None;
        self.conversations[index].packets.clear();
        if let Some(binding) = self.conversations[index].binding {
            if protocol == Protocol::Udp && binding.announced && self.udp_children(index) { return Err(Error::Eexists); }
        }
        let shared = self.conversations[index].udp_parent.take().is_some();
        if let Some(binding) = self.conversations[index].binding.take().filter(|_| !shared) {
            let medium = self.medium_even_disabled(binding.interface).ok_or(Error::Eio)?;
            if protocol == Protocol::Tcp {
                medium
                    .sockets
                    .get_mut::<tcp::Socket>(binding.handle)
                    .abort();
                medium.iface.poll_egress(timestamp(), &mut medium.link, &mut medium.sockets);
            }
            medium.sockets.remove(binding.handle);
        }
        for listener in core::mem::take(&mut self.conversations[index].listeners) {
            self.medium_even_disabled(listener.interface).ok_or(Error::Eio)?.sockets.remove(listener.handle);
        }
        self.conversations[index].datagrams.clear();
        self.conversations[index].reserved = None;
        Ok(())
    }

    fn finish_rudp(&mut self, index: usize) {
        if let Some(flow) = self.conversations[index].rudp.take() {
            if let Some(packet) = flow.hangup() {
                if let Ok(medium) = self.medium(flow.interface) {
                    let _ = medium.send_raw(&packet);
                }
            }
        }
    }

    pub fn read(
        &mut self,
        protocol: Protocol,
        id: u32,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        if protocol == Protocol::Esp {
            return self.read_esp(id, buffer);
        }
        if matches!(protocol, Protocol::Ipmux | Protocol::Rudp) {
            let index = self.index(protocol, id)?;
            let conversation = &mut self.conversations[index];
            if (protocol == Protocol::Ipmux && conversation.filter.is_none())
                || (protocol == Protocol::Rudp && conversation.binding.is_none())
            {
                return Err(Error::Eclosed);
            }
            let Some(packet) = conversation.packets.pop_front() else {
                return if conversation.rudp.as_ref().is_some_and(|flow| flow.closed) { Err(Error::Eclosed) } else { Ok(None) };
            };
            let length = buffer.len().min(packet.len());
            buffer[..length].copy_from_slice(&packet[..length]);
            return Ok(Some(length));
        }
        let mut binding = self.binding(protocol, id)?;
        if protocol == Protocol::Udp {
            let index = self.index(protocol, id)?;
            if self.conversations[index].udp_parent.is_some() {
                let Some(packet) = self.conversations[index].datagrams.pop_front() else { return Ok(None); };
                let length = buffer.len().min(packet.data.len());
                buffer[..length].copy_from_slice(&packet.data[..length]);
                return Ok(Some(length));
            }
            if binding.announced && !binding.udp_headers { return Err(Error::Einval); }
            if binding.udp_headers {
                let listeners = self.conversations[index].listeners.clone();
                let mut ready = None;
                for candidate in core::iter::once(binding).chain(listeners) {
                    if self.medium(candidate.interface)?.sockets.get::<udp::Socket>(candidate.handle).can_recv() {
                        ready = Some(candidate);
                        break;
                    }
                }
                let Some(candidate) = ready else { return Ok(None); };
                binding = candidate;
            }
        }
        let medium = self.medium(binding.interface)?;
        match protocol {
            Protocol::Tcp => {
                if binding.announced {
                    return Err(Error::Einval);
                }
                let socket = medium.sockets.get_mut::<tcp::Socket>(binding.handle);
                if socket.can_recv() {
                    socket.recv_slice(buffer).map(Some).map_err(|_| Error::Eio)
                } else if socket.may_recv() {
                    Ok(None)
                } else {
                    Ok(Some(0))
                }
            }
            Protocol::Udp => {
                if binding.udp_headers && buffer.len() < UDP_HEADER {
                    return Err(Error::Einval);
                }
                let socket = medium.sockets.get_mut::<udp::Socket>(binding.handle);
                while let Ok((packet, metadata)) = socket.recv() {
                    if !binding.announced && binding.remote != Some(metadata.endpoint) {
                        continue;
                    }
                    let offset = if binding.udp_headers {
                        let local = metadata.local_address.ok_or(Error::Eio)?;
                        buffer[..16].copy_from_slice(&header_ip(metadata.endpoint.addr));
                        buffer[16..32].copy_from_slice(&header_ip(local));
                        let interface = medium.iface.get_source_address(&metadata.endpoint.addr)
                            .unwrap_or(local);
                        buffer[32..48].copy_from_slice(&header_ip(interface));
                        buffer[48..50].copy_from_slice(&metadata.endpoint.port.to_be_bytes());
                        buffer[50..52].copy_from_slice(&binding.local.port.to_be_bytes());
                        UDP_HEADER
                    } else {
                        0
                    };
                    let count = (buffer.len() - offset).min(packet.len());
                    buffer[offset..offset + count].copy_from_slice(&packet[..count]);
                    return Ok(Some(count + offset));
                }
                Ok(None)
            }
            Protocol::Icmp | Protocol::Icmp6 => {
                let socket = medium.sockets.get_mut::<icmp::Socket>(binding.handle);
                while let Ok((packet, source)) = socket.recv() {
                    let reply = if protocol == Protocol::Icmp6 { 129 } else { 0 };
                    if binding.remote.is_some_and(|peer| peer.addr == source)
                        && packet.first() == Some(&reply)
                    {
                        let count = buffer.len().min(packet.len());
                        buffer[..count].copy_from_slice(&packet[..count]);
                        return Ok(Some(count));
                    }
                }
                Ok(None)
            }
            Protocol::Gre => {
                let peer = binding.remote.ok_or(Error::Einval)?;
                let local = binding.local.addr.ok_or(Error::Einval)?;
                let socket = medium.sockets.get_mut::<raw::Socket>(binding.handle);
                while let Ok(packet) = socket.recv() {
                    let Ok(packet) = Ipv4Packet::new_checked(packet) else { continue; };
                    let payload = packet.payload();
                    if IpAddress::from(packet.src_addr()) != peer.addr || IpAddress::from(packet.dst_addr()) != local
                        || payload.get(2..4) != Some(&peer.port.to_be_bytes()) || !valid_gre(payload, true) {
                        continue;
                    }
                    let length = buffer.len().min(payload.len());
                    buffer[..length].copy_from_slice(&payload[..length]);
                    return Ok(Some(length));
                }
                Ok(None)
            }
            Protocol::Esp | Protocol::Ipmux | Protocol::Rudp => unreachable!(),
        }
    }

    pub fn write(
        &mut self,
        protocol: Protocol,
        id: u32,
        buffer: &[u8],
    ) -> Result<Option<usize>, Error> {
        if protocol == Protocol::Esp {
            return self.write_esp(id, buffer);
        }
        if protocol == Protocol::Rudp {
            if buffer.len() > rudp::MAX_PAYLOAD { return Err(Error::Einval); }
            let index = self.index(protocol, id)?;
            let Some(flow) = self.conversations[index].rudp.as_mut() else { return Err(Error::Eclosed); };
            if flow.closed { return Err(Error::Eclosed); }
            return Ok(flow.queue(buffer, timestamp()).then_some(buffer.len()));
        }
        if protocol == Protocol::Ipmux {
            self.index(protocol, id)?;
            return self.write_ipmux(buffer);
        }
        let mut binding = self.binding(protocol, id)?;
        if protocol == Protocol::Udp && binding.udp_headers && binding.local.addr.is_none() {
            let header = buffer.get(..UDP_HEADER).ok_or(Error::Einval)?;
            let destination = read_header_ip(header[..16].try_into().map_err(|_| Error::Einval)?);
            let source = read_header_ip(header[16..32].try_into().map_err(|_| Error::Einval)?);
            let local = (!source.is_unspecified()).then_some(source);
            let interface = self.select_interface(local, Some(destination))?.ok_or(Error::Enoent)?;
            let index = self.index(protocol, id)?;
            binding = self.conversations[index].binding.iter().chain(&self.conversations[index].listeners)
                .find(|binding| binding.interface == interface).copied().ok_or(Error::Enoent)?;
        }
        let medium = self.medium(binding.interface)?;
        match protocol {
            Protocol::Tcp => {
                if binding.announced {
                    return Err(Error::Einval);
                }
                let socket = medium.sockets.get_mut::<tcp::Socket>(binding.handle);
                if socket.can_send() {
                    socket.send_slice(buffer).map(Some).map_err(|_| Error::Eio)
                } else if socket.may_send() {
                    Ok(None)
                } else {
                    Err(Error::Eclosed)
                }
            }
            Protocol::Udp => {
                let (metadata, payload) = if binding.udp_headers {
                    let (header, payload) = buffer.split_at_checked(UDP_HEADER).ok_or(Error::Einval)?;
                    let mut address = [0; 16];
                    address.copy_from_slice(&header[..16]);
                    let destination = read_header_ip(address);
                    let port = u16::from_be_bytes([header[48], header[49]]);
                    if port == 0 || destination.is_unspecified() {
                        return Err(Error::Einval);
                    }
                    address.copy_from_slice(&header[16..32]);
                    let source = read_header_ip(address);
                    let mut metadata = udp::UdpMetadata::from(IpEndpoint::new(destination, port));
                    metadata.local_address = binding.local.addr.or_else(|| {
                        (source.version() == destination.version() && medium.iface.has_ip_addr(source))
                            .then_some(source)
                    });
                    if metadata.local_address.is_some_and(|source| source.version() != destination.version()) {
                        return Err(Error::Einval);
                    }
                    (metadata, payload)
                } else {
                    let mut metadata = udp::UdpMetadata::from(binding.remote.ok_or(Error::Einval)?);
                    metadata.local_address = binding.local.addr;
                    (metadata, buffer)
                };
                let limit = if matches!(metadata.endpoint.addr, IpAddress::Ipv4(_)) {
                    1472
                } else {
                    1452
                };
                if payload.len() > limit {
                    return Err(Error::Einval);
                }
                let socket = medium.sockets.get_mut::<udp::Socket>(binding.handle);
                match socket.send_slice(payload, metadata) {
                    Ok(()) => Ok(Some(buffer.len())),
                    Err(udp::SendError::BufferFull) => Ok(None),
                    Err(_) => Err(Error::Eio),
                }
            }
            Protocol::Icmp | Protocol::Icmp6 => {
                let remote = binding.remote.ok_or(Error::Einval)?;
                let (request, limit) = if protocol == Protocol::Icmp6 {
                    (128, 1460)
                } else {
                    (8, 1480)
                };
                if !(8..=limit).contains(&buffer.len()) || buffer[0] != request || buffer[1] != 0 {
                    return Err(Error::Einval);
                }
                let socket = medium.sockets.get_mut::<icmp::Socket>(binding.handle);
                match socket.send(buffer.len(), remote.addr) {
                    Ok(packet) => {
                        packet.copy_from_slice(buffer);
                        packet[4..6].copy_from_slice(&binding.local.port.to_be_bytes());
                        Ok(Some(buffer.len()))
                    }
                    Err(icmp::SendError::BufferFull) => Ok(None),
                    Err(_) => Err(Error::Eio),
                }
            }
            Protocol::Gre => {
                let endpoint = binding.remote.ok_or(Error::Einval)?;
                let IpAddress::Ipv4(dst_addr) = endpoint.addr else { return Err(Error::Einval); };
                let Some(IpAddress::Ipv4(src_addr)) = binding.local.addr else { return Err(Error::Einval); };
                if buffer.len() > 1480 || !valid_gre(buffer, false) {
                    return Err(Error::Einval);
                }
                let header = Ipv4Repr { src_addr, dst_addr, next_header: GRE_PROTOCOL, payload_len: buffer.len(), hop_limit: 64 };
                let socket = medium.sockets.get_mut::<raw::Socket>(binding.handle);
                let Ok(packet) = socket.send(header.buffer_len() + buffer.len()) else { return Ok(None); };
                let mut packet = Ipv4Packet::new_unchecked(packet);
                header.emit(&mut packet, &smoltcp::phy::ChecksumCapabilities::default());
                let payload = packet.payload_mut();
                payload.copy_from_slice(buffer);
                payload[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
                if payload[0] & 0x80 != 0 {
                    payload[4..8].fill(0);
                    let checksum = internet_checksum(&[payload]);
                    payload[4..6].copy_from_slice(&checksum.to_be_bytes());
                }
                Ok(Some(buffer.len()))
            }
            Protocol::Esp | Protocol::Ipmux | Protocol::Rudp => unreachable!(),
        }
    }

    pub fn describe(&mut self, protocol: Protocol, id: u32, file: &str) -> Result<String, Error> {
        let index = self.index(protocol, id)?;
        if let Some(association) = &self.conversations[index].esp {
            return Ok(match file {
                "local" if association.incoming => format!("{}!{}\n", association.local, association.spi),
                "local" => format!("{}\n", association.local),
                "remote" if !association.incoming => format!("{}!{}\n", association.peer, association.spi),
                "remote" => format!("{}\n", association.peer),
                _ if association.ready() => "Open\n".into(),
                _ => "Configuring\n".into(),
            });
        }
        if file == "status" && self.conversations[index].filter.is_some() {
            return Ok("Connected\n".into());
        }
        let Some(binding) = self.conversations[index].binding else {
            let reserved = self.conversations[index].reserved;
            return Ok(match file {
                "status" if reserved.is_some() => "Bound\n".into(),
                "status" => "Closed\n".into(),
                "local" => reserved.map_or_else(|| "0.0.0.0!0\n".into(), |local| format!("*!{}\n", local.port)),
                _ => "0.0.0.0!0\n".into(),
            });
        };
        let mut local = binding.local;
        let mut remote = binding.remote;
        let status = if let Some(flow) = self.conversations[index].rudp.as_ref() {
            local.addr = Some(flow.local.address.into());
            remote = Some(IpEndpoint::new(flow.peer.address.into(), flow.peer.port));
            if flow.closed { "Closed\n".into() } else { "Open\n".into() }
        } else if protocol == Protocol::Tcp {
            let socket = self
                .medium(binding.interface)?
                .sockets
                .get::<tcp::Socket>(binding.handle);
            if let Some(endpoint) = socket.local_endpoint() {
                local = IpListenEndpoint {
                    addr: Some(endpoint.addr),
                    port: endpoint.port,
                };
            }
            remote = socket.remote_endpoint().or(remote);
            format!("{:?}\n", socket.state())
        } else if binding.announced {
            "Announced\n".into()
        } else {
            "Connected\n".into()
        };
        Ok(match file {
            "local" => local.addr.map_or_else(
                || format!("*!{}\n", local.port),
                |addr| format!("{addr}!{}\n", local.port),
            ),
            "remote" => remote.map_or_else(
                || "0.0.0.0!0\n".into(),
                |endpoint| format!("{}!{}\n", endpoint.addr, endpoint.port),
            ),
            _ => status,
        })
    }

    pub fn connect_filter(&mut self, id: u32, expression: &str) -> Result<(), Error> {
        let index = self.index(Protocol::Ipmux, id)?;
        let conversation = &mut self.conversations[index];
        if conversation.filter.is_some() { return Err(Error::Eexists); }
        conversation.filter = Some(Filter::parse(expression)?);
        Ok(())
    }

    pub fn connect_esp(&mut self, id: u32, peer: IpAddress, spi: Option<u32>) -> Result<Option<()>, Error> {
        let index = self.index(Protocol::Esp, id)?;
        if self.conversations[index].binding.is_some() {
            return Err(Error::Eexists);
        }
        if !peer.is_unicast() || spi.is_some_and(|value| value < 256) {
            return Err(Error::Einval);
        }
        let Some(interface) = self.select_interface(None, Some(peer))? else {
            return Ok(None);
        };
        let Some(local) = self.medium(interface)?.iface.get_source_address(&peer) else {
            return Ok(None);
        };
        if local.is_unspecified() || local.version() != peer.version() {
            return Ok(None);
        }
        let incoming = spi.is_none();
        let spi = match spi {
            Some(spi) => {
                if self.conversations.iter().filter_map(|conversation| conversation.esp.as_ref()).any(|association| {
                    !association.incoming && association.local == local && association.peer == peer && association.spi == spi
                }) {
                    return Err(Error::Eexists);
                }
                spi
            }
            None => {
                let spi = self.next_spi;
                self.next_spi = spi.checked_add(1).ok_or(Error::Enospace)?;
                spi
            }
        };
        let handle = self.medium(interface)?.add_socket(Protocol::Esp);
        let conversation = &mut self.conversations[index];
        conversation.binding = Some(Binding {
            handle,
            interface,
            local: IpListenEndpoint { addr: Some(local), port: 0 },
            remote: Some(IpEndpoint::new(peer, 0)),
            announced: false,
            udp_headers: false,
        });
        conversation.esp = Some(esp::Association::new(local, peer, spi, incoming));
        Ok(Some(()))
    }

    pub fn control_esp(&mut self, id: u32, command: &str) -> Result<(), Error> {
        let index = self.index(Protocol::Esp, id)?;
        self.conversations[index].esp.as_mut().ok_or(Error::Eclosed)?.control(command)
    }

    fn read_esp(&mut self, id: u32, buffer: &mut [u8]) -> Result<Option<usize>, Error> {
        let index = self.index(Protocol::Esp, id)?;
        let binding = self.binding(Protocol::Esp, id)?;
        let (ethernet, local, conversations) = (&mut self.ethernet, &mut self.local, &mut self.conversations);
        let association = conversations[index].esp.as_mut().ok_or(Error::Eclosed)?;
        if !association.incoming || !association.ready() {
            return Err(Error::Eperm);
        }
        let medium = match nic_index(binding.interface) {
            Some(index) => ethernet.get_mut(index).ok_or(Error::Eio)?,
            None => local,
        };
        if !medium.enabled {
            return Err(Error::Eclosed);
        }
        let socket = medium.sockets.get_mut::<raw::Socket>(binding.handle);
        while let Ok(bytes) = socket.recv() {
            let payload = match (association.peer, association.local) {
                (IpAddress::Ipv4(peer), IpAddress::Ipv4(local)) => {
                    let Ok(packet) = Ipv4Packet::new_checked(bytes) else { continue; };
                    if packet.version() != 4 || packet.src_addr() != peer || packet.dst_addr() != local {
                        continue;
                    }
                    packet.payload()
                }
                (IpAddress::Ipv6(peer), IpAddress::Ipv6(local)) => {
                    let Ok(packet) = Ipv6Packet::new_checked(bytes) else { continue; };
                    if packet.version() != 6 || packet.src_addr() != peer || packet.dst_addr() != local {
                        continue;
                    }
                    packet.payload()
                }
                _ => return Err(Error::Einval),
            };
            if let Some(length) = association.decode(payload, buffer) {
                return Ok(Some(length));
            }
        }
        Ok(None)
    }

    fn write_esp(&mut self, id: u32, buffer: &[u8]) -> Result<Option<usize>, Error> {
        let index = self.index(Protocol::Esp, id)?;
        let binding = self.binding(Protocol::Esp, id)?;
        let association = self.conversations[index].esp.as_ref().ok_or(Error::Eclosed)?;
        let (source, destination) = (association.local, association.peer);
        let header_len = if destination.version() == IpVersion::Ipv4 { 20 } else { 40 };
        let payload = association.encode(buffer, header_len)?;
        let medium = self.medium(binding.interface)?;
        if !medium.iface.has_ip_addr(source) {
            return Err(Error::Eclosed);
        }
        let socket = medium.sockets.get_mut::<raw::Socket>(binding.handle);
        let Ok(bytes) = socket.send(header_len + payload.len()) else { return Ok(None); };
        match (source, destination) {
            (IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                let header = Ipv4Repr { src_addr, dst_addr, next_header: esp::PROTOCOL, payload_len: payload.len(), hop_limit: 64 };
                let mut packet = Ipv4Packet::new_unchecked(bytes);
                header.emit(&mut packet, &smoltcp::phy::ChecksumCapabilities::default());
                packet.payload_mut().copy_from_slice(&payload);
            }
            (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                let header = Ipv6Repr { src_addr, dst_addr, next_header: esp::PROTOCOL, payload_len: payload.len(), hop_limit: 64 };
                let mut packet = Ipv6Packet::new_unchecked(bytes);
                header.emit(&mut packet);
                packet.payload_mut().copy_from_slice(&payload);
            }
            _ => unreachable!(),
        }
        self.conversations[index].esp.as_mut().ok_or(Error::Eclosed)?.sent();
        Ok(Some(buffer.len()))
    }

    pub fn interface_status(&mut self, interface: usize) -> Result<String, Error> {
        use core::fmt::Write;
        let medium = self.medium_even_disabled(interface).ok_or(Error::Enoent)?;
        let name = nic_index(interface).map_or_else(|| String::from("loopback"), |index| format!("ether{index}"));
        let state = if medium.enabled { "bound" } else { "unbound" };
        let mut text = format!("device {name} mtu 1500 {state}\n");
        for address in medium.iface.ip_addrs() {
            let _ = writeln!(text, "{address}");
        }
        for dns in medium.dns.into_iter().flatten() {
            let _ = writeln!(text, "dns {dns}");
        }
        Ok(text)
    }

    pub fn interface_ids(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.ethernet.len()).map(nic_interface).chain(core::iter::once(LOOPBACK))
    }

    pub fn claim_interface(&mut self) -> Result<(usize, Arc<()>), Error> {
        let (nic, medium) = self.ethernet.iter_mut().enumerate()
            .find(|(_, medium)| !medium.enabled && medium.claim.strong_count() == 0)
            .ok_or(Error::Enospace)?;
        let reference = Arc::new(());
        medium.claim = Arc::downgrade(&reference);
        Ok((nic_interface(nic), reference))
    }

    pub fn nic_count(&self) -> usize {
        self.ethernet.len()
    }

    pub fn ethernet_link(&mut self, nic: usize) -> Result<&mut Link, Error> {
        self.ethernet.get_mut(nic).map(|medium| &mut medium.link).ok_or(Error::Enoent)
    }

    pub fn arp(&mut self) -> String {
        let mut output = String::new();
        for medium in &mut self.ethernet {
            if let Ok(port) = medium.link.port() { port.arp(&mut output); }
        }
        output
    }

    fn write_ipmux(&mut self, buffer: &[u8]) -> Result<Option<usize>, Error> {
        let destination = raw_destination(buffer)?;
        let time = timestamp();
        let address = IpAddr::from(destination);
        if address.is_loopback() || address.is_multicast()
            || address == IpAddr::V4(Ipv4Addr::BROADCAST)
            || self.ethernet.iter().filter(|medium| medium.enabled).any(|medium| {
                medium.iface.has_ip_addr(destination) || medium.iface.ip_addrs().iter().any(|subnet| {
                    matches!((subnet, destination), (IpCidr::Ipv4(subnet), IpAddress::Ipv4(address))
                        if subnet.broadcast() == Some(address))
                })
            })
        {
            let interface = self.select_interface(None, Some(destination))?.ok_or(Error::Enoent)?;
            return self.medium(interface)?.send_raw(buffer);
        }
        let (interface, next_hop, source) = self.transit_route(destination, time).ok_or(Error::Enoent)?;
        if self.transit.len() >= TRANSIT_LIMIT {
            return Ok(None);
        }
        let mut bytes = buffer.to_vec();
        if address.is_ipv4() {
            Ipv4Packet::new_unchecked(bytes.as_mut_slice()).fill_checksum();
        }
        self.queue_transit(interface, next_hop, source, bytes, TransitKind::RawOutput, time);
        Ok(Some(buffer.len()))
    }

    pub fn set_neighbor(&mut self, ip: Ipv4Addr, mac: [u8; 6]) -> Result<(), Error> {
        let medium = self.ethernet.iter_mut().find(|medium| {
            medium.enabled && medium.iface.ip_addrs().iter().any(|cidr| match cidr {
                IpCidr::Ipv4(subnet) => subnet.address() != ip && subnet.contains_addr(&ip),
                _ => false,
            })
        }).ok_or(Error::Enoent)?;
        medium.link.port()?.set_neighbor(ip, mac)?;
        medium.iface.update_ip_addrs(|_| {});
        Ok(())
    }

    pub fn clear_neighbors(&mut self, ip: Option<Ipv4Addr>) {
        for medium in &mut self.ethernet {
            if let Ok(port) = medium.link.port() { port.clear_neighbors(ip); }
            medium.iface.update_ip_addrs(|_| {});
        }
    }

    pub fn set_link(&mut self, interface: usize, nic: Option<usize>, enabled: bool) -> Result<(), Error> {
        if interface == LOOPBACK || nic.is_some_and(|nic| nic_interface(nic) != interface) {
            return Err(Error::Einval);
        }
        if !enabled && self.conversations.iter().any(|conv| conv.binding.iter().chain(&conv.listeners).any(|binding| binding.interface == interface)) {
            return Err(Error::Eexists);
        }
        let medium = self.medium_even_disabled(interface).ok_or(Error::Enoent)?;
        if medium.enabled != enabled {
            let address = medium.iface.hardware_addr();
            medium.iface = Medium::interface(address, &mut medium.link);
            medium.link.port()?.clear_neighbors(None);
            medium.raw_output = SocketSet::new(Vec::new());
            medium.raw_sender = None;
            if let Some(handle) = medium.dhcp.take() { medium.sockets.remove(handle); }
            medium.lease = None;
            medium.dns.fill(None);
            medium.dhcp = enabled.then(|| medium.sockets.add(dhcpv4::Socket::new()));
            medium.enabled = enabled;
        }
        Ok(())
    }

    pub fn routes(&mut self) -> Result<String, Error> {
        use core::fmt::Write;
        let mut text = String::new();
        for (index, ethernet) in self.ethernet.iter_mut().enumerate().filter(|(_, medium)| medium.enabled) {
            for address in ethernet.iface.ip_addrs() {
                let _ = writeln!(text, "{address} ether{index}");
            }
            ethernet.iface.routes_mut().update(|routes| {
                for route in routes {
                    let _ = writeln!(text, "{} {} ether{index}", route.cidr, route.via_router);
                }
            });
        }
        Ok(text)
    }

    pub fn configure_ipv4(&mut self, interface: usize, address: Option<IpCidr>) -> Result<(), Error> {
        if !self
            .conversations
            .iter()
            .all(|conv| conv.binding.iter().chain(&conv.listeners).all(|binding| binding.interface != interface))
        {
            return Err(Error::Eexists);
        }
        let medium = self.medium(interface)?;
        if let Some(handle) = medium.dhcp.take() {
            medium.sockets.remove(handle);
        }
        medium.lease = None;
        medium.iface.routes_mut().remove_default_ipv4_route();
        medium.dns.fill(None);
        medium.iface.update_ip_addrs(|addresses| {
            addresses.retain(|entry| !matches!(entry, IpCidr::Ipv4(_)));
            if let Some(address) = address {
                let _ = addresses.push(address);
            }
        });
        if address.is_none() {
            medium.dhcp = Some(medium.sockets.add(dhcpv4::Socket::new()));
        }
        Ok(())
    }

    pub fn route(&mut self, cidr: IpCidr, gateway: Option<IpAddress>) -> Result<(), Error> {
        if gateway.is_some_and(|via| !via.is_unicast() || via.version() != cidr.address().version()) {
            return Err(Error::Einval);
        }
        if let Some(via_router) = gateway {
            let interface = self.select_interface(None, Some(via_router))?.ok_or(Error::Einval)?;
            let mut result = Ok(());
            self.medium(interface)?.iface.routes_mut().update(|routes| {
                routes.retain(|route| route.cidr != cidr);
                result = routes.push(Route { cidr, via_router, preferred_until: None, expires_at: None })
                    .map_err(|_| Error::Enospace);
            });
            result?;
            for (index, medium) in self.ethernet.iter_mut().enumerate() {
                if nic_interface(index) != interface {
                    medium.iface.routes_mut().update(|routes| routes.retain(|route| route.cidr != cidr));
                }
            }
        } else {
            for medium in &mut self.ethernet {
                medium.iface.routes_mut().update(|routes| routes.retain(|route| route.cidr != cidr));
            }
        }
        Ok(())
    }

    pub fn flush_routes(&mut self) -> Result<(), Error> {
        for medium in &mut self.ethernet {
            medium.iface.routes_mut().update(|routes| routes.clear());
        }
        Ok(())
    }

    pub fn self_addresses(&mut self) -> String {
        use core::fmt::Write;
        let mut text = String::new();
        for medium in self.ethernet.iter().chain(core::iter::once(&self.local)).filter(|medium| medium.enabled) {
            for address in medium.iface.ip_addrs() {
                let _ = writeln!(text, "{} u", address.address());
            }
        }
        text
    }

    pub fn add_address(&mut self, interface: usize, address: IpCidr) -> Result<(), Error> {
        if !address.address().is_unicast() {
            return Err(Error::Einval);
        }
        let medium = self.medium(interface)?;
        let mut result = Ok(());
        medium.iface.update_ip_addrs(|addresses| {
            if !addresses.contains(&address) {
                result = addresses.push(address).map_err(|_| Error::Enospace);
            }
        });
        result
    }

    pub fn remove_address(&mut self, interface: usize, address: IpCidr) -> Result<(), Error> {
        let medium = self.medium(interface)?;
        medium.iface.update_ip_addrs(|addresses| addresses.retain(|entry| *entry != address));
        Ok(())
    }
}

fn raw_destination(bytes: &[u8]) -> Result<IpAddress, Error> {
    if bytes.len() > 1500 { return Err(Error::Einval); }
    match IpVersion::of_packet(bytes).map_err(|_| Error::Einval)? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(bytes).map_err(|_| Error::Einval)?;
            if packet.header_len() != 20 || usize::from(packet.total_len()) != bytes.len()
                || packet.more_frags() || packet.frag_offset() != 0
            {
                return Err(Error::Einval);
            }
            if packet.dst_addr().is_unspecified() { return Err(Error::Einval); }
            Ok(packet.dst_addr().into())
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(bytes).map_err(|_| Error::Einval)?;
            if usize::from(packet.payload_len()) + 40 != bytes.len() {
                return Err(Error::Einval);
            }
            if packet.dst_addr().is_unspecified() { return Err(Error::Einval); }
            Ok(packet.dst_addr().into())
        }
    }
}

fn forwardable(address: Ipv4Addr) -> bool {
    address.octets()[0] != 0 && !address.is_loopback() && !address.is_link_local()
        && !address.is_multicast() && !address.is_broadcast()
}

fn forwardable_ipv6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_loopback() && !address.is_unicast_link_local()
        && !address.is_multicast() && address.to_ipv4_mapped().is_none()
}

fn valid_gre(packet: &[u8], verify_checksum: bool) -> bool {
    let Some(header) = packet.get(..4) else { return false; };
    let flags = u16::from_be_bytes([header[0], header[1]]);
    if flags & !0xb000 != 0 { return false; }
    let length = 4 + 4 * flags.count_ones() as usize;
    if packet.len() < length { return false; }
    !verify_checksum || flags & 0x8000 == 0 || internet_checksum(&[packet]) == 0
}

pub(crate) fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for word in parts.iter().flat_map(|part| part.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]));
    }
    while sum > 0xffff { sum = (sum >> 16) + (sum & 0xffff); }
    !(sum as u16)
}

fn take_generation(next: &mut u32) -> u32 {
    let generation = *next;
    *next = if generation == u32::MAX - 1 { 1 } else { generation + 1 };
    generation
}

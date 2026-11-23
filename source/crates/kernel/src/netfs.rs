//! Plan 9-style network conversations exposed by #I under /net.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use smoltcp::wire::{IpCidr, IpEndpoint, IpListenEndpoint};

use crate::dev::{devtype, qidtype, Chan, Dev, DirEntry, Error, Qid};
use crate::netlookup;
use crate::netstack::{self, Protocol};

const ROOT: u64 = 0;
const ROUTES: u64 = 1;
const IPIFC: u64 = 2;
const DNS: u64 = 8;
const CS: u64 = 9;
const SELF: u64 = 10;
const NDB: u64 = 11;
const ARP: u64 = 12;
const ETHER_ROOT: u64 = 13;
const TRACE: u64 = 14;
const IPIFC_CLONE: u64 = 15;
const IPIFC_STATS: u64 = 16;
const ETHER_BASE: u64 = 128;
const ETHER_STRIDE: u64 = 128;
const IPIFC_BASE: u64 = 32;
const IF_DIR: u64 = 0;
const IF_CTL: u64 = 1;
const IF_STATUS: u64 = 2;

fn interface_qid(id: usize, kind: u64) -> Qid {
    qid(IPIFC_BASE + id as u64 * 4 + kind, kind == IF_DIR)
}

fn interface_path(path: u64) -> Option<(usize, u64)> {
    let relative = path.checked_sub(IPIFC_BASE)?;
    (relative < 20).then_some(((relative / 4) as usize, relative % 4))
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum EtherFile { Dir, Clone, Addr, Stats, Ifstats, TapDir, Ctl, Data, Type }

const ETHER_FILES: [(EtherFile, &str); 8] = [
    (EtherFile::Clone, "clone"), (EtherFile::Addr, "addr"),
    (EtherFile::Stats, "stats"), (EtherFile::Ifstats, "ifstats"),
    (EtherFile::TapDir, ""), (EtherFile::Ctl, "ctl"),
    (EtherFile::Data, "data"), (EtherFile::Type, "type"),
];

fn ether_qid(nic: usize, tap: usize, file: EtherFile) -> Qid {
    qid(ETHER_BASE + nic as u64 * ETHER_STRIDE + tap as u64 * 16 + file as u64,
        matches!(file, EtherFile::Dir | EtherFile::TapDir))
}

fn ether_path(path: u64) -> Option<(usize, usize, EtherFile)> {
    let path = path.checked_sub(ETHER_BASE)?;
    if path >= 4 * ETHER_STRIDE { return None; }
    let file = match path % 16 {
        0 => EtherFile::Dir,
        number => ETHER_FILES.get(number as usize - 1)?.0,
    };
    Some(((path / ETHER_STRIDE) as usize, (path % ETHER_STRIDE / 16) as usize, file))
}

fn require_owner() -> Result<(), Error> {
    if crate::proc::curproc().is_none_or(|process| process.uid == 0) { Ok(()) } else { Err(Error::Eperm) }
}

fn ether_walk(nic: usize, tap: usize, file: EtherFile, name: &str) -> Result<Qid, Error> {
    match file {
        EtherFile::Dir => {
            if let Some((kind, _)) = ETHER_FILES[..4].iter().find(|(_, entry)| *entry == name) {
                return Ok(ether_qid(nic, 0, *kind));
            }
            let tap = name.parse().map_err(|_| Error::Enoent)?;
            netstack::with_network(|network| network.ethernet_link(nic)?.port()?.reference(tap))?;
            Ok(ether_qid(nic, tap, EtherFile::TapDir))
        }
        EtherFile::TapDir => {
            let kind = ETHER_FILES.iter().find(|(kind, entry)| {
                *entry == name && matches!(kind, EtherFile::Ctl | EtherFile::Data | EtherFile::Type | EtherFile::Stats | EtherFile::Ifstats)
            }).ok_or(Error::Enoent)?.0;
            Ok(ether_qid(nic, tap, kind))
        }
        _ => Err(Error::Enotdir),
    }
}
const PROTOCOL_SHIFT: u32 = 40;
const KIND_MASK: u64 = 0xff;
const PROTOCOLS: [(Protocol, &str); 8] = [
    (Protocol::Tcp, "tcp"),
    (Protocol::Udp, "udp"),
    (Protocol::Icmp, "icmp"),
    (Protocol::Icmp6, "icmpv6"),
    (Protocol::Gre, "gre"),
    (Protocol::Ipmux, "ipmux"),
    (Protocol::Rudp, "rudp"),
    (Protocol::Esp, "esp"),
];
const FILES: [(Kind, &str); 8] = [
    (Kind::Ctl, "ctl"),
    (Kind::Data, "data"),
    (Kind::Local, "local"),
    (Kind::Remote, "remote"),
    (Kind::Status, "status"),
    (Kind::Listen, "listen"),
    (Kind::Err, "err"),
    (Kind::Stats, "stats"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Protocol,
    Clone,
    Conversation,
    Ctl,
    Data,
    Local,
    Remote,
    Status,
    Listen,
    Err,
    Stats,
}

fn qid(path: u64, directory: bool) -> Qid {
    Qid::new(path, 0, if directory { qidtype::DIR } else { 0 })
}

fn protocol_qid(protocol: Protocol, id: u32, kind: Kind) -> Qid {
    let tag = 1 + protocol as u64;
    qid(
        (tag << PROTOCOL_SHIFT) | (u64::from(id) << 8) | kind as u64,
        matches!(kind, Kind::Protocol | Kind::Conversation),
    )
}

fn decode(path: u64) -> Option<(Protocol, u32, Kind)> {
    let tag = (path >> PROTOCOL_SHIFT).checked_sub(1)?;
    let protocol = PROTOCOLS.get(tag as usize)?.0;
    let kind = match path & KIND_MASK {
        0 => Kind::Protocol,
        1 => Kind::Clone,
        2 => Kind::Conversation,
        value => FILES.iter().find(|(kind, _)| *kind as u64 == value)?.0,
    };
    Some((protocol, (path >> 8) as u32, kind))
}

pub(crate) fn tcp_data_channel(channel: &Chan) -> Option<u32> {
    if crate::dev::devs().find_by_char('I') != Some(channel.dev) {
        return None;
    }
    match decode(channel.qid.path) {
        Some((Protocol::Tcp, id, Kind::Data)) => Some(id),
        _ => None,
    }
}

fn endpoint(value: &str, protocol: Protocol) -> Option<IpEndpoint> {
    if let Some((address, port)) = value.split_once('!') {
        return Some(IpEndpoint::new(address.parse().ok()?, port.parse().ok()?));
    }
    if matches!(protocol, Protocol::Icmp | Protocol::Icmp6) {
        return Some(IpEndpoint::new(value.parse().ok()?, 0));
    }
    let socket: core::net::SocketAddr = value.parse().ok()?;
    Some(IpEndpoint::new(socket.ip().into(), socket.port()))
}

fn local_endpoint(value: &str) -> Option<IpListenEndpoint> {
    let (address, port) = value.split_once('!').unwrap_or(("*", value));
    let addr = if address == "*" {
        None
    } else {
        Some(address.parse::<IpAddr>().ok()?)
            .filter(|address| !address.is_unspecified())
            .map(Into::into)
    };
    let port = if port == "*" { 0 } else { port.parse().ok()? };
    Some(IpListenEndpoint { addr, port })
}

fn read_text(text: &str, buffer: &mut [u8], offset: u64) -> usize {
    let suffix = text.as_bytes().get(offset as usize..).unwrap_or_default();
    let count = suffix.len().min(buffer.len());
    buffer[..count].copy_from_slice(&suffix[..count]);
    count
}

fn lookup_response(channel: &Chan) -> Result<&spin::Mutex<String>, Error> {
    channel.aux.as_deref()
        .and_then(|state| state.downcast_ref::<spin::Mutex<String>>())
        .ok_or(Error::Ebadfd)
}

fn cidr(address: &str, mask: Option<&str>, canonical: bool) -> Result<IpCidr, Error> {
    let (address, mask) = match (address.split_once('/'), mask) {
        (Some((address, prefix)), None) => (address, prefix),
        (None, Some(mask)) => (address, mask),
        _ => return Err(Error::Einval),
    };
    let address = address.parse::<IpAddr>().map_err(|_| Error::Einval)?;
    let prefix = match address {
        IpAddr::V4(_) => mask.trim_start_matches('/') .parse::<u8>().ok().filter(|bits| *bits <= 32)
            .or_else(|| mask.parse::<Ipv4Addr>().ok().and_then(|mask| {
                let mask = u32::from(mask);
                (mask.leading_ones() + mask.trailing_zeros() == 32).then_some(mask.leading_ones() as u8)
            })),
        IpAddr::V6(_) => mask.trim_start_matches('/') .parse::<u8>().ok().filter(|bits| *bits <= 128)
            .or_else(|| mask.parse::<Ipv6Addr>().ok().and_then(|mask| {
                let mask = u128::from(mask);
                (mask.leading_ones() + mask.trailing_zeros() == 128).then_some(mask.leading_ones() as u8)
            })),
    }.ok_or(Error::Einval)?;
    let address = if canonical {
        match address {
            IpAddr::V4(address) => Ipv4Addr::from(u32::from(address) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)).into(),
            IpAddr::V6(address) => Ipv6Addr::from(u128::from(address) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)).into(),
        }
    } else {
        address
    };
    Ok(IpCidr::new(address.into(), prefix))
}

pub struct NetFs { ethernet: bool }

impl NetFs {
    pub const fn new() -> Self {
        Self { ethernet: false }
    }

    pub const fn ethernet() -> Self { Self { ethernet: true } }

    fn directory(path: u64) -> Result<String, Error> {
        match path {
            ROOT => return netstack::with_network(|network| {
                use core::fmt::Write;
                let mut text = String::new();
                for (_, name) in PROTOCOLS {
                    let _ = writeln!(text, "{name}");
                }
                text.push_str("ipifc\niproute\ndns\ncs\nipselftab\nndb\narp\ntrace\n");
                for nic in 0..network.nic_count() { let _ = writeln!(text, "ether{nic}"); }
                Ok(text)
            }),
            IPIFC => {
                return netstack::with_network(|network| {
                    use core::fmt::Write;
                    let mut text = String::from("clone\nstats\n");
                    for interface in network.interface_ids() { let _ = writeln!(text, "{interface}"); }
                    Ok(text)
                })
            }
            _ if matches!(interface_path(path), Some((_, IF_DIR))) => {
                return Ok(if interface_path(path) == Some((netstack::LOOPBACK, IF_DIR)) {
                    "status\n"
                } else { "ctl\nstatus\n" }.into());
            }
            _ => {}
        }
        if let Some((nic, _, file)) = ether_path(path) {
            return match file {
                EtherFile::Dir => netstack::with_network(|network| {
                    use core::fmt::Write;
                    let mut text = String::from("clone\naddr\nstats\nifstats\n");
                    for tap in network.ethernet_link(nic)?.port()?.ids() { let _ = writeln!(text, "{tap}"); }
                    Ok(text)
                }),
                EtherFile::TapDir => Ok("ctl\ndata\ntype\nstats\nifstats\n".into()),
                _ => Err(Error::Enotdir),
            };
        }
        match decode(path) {
            Some((protocol, _, Kind::Protocol)) => netstack::with_network(|network| {
                use core::fmt::Write;
                let mut text = String::from("clone\nstats\n");
                for id in network.ids(protocol) {
                    let _ = writeln!(text, "{id}");
                }
                Ok(text)
            }),
            Some((protocol, id, Kind::Conversation)) => netstack::with_network(|network| {
                network.reference(protocol, id)?;
                Ok(if matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                    "ctl\ndata\nlocal\nremote\nstatus\nlisten\nerr\n"
                } else {
                    "ctl\ndata\nlocal\nremote\nstatus\nerr\n"
                }
                .into())
            }),
            _ => Err(Error::Enotdir),
        }
    }

    fn control(protocol: Protocol, id: u32, command: &str) -> Result<(), Error> {
        if protocol == Protocol::Esp {
            let mut fields = command.split_whitespace();
            return match (fields.next(), fields.next(), fields.next()) {
                (Some("connect"), Some(endpoint), None) => {
                    let (peer, spi) = endpoint.split_once('!').ok_or(Error::Einval)?;
                    let peer: IpAddr = peer.parse().map_err(|_| Error::Einval)?;
                    let spi = if spi == "*" { None } else { Some(spi.parse().map_err(|_| Error::Einval)?) };
                    netstack::wait(|network| network.connect_esp(id, peer.into(), spi))
                }
                (Some("hangup"), None, None) => netstack::with_network(|network| network.hangup(protocol, id)),
                _ => netstack::with_network(|network| network.control_esp(id, command)),
            };
        }
        if protocol == Protocol::Ipmux {
            let command = command.trim();
            return if command == "hangup" {
                netstack::with_network(|network| network.hangup(protocol, id))
            } else {
                let (verb, expression) = command.split_once(char::is_whitespace).ok_or(Error::Einval)?;
                if verb != "connect" { return Err(Error::Einval); }
                netstack::with_network(|network| network.connect_filter(id, expression.trim()))
            };
        }
        let mut fields = command.split_whitespace();
        match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some("connect"), Some(remote), local, None) => {
                let remote = endpoint(remote, protocol).ok_or(Error::Einval)?;
                let local = local_endpoint(local.unwrap_or("*")).ok_or(Error::Einval)?;
                netstack::wait(|network| {
                    network
                        .start(protocol, id, local, Some(remote))
                        .map(|started| started.then_some(()))
                })?;
                if protocol == Protocol::Tcp {
                    let result = netstack::wait(|network| network.connected(id));
                    if result.is_err() {
                        let _ = netstack::with_network(|network| network.hangup(protocol, id));
                    }
                    result?;
                }
                Ok(())
            }
            (Some("announce"), Some(address), None, None) => {
                let local = local_endpoint(address).ok_or(Error::Einval)?;
                netstack::with_network(|network| {
                    network.start(protocol, id, local, None).map(|_| ())
                })
            }
            (Some("bind"), Some(address), None, None) => {
                let local = local_endpoint(address).ok_or(Error::Einval)?;
                netstack::with_network(|network| network.bind(protocol, id, local))
            }
            (Some("hangup"), None, None, None) => {
                netstack::with_network(|network| network.hangup(protocol, id))
            }
            (Some("headers" | "noheaders"), None, None, None) if protocol == Protocol::Udp => {
                netstack::with_network(|network| network.udp_headers(id, command.trim() == "headers"))
            }
            _ => Err(Error::Einval),
        }
    }

    fn net_control(path: u64, command: &str) -> Result<(), Error> {
        if path == ARP {
            let mut fields = command.split_whitespace();
            return match (fields.next(), fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some("add"), Some("ether"), Some(ip), Some(mac), None) => {
                    let ip = arp_ip(ip)?;
                    let mac = arp_mac(mac)?;
                    netstack::with_network(|network| network.set_neighbor(ip, mac))
                }
                (Some("del"), Some(ip), None, None, None) => {
                    let ip = arp_ip(ip)?;
                    netstack::with_network(|network| { network.clear_neighbors(Some(ip)); Ok(()) })
                }
                (Some("flush"), None, None, None, None) => {
                    netstack::with_network(|network| { network.clear_neighbors(None); Ok(()) })
                }
                _ => Err(Error::Einval),
            };
        }
        let mut fields = command.split_whitespace();
        let interface = interface_path(path).filter(|(id, kind)| *id != netstack::LOOPBACK && *kind == IF_CTL).map(|(id, _)| id);
        match (
            interface,
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) {
            (Some(interface), Some("dhcp"), None, None, None, None) => {
                netstack::with_network(|network| network.configure_ipv4(interface, None))
            }
            (Some(interface), Some("static"), Some(address), None, None, None) => {
                let address = cidr(address, None, false)?;
                let IpAddr::V4(ip) = IpAddr::from(address.address()) else { return Err(Error::Einval); };
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() { return Err(Error::Einval); }
                netstack::with_network(|network| {
                    network.configure_ipv4(interface, Some(address))
                })
            }
            (Some(interface), Some("add"), Some(address), mask, None, None) => {
                let address = cidr(address, mask, false)?;
                netstack::with_network(|network| network.add_address(interface, address))
            }
            (Some(interface), Some("remove"), Some(address), mask, None, None) => {
                let address = cidr(address, mask, false)?;
                netstack::with_network(|network| network.remove_address(interface, address))
            }
            (Some(interface), Some("bind"), Some("ether"), Some(device), None, None) => {
                let nic = device.strip_prefix("/net/").unwrap_or(device).strip_prefix("ether")
                    .and_then(|index| index.parse::<usize>().ok()).filter(|index| *index < 4).ok_or(Error::Einval)?;
                netstack::with_network(|network| network.set_link(interface, Some(nic), true))
            }
            (Some(interface), Some("unbind"), None, None, None, None) => {
                netstack::with_network(|network| network.set_link(interface, None, false))
            }
            (Some(_), Some("iprouting"), enabled, None, None, None) => {
                let enabled = enabled.map_or(Ok(true), |value| {
                    value.parse::<i32>().map(|value| value != 0).map_err(|_| Error::Einval)
                })?;
                netstack::with_network(|network| { network.set_forwarding(enabled); Ok(()) })
            }
            (None, Some("add"), Some(address), Some(mask_or_gateway), gateway, None) if path == ROUTES => {
                let (mask, gateway) = gateway.map_or((None, mask_or_gateway), |gateway| (Some(mask_or_gateway), gateway));
                let route = cidr(address, mask, true)?;
                let gateway = gateway.parse::<IpAddr>().map_err(|_| Error::Einval)?;
                if gateway.is_loopback() || gateway == IpAddr::V4(Ipv4Addr::BROADCAST) {
                    return Err(Error::Einval);
                }
                netstack::with_network(|network| network.route(route, Some(gateway.into())))
            }
            (None, Some("remove"), Some(address), mask, None, None) if path == ROUTES => {
                let route = cidr(address, mask, true)?;
                netstack::with_network(|network| network.route(route, None))
            }
            (None, Some("flush"), None, None, None, None) if path == ROUTES => netstack::with_network(|network| network.flush_routes()),
            _ => Err(Error::Einval),
        }
    }
}

impl Dev for NetFs {
    fn attach(&mut self, spec: Option<&str>) -> Result<Chan, Error> {
        if self.ethernet {
            let nic = match spec.unwrap_or("") {
                "" => 0,
                value => value.parse().map_err(|_| Error::Enoent)?,
            };
            netstack::with_network(|network| network.ethernet_link(nic).map(|_| ()))?;
            return Ok(Chan::new(devtype::ETHER, qid(ETHER_ROOT + ((nic as u64) << 32), true), 0));
        }
        if !matches!(spec, None | Some("" | "0")) {
            return Err(Error::Enoent);
        }
        Ok(Chan::new(devtype::IP, qid(ROOT, true), 0))
    }

    fn walk(&mut self, channel: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        if channel.qid.type_ & qidtype::DIR == 0 {
            return Err(Error::Enotdir);
        }
        let path = channel.qid.path;
        let ether_root = self.ethernet.then_some(path).filter(|path| *path as u32 == ETHER_ROOT as u32);
        let child = if name == "." {
            channel.qid
        } else if let Some(root) = ether_root {
            let nic = (root >> 32) as usize;
            if name == ".." { channel.qid } else if name.strip_prefix("ether").and_then(|index| index.parse::<usize>().ok()) == Some(nic) {
                ether_qid(nic, 0, EtherFile::Dir)
            } else { return Err(Error::Enoent); }
        } else if let Some((nic, tap, file)) = ether_path(path) {
            if name == ".." {
                match file {
                    EtherFile::Dir if self.ethernet => qid(ETHER_ROOT + ((nic as u64) << 32), true),
                    EtherFile::Dir => qid(ROOT, true),
                    _ => ether_qid(nic, 0, EtherFile::Dir),
                }
            } else { ether_walk(nic, tap, file, name)? }
        } else if name == ".." {
            match decode(path) {
                Some((protocol, _, Kind::Conversation)) => {
                    protocol_qid(protocol, 0, Kind::Protocol)
                }
                _ => qid(
                    if interface_path(path).is_some() {
                        IPIFC
                    } else {
                        ROOT
                    },
                    true,
                ),
            }
        } else if path == ROOT {
            match name {
                "ipifc" => qid(IPIFC, true),
                "iproute" => qid(ROUTES, false),
                "dns" => qid(DNS, false),
                "cs" => qid(CS, false),
                "ipselftab" => qid(SELF, false),
                "ndb" => qid(NDB, false),
                "trace" => qid(TRACE, false),
                "arp" => qid(ARP, false),
                _ if name.starts_with("ether") => {
                    let nic = name[5..].parse().map_err(|_| Error::Enoent)?;
                    netstack::with_network(|network| network.ethernet_link(nic).map(|_| ()))?;
                    ether_qid(nic, 0, EtherFile::Dir)
                }
                _ => {
                    let (protocol, _) = PROTOCOLS
                        .iter()
                        .find(|(_, entry)| *entry == name)
                        .ok_or(Error::Enoent)?;
                    protocol_qid(*protocol, 0, Kind::Protocol)
                }
            }
        } else if path == IPIFC {
            if name == "clone" {
                channel.qid = qid(IPIFC_CLONE, false);
                return Ok(Some(channel.qid));
            }
            if name == "stats" {
                channel.qid = qid(IPIFC_STATS, false);
                return Ok(Some(channel.qid));
            }
            let id = name.parse().map_err(|_| Error::Enoent)?;
            if !netstack::with_network(|network| Ok(network.interface_ids().any(|interface| interface == id)))? { return Err(Error::Enoent); }
            interface_qid(id, IF_DIR)
        } else if let Some((id, IF_DIR)) = interface_path(path) {
            match name {
                "ctl" if id != netstack::LOOPBACK => interface_qid(id, IF_CTL),
                "status" => interface_qid(id, IF_STATUS),
                _ => return Err(Error::Enoent),
            }
        } else {
            match decode(path) {
                Some((protocol, _, Kind::Protocol)) if name == "clone" => {
                    protocol_qid(protocol, 0, Kind::Clone)
                }
                Some((protocol, _, Kind::Protocol)) if name == "stats" => protocol_qid(protocol, 0, Kind::Stats),
                Some((protocol, _, Kind::Protocol)) => {
                    let id = name.parse().map_err(|_| Error::Enoent)?;
                    netstack::with_network(|network| network.reference(protocol, id))?;
                    protocol_qid(protocol, id, Kind::Conversation)
                }
                Some((protocol, id, Kind::Conversation)) => {
                    netstack::with_network(|network| network.reference(protocol, id))?;
                    let (kind, _) = FILES
                        .iter()
                        .find(|(kind, entry)| {
                            *entry == name && *kind != Kind::Stats
                                && (*kind != Kind::Listen || matches!(protocol, Protocol::Tcp | Protocol::Udp))
                        })
                        .ok_or(Error::Enoent)?;
                    protocol_qid(protocol, id, *kind)
                }
                _ => return Err(Error::Enoent),
            }
        };
        channel.qid = child;
        Ok(Some(child))
    }

    fn open(&mut self, channel: &mut Chan, mode: u8) -> Result<(), Error> {
        let path = channel.qid.path;
        let kind = decode(path);
        let writing = mode & 3 != 0;
        if path == IPIFC_CLONE {
            require_owner()?;
            let (interface, claim) = netstack::with_network(|network| network.claim_interface())?;
            channel.qid = interface_qid(interface, IF_CTL);
            channel.aux = Some(claim);
            channel.mode = mode;
            return Ok(());
        }
        if let Some((nic, tap, file)) = ether_path(path) {
            match file {
                EtherFile::Clone => {
                    require_owner()?;
                    let (tap, reference) = netstack::with_network(|network| network.ethernet_link(nic)?.port()?.clone_tap())?;
                    channel.qid = ether_qid(nic, tap, EtherFile::Ctl);
                    channel.aux = Some(reference);
                }
                EtherFile::Ctl | EtherFile::Data => {
                    require_owner()?;
                    channel.aux = Some(netstack::with_network(|network| network.ethernet_link(nic)?.port()?.reference(tap))?);
                }
                _ if writing => return Err(Error::Eperm),
                _ => {}
            }
            channel.mode = mode;
            return Ok(());
        }
        if writing && (matches!(path, ROUTES | NDB | ARP) || matches!(interface_path(path), Some((_, IF_CTL)))) { require_owner()?; }
        if writing
            && !matches!(path, ROUTES | DNS | CS | NDB | TRACE | ARP)
            && !matches!(interface_path(path), Some((_, IF_CTL)))
            && !matches!(kind, Some((_, _, Kind::Clone | Kind::Ctl | Kind::Data)))
        {
            return Err(Error::Eperm);
        }
        if let Some((protocol, id, kind)) = kind {
            if protocol == Protocol::Ipmux && matches!(kind, Kind::Clone | Kind::Ctl | Kind::Data) {
                require_owner()?;
            }
            match kind {
                Kind::Clone => {
                    let (id, reference) =
                        netstack::with_network(|network| network.allocate(protocol))?;
                    channel.qid = protocol_qid(protocol, id, Kind::Ctl);
                    channel.aux = Some(reference);
                }
                Kind::Listen => {
                    let (id, reference) = netstack::wait(|network| network.accept(protocol, id))?;
                    channel.qid = protocol_qid(protocol, id, Kind::Ctl);
                    channel.aux = Some(reference);
                }
                Kind::Protocol | Kind::Stats => {}
                _ => channel.aux = Some(netstack::with_network(|network| {
                    network.reference(protocol, id)
                })?),
            }
        } else if matches!(path, DNS | CS | TRACE) {
            channel.aux = Some(Arc::new(spin::Mutex::new(String::new())));
        }
        channel.mode = mode;
        Ok(())
    }

    fn close(&mut self, channel: &mut Chan) {
        if channel.aux.take().is_some() {
            let _ = netstack::with_network(|_| Ok(()));
            netstack::poll();
        }
    }

    fn read(&mut self, channel: &mut Chan, buffer: &mut [u8], offset: u64) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let path = channel.qid.path;
        if self.ethernet && path as u32 == ETHER_ROOT as u32 {
            return Ok(read_text(&format!("ether{}\n", path >> 32), buffer, offset));
        }
        if let Some((nic, tap, file)) = ether_path(path) {
            if file == EtherFile::Data {
                require_owner()?;
                return netstack::wait(|network| network.ethernet_link(nic)?.port()?.pop(tap, buffer));
            }
            let text = match file {
                EtherFile::Dir | EtherFile::TapDir => Self::directory(path)?,
                EtherFile::Ctl => tap.to_string(),
                EtherFile::Type => netstack::with_network(|network| Ok(network.ethernet_link(nic)?.port()?.kind(tap)?.to_string()))?,
                EtherFile::Addr => netstack::with_network(|network| Ok(network.ethernet_link(nic)?.port()?.addr()))?,
                EtherFile::Stats => netstack::with_network(|network| Ok(network.ethernet_link(nic)?.port()?.stats()))?,
                EtherFile::Ifstats => netstack::with_network(|network| network.ethernet_link(nic)?.driver_stats())?,
                _ => return Err(Error::Eperm),
            };
            return Ok(read_text(&text, buffer, offset));
        }
        if matches!(path, DNS | CS | TRACE) {
            let response = lookup_response(channel)?.lock();
            let offset = usize::try_from(offset).map_err(|_| Error::Einval)?;
            let rest = response.as_bytes().get(offset..).unwrap_or_default();
            let length = rest.iter().position(|byte| *byte == b'\n')
                .map_or(rest.len(), |index| index + 1);
            let count = length.min(buffer.len());
            buffer[..count].copy_from_slice(&rest[..count]);
            return Ok(count);
        }
        let text = if channel.qid.type_ & qidtype::DIR != 0 {
            Self::directory(path)?
        } else {
            match decode(path) {
                Some((protocol, id, Kind::Data)) => {
                    let result = netstack::wait(|network| network.read(protocol, id, buffer));
                    let _ = netstack::with_network(|network| {
                        network.account(protocol, id, true, &result);
                        Ok(())
                    });
                    return result;
                }
                Some((protocol, id, Kind::Err)) => netstack::with_network(|network| network.error(protocol, id))?.into(),
                Some((protocol, _, Kind::Stats)) => netstack::with_network(|network| Ok(network.protocol_stats(protocol)))?,
                Some((_, id, Kind::Ctl)) => id.to_string(),
                Some((protocol, id, Kind::Local)) => {
                    netstack::with_network(|network| network.describe(protocol, id, "local"))?
                }
                Some((protocol, id, Kind::Remote)) => {
                    netstack::with_network(|network| network.describe(protocol, id, "remote"))?
                }
                Some((protocol, id, Kind::Status)) => {
                    netstack::with_network(|network| network.describe(protocol, id, "status"))?
                }
                _ if matches!(interface_path(path), Some((_, IF_STATUS))) => {
                    let (interface, _) = interface_path(path).ok_or(Error::Enoent)?;
                    netstack::with_network(|network| network.interface_status(interface))?
                }
                _ if matches!(interface_path(path), Some((_, IF_CTL))) => {
                    interface_path(path).ok_or(Error::Enoent)?.0.to_string()
                }
                _ if path == ROUTES => netstack::with_network(|network| network.routes())?,
                _ if path == SELF => netstack::with_network(|network| Ok(network.self_addresses()))?,
                _ if path == ARP => netstack::with_network(|network| Ok(network.arp()))?,
                _ if path == IPIFC_STATS => netstack::with_network(|network| Ok(network.interface_stats()))?,
                _ if path == NDB => return Ok(read_text(&netlookup::DATABASE.lock(), buffer, offset)),
                _ => return Err(Error::Eperm),
            }
        };
        Ok(read_text(&text, buffer, offset))
    }

    fn read_interruptible(&mut self, channel: &mut Chan, buffer: &mut [u8], offset: u64) -> Result<usize, Error> {
        if let Some((protocol, id, Kind::Data)) = decode(channel.qid.path) {
            let result = netstack::wait_io(|network| network.read(protocol, id, buffer), true);
            if !matches!(result, Err(Error::Eintr)) {
                let _ = netstack::with_network(|network| {
                    network.account(protocol, id, true, &result);
                    Ok(())
                });
            }
            return result;
        }
        self.read(channel, buffer, offset)
    }

    fn write(&mut self, channel: &mut Chan, buffer: &[u8], _offset: u64) -> Result<usize, Error> {
        let path = channel.qid.path;
        if let Some((nic, tap, file)) = ether_path(path) {
            require_owner()?;
            if file == EtherFile::Data {
                return netstack::wait(|network| network.ethernet_link(nic)?.raw_write(tap, buffer, smoltcp::time::Instant::from_millis(netstack::now() as i64)));
            }
            if file != EtherFile::Ctl { return Err(Error::Eperm); }
            let command = core::str::from_utf8(buffer).map_err(|_| Error::Einval)?;
            let mut fields = command.split_whitespace();
            netstack::with_network(|network| {
                let link = network.ethernet_link(nic)?;
                match (fields.next(), fields.next(), fields.next()) {
                    (Some("connect"), Some(kind), None) => link.port()?.connect(tap, kind.parse().map_err(|_| Error::Einval)?),
                    (Some("promiscuous"), None | Some("1"), None) => link.raw_promiscuous(tap, true),
                    (Some("promiscuous"), Some("0"), None) => link.raw_promiscuous(tap, false),
                    _ => Err(Error::Einval),
                }
            })?;
            return Ok(buffer.len());
        }
        if matches!(path, ROUTES | NDB | ARP) || matches!(interface_path(path), Some((_, IF_CTL))) { require_owner()?; }
        if let Some((protocol, id, Kind::Data)) = decode(path) {
            let result = netstack::wait(|network| network.write(protocol, id, buffer));
            let _ = netstack::with_network(|network| {
                network.account(protocol, id, false, &result);
                Ok(())
            });
            return result;
        }
        let command = core::str::from_utf8(buffer).map_err(|_| Error::Einval)?;
        if path == NDB {
            if buffer.len() > 4096 {
                return Err(Error::Enospace);
            }
            let mut database = netlookup::DATABASE.lock();
            if _offset == 0 {
                database.clear();
            } else if _offset != database.len() as u64 {
                return Err(Error::Einval);
            }
            if database.len() + command.len() > 4096 {
                return Err(Error::Enospace);
            }
            database.push_str(command);
        } else if matches!(path, DNS | CS | TRACE) {
            let response = lookup_response(channel)?;
            response.lock().clear();
            if command.len() > 320 {
                return Err(Error::Einval);
            }
            let result = match path {
                DNS => netlookup::dns(command),
                CS => netlookup::cs(command),
                _ => crate::nettrace::query(command),
            }?;
            *response.lock() = result;
        } else if let Some((protocol, id, Kind::Ctl)) = decode(path) {
            Self::control(protocol, id, command)?;
        } else {
            Self::net_control(path, command)?;
        }
        Ok(buffer.len())
    }

    fn stat(&mut self, channel: &mut Chan) -> Result<DirEntry, Error> {
        let path = channel.qid.path;
        let (name, mode) = if let Some((nic, tap, file)) = ether_path(path) {
            match file {
                EtherFile::Dir => (format!("ether{nic}"), 0o555),
                EtherFile::TapDir => (tap.to_string(), 0o555),
                _ => (ETHER_FILES[file as usize - 1].1.into(), if matches!(file, EtherFile::Clone | EtherFile::Ctl | EtherFile::Data) { 0o600 } else { 0o444 }),
            }
        } else if self.ethernet && path as u32 == ETHER_ROOT as u32 {
            ("ether".into(), 0o555)
        } else { match decode(path) {
            Some((protocol, _, Kind::Protocol)) => (PROTOCOLS[protocol as usize].1.into(), 0o555),
            Some((_, _, Kind::Clone)) => ("clone".into(), 0o666),
            Some((_, id, Kind::Conversation)) => (id.to_string(), 0o555),
            Some((_, _, kind)) => {
                let (_, name) = FILES
                    .iter()
                    .find(|(entry, _)| *entry == kind)
                    .ok_or(Error::Enoent)?;
                (
                    (*name).into(),
                    if matches!(kind, Kind::Ctl | Kind::Data) {
                        0o666
                    } else {
                        0o444
                    },
                )
            }
            None => match path {
                ROOT => ("net".into(), 0o555),
                ROUTES => ("iproute".into(), 0o644),
                IPIFC => ("ipifc".into(), 0o555),
                IPIFC_CLONE => ("clone".into(), 0o600),
                DNS => ("dns".into(), 0o666),
                CS => ("cs".into(), 0o666),
                TRACE => ("trace".into(), 0o666),
                SELF => ("ipselftab".into(), 0o444),
                NDB => ("ndb".into(), 0o644),
                ARP => ("arp".into(), 0o644),
                IPIFC_STATS => ("stats".into(), 0o444),
                _ => match interface_path(path) {
                    Some((id, IF_DIR)) => (id.to_string(), 0o555),
                    Some((_, IF_CTL)) => ("ctl".into(), 0o644),
                    Some((_, IF_STATUS)) => ("status".into(), 0o444),
                    _ => return Err(Error::Enoent),
                },
            },
        }};
        Ok(DirEntry {
            dev: channel.dev,
            qid: channel.qid,
            mode: mode
                | if channel.qid.type_ & qidtype::DIR != 0 {
                    0x8000_0000
                } else {
                    0
                },
            atime: 0,
            mtime: 0,
            length: 0,
            name: name.into_bytes(),
            uid: 0,
            gid: 0,
        })
    }

    fn dev_char(&self) -> char {
        if self.ethernet { 'l' } else { 'I' }
    }

    fn name(&self) -> &'static str {
        if self.ethernet { "ether" } else { "net" }
    }
}

fn arp_ip(text: &str) -> Result<Ipv4Addr, Error> {
    let ip = text.parse::<Ipv4Addr>().map_err(|_| Error::Einval)?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || ip.is_broadcast() {
        return Err(Error::Einval);
    }
    Ok(ip)
}

fn arp_mac(text: &str) -> Result<[u8; 6], Error> {
    let mut mac = [0; 6];
    if text.len() == 12 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        for (index, byte) in mac.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| Error::Einval)?;
        }
    } else {
        let mut fields = text.split(':');
        for byte in &mut mac {
            let field = fields.next().filter(|field| field.len() == 2).ok_or(Error::Einval)?;
            *byte = u8::from_str_radix(field, 16).map_err(|_| Error::Einval)?;
        }
        if fields.next().is_some() { return Err(Error::Einval); }
    }
    if mac == [0; 6] || mac[0] & 1 != 0 { return Err(Error::Einval); }
    Ok(mac)
}

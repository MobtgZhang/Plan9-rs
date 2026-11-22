use alloc::{format, string::String};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use smoltcp::wire::{Icmpv4Packet, Icmpv6Packet, Ipv4Packet, Ipv6Packet};

use crate::{dev::Error, netstack};

fn envelope(packet: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 && packet[9] == 1 => {
            let header = usize::from(packet[0] & 15) * 4;
            if header < 20 { return None; }
            let source = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
            let target = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
            Some((source.into(), target.into(), packet.get(header..)?))
        }
        6 if packet.len() >= 40 && packet[6] == 58 => {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            Some((source.into(), target.into(), &packet[40..]))
        }
        _ => None,
    }
}

pub fn reply(packet: &[u8], local: IpAddr, remote: IpAddr, probe: &[u8; 8]) -> Option<(&'static str, IpAddr)> {
    let (source, target, echo) = envelope(packet)?;
    if target != local || echo.len() < 8 { return None; }
    let (reply, exceeded, unreachable) = match (source, target) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            Ipv4Packet::new_checked(packet).ok()?;
            if !Icmpv4Packet::new_checked(echo).ok()?.verify_checksum() { return None; }
            (0, 11, 3)
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            Ipv6Packet::new_checked(packet).ok()?;
            if !Icmpv6Packet::new_checked(echo).ok()?.verify_checksum(&source, &target) { return None; }
            (129, 3, 1)
        }
        _ => return None,
    };
    if echo[0] == reply && echo[1] == 0 && source == remote && echo[4..] == probe[4..] {
        return Some(("reached", source));
    }
    if !(echo[0] == exceeded && echo[1] == 0 || echo[0] == unreachable) { return None; }
    let (origin, destination, original) = envelope(&echo[8..])?;
    if origin != local || destination != remote || original.get(..2)? != &probe[..2]
        || original.get(4..8)? != &probe[4..8] {
        return None;
    }
    Some((if echo[0] == exceeded { "hop" } else { "unreachable" }, source))
}

pub fn query(request: &str) -> Result<String, Error> {
    let mut fields = request.split_whitespace();
    let destination = fields.next().and_then(|field| field.parse::<IpAddr>().ok()).ok_or(Error::Einval)?;
    let ttl = fields.next().and_then(|field| field.parse::<u8>().ok()).filter(|ttl| *ttl != 0).ok_or(Error::Einval)?;
    if fields.next().is_some() || destination.is_unspecified() || destination.is_multicast() {
        return Err(Error::Einval);
    }
    let start = netstack::now();
    match netstack::trace(destination, ttl)? {
        Some((status, sender)) => Ok(format!("{status} {sender} {}\n", netstack::now().saturating_sub(start))),
        None => Ok(String::from("*\n")),
    }
}

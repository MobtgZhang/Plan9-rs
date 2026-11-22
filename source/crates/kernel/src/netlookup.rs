use alloc::{format, string::String, vec, vec::Vec};
use core::{fmt::Write, net::{IpAddr, Ipv4Addr, Ipv6Addr}};
use smoltcp::wire::DnsQueryType;

use crate::{dev::Error, netstack};

pub static DATABASE: spin::Mutex<String> = spin::Mutex::new(String::new());

fn tuples(entry: &str) -> impl Iterator<Item = (&str, &str)> {
    entry.lines().flat_map(|line| line.split('#').next().unwrap_or("")
        .split_whitespace().filter_map(|tuple| tuple.split_once('=')))
}

fn entries(database: &str) -> impl Iterator<Item = &str> {
    let mut start = 0;
    let mut end = 0;
    let mut lines = database.split_inclusive('\n');
    core::iter::from_fn(move || {
        for line in lines.by_ref() {
            let previous = end;
            end += line.len();
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with([' ', '\t']) {
                continue;
            }
            let entry = &database[start..previous];
            start = previous;
            if !entry.trim().is_empty() { return Some(entry); }
        }
        let entry = database.get(start..end).filter(|entry| !entry.is_empty());
        start = end;
        entry
    })
}

fn local_addresses(name: &str, ipv6: bool) -> Vec<IpAddr> {
    let database = DATABASE.lock();
    let mut addresses = Vec::new();
    for entry in entries(&database) {
        if !tuples(entry).any(|(key, value)| matches!(key, "dom" | "sys")
            && value.trim_end_matches('.').eq_ignore_ascii_case(name)) {
            continue;
        }
        for (key, value) in tuples(entry) {
            if matches!(key, "ip" | "ipv6") {
                if let Ok(address) = value.parse::<IpAddr>() {
                    if address.is_ipv6() == ipv6 && !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
            }
        }
    }
    addresses
}

pub fn name_servers() -> Vec<IpAddr> {
    tuples(&DATABASE.lock()).filter(|(key, _)| *key == "dns")
        .filter_map(|(_, value)| value.parse().ok()).take(4).collect()
}

fn resolve(host: &str, ipv6: bool) -> Result<Vec<IpAddr>, Error> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(if address.is_ipv6() == ipv6 { vec![address] } else { Vec::new() });
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.eq_ignore_ascii_case("localhost") {
        return Ok(vec![if ipv6 { Ipv6Addr::LOCALHOST.into() } else { Ipv4Addr::LOCALHOST.into() }]);
    }
    if name.len() > 253 || name.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || !label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
        })
    }) {
        return Err(Error::Einval);
    }
    let addresses = local_addresses(name, ipv6);
    if !addresses.is_empty() { return Ok(addresses); }

    let query = if ipv6 { DnsQueryType::Aaaa } else { DnsQueryType::A };
    Ok(netstack::resolve_dns(host, query)?.into_iter().map(Into::into).collect())
}

pub fn dns(request: &str) -> Result<String, Error> {
    let mut fields = request.split_whitespace();
    let host = fields.next().ok_or(Error::Einval)?;
    let (record, ipv6) = match (fields.next(), fields.next()) {
        (Some("ip" | "a" | "A"), None) => ("ip", false),
        (Some("ipv6" | "aaaa" | "AAAA"), None) => ("ipv6", true),
        _ => return Err(Error::Einval),
    };
    let mut response = String::new();
    for address in resolve(host, ipv6)? {
        let _ = writeln!(response, "{host} {record} {address}");
    }
    if response.is_empty() { Err(Error::Enoent) } else { Ok(response) }
}

fn service_port(protocol: &str, service: &str) -> Option<u16> {
    service.parse().ok().or_else(|| {
        let database = DATABASE.lock();
        let port = entries(&database)
            .filter(|entry| tuples(entry).any(|(key, value)| key == protocol && value == service))
            .find_map(|entry| tuples(entry).find_map(|(key, value)| (key == "port").then(|| value.parse().ok()).flatten()));
        port
    }).or_else(|| match (protocol, service) {
        (_, "domain") => Some(53),
        ("tcp", "ssh") => Some(22),
        ("tcp", "smtp") => Some(25),
        ("tcp", "http") => Some(80),
        ("tcp", "https") => Some(443),
        ("tcp", "9fs" | "9p") => Some(564),
        ("udp", "ntp") => Some(123),
        _ => None,
    }).filter(|port| *port != 0)
}

pub fn cs(request: &str) -> Result<String, Error> {
    let mut fields = request.trim().split('!');
    let first = fields.next().ok_or(Error::Einval)?;
    let second = fields.next().ok_or(Error::Einval)?;
    let (protocol, host, service) = match (fields.next(), fields.next()) {
        (Some(service), None) => (first, second, service),
        (None, None) => ("net", first, second),
        _ => return Err(Error::Einval),
    };
    let protocols: &[&str] = match protocol {
        "net" => &["tcp", "udp"],
        "tcp" => &["tcp"],
        "udp" => &["udp"],
        "gre" => &["gre"],
        "rudp" => &["rudp"],
        _ => return Err(Error::Enotsup),
    };
    if !protocols.iter().any(|protocol| service_port(protocol, service).is_some()) {
        return Err(Error::Enoent);
    }
    let addresses = if host == "*" {
        vec![String::from("*")]
    } else if let Ok(address) = host.parse::<IpAddr>() {
        vec![format!("{address}")]
    } else {
        let mut addresses = Vec::new();
        for ipv6 in [false, true] {
            if let Ok(resolved) = resolve(host, ipv6) {
                addresses.extend(resolved.into_iter().map(|address| format!("{address}")));
            }
        }
        addresses
    };
    let mut response = String::new();
    for protocol in protocols {
        if let Some(port) = service_port(protocol, service) {
            for address in &addresses {
                let _ = writeln!(response, "/net/{protocol}/clone {address}!{port}");
            }
        }
    }
    if response.is_empty() { Err(Error::Enoent) } else { Ok(response) }
}

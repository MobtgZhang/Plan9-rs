use core::{
    fmt::{self, Write},
    net::IpAddr,
    str,
};

use crate::{arg, out, outln, syscall};

struct Text {
    bytes: [u8; 384],
    length: usize,
}

impl Text {
    fn new(args: fmt::Arguments<'_>) -> Result<Self, &'static str> {
        let mut text = Self {
            bytes: [0; 384],
            length: 0,
        };
        text.write_fmt(args).map_err(|_| "argument too long")?;
        Ok(text)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.length + text.len();
        if end >= self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.length..end].copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}

struct File(i64);

impl File {
    fn open(path: fmt::Arguments<'_>, mode: u32) -> Result<Self, &'static str> {
        let path = Text::new(path)?;
        let fd = syscall::open(path.bytes.as_ptr(), mode);
        if fd < 0 {
            Err("open failed")
        } else {
            Ok(Self(fd))
        }
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let count = syscall::read(self.0, buffer.as_mut_ptr(), buffer.len());
        if count < 0 {
            Err("read failed or timed out")
        } else {
            Ok(count as usize)
        }
    }

    fn write(&self, data: &[u8]) -> Result<(), &'static str> {
        let count = syscall::write(self.0, data.as_ptr(), data.len());
        if count == data.len() as i64 {
            Ok(())
        } else {
            Err("write failed or timed out")
        }
    }

    fn id(&self) -> Result<u32, &'static str> {
        let mut buffer = [0; 16];
        let count = self.read(&mut buffer)?;
        str::from_utf8(&buffer[..count])
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or("invalid conversation number")
    }

    fn query(path: &str, request: &[u8]) -> Result<Self, &'static str> {
        let file = Self::open(format_args!("{path}"), syscall::ORDWR)?;
        file.write(request).map_err(|_| "network name or service not found")?;
        if syscall::seek(file.0, 0, 0) != 0 {
            return Err("cannot rewind query file");
        }
        Ok(file)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        syscall::close(self.0);
    }
}

fn run(name: &str, result: Result<(), &'static str>) -> i32 {
    if let Err(error) = result {
        syscall::write_all(2, name.as_bytes());
        syscall::write_all(2, b": ");
        syscall::write_all(2, error.as_bytes());
        syscall::write_all(2, b"\n");
        1
    } else {
        0
    }
}

pub fn ping(argc: usize, argv: *const *const u8) -> i32 {
    run(
        "ping",
        (|| {
            const USAGE: &str = "usage: ip/ping [-6q] [-n count] [-i millisecs] address";
            let mut count = 4;
            let mut interval = 1000;
            let mut ipv6_only = false;
            let mut quiet = false;
            let mut index = 1;
            let address = loop {
                match arg(argc, argv, index).ok_or(USAGE)? {
                    "-6" => ipv6_only = true,
                    "-q" => quiet = true,
                    "-6q" | "-q6" => {
                        ipv6_only = true;
                        quiet = true;
                    }
                    "-n" | "-c" => {
                        index += 1;
                        count = arg(argc, argv, index)
                            .and_then(|value| value.parse::<u16>().ok())
                            .filter(|count| *count != 0)
                            .ok_or(USAGE)?;
                    }
                    "-i" => {
                        index += 1;
                        interval = arg(argc, argv, index)
                            .and_then(|value| value.parse::<u32>().ok())
                            .ok_or(USAGE)?;
                    }
                    address if index + 1 == argc && !address.starts_with('-') => break address,
                    _ => return Err(USAGE),
                }
                index += 1;
            };
            let address = match address.parse::<IpAddr>() {
                Ok(address) => address,
                Err(_) if ipv6_only => resolve_address(address, "ipv6")?,
                Err(_) => resolve_address(address, "ip")
                    .or_else(|_| resolve_address(address, "ipv6"))?,
            };
            if ipv6_only && address.is_ipv4() {
                return Err("-6 requires an IPv6 address");
            }
            let (protocol, request, reply) = if address.is_ipv6() {
                ("icmpv6", 128, 129)
            } else {
                ("icmp", 8, 0)
            };
            let ctl = File::open(format_args!("/net/{protocol}/clone"), syscall::ORDWR)?;
            let id = ctl.id()?;
            ctl.write(Text::new(format_args!("connect {address}"))?.as_bytes())?;
            let data = File::open(format_args!("/net/{protocol}/{id}/data"), syscall::ORDWR)?;
            let mut received = 0;
            for sequence in 0..count {
                let mut packet = [0; 24];
                packet[0] = request;
                packet[6..8].copy_from_slice(&sequence.to_be_bytes());
                packet[8..].copy_from_slice(b"Plan9-rs ICMP\0\0\0");
                let start = syscall::time(1);
                data.write(&packet)?;
                let sequence_bytes = sequence.to_be_bytes();
                let mut response = [0; 24];
                let matched = loop {
                    match data.read(&mut response) {
                        Ok(length)
                            if length == packet.len()
                                && response[0] == reply
                                && response[6..8] == sequence_bytes
                                && response[8..] == packet[8..] =>
                        {
                            break true
                        }
                        Ok(_) if syscall::time(1).saturating_sub(start) < 5000 => continue,
                        _ => break false,
                    }
                };
                if matched {
                    received += 1;
                    if !quiet {
                        let elapsed = syscall::time(1).saturating_sub(start);
                        out(Text::new(format_args!(
                            "reply from {address}: icmp_seq={sequence} time={elapsed} ms\n"
                        ))?
                        .as_bytes());
                    }
                } else if !quiet {
                    out(Text::new(format_args!(
                        "timeout from {address}: icmp_seq={sequence}\n"
                    ))?
                    .as_bytes());
                }
                if sequence + 1 < count && interval != 0 {
                    syscall::sleep_ms(u64::from(interval));
                }
            }
            out(Text::new(format_args!("{count} sent, {received} received\n"))?.as_bytes());
            if received == 0 {
                Err("no replies")
            } else {
                Ok(())
            }
        })(),
    )
}

fn resolve_address(host: &str, record: &str) -> Result<IpAddr, &'static str> {
    let query = Text::new(format_args!("{host} {record}"))?;
    let file = File::query("/net/dns", query.as_bytes())?;
    let mut buffer = [0; 320];
    let length = file.read(&mut buffer)?;
    str::from_utf8(&buffer[..length]).ok()
        .and_then(|answer| answer.split_whitespace().last())
        .and_then(|address| address.parse().ok())
        .ok_or("invalid DNS answer")
}

pub fn traceroute(argc: usize, argv: *const *const u8) -> i32 {
    run("traceroute", (|| {
        const USAGE: &str = "usage: ip/traceroute [-6] [-a tries] [-t max-ttl] destination";
        let mut max_ttl = 30;
        let mut attempts = 3;
        let mut ipv6 = false;
        let mut index = 1;
        let host = loop {
            match arg(argc, argv, index).ok_or(USAGE)? {
                "-6" => ipv6 = true,
                "-n" => (),
                option @ ("-t" | "-a") => {
                    index += 1;
                    let value = arg(argc, argv, index).and_then(|value| value.parse::<u8>().ok())
                        .filter(|value| *value != 0).ok_or(USAGE)?;
                    if option == "-t" { max_ttl = value; }
                    else if value <= 10 { attempts = value; }
                    else { return Err(USAGE); }
                }
                host if index + 1 == argc && !host.starts_with('-') => break host,
                _ => return Err(USAGE),
            }
            index += 1;
        };
        let address = host.parse::<IpAddr>().or_else(|_| {
            if ipv6 { resolve_address(host, "ipv6") }
            else { resolve_address(host, "ip").or_else(|_| resolve_address(host, "ipv6")) }
        })?;
        if ipv6 && address.is_ipv4() { return Err("-6 requires an IPv6 address"); }
        out(Text::new(format_args!("traceroute to {address}\n"))?.as_bytes());
        for ttl in 1..=max_ttl {
            out(Text::new(format_args!("{ttl:3}"))?.as_bytes());
            let mut reached = false;
            let mut unreachable = false;
            for _ in 0..attempts {
                let query = Text::new(format_args!("{address} {ttl}"))?;
                let file = File::query("/net/trace", query.as_bytes())?;
                let mut buffer = [0; 96];
                let count = file.read(&mut buffer)?;
                let mut fields = str::from_utf8(&buffer[..count]).map_err(|_| "invalid trace response")?
                    .split_whitespace();
                match fields.next() {
                    Some("*") => out(b"  *"),
                    Some(status @ ("reached" | "hop" | "unreachable")) => {
                        let sender = fields.next().ok_or("missing hop address")?;
                        let elapsed = fields.next().ok_or("missing hop time")?;
                        let marker = if status == "unreachable" { " !" } else { "" };
                        out(Text::new(format_args!("  {sender} {elapsed} ms{marker}"))?.as_bytes());
                        reached |= status == "reached";
                        unreachable |= status == "unreachable";
                    }
                    _ => return Err("invalid trace response"),
                }
            }
            out(b"\n");
            if reached { return Ok(()); }
            if unreachable { return Err("destination unreachable"); }
        }
        Err("destination not reached")
    })())
}

pub fn lookup(argc: usize, argv: *const *const u8, dns: bool) -> i32 {
    run(if dns { "dnsquery" } else { "csquery" }, (|| {
        let (path, query) = if dns && (2..=3).contains(&argc) {
            let host = arg(argc, argv, 1).ok_or("missing hostname")?;
            let record = arg(argc, argv, 2).unwrap_or("ip");
            ("/net/dns", Text::new(format_args!("{host} {record}"))?)
        } else if !dns && argc == 2 {
            let destination = arg(argc, argv, 1).ok_or("missing destination")?;
            ("/net/cs", Text::new(format_args!("{destination}"))?)
        } else if dns {
            return Err("usage: ndb/dnsquery hostname [ip|ipv6]");
        } else {
            return Err("usage: ndb/csquery [net!]host!service");
        };
        let file = File::query(path, query.as_bytes())?;
        let mut buffer = [0; 320];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            out(&buffer[..count]);
        }
    })())
}

pub fn snoopy(argc: usize, argv: *const *const u8) -> i32 {
    run("snoopy", (|| {
        const USAGE: &str = "usage: snoopy [-n count] ([-p] [-t ethertype] [etherN] | -f ipmux-filter ...)";
        let mut port = "ether0";
        let mut count = 0;
        let mut kind = -1;
        let mut promiscuous = false;
        let mut filters = [""; MAX_SNOOP_FILTERS];
        let mut filter_count = 0;
        let mut index = 1;
        while let Some(option) = arg(argc, argv, index) {
            match option {
                "-p" => promiscuous = true,
                "-f" => {
                    index += 1;
                    *filters.get_mut(filter_count).ok_or(USAGE)? = arg(argc, argv, index).ok_or(USAGE)?;
                    filter_count += 1;
                }
                "-n" => {
                    index += 1;
                    count = arg(argc, argv, index).and_then(|value| value.parse::<u32>().ok())
                        .filter(|count| *count != 0).ok_or(USAGE)?;
                }
                "-t" => {
                    index += 1;
                    let value = arg(argc, argv, index).ok_or(USAGE)?;
                    kind = if let Some(hex) = value.strip_prefix("0x") {
                        u16::from_str_radix(hex, 16).map(i32::from).map_err(|_| USAGE)?
                    } else { value.parse::<u16>().map(i32::from).map_err(|_| USAGE)? };
                }
                name if index + 1 == argc && matches!(name, "ether0" | "ether1" | "ether2" | "ether3") => port = name,
                _ => return Err(USAGE),
            }
            index += 1;
        }
        if filter_count != 0 {
            if promiscuous || kind != -1 || port != "ether0" || (filter_count > 1 && count == 0) {
                return Err(USAGE);
            }
            return snoop_ip(&filters[..filter_count], count);
        }
        let nic = &port["ether".len()..];
        let ctl = File::open(format_args!("#l{nic}/{port}/clone"), syscall::ORDWR)?;
        let id = ctl.id()?;
        ctl.write(Text::new(format_args!("connect {kind}"))?.as_bytes())?;
        if promiscuous { ctl.write(b"promiscuous")?; }
        let data = File::open(format_args!("#l{nic}/{port}/{id}/data"), syscall::OREAD)?;
        let mut frame = [0; 1514];
        loop {
            let length = data.read(&mut frame)?;
            if length < 14 { continue; }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let label = match ethertype {
                0x0800 => "IPv4",
                0x0806 => "ARP",
                0x86dd => "IPv6",
                _ => "Ethernet",
            };
            let mut output = Text::new(format_args!("{port} "))?;
            for byte in &frame[6..12] { write!(output, "{byte:02x}").map_err(|_| "frame output too long")?; }
            output.write_str(" > ").map_err(|_| "frame output too long")?;
            for byte in &frame[..6] { write!(output, "{byte:02x}").map_err(|_| "frame output too long")?; }
            write!(output, " {label} 0x{ethertype:04x} {length} bytes").map_err(|_| "frame output too long")?;
            match ethertype {
                0x0800 if length >= 34 && frame[14] >> 4 == 4 => {
                    let source = core::net::Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
                    let target = core::net::Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
                    write!(output, " {source} > {target} proto={} ttl={}", frame[23], frame[22]).map_err(|_| "frame output too long")?;
                }
                0x86dd if length >= 54 && frame[14] >> 4 == 6 => {
                    let mut source = [0; 16];
                    let mut target = [0; 16];
                    source.copy_from_slice(&frame[22..38]);
                    target.copy_from_slice(&frame[38..54]);
                    let (source, target) = (core::net::Ipv6Addr::from(source), core::net::Ipv6Addr::from(target));
                    write!(output, " {source} > {target} proto={} hop={}", frame[20], frame[21])
                        .map_err(|_| "frame output too long")?;
                }
                _ => ()
            }
            out(output.as_bytes());
            out(b"\n");
            if count != 0 {
                count -= 1;
                if count == 0 { return Ok(()); }
            }
        }
    })())
}

const MAX_SNOOP_FILTERS: usize = 8;

fn snoop_ip(filters: &[&str], count: u32) -> Result<(), &'static str> {
    let mut conversations: [Option<(File, File)>; MAX_SNOOP_FILTERS] = core::array::from_fn(|_| None);
    for (slot, filter) in conversations.iter_mut().zip(filters) {
        let ctl = File::open(format_args!("/net/ipmux/clone"), syscall::ORDWR)?;
        let id = ctl.id()?;
        ctl.write(Text::new(format_args!("connect {filter}"))?.as_bytes())?;
        let data = File::open(format_args!("/net/ipmux/{id}/data"), syscall::OREAD)?;
        *slot = Some((ctl, data));
    }
    let mut frame = [0; 1516];
    for (_, data) in conversations.iter().flatten() {
        let mut remaining = count;
        loop {
            let length = data.read(&mut frame)?;
            if length < 36 {
                return Err("short ipmux packet");
            }
            let interface = core::net::Ipv4Addr::new(frame[12], frame[13], frame[14], frame[15]);
            let source = core::net::Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
            let target = core::net::Ipv4Addr::new(frame[32], frame[33], frame[34], frame[35]);
            out(Text::new(format_args!("ipmux {interface} {source} > {target} proto={} ttl={} {} bytes\n",
                frame[25], frame[24], length - 16))?.as_bytes());
            if count != 0 {
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn transfer(
    socket: &File,
    payload: Option<&str>,
    udp: bool,
    listen: bool,
) -> Result<(), &'static str> {
    let mut buffer = [0; 1400];
    if !listen {
        if let Some(payload) = payload {
            socket.write(payload.as_bytes())?;
        } else {
            loop {
                let count = syscall::read(0, buffer.as_mut_ptr(), buffer.len());
                if count < 0 {
                    return Err("stdin read failed");
                }
                if count == 0 {
                    break;
                }
                socket.write(&buffer[..count as usize])?;
                if udp {
                    break;
                }
            }
        }
    }
    loop {
        let count = socket.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        out(&buffer[..count]);
        if udp || listen {
            break;
        }
    }
    if listen {
        if let Some(payload) = payload {
            socket.write(payload.as_bytes())?;
        }
    }
    Ok(())
}

fn esp_transfer(
    config: &str,
    peer: &str,
    spi: &str,
    payload: Option<&str>,
    count: u32,
) -> Result<(), &'static str> {
    let incoming = spi == "*";
    if incoming && payload.is_some() {
        return Err("an inbound ESP association is read-only");
    }
    let config = File::open(format_args!("{config}"), syscall::OREAD)?;
    let mut buffer = [0; 1500];
    let mut length = 0;
    while length < buffer.len() {
        let count = config.read(&mut buffer[length..])?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if length == buffer.len() {
        return Err("ESP configuration is too long");
    }
    let settings = str::from_utf8(&buffer[..length]).map_err(|_| "invalid ESP configuration")?;
    let ctl = File::open(format_args!("/net/esp/clone"), syscall::ORDWR)?;
    let id = ctl.id()?;
    ctl.write(Text::new(format_args!("connect {peer}!{spi}"))?.as_bytes())?;
    for setting in settings.lines().map(str::trim).filter(|setting| !setting.is_empty()) {
        if !matches!(setting.split_whitespace().next(), Some("esp" | "ah" | "ivseed" | "header" | "noheader")) {
            return Err("unknown ESP setting");
        }
        ctl.write(setting.as_bytes())?;
    }
    buffer.fill(0);
    if incoming {
        let local = File::open(format_args!("/net/esp/{id}/local"), syscall::OREAD)?;
        let length = local.read(&mut buffer)?;
        syscall::write_all(2, b"ESP listening on ");
        syscall::write_all(2, &buffer[..length]);
        let data = File::open(format_args!("/net/esp/{id}/data"), syscall::OREAD)?;
        for _ in 0..count {
            let length = data.read(&mut buffer)?;
            out(&buffer[..length]);
        }
    } else {
        let data = File::open(format_args!("/net/esp/{id}/data"), syscall::OWRITE)?;
        if let Some(payload) = payload {
            data.write(payload.as_bytes())?;
        } else {
            loop {
                let length = syscall::read(0, buffer.as_mut_ptr(), 1400);
                if length < 0 {
                    return Err("stdin read failed");
                }
                if length == 0 {
                    break;
                }
                data.write(&buffer[..length as usize])?;
            }
        }
    }
    Ok(())
}

pub fn netcat(argc: usize, argv: *const *const u8) -> i32 {
    run(
        "netcat",
        (|| {
            const USAGE: &str = "usage: netcat [-u|-r] [-l] [-m message] address port | netcat -u -l -H [-n count] address port | netcat -g -m message address ethertype | netcat -E config [-m message | -n count] address spi | netcat -I packet-file";
            if arg(argc, argv, 1) == Some("-I") {
                if argc != 3 {
                    return Err(USAGE);
                }
                return send_ip_packet(arg(argc, argv, 2).ok_or(USAGE)?);
            }
            let mut index = 1;
            let mut udp = false;
            let mut gre = false;
            let mut rudp = false;
            let mut listen = false;
            let mut headers = false;
            let mut payload = None;
            let mut esp = None;
            let mut count = None;
            while let Some(option) = arg(argc, argv, index) {
                match option {
                    "-u" => udp = true,
                    "-g" => gre = true,
                    "-r" => rudp = true,
                    "-l" => listen = true,
                    "-H" => headers = true,
                    "-E" => {
                        index += 1;
                        esp = Some(arg(argc, argv, index).ok_or(USAGE)?);
                    }
                    "-n" => {
                        index += 1;
                        count = Some(arg(argc, argv, index).and_then(|value| value.parse::<u32>().ok())
                            .filter(|count| *count != 0).ok_or(USAGE)?);
                    }
                    "-m" => {
                        index += 1;
                        payload = Some(arg(argc, argv, index).ok_or(USAGE)?);
                    }
                    _ => break,
                }
                index += 1;
            }
            if argc != index + 2 {
                return Err(USAGE);
            }
            let host = arg(argc, argv, index).ok_or(USAGE)?;
            let service = arg(argc, argv, index + 1).ok_or(USAGE)?;
            if let Some(config) = esp {
                if udp || gre || rudp || listen || headers || (count.is_some() && service != "*") {
                    return Err(USAGE);
                }
                return esp_transfer(config, host, service, payload, count.unwrap_or(1));
            }
            if headers && (!udp || !listen || payload.is_some()) || !headers && count.is_some() {
                return Err(USAGE);
            }
            if gre && (udp || rudp || listen || payload.is_none()) || udp && rudp { return Err(USAGE); }
            let protocol = if gre { "gre" } else if udp { "udp" } else if rudp { "rudp" } else { "tcp" };
            let request = Text::new(format_args!("{protocol}!{host}!{service}"))?;
            let resolver = File::query("/net/cs", request.as_bytes())?;
            let mut result = [0; 128];
            let action = if listen { "announce" } else { "connect" };
            let (ctl, id) = loop {
                let count = resolver.read(&mut result)?;
                if count == 0 {
                    return Err("no reachable address");
                }
                let (path, destination) = str::from_utf8(&result[..count]).ok()
                    .and_then(|text| text.trim_end().split_once(' '))
                    .ok_or("invalid connection service answer")?;
                let ctl = File::open(format_args!("{path}"), syscall::ORDWR)?;
                let id = ctl.id()?;
                if ctl.write(Text::new(format_args!("{action} {destination}"))?.as_bytes()).is_ok() {
                    break (ctl, id);
                }
            };
            if headers {
                const UDP_HEADER: usize = 52;
                ctl.write(b"headers")?;
                let data = File::open(format_args!("/net/udp/{id}/data"), syscall::ORDWR)?;
                syscall::write_all(2, b"netcat: UDP headers ready\n");
                let mut packet = [0; UDP_HEADER + 1472];
                for _ in 0..count.unwrap_or(1) {
                    let length = data.read(&mut packet)?;
                    let message = packet.get(UDP_HEADER..length).ok_or("short UDP header")?;
                    data.write(&packet[..length])?;
                    out(message);
                }
                Ok(())
            } else if gre {
                let data = File::open(format_args!("/net/gre/{id}/data"), syscall::ORDWR)?;
                let payload = payload.ok_or(USAGE)?.as_bytes();
                let mut packet = [0; 1480];
                let end = 4 + payload.len();
                packet.get_mut(4..end).ok_or("GRE payload is too long")?.copy_from_slice(payload);
                data.write(&packet[..end])?;
                let count = data.read(&mut packet)?;
                out(packet.get(4..count).ok_or("short GRE response")?);
                Ok(())
            } else if listen && !rudp {
                let accepted = File::open(format_args!("/net/{protocol}/{id}/listen"), syscall::OREAD)?;
                let child = accepted.id()?;
                let data = File::open(format_args!("/net/{protocol}/{child}/data"), syscall::ORDWR)?;
                transfer(&data, payload, udp || rudp, listen)
            } else {
                let data = File::open(format_args!("/net/{protocol}/{id}/data"), syscall::ORDWR)?;
                transfer(&data, payload, udp || rudp, listen)
            }
        })(),
    )
}

fn send_ip_packet(path: &str) -> Result<(), &'static str> {
    let input = File::open(format_args!("{path}"), syscall::OREAD)?;
    let mut buffer = [0; 1501];
    let mut length = 0;
    while length < buffer.len() {
        let count = input.read(&mut buffer[length..])?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if !(1..=1500).contains(&length) {
        return Err("expected one IP packet of at most 1500 bytes");
    }
    let ctl = File::open(format_args!("/net/ipmux/clone"), syscall::ORDWR)?;
    let id = ctl.id()?;
    File::open(format_args!("/net/ipmux/{id}/data"), syscall::OWRITE)?
        .write(&buffer[..length])
}

pub fn ipconfig(argc: usize, argv: *const *const u8) -> i32 {
    run(
        "ipconfig",
        (|| {
            const USAGE: &str = "usage: ipconfig [dhcp | add address/prefix [gateway] | routes]";
            match arg(argc, argv, 1) {
                None | Some("routes") if argc <= 2 => {
                    let mut buffer = [0; 256];
                    for interface in 0..if argc == 2 { 1 } else { 5 } {
                        let file = if argc == 2 {
                            File::open(format_args!("/net/iproute"), syscall::OREAD)
                        } else {
                            File::open(format_args!("/net/ipifc/{interface}/status"), syscall::OREAD)
                        };
                        let Ok(file) = file else {
                            continue;
                        };
                        loop {
                            let count = file.read(&mut buffer)?;
                            if count == 0 {
                                break;
                            }
                            out(&buffer[..count]);
                        }
                    }
                    Ok(())
                }
                Some("dhcp") if argc == 2 => {
                    File::open(format_args!("/net/ipifc/0/ctl"), syscall::OWRITE)?
                        .write(b"dhcp")?;
                    outln("DHCP discovery started");
                    Ok(())
                }
                Some("add") if (3..=4).contains(&argc) => {
                    let cidr = arg(argc, argv, 2).ok_or(USAGE)?;
                    let gateway = arg(argc, argv, 3)
                        .map(|value| value.parse::<core::net::Ipv4Addr>())
                        .transpose()
                        .map_err(|_| "invalid IPv4 gateway")?;
                    File::open(format_args!("/net/ipifc/0/ctl"), syscall::OWRITE)?
                        .write(Text::new(format_args!("static {cidr}"))?.as_bytes())?;
                    if let Some(gateway) = gateway {
                        File::open(format_args!("/net/iproute"), syscall::OWRITE)?.write(
                            Text::new(format_args!("add 0.0.0.0 0.0.0.0 {gateway}"))?.as_bytes(),
                        )?;
                    }
                    Ok(())
                }
                _ => Err(USAGE),
            }
        })(),
    )
}

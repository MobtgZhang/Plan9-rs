//! Kernel NIC and TCP data plane.
//!
//! Wires the E1000 driver into the `plan9_net` stack and implements a small
//! synchronous TCP client used by the Plan 9 `/net` device.  The NIC is
//! polled directly because the kernel does not install an interrupt handler
//! for the network device in this boot path.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::plan9_common::sync::Spinlock;
use crate::serial;
use plan9_common::types::PhysAddr;
use plan9_drivers::network::E1000;
use plan9_drivers::pci::{PciHeader};
use plan9_net::netstack::{Frame, NetBackend, set_backend, try_tx};

/// Guest IP used by QEMU's default user-mode network.
const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
/// QEMU's user-mode gateway (host side).
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const TCP_HEADER_LEN: usize = 20;
const IPV4_HEADER_LEN: usize = 20;
const MAX_FRAME: usize = 2048;

// ============================================================================
// NIC backend
// ============================================================================

pub struct NicBackend {
    nic: Spinlock<E1000>,
    pub mac: [u8; 6],
}

impl NicBackend {
    pub fn receive(&self, buffer: &mut [u8]) -> usize {
        let mut nic = self.nic.lock();
        nic.receive(buffer).unwrap_or(0)
    }

    fn transmit(&self, bytes: &[u8]) -> bool {
        let mut nic = self.nic.lock();
        nic.transmit(bytes).is_ok()
    }
}

impl NetBackend for NicBackend {
    fn tx(&self, frame: &Frame) -> bool {
        let mut out = Vec::with_capacity(14 + frame.payload.len());
        out.extend_from_slice(&frame.dst);
        out.extend_from_slice(&frame.src);
        out.extend_from_slice(&frame.ethertype.to_be_bytes());
        out.extend_from_slice(&frame.payload);
        self.transmit(&out)
    }

    fn dispatch_rx(&self, frame: Frame) {
        // The synchronous TCP path polls the receive ring directly.  This
        // hook exists so the backend remains a valid `NetBackend`.
        let _ = frame;
    }
}

static NIC: Spinlock<Option<Arc<NicBackend>>> = Spinlock::new(None);

fn backend() -> Option<Arc<NicBackend>> {
    NIC.lock().clone()
}

fn local_mac() -> [u8; 6] {
    backend().map(|b| b.mac).unwrap_or([0; 6])
}

// ============================================================================
// ARP
// ============================================================================

static ARP: Spinlock<Vec<([u8; 4], [u8; 6])>> = Spinlock::new(Vec::new());

fn arp_get(ip: [u8; 4]) -> Option<[u8; 6]> {
    let table = ARP.lock();
    for (addr, mac) in table.iter() {
        if *addr == ip {
            return Some(*mac);
        }
    }
    None
}

fn arp_set(ip: [u8; 4], mac: [u8; 6]) {
    let mut table = ARP.lock();
    if let Some(e) = table.iter_mut().find(|(a, _)| *a == ip) {
        e.1 = mac;
    } else {
        table.push((ip, mac));
    }
}

fn send_eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> bool {
    try_tx(&Frame {
        dst,
        src,
        ethertype,
        payload: payload.to_vec(),
    })
}

fn send_arp_request() -> bool {
    let src = local_mac();
    let mut p = vec![0u8; 28];
    p[0..2].copy_from_slice(&1u16.to_be_bytes());          // Ethernet
    p[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // IPv4 protocol
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&1u16.to_be_bytes());          // request
    p[8..14].copy_from_slice(&src);
    p[14..18].copy_from_slice(&LOCAL_IP);
    // target MAC is zero
    p[24..28].copy_from_slice(&GATEWAY_IP);
    send_eth([0xff; 6], src, ETHERTYPE_ARP, &p)
}

fn ensure_arp(ip: [u8; 4]) -> Option<[u8; 6]> {
    if let Some(m) = arp_get(ip) {
        return Some(m);
    }
    if backend().is_none() {
        return None;
    }
    send_arp_request();
    // Poll for an ARP reply.  The gateway normally answers immediately.
    for _ in 0..3000 {
        if let Some(bytes) = poll_frame() {
            handle_frame(&bytes);
            if let Some(m) = arp_get(ip) {
                return Some(m);
            }
        }
    }
    None
}

fn handle_arp(payload: &[u8]) {
    if payload.len() < 28 {
        return;
    }
    let op = be16(&payload[6..8]);
    let sender_mac = [
        payload[8], payload[9], payload[10], payload[11], payload[12], payload[13],
    ];
    let sender_ip = [payload[14], payload[15], payload[16], payload[17]];
    let target_ip = [payload[24], payload[25], payload[26], payload[27]];

    if op == 2 {
        arp_set(sender_ip, sender_mac);
    } else if op == 1 && target_ip == LOCAL_IP {
        // Reply to a local ARP request.
        let src = local_mac();
        let mut p = vec![0u8; 28];
        p[0..2].copy_from_slice(&1u16.to_be_bytes());
        p[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        p[4] = 6;
        p[5] = 4;
        p[6..8].copy_from_slice(&2u16.to_be_bytes());
        p[8..14].copy_from_slice(&src);
        p[14..18].copy_from_slice(&LOCAL_IP);
        p[18..24].copy_from_slice(&sender_mac);
        p[24..28].copy_from_slice(&sender_ip);
        send_eth(sender_mac, src, ETHERTYPE_ARP, &p);
    }
}

// ============================================================================
// TCP connection state
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    TimeWait,
}

#[derive(Debug, Clone)]
struct TcpConn {
    id: u32,
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    state: TcpConnState,
    seq: u32,
    ack: u32,
    rx: Vec<u8>,
}

static CONNS: Spinlock<Vec<TcpConn>> = Spinlock::new(Vec::new());

fn find_conn(id: u32) -> Option<TcpConn> {
    CONNS.lock().iter().find(|c| c.id == id).cloned()
}

fn find_conn_mut<F: FnOnce(&mut TcpConn)>(id: u32, f: F) -> bool {
    let mut g = CONNS.lock();
    if let Some(c) = g.iter_mut().find(|c| c.id == id) {
        f(c);
        true
    } else {
        false
    }
}

pub fn tcp_open(id: u32) {
    let mut g = CONNS.lock();
    if !g.iter().any(|c| c.id == id) {
        g.push(TcpConn {
            id,
            local_port: 40000 + (id % 1000) as u16,
            remote_ip: [0, 0, 0, 0],
            remote_port: 0,
            state: TcpConnState::Closed,
            seq: 0,
            ack: 0,
            rx: Vec::new(),
        });
    }
}

pub fn tcp_is_established(id: u32) -> bool {
    find_conn(id).map(|c| c.state == TcpConnState::Established).unwrap_or(false)
}

pub fn tcp_state(id: u32) -> Option<TcpConnState> {
    find_conn(id).map(|c| c.state)
}

pub fn tcp_connect(id: u32, remote_ip: [u8; 4], remote_port: u16) -> bool {
    if tcp_is_established(id) {
        return true;
    }

    // Record the endpoint before polling so incoming SYN-ACK can match it.
    let (local_port, seq) = {
        let mut g = CONNS.lock();
        let c = match g.iter_mut().find(|c| c.id == id) {
            Some(c) => c,
            None => return false,
        };
        c.remote_ip = remote_ip;
        c.remote_port = remote_port;
        let s = (0x1234_5678u32 ^ id) ^ ((remote_port as u32) << 16);
        c.seq = s;
        c.ack = 0;
        c.state = TcpConnState::SynSent;
        (c.local_port, s)
    };

    let dst_mac = match ensure_arp(remote_ip) {
        Some(m) => m,
        None => return false,
    };
    let src_mac = local_mac();

    let syn = build_ipv4_tcp(
        LOCAL_IP,
        remote_ip,
        local_port,
        remote_port,
        seq,
        0,
        0x02, // SYN
        &[],
    );
    if !send_eth(dst_mac, src_mac, ETHERTYPE_IPV4, &syn) {
        return false;
    }

    for _ in 0..6000 {
        if let Some(bytes) = poll_frame() {
            handle_frame(&bytes);
            if tcp_is_established(id) {
                return true;
            }
        }
        // Give the emulated NIC and the host network stack time to deliver
        // the reply.  A tight polling loop can finish before QEMU processes
        // the incoming frame.
        poll_delay();
    }

    return false;
}

pub fn tcp_write(id: u32, data: &[u8]) -> usize {
    let conn = match find_conn(id) {
        Some(c) if c.state == TcpConnState::Established => c,
        _ => return 0,
    };
    let dst_mac = match arp_get(conn.remote_ip) {
        Some(m) => m,
        None => return 0,
    };
    let src_mac = local_mac();

    let mut sent = 0usize;
    while sent < data.len() {
        let chunk = &data[sent..core::cmp::min(data.len(), sent + 1460)];
        let packet = build_ipv4_tcp(
            LOCAL_IP,
            conn.remote_ip,
            conn.local_port,
            conn.remote_port,
            conn.seq,
            conn.ack,
            0x18, // PSH | ACK
            chunk,
        );
        if !send_eth(dst_mac, src_mac, ETHERTYPE_IPV4, &packet) {
            return sent;
        }
        let next_seq = conn.seq.wrapping_add(chunk.len() as u32);
        find_conn_mut(id, |c| {
            c.seq = next_seq;
        });
        sent += chunk.len();
    }
    sent
}

pub fn tcp_read(id: u32, buf: &mut [u8]) -> usize {
    for _ in 0..5000 {
        if let Some(bytes) = poll_frame() {
            handle_frame(&bytes);
        }
        let conn = match find_conn(id) {
            Some(c) => c,
            None => return 0,
        };
        if conn.state == TcpConnState::Closed {
            return 0;
        }
        if !conn.rx.is_empty() {
            let n = core::cmp::min(buf.len(), conn.rx.len());
            buf[..n].copy_from_slice(&conn.rx[..n]);
            find_conn_mut(id, |c| {
                c.rx.drain(0..n);
            });
            return n;
        }
        poll_delay();
    }
    0
}

pub fn tcp_close(id: u32) {
    let conn = match find_conn(id) {
        Some(c) => c,
        None => return,
    };
    if conn.state == TcpConnState::Established {
        if let Some(dst_mac) = arp_get(conn.remote_ip) {
            let src_mac = local_mac();
            let fin = build_ipv4_tcp(
                LOCAL_IP,
                conn.remote_ip,
                conn.local_port,
                conn.remote_port,
                conn.seq,
                conn.ack,
                0x11, // FIN | ACK
                &[],
            );
            send_eth(dst_mac, src_mac, ETHERTYPE_IPV4, &fin);
        }
    }
    find_conn_mut(id, |c| {
        c.state = TcpConnState::Closed;
        c.rx.clear();
    });
}

// ============================================================================
// Frame handling
// ============================================================================

fn poll_frame() -> Option<Vec<u8>> {
    let b = backend()?;
    let mut buf = [0u8; MAX_FRAME];
    let n = b.receive(&mut buf);
    if n > 0 {
        Some(buf[..n].to_vec())
    } else {
        None
    }
}

/// Short busy wait between synchronous NIC polls.  The NIC is polled without
/// interrupts, so the guest must yield enough real time for QEMU to deliver
/// the next frame.
fn poll_delay() {
    for _ in 0..20_000 {
        core::hint::spin_loop();
    }
}

fn handle_frame(bytes: &[u8]) {
    if bytes.len() < 14 {
        return;
    }
    let ethertype = be16(&bytes[12..14]);
    let payload = &bytes[14..];

    if ethertype == ETHERTYPE_ARP {
        handle_arp(payload);
    } else if ethertype == ETHERTYPE_IPV4 {
        handle_ipv4(payload);
    }
}

fn handle_ipv4(payload: &[u8]) {
    if payload.len() < IPV4_HEADER_LEN {
        return;
    }
    let ihl = ((payload[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HEADER_LEN || payload.len() < ihl {
        return;
    }
    let total = be16(&payload[2..4]) as usize;
    let proto = payload[9];
    if proto != 6 || total < ihl + TCP_HEADER_LEN || total > payload.len() {
        return;
    }

    let src_ip = [payload[12], payload[13], payload[14], payload[15]];
    let dst_ip = [payload[16], payload[17], payload[18], payload[19]];

    let tcp = &payload[ihl..total];
    let src_port = be16(&tcp[0..2]);
    let dst_port = be16(&tcp[2..4]);
    let seq = be32(&tcp[4..8]);
    let ack = be32(&tcp[8..12]);
    let offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    if offset < TCP_HEADER_LEN || offset > tcp.len() {
        return;
    }
    let body = &tcp[offset..];

    let mut send_ack = false;
    let mut new_state = None;
    let mut conn_seq = 0u32;
    let mut conn_ack = 0u32;
    let mut conn_local_port = 0u16;

    let mut g = CONNS.lock();
    if let Some(c) = g.iter_mut().find(|c| {
        c.remote_ip == src_ip && c.remote_port == src_port && c.local_port == dst_port
    }) {
        conn_local_port = c.local_port;

        if c.state == TcpConnState::SynSent && (flags & 0x02) != 0 && (flags & 0x10) != 0 {
            // SYN-ACK: local SYN consumed one sequence number.
            c.ack = seq.wrapping_add(1);
            c.seq = c.seq.wrapping_add(1);
            c.state = TcpConnState::Established;
            new_state = Some(c.state);
            conn_seq = c.seq;
            conn_ack = c.ack;
            send_ack = true;
        } else if c.state == TcpConnState::Established {
            if !body.is_empty() {
                c.rx.extend_from_slice(body);
                c.ack = seq.wrapping_add(body.len() as u32);
            }
            conn_seq = c.seq;
            conn_ack = c.ack;
            if (flags & 0x01) != 0 {
                c.state = TcpConnState::FinWait1;
                new_state = Some(c.state);
            }
        }
    }
    drop(g);

    if send_ack {
        if let Some(dst_mac) = arp_get(src_ip) {
            let src_mac = local_mac();
            let packet = build_ipv4_tcp(
                LOCAL_IP,
                src_ip,
                conn_local_port,
                src_port,
                conn_seq,
                conn_ack,
                0x10, // ACK
                &[],
            );
            send_eth(dst_mac, src_mac, ETHERTYPE_IPV4, &packet);
        }
    }

    let _ = (dst_ip, new_state, ack);
}

// ============================================================================
// Packet construction
// ============================================================================

fn build_ipv4_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = vec![0u8; TCP_HEADER_LEN + payload.len()];
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    let offset_flags = (5u16 << 12) | (flags as u16);
    seg[12..14].copy_from_slice(&offset_flags.to_be_bytes());
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    // checksum field left zero for calculation
    seg[16..18].copy_from_slice(&[0, 0]);
    seg[18..20].copy_from_slice(&[0, 0]);
    seg[TCP_HEADER_LEN..].copy_from_slice(payload);

    let csum = tcp_checksum(src_ip, dst_ip, &seg);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut ip = vec![0u8; IPV4_HEADER_LEN + seg.len()];
    ip[0] = 0x45; // IPv4, 20-byte header
    ip[1] = 0;
    let total = (IPV4_HEADER_LEN + seg.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let ip_csum = checksum16(&ip[..IPV4_HEADER_LEN]);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    ip[IPV4_HEADER_LEN..].copy_from_slice(&seg);

    ip
}

fn net_init() {
    serial::put_bytes(b"[net] scanning for NIC\n");

    let mut found: Option<(u64, u32, u32)> = None;
    for d in crate::dev::pci_iter() {
        if d.class_code != 0x02 {
            continue;
        }
        let header = PciHeader::read(d.bus, d.dev, d.func);
        for i in 0..6 {
            let bar = header.read_bar(d.bus, d.dev, d.func, i);
            if bar == 0 || (bar & 1) != 0 {
                continue;
            }
            let addr = bar & !0xFu32;
            if addr != 0 && addr != 0xFFFF_FFFF {
                found = Some((addr as u64, d.vendor_id as u32, d.device_id as u32));
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }

    let (base, vendor, device) = match found {
        Some(v) => v,
        None => {
            serial::put_bytes(b"[net] no PCI NIC found; installing loopback backend\n");
            plan9_net::netstack::install_default_backend();
            return;
        }
    };

    serial::put_bytes(b"[net] NIC vendor=");
    serial::put_hex_u32(vendor);
    serial::put_bytes(b" device=");
    serial::put_hex_u32(device);
    serial::put_bytes(b" base=");
    serial::put_hex_u64(base);
    serial::put_bytes(b"\n");

    let tx_desc = match crate::frame_alloc::frame_alloc_zeroed() {
        Some(p) => p,
        None => {
            serial::put_bytes(b"[net] no DMA frame for TX descriptors\n");
            plan9_net::netstack::install_default_backend();
            return;
        }
    };
    let rx_desc = match crate::frame_alloc::frame_alloc_zeroed() {
        Some(p) => p,
        None => {
            serial::put_bytes(b"[net] no DMA frame for RX descriptors\n");
            plan9_net::netstack::install_default_backend();
            return;
        }
    };
    let tx_buf = match crate::frame_alloc::frame_alloc_zeroed() {
        Some(p) => p,
        None => {
            serial::put_bytes(b"[net] no DMA frame for TX buffer\n");
            plan9_net::netstack::install_default_backend();
            return;
        }
    };

    let mut rx_buffers = [PhysAddr::new(0); 16];
    for i in 0..16 {
        match crate::frame_alloc::frame_alloc_zeroed() {
            Some(p) => rx_buffers[i] = p,
            None => {
                serial::put_bytes(b"[net] no DMA frame for RX buffer\n");
                plan9_net::netstack::install_default_backend();
                return;
            }
        }
    }

    let mut nic = E1000::new(PhysAddr::new(base));
    nic.tx_size = 64;
    nic.rx_size = 16;
    if let Err(_e) = nic.init_dma(tx_desc, rx_desc, tx_buf, rx_buffers) {
        serial::put_bytes(b"[net] E1000 DMA setup failed\n");
        plan9_net::netstack::install_default_backend();
        return;
    }
    if let Err(_e) = nic.init() {
        serial::put_bytes(b"[net] E1000 init failed\n");
        plan9_net::netstack::install_default_backend();
        return;
    }

    let mac = nic.mac_address();
    let link = nic.link_up();
    serial::put_bytes(b"[net] mac=");
    for b in mac.iter() {
        serial::put_hex_u32(*b as u32);
        serial::put_bytes(b":");
    }
    serial::put_bytes(b" link=");
    serial::put_hex_u32(if link { 1 } else { 0 });
    serial::put_bytes(b"\n");

    let backend = Arc::new(NicBackend {
        nic: Spinlock::new(nic),
        mac,
    });
    *NIC.lock() = Some(backend.clone());
    set_backend(backend);
    serial::put_bytes(b"[net] E1000 registered with plan9_net::netstack\n");
    serial::put_bytes(b"[net] local ip=");
    serial::put_bytes(b"10.0.2.15\n");
}

/// Public init hook called once from `entry::kstart`.
pub fn init() {
    net_init();
}

pub fn is_ready() -> bool {
    NIC.lock().is_some()
}

// ============================================================================
// Byte helpers
// ============================================================================

fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

fn be32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += ((src[0] as u32) << 8) | src[1] as u32;
    sum += ((src[2] as u32) << 8) | src[3] as u32;
    sum += ((dst[0] as u32) << 8) | dst[1] as u32;
    sum += ((dst[2] as u32) << 8) | dst[3] as u32;
    sum += 6;
    sum += seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        sum += ((seg[i] as u32) << 8) | seg[i + 1] as u32;
        i += 2;
    }
    if i < seg.len() {
        sum += (seg[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

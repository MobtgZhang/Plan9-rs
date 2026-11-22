//! PCI Ethernet and loopback media for the kernel IP stack.

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::net::{Ipv4Addr, Ipv6Addr};
use plan9_common::types::PhysAddr;
use plan9_drivers::{network::{E1000, ethervirtio::{DMA_PAGES, VirtioNet}}, pci};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, Icmpv6Packet, Icmpv6Repr, IpAddress, IpProtocol, Ipv6Packet, Ipv6Repr, NdiscRepr};
use crate::{dev::Error, etherport::EtherPort};

const FRAME_SIZE: usize = 1514;
const LOOP_CAPACITY: usize = 16;

pub struct Link {
    medium: LinkMedium,
    rx: Box<[u8]>,
    pending: Option<usize>,
    tx: Box<[u8]>,
    port: Option<Box<EtherPort>>,
    promiscuous: bool,
}

enum LinkMedium {
    Ethernet(Box<E1000>),
    Virtio(Box<VirtioNet>),
    Loopback {
        spare: Vec<Box<[u8]>>,
        queue: VecDeque<(Box<[u8]>, usize)>,
    },
}

fn dma_pages<const COUNT: usize>() -> Option<[PhysAddr; COUNT]> {
    let mut pages = [PhysAddr::new(0); COUNT];
    for index in 0..COUNT {
        let Some(page) = crate::frame_alloc::frame_alloc_zeroed() else {
            free_pages(&pages[..index]);
            return None;
        };
        pages[index] = page;
    }
    Some(pages)
}

fn free_pages(pages: &[PhysAddr]) {
    for page in pages {
        let _ = crate::vm::free_frame(*page);
    }
}

fn virtio_mmio(base: u64, length: u32) -> Option<u64> {
    if length == 0 { return None; }
    #[cfg(target_arch = "x86_64")]
    {
        let address = unsafe { crate::vm::map_phys_range(base, u64::from(length)) };
        (!address.is_null()).then_some(address as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (base + u64::from(length) <= (4u64 << 30)).then(|| pci::mmio_address(base))
    }
}

impl Link {
    fn new(medium: LinkMedium) -> Self {
        let port = match &medium {
            LinkMedium::Ethernet(nic) => Some(EtherPort::new(nic.mac_address())),
            LinkMedium::Virtio(nic) => Some(EtherPort::new(nic.mac_address())),
            LinkMedium::Loopback { .. } => None,
        };
        Self {
            medium,
            rx: alloc::vec![0; FRAME_SIZE].into_boxed_slice(),
            pending: None,
            tx: alloc::vec![0; FRAME_SIZE].into_boxed_slice(),
            port,
            promiscuous: false,
        }
    }

    pub fn ethernet() -> Vec<([u8; 6], Self)> {
        let mut links = Vec::new();
        for device in crate::dev::pci_iter() {
            if links.len() >= 4 { break; }
            let (bus, slot, func) = (device.bus, device.dev, device.func);
            if matches!((device.vendor_id, device.device_id), (0x1af4, 0x1041 | 0x1000)) {
                let Some(pages) = dma_pages::<DMA_PAGES>() else { break; };
                if let Some(nic) = unsafe { VirtioNet::attach(bus, slot, func, pages, virtio_mmio) } {
                    crate::serial::put_bytes(b"[net] virtio-net registered\n");
                    links.push((nic.mac_address(), Self::new(LinkMedium::Virtio(Box::new(nic)))));
                } else {
                    free_pages(&pages);
                }
                continue;
            }
            if (device.vendor_id, device.device_id) != (0x8086, 0x100e) {
                continue;
            }
            let header = pci::PciHeader::read(bus, slot, func);
            let bar = header.read_bar(bus, slot, func, 0);
            if bar == u32::MAX || bar & 1 != 0 || bar & 6 != 0 || bar & !15 == 0 {
                continue;
            }

            let register = pci::PciConfigAddr::new(bus, slot, func, 4);
            let command = u32::from(header.command);
            pci::pci_config_write(register, (command | 2) & !4);
            let Some(pages) = dma_pages::<19>() else {
                pci::pci_config_write(register, command);
                break;
            };

            let mut nic = Box::new(E1000::new(PhysAddr::new(u64::from(bar & !15))));
            nic.stop();
            let mut receive = [PhysAddr::new(0); 16];
            receive.copy_from_slice(&pages[3..]);
            if unsafe { nic.init_dma(pages[0], pages[1], pages[2], receive) }.is_err()
                || nic.init().is_err()
            {
                nic.stop();
                free_pages(&pages);
                pci::pci_config_write(register, command);
                continue;
            }
            pci::pci_config_write(register, command | 6);
            crate::serial::put_bytes(b"[net] e1000 registered\n");
            links.push((nic.mac_address(), Self::new(LinkMedium::Ethernet(nic))));
        }
        links
    }

    pub fn loopback() -> Self {
        Self::new(LinkMedium::Loopback {
            spare: (0..LOOP_CAPACITY)
                .map(|_| alloc::vec![0; FRAME_SIZE].into_boxed_slice())
                .collect(),
            queue: VecDeque::with_capacity(LOOP_CAPACITY),
        })
    }

    pub fn port(&mut self) -> Result<&mut EtherPort, Error> {
        self.port.as_deref_mut().ok_or(Error::Enoent)
    }

    pub fn driver_stats(&self) -> Result<alloc::string::String, Error> {
        Ok(match &self.medium {
            LinkMedium::Ethernet(nic) => alloc::format!("driver: e1000\nlink: {}\nstatus: {:08x}\n", nic.link_up(), nic.status()),
            LinkMedium::Virtio(_) => alloc::string::String::from("driver: virtio-net\ntransport: modern-pci\n"),
            _ => return Err(Error::Enoent),
        })
    }

    pub fn update_promiscuous(&mut self) {
        if let (Some(port), LinkMedium::Ethernet(nic)) = (&mut self.port, &mut self.medium) {
            port.reap();
            let enabled = port.wants_promiscuous();
            if enabled != self.promiscuous {
                nic.set_promiscuous(enabled);
                self.promiscuous = enabled;
            }
        }
    }

    pub fn raw_promiscuous(&mut self, tap: usize, enabled: bool) -> Result<(), Error> {
        if !matches!(self.medium, LinkMedium::Ethernet(_)) { return Err(Error::Enotsup); }
        self.port()?.promiscuous(tap, enabled)?;
        self.update_promiscuous();
        Ok(())
    }

    pub fn drain_ethernet(&mut self) {
        self.update_promiscuous();
        for _ in 0..16 {
            if self.receive_packet().is_err() { break; }
        }
    }

    pub fn stage_ingress(&mut self) -> bool {
        self.update_promiscuous();
        self.pending = self.next_frame();
        self.pending.is_some()
    }

    pub fn staged_ip(&self) -> Option<&[u8]> {
        let frame = &self.rx[..self.pending?];
        if self.port.is_none() {
            Some(frame)
        } else if matches!((frame.get(12..14), frame.get(14).map(|byte| byte >> 4)),
            (Some([0x08, 0x00]), Some(4)) | (Some([0x86, 0xdd]), Some(6)))
        {
            frame.get(14..)
        } else {
            None
        }
    }

    pub fn staged_unicast(&self) -> bool {
        self.port.as_deref().is_some_and(|port| self.rx[..6] == port.mac())
    }

    pub fn discard_ingress(&mut self) {
        self.pending = None;
    }

    pub fn forward_ip(&mut self, next_hop: IpAddress, bytes: &[u8], time: Instant) -> Option<bool> {
        if bytes.len() > FRAME_SIZE - 14 { return Some(false); }
        let port = self.port.as_deref()?;
        let destination = port.neighbor(next_hop.into())?;
        let source = port.mac();
        if let Some(tx) = self.transmit(time) {
            tx.consume(14 + bytes.len(), |frame| {
                frame[..6].copy_from_slice(&destination);
                frame[6..12].copy_from_slice(&source);
                let ether_type = match next_hop {
                    IpAddress::Ipv4(_) => [0x08, 0x00],
                    IpAddress::Ipv6(_) => [0x86, 0xdd],
                };
                frame[12..14].copy_from_slice(&ether_type);
                frame[14..].copy_from_slice(bytes);
            });
            Some(true)
        } else {
            Some(false)
        }
    }

    pub fn request_arp(&mut self, source: Ipv4Addr, target: Ipv4Addr, time: Instant) {
        let Some(port) = self.port.as_deref() else { return; };
        let mac = port.mac();
        if let Some(tx) = self.transmit(time) {
            tx.consume(42, |frame| {
                frame[..6].fill(0xff);
                frame[6..12].copy_from_slice(&mac);
                frame[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
                frame[22..28].copy_from_slice(&mac);
                frame[28..32].copy_from_slice(&source.octets());
                frame[32..38].fill(0);
                frame[38..42].copy_from_slice(&target.octets());
            });
        }
    }

    pub fn request_ndp(&mut self, source: Ipv6Addr, target: Ipv6Addr, time: Instant) {
        let Some(port) = self.port.as_deref() else { return; };
        let mac = port.mac();
        let target_bytes = target.octets();
        let destination = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | u16::from(target_bytes[13]),
            u16::from_be_bytes([target_bytes[14], target_bytes[15]]));
        let message = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: target,
            lladdr: Some(HardwareAddress::Ethernet(EthernetAddress(mac)).into()),
        });
        let header = Ipv6Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Icmpv6,
            payload_len: message.buffer_len(),
            hop_limit: 255,
        };
        if let Some(tx) = self.transmit(time) {
            tx.consume(14 + header.buffer_len() + header.payload_len, |frame| {
                frame[..6].copy_from_slice(&[0x33, 0x33, 0xff, target_bytes[13], target_bytes[14], target_bytes[15]]);
                frame[6..12].copy_from_slice(&mac);
                frame[12..14].copy_from_slice(&[0x86, 0xdd]);
                let mut packet = Ipv6Packet::new_unchecked(&mut frame[14..]);
                header.emit(&mut packet);
                let mut payload = Icmpv6Packet::new_unchecked(packet.payload_mut());
                message.emit(&source, &destination, &mut payload, &ChecksumCapabilities::default());
            });
        }
    }

    pub fn raw_write(&mut self, tap: usize, frame: &[u8], time: Instant) -> Result<Option<usize>, Error> {
        if !(14..=FRAME_SIZE).contains(&frame.len()) { return Err(Error::Einval); }
        let port = self.port()?;
        port.reference(tap)?;
        let mac = port.mac();
        Ok(self.transmit(time).map(|mut tx| {
            tx.3 = false;
            tx.consume(frame.len(), |out| {
            out.copy_from_slice(frame);
            out[6..12].copy_from_slice(&mac);
            frame.len()
            })
        }))
    }
}

pub struct Receive<'a>(&'a [u8]);

impl RxToken for Receive<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, consume: F) -> R {
        consume(self.0)
    }
}

pub struct Transmit<'a>(&'a mut LinkMedium, &'a mut [u8], Option<&'a mut EtherPort>, bool);

impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, length: usize, produce: F) -> R {
        let packet = &mut self.1[..length];
        let result = produce(packet);
        if self.3 && self.2.as_deref_mut().is_some_and(|port| port.answer_arp(packet)) {
            return result;
        }
        let sent = match self.0 {
            LinkMedium::Ethernet(nic) => nic.transmit(packet).is_ok(),
            LinkMedium::Virtio(nic) => nic.transmit(packet).is_ok(),
            LinkMedium::Loopback { spare, queue } => {
                if let Some(mut frame) = spare.pop() {
                    frame[..length].copy_from_slice(packet);
                    queue.push_back((frame, length));
                }
                false
            }
        };
        if sent {
            if let Some(port) = self.2 { port.observe(packet, false); }
        }
        result
    }
}

impl Device for Link {
    type RxToken<'a> = Receive<'a>;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _time: Instant) -> Option<(Receive<'_>, Transmit<'_>)> {
        self.update_promiscuous();
        let length = self.pending.take().or_else(|| self.next_frame())?;
        Some((
            Receive(&self.rx[..length]),
            Transmit(&mut self.medium, &mut self.tx, self.port.as_deref_mut(), true),
        ))
    }

    fn transmit(&mut self, _time: Instant) -> Option<Transmit<'_>> {
        let ready = match &mut self.medium {
            LinkMedium::Ethernet(nic) => nic.tx_ready(),
            LinkMedium::Virtio(nic) => nic.tx_ready(),
            LinkMedium::Loopback { spare, .. } => !spare.is_empty(),
        };
        ready.then_some(Transmit(&mut self.medium, &mut self.tx, self.port.as_deref_mut(), true))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = if self.port.is_some() { Medium::Ethernet } else { Medium::Ip };
        caps.max_transmission_unit = if caps.medium == Medium::Ethernet { FRAME_SIZE } else { 1500 };
        caps.max_burst_size = Some(16);
        caps
    }
}

impl Link {
    fn next_frame(&mut self) -> Option<usize> {
        for _ in 0..16 {
            if let Some(length) = self.receive_packet().ok()? {
                return Some(length);
            }
        }
        None
    }

    fn receive_packet(&mut self) -> Result<Option<usize>, ()> {
        if let Some(reply) = self.port.as_deref_mut().and_then(EtherPort::local_arp_reply) {
            self.rx[..reply.len()].copy_from_slice(&reply);
            return Ok(Some(reply.len()));
        }
        let length = match &mut self.medium {
            LinkMedium::Ethernet(nic) => {
                if !nic.tx_ready() {
                    return Err(());
                }
                let length = nic.receive(&mut self.rx).map_err(|_| ())?;
                if length == 0 {
                    return Err(());
                }
                length
            }
            LinkMedium::Virtio(nic) => {
                if !nic.tx_ready() { return Err(()); }
                let length = nic.receive(&mut self.rx).map_err(|_| ())?;
                if length == 0 { return Err(()); }
                length
            }
            LinkMedium::Loopback { spare, queue } => {
                let (frame, length) = queue.pop_front().ok_or(())?;
                self.rx[..length].copy_from_slice(&frame[..length]);
                spare.push(frame);
                length
            }
        };
        if let Some(port) = self.port.as_deref_mut() {
            if !port.observe(&self.rx[..length], true) {
                return Ok(None);
            }
            port.enforce_arp(&mut self.rx[..length]);
        }
        Ok(Some(length))
    }
}

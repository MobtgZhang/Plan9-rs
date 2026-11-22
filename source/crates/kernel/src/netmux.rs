//! Plan 9 IPv4 packet multiplexor filters.

use alloc::vec::Vec;
use core::{cmp::Reverse, net::Ipv4Addr};

use crate::dev::Error;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Field {
    Protocol,
    Data,
    Header,
    Source,
    Destination,
    Interface,
}

struct Relation {
    field: Field,
    offset: usize,
    mask: Option<Vec<u8>>,
    choices: Vec<Vec<u8>>,
}

impl Relation {
    fn priority(&self) -> impl Ord + '_ {
        (self.field, self.offset, Reverse(self.choices[0].len()), Reverse(&self.mask))
    }

    fn parse(text: &str) -> Result<Self, Error> {
        let (field, expression) = text.split_once('=').ok_or(Error::Einval)?;
        let (field, offset, length) = match field.trim() {
            "proto" => (Field::Protocol, 0, 1),
            "src" => (Field::Source, 0, 4),
            "dst" => (Field::Destination, 0, 4),
            "ifc" => (Field::Interface, 0, 4),
            field => {
                let (name, offsets) = field.split_once('[').ok_or(Error::Einval)?;
                let kind = match name.trim() {
                    "data" => Field::Data,
                    "iph" => Field::Header,
                    _ => return Err(Error::Einval),
                };
                let offsets = offsets.strip_suffix(']').ok_or(Error::Einval)?;
                let (start, end) = offsets.split_once(':').unwrap_or((offsets, offsets));
                let start = start.trim().parse::<usize>().map_err(|_| Error::Einval)?;
                let end = end.trim().parse::<usize>().map_err(|_| Error::Einval)?;
                if end < start || end >= 1500 { return Err(Error::Einval); }
                (kind, start, end - start + 1)
            }
        };
        let parse_value = |value: &str| -> Result<Vec<u8>, Error> {
            let value = value.trim();
            if matches!(field, Field::Source | Field::Destination | Field::Interface) {
                let address = value.parse::<Ipv4Addr>().map_err(|_| Error::Einval)?;
                return Ok(address.octets().to_vec());
            }
            if value.len() != length * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::Einval);
            }
            (0..length).map(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| Error::Einval)
            }).collect()
        };
        let (values, mask) = match expression.split_once('&') {
            Some((values, mask)) => (values, Some(parse_value(mask)?)),
            None => (expression, None),
        };
        let choices = values.split('|').map(parse_value).collect::<Result<Vec<_>, _>>()?;
        if choices.len() > 20 { return Err(Error::Einval); }
        Ok(Self { field, offset, mask, choices })
    }

    fn matches(&self, header: &[u8], data: &[u8], interface: [u8; 4]) -> bool {
        let bytes = match self.field {
            Field::Protocol => &header[9..10],
            Field::Data => data,
            Field::Header => header,
            Field::Source => &header[12..16],
            Field::Destination => &header[16..20],
            Field::Interface => &interface,
        };
        let end = self.offset + self.choices[0].len();
        let Some(bytes) = bytes.get(self.offset..end) else { return false; };
        self.choices.iter().any(|value| {
            if let Some(mask) = &self.mask {
                bytes.iter().zip(mask).zip(value).all(|((byte, mask), value)| byte & mask == *value)
            } else {
                bytes == value
            }
        })
    }
}

pub struct Filter(Vec<Relation>);

impl Filter {
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > 4096 { return Err(Error::Einval); }
        let mut relations = text.split(';').map(Relation::parse).collect::<Result<Vec<_>, _>>()?;
        if relations.len() > 10 { return Err(Error::Einval); }
        relations.sort_by(|first, second| first.priority().cmp(&second.priority()));
        Ok(Self(relations))
    }

    pub fn matches(&self, header: &[u8], data: &[u8], interface: [u8; 4]) -> bool {
        self.0.iter().all(|relation| relation.matches(header, data, interface))
    }

    pub fn precedes(&self, other: &Self) -> bool {
        for (first, second) in self.0.iter().zip(&other.0) {
            match first.priority().cmp(&second.priority()) {
                core::cmp::Ordering::Less => return true,
                core::cmp::Ordering::Greater => return false,
                core::cmp::Ordering::Equal => {}
            }
        }
        self.0.len() > other.0.len()
    }
}

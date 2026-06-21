//! ASN.1 BER/DER Encoding and Decoding
//!
//! Implements Basic Encoding Rules (BER) and Distinguished Encoding Rules (DER)
//! for ASN.1 data structures.

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use crate::bigint::BigInt;
use crate::SecurityError;

/// ASN.1 tag classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// ASN.1 universal tags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalTag {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    Oid,
    ObjectDescriptor,
    External,
    Real,
    Enumerated,
    EmbeddedPdv,
    Utf8String,
    RelativeOid,
    Sequence,
    Set,
    NumericString,
    PrintableString,
    T61String,
    VideotexString,
    Ia5String,
    UtcTime,
    GeneralizedTime,
    GraphicString,
    VisibleString,
    GeneralString,
    CharacterString,
}

impl UniversalTag {
    pub fn to_tag(&self) -> u8 {
        match self {
            UniversalTag::Boolean => 0x01,
            UniversalTag::Integer => 0x02,
            UniversalTag::BitString => 0x03,
            UniversalTag::OctetString => 0x04,
            UniversalTag::Null => 0x05,
            UniversalTag::Oid => 0x06,
            UniversalTag::ObjectDescriptor => 0x07,
            UniversalTag::External => 0x08,
            UniversalTag::Real => 0x09,
            UniversalTag::Enumerated => 0x0A,
            UniversalTag::EmbeddedPdv => 0x0B,
            UniversalTag::Utf8String => 0x0C,
            UniversalTag::RelativeOid => 0x0D,
            UniversalTag::Sequence => 0x30,
            UniversalTag::Set => 0x31,
            UniversalTag::NumericString => 0x12,
            UniversalTag::PrintableString => 0x13,
            UniversalTag::T61String => 0x14,
            UniversalTag::VideotexString => 0x15,
            UniversalTag::Ia5String => 0x16,
            UniversalTag::UtcTime => 0x17,
            UniversalTag::GeneralizedTime => 0x18,
            UniversalTag::GraphicString => 0x19,
            UniversalTag::VisibleString => 0x1A,
            UniversalTag::GeneralString => 0x1B,
            UniversalTag::CharacterString => 0x1B,
        }
    }
}

/// ASN.1 value
#[derive(Debug, Clone)]
pub enum Asn1Value {
    Boolean(bool),
    Integer(BigInt),
    BitString(Vec<u8>),
    OctetString(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    Utf8String(String),
    PrintableString(String),
    Ia5String(String),
    UtcTime(String),
    GeneralizedTime(String),
    Sequence(Vec<Asn1Element>),
    Set(Vec<Asn1Element>),
    ContextSpecific(u32, Vec<u8>),
}

/// ASN.1 element
#[derive(Debug, Clone)]
pub struct Asn1Element {
    pub tag: u8,
    pub class: u8,
    pub constructed: bool,
    pub value: Asn1Value,
}

impl Asn1Element {
    /// Decode BER data
    pub fn decode_ber(data: &[u8]) -> Result<(Self, usize), SecurityError> {
        if data.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }

        let (element, consumed) = Self::parse_element(data)?;
        Ok((element, consumed))
    }

    fn parse_element(data: &[u8]) -> Result<(Asn1Element, usize), SecurityError> {
        if data.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }

        let mut offset = 0;
        
        // Parse tag
        let tag = data[offset];
        offset += 1;
        
        let class = (tag >> 6) & 0x03;
        let constructed = (tag & 0x20) != 0;
        let tag_number = tag & 0x1F;
        
        // Parse length
        if offset >= data.len() {
            return Err(SecurityError::InvalidInputLength);
        }
        
        let len = data[offset];
        offset += 1;
        
        let content_len = if len & 0x80 != 0 {
            // Long form length
            let num_octets = (len & 0x7F) as usize;
            if num_octets == 0 || offset + num_octets > data.len() {
                return Err(SecurityError::InvalidInputLength);
            }
            
            let mut length = 0usize;
            for i in 0..num_octets {
                length = (length << 8) | (data[offset + i] as usize);
            }
            offset += num_octets;
            length
        } else {
            len as usize
        };
        
        if offset + content_len > data.len() {
            return Err(SecurityError::InvalidInputLength);
        }
        
        let content = &data[offset..offset + content_len];
        
        // Parse content
        let value = Self::parse_content(tag_number, constructed, content)?;
        
        Ok((
            Self {
                tag: tag_number,
                class,
                constructed,
                value,
            },
            offset + content_len,
        ))
    }

    fn parse_content(tag: u8, constructed: bool, content: &[u8]) -> Result<Asn1Value, SecurityError> {
        match tag {
            0x01 => {
                // Boolean
                if content.is_empty() {
                    return Ok(Asn1Value::Boolean(false));
                }
                Ok(Asn1Value::Boolean(content[0] != 0))
            }
            0x02 => {
                // Integer
                let n = BigInt::from_bytes_be(content);
                Ok(Asn1Value::Integer(n))
            }
            0x03 => {
                // BitString
                Ok(Asn1Value::BitString(content.to_vec()))
            }
            0x04 => {
                // OctetString
                Ok(Asn1Value::OctetString(content.to_vec()))
            }
            0x05 => {
                // Null
                Ok(Asn1Value::Null)
            }
            0x06 => {
                // OID
                Self::parse_oid(content)
            }
            0x0C | 0x12 | 0x13 | 0x16 => {
                // String types
                Ok(Asn1Value::Utf8String(String::from_utf8_lossy(content).into_owned()))
            }
            0x17 => {
                // UTCTime
                Ok(Asn1Value::UtcTime(String::from_utf8_lossy(content).into_owned()))
            }
            0x18 => {
                // GeneralizedTime
                Ok(Asn1Value::GeneralizedTime(String::from_utf8_lossy(content).into_owned()))
            }
            0x30 | 0x31 => {
                // Sequence or Set
                if !constructed {
                    return Err(SecurityError::InvalidInputLength);
                }
                Self::parse_sequence_or_set(content)
            }
            _ => {
                // Unknown - store as context-specific
                Ok(Asn1Value::OctetString(content.to_vec()))
            }
        }
    }

    fn parse_oid(content: &[u8]) -> Result<Asn1Value, SecurityError> {
        if content.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }
        
        let mut oid = Vec::new();
        oid.push((content[0] / 40) as u32);
        oid.push((content[0] % 40) as u32);
        
        let mut value = 0u32;
        for &byte in &content[1..] {
            value = (value << 7) | ((byte & 0x7F) as u32);
            if byte & 0x80 == 0 {
                oid.push(value);
                value = 0;
            }
        }
        
        Ok(Asn1Value::Oid(oid))
    }

    fn parse_sequence_or_set(content: &[u8]) -> Result<Asn1Value, SecurityError> {
        let mut elements = Vec::new();
        let mut offset = 0;
        
        while offset < content.len() {
            let (elem, consumed) = Self::parse_element(&content[offset..])?;
            elements.push(elem);
            offset += consumed;
        }
        
        Ok(Asn1Value::Sequence(elements))
    }

    /// Encode to DER
    pub fn encode_der(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Tag byte
        let tag_byte = ((self.class & 0x03) << 6) | (if self.constructed { 0x20 } else { 0 }) | (self.tag & 0x1F);
        result.push(tag_byte);
        
        // Content encoding
        let content = self.encode_content();
        
        // Length
        let len = content.len();
        if len < 128 {
            result.push(len as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut temp = len;
            while temp > 0 {
                len_bytes.push((temp & 0xFF) as u8);
                temp >>= 8;
            }
            len_bytes.reverse();
            result.push((0x80 | len_bytes.len()) as u8);
            result.extend_from_slice(&len_bytes);
        }
        
        result.extend_from_slice(&content);
        result
    }

    fn encode_content(&self) -> Vec<u8> {
        match &self.value {
            Asn1Value::Boolean(b) => alloc::vec![if *b { 0xFF } else { 0 }],
            Asn1Value::Integer(n) => n.to_bytes_be(),
            Asn1Value::BitString(data) => data.clone(),
            Asn1Value::OctetString(data) => data.clone(),
            Asn1Value::Null => alloc::vec![],
            Asn1Value::Oid(oid) => Self::encode_oid(oid),
            Asn1Value::Utf8String(s) => s.as_bytes().to_vec(),
            Asn1Value::PrintableString(s) => s.as_bytes().to_vec(),
            Asn1Value::Ia5String(s) => s.as_bytes().to_vec(),
            Asn1Value::UtcTime(s) => s.as_bytes().to_vec(),
            Asn1Value::GeneralizedTime(s) => s.as_bytes().to_vec(),
            Asn1Value::Sequence(elements) | Asn1Value::Set(elements) => {
                let mut content = Vec::new();
                for elem in elements {
                    content.extend_from_slice(&elem.encode_der());
                }
                content
            }
            Asn1Value::ContextSpecific(_, data) => data.clone(),
        }
    }

    fn encode_oid(oid: &[u32]) -> Vec<u8> {
        let mut result = Vec::new();
        
        if oid.len() >= 2 {
            result.push((oid[0] * 40 + oid[1]) as u8);
            
            for &component in &oid[2..] {
                let mut octets = Vec::new();
                let mut value = component;
                while value > 0 {
                    octets.push((value & 0x7F) as u8);
                    value >>= 7;
                }
                octets.reverse();
                
                for (i, octet) in octets.iter().enumerate() {
                    result.push(if i < octets.len() - 1 { octet | 0x80 } else { *octet });
                }
            }
        }
        
        result
    }
}

//! DNS Client Implementation
//!
//! Implements Domain Name System (DNS) resolver.
//! Supports A, AAAA, CNAME, MX, NS, TXT record types.

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;

// ============================================================================
// DNS Constants
// ============================================================================

/// DNS port
pub const DNS_PORT: u16 = 53;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// IPv4 address
    A = 1,
    /// Name server
    NS = 2,
    /// Canonical name
    CNAME = 5,
    /// Start of authority
    SOA = 6,
    /// Pointer
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// Text
    TXT = 16,
    /// IPv6 address
    AAAA = 28,
    /// Service locator
    SRV = 33,
    /// All records
    ANY = 255,
}

impl DnsRecordType {
    /// Convert to numeric value
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Convert from numeric value
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(DnsRecordType::A),
            2 => Some(DnsRecordType::NS),
            5 => Some(DnsRecordType::CNAME),
            6 => Some(DnsRecordType::SOA),
            12 => Some(DnsRecordType::PTR),
            15 => Some(DnsRecordType::MX),
            16 => Some(DnsRecordType::TXT),
            28 => Some(DnsRecordType::AAAA),
            33 => Some(DnsRecordType::SRV),
            255 => Some(DnsRecordType::ANY),
            _ => None,
        }
    }
}

/// DNS record classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    /// Internet
    IN = 1,
    /// Chaosnet
    CH = 3,
    /// Hesiod
    HS = 4,
    /// Any class
    ANY = 255,
}

impl DnsClass {
    /// Convert to numeric value
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Convert from numeric value
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(DnsClass::IN),
            3 => Some(DnsClass::CH),
            4 => Some(DnsClass::HS),
            255 => Some(DnsClass::ANY),
            _ => None,
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    /// No error
    NoError = 0,
    /// Format error
    FormErr = 1,
    /// Server failure
    ServFail = 2,
    /// Name does not exist
    NXDomain = 3,
    /// Not implemented
    NotImp = 4,
    /// Query refused
    Refused = 5,
}

impl DnsRcode {
    /// Convert from numeric value
    pub fn from_u8(v: u8) -> Self {
        match v & 0x0F {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormErr,
            2 => DnsRcode::ServFail,
            3 => DnsRcode::NXDomain,
            4 => DnsRcode::NotImp,
            5 => DnsRcode::Refused,
            _ => DnsRcode::ServFail,
        }
    }
}

/// Maximum label length
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum domain name length
pub const MAX_NAME_LEN: usize = 255;

/// Maximum DNS packet size
pub const DNS_MAX_SIZE: usize = 512;

// ============================================================================
// DNS Packet Structure
// ============================================================================

/// DNS header
#[derive(Debug, Clone, Default)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags
    pub flags: u16,
    /// Questions
    pub questions: u16,
    /// Answers
    pub answers: u16,
    /// Authority records
    pub authority: u16,
    /// Additional records
    pub additional: u16,
}

impl DnsHeader {
    /// Create a new header for a query
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            flags: 0x0100, // RD flag set (recursion desired)
            questions: 0,
            answers: 0,
            authority: 0,
            additional: 0,
        }
    }

    /// Check if this is a response
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get response code
    pub fn rcode(&self) -> DnsRcode {
        DnsRcode::from_u8((self.flags & 0x000F) as u8)
    }

    /// Get number of questions
    pub fn question_count(&self) -> u16 {
        self.questions
    }

    /// Get number of answers
    pub fn answer_count(&self) -> u16 {
        self.answers
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.questions.to_be_bytes());
        buf[6..8].copy_from_slice(&self.answers.to_be_bytes());
        buf[8..10].copy_from_slice(&self.authority.to_be_bytes());
        buf[10..12].copy_from_slice(&self.additional.to_be_bytes());
        buf
    }

    /// Parse from bytes
    pub fn from_bytes(buf: &[u8; 12]) -> Self {
        Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            questions: u16::from_be_bytes([buf[4], buf[5]]),
            answers: u16::from_be_bytes([buf[6], buf[7]]),
            authority: u16::from_be_bytes([buf[8], buf[9]]),
            additional: u16::from_be_bytes([buf[10], buf[11]]),
        }
    }
}

/// DNS question
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// Domain name
    pub name: String,
    /// Record type
    pub qtype: u16,
    /// Record class
    pub qclass: u16,
}

impl DnsQuestion {
    /// Create a new question
    pub fn new(name: &str, qtype: DnsRecordType, qclass: DnsClass) -> Self {
        Self {
            name: alloc::string::String::from(name),
            qtype: qtype.as_u16(),
            qclass: qclass.as_u16(),
        }
    }

    /// Encode name to DNS wire format
    pub fn encode_name(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in self.name.split('.') {
            if label.is_empty() {
                break;
            }
            let bytes = label.as_bytes();
            if bytes.len() > MAX_LABEL_LEN {
                continue;
            }
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0); // Null terminator
        buf
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.encode_name();
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
        buf
    }
}

/// DNS resource record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Domain name
    pub name: String,
    /// Record type
    pub rtype: u16,
    /// Record class
    pub rclass: u16,
    /// TTL (time to live)
    pub ttl: u32,
    /// RDLENGTH (resource data length)
    pub rdlength: u16,
    /// RDATA (resource data)
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// Get IPv4 address (for A records)
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        if self.rtype == 1 && self.rdlength == 4 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&self.rdata[..4]);
            Some(addr)
        } else {
            None
        }
    }

    /// Get IPv6 address (for AAAA records)
    pub fn as_ipv6(&self) -> Option<[u8; 16]> {
        if self.rtype == 28 && self.rdlength == 16 {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&self.rdata[..16]);
            Some(addr)
        } else {
            None
        }
    }

    /// Get canonical name (for CNAME records)
    pub fn as_cname(&self) -> Option<String> {
        if self.rtype == 5 {
            Self::decode_name(&self.rdata).ok()
        } else {
            None
        }
    }

    /// Decode DNS name from wire format
    pub fn decode_name(buf: &[u8]) -> Result<String, ()> {
        let mut result = String::new();
        let mut i = 0;
        let mut jumped = false;

        while i < buf.len() {
            let len = buf[i];

            if len == 0 {
                // Track end offset only on the first walk so callers can
                // continue parsing the remaining record fields.
                if !jumped {
                    let _end_offset = i + 1;
                }
                break;
            }

            // Check for compression pointer
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    i += 2;
                }
                if i >= buf.len() {
                    return Err(());
                }
                let jump_offset = ((len & 0x3F) as usize) << 8 | (buf[i - 1] as usize);
                i = jump_offset;
                jumped = true;
                continue;
            }

            i += 1;
            if i + (len as usize) > buf.len() {
                return Err(());
            }

            if !result.is_empty() {
                result.push('.');
            }

            let label = &buf[i..i + (len as usize)];
            if let Ok(s) = core::str::from_utf8(label) {
                result.push_str(s);
            } else {
                return Err(());
            }
            i += len as usize;
        }

        Ok(result)
    }
}

/// DNS packet
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Header
    pub header: DnsHeader,
    /// Questions
    pub questions: Vec<DnsQuestion>,
    /// Answers
    pub answers: Vec<DnsRecord>,
    /// Authority records
    pub authority: Vec<DnsRecord>,
    /// Additional records
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Create a new DNS query
    pub fn new_query(id: u16, name: &str, qtype: DnsRecordType) -> Self {
        let question = DnsQuestion::new(name, qtype, DnsClass::IN);
        let mut packet = Self {
            header: DnsHeader::new_query(id),
            questions: vec![question],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };
        packet.header.questions = 1;
        packet
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Header
        buf.extend_from_slice(&self.header.to_bytes());
        
        // Questions
        for q in &self.questions {
            buf.extend_from_slice(&q.to_bytes());
        }
        
        buf
    }

    /// Parse from bytes
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ()> {
        if buf.len() < 12 {
            return Err(());
        }

        let header = DnsHeader::from_bytes(&buf[..12].try_into().map_err(|_| ())?);
        let mut offset = 12;

        // Parse questions
        let mut questions = Vec::new();
        for _ in 0..header.questions {
            let (name, end) = Self::parse_name(buf, offset)?;
            offset = end;
            
            if offset + 4 > buf.len() {
                return Err(());
            }
            
            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
            offset += 4;
        }

        // Parse records (answers, authority, additional)
        let mut parse_records = |count: u16| -> Result<Vec<DnsRecord>, ()> {
            let mut records = Vec::new();
            for _ in 0..count {
                let (name, end) = Self::parse_name(buf, offset)?;
                offset = end;
                
                if offset + 10 > buf.len() {
                    return Err(());
                }
                
                let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
                let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]);
                offset += 10;
                
                if offset + (rdlength as usize) > buf.len() {
                    return Err(());
                }
                
                let rdata = buf[offset..offset + (rdlength as usize)].to_vec();
                offset += rdlength as usize;
                
                records.push(DnsRecord {
                    name,
                    rtype,
                    rclass,
                    ttl,
                    rdlength,
                    rdata,
                });
            }
            Ok(records)
        };

        let answers = parse_records(header.answers)?;
        let authority = parse_records(header.authority)?;
        let additional = parse_records(header.additional)?;

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Parse a domain name from wire format
    fn parse_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), ()> {
        let mut result = String::new();
        let _original_offset = offset;
        let mut jumped = false;
        let mut jumps = 0;
        const MAX_JUMPS: usize = 10;

        loop {
            if jumps > MAX_JUMPS {
                return Err(());
            }

            if offset >= buf.len() {
                return Err(());
            }

            let len = buf[offset];

            if len == 0 {
                if !jumped {
                    offset += 1;
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return Err(());
                }
                if !jumped {
                    offset += 2;
                }
                let new_offset = ((len & 0x3F) as usize) << 8 | (buf[offset + 1 - (if jumped {2} else {0})] as usize);
                offset = new_offset;
                jumped = true;
                jumps += 1;
                continue;
            }

            offset += 1;
            if offset + (len as usize) > buf.len() {
                return Err(());
            }

            if !result.is_empty() {
                result.push('.');
            }

            let label = &buf[offset..offset + (len as usize)];
            if let Ok(s) = core::str::from_utf8(label) {
                result.push_str(s);
            } else {
                return Err(());
            }
            offset += len as usize;
        }

        Ok((result, offset))
    }

    /// Get all A records (IPv4 addresses)
    pub fn get_a_records(&self) -> Vec<[u8; 4]> {
        self.answers.iter()
            .filter_map(|r| r.as_ipv4())
            .collect()
    }

    /// Get all AAAA records (IPv6 addresses)
    pub fn get_aaaa_records(&self) -> Vec<[u8; 16]> {
        self.answers.iter()
            .filter_map(|r| r.as_ipv6())
            .collect()
    }

    /// Get first A record
    pub fn get_first_a(&self) -> Option<[u8; 4]> {
        self.get_a_records().into_iter().next()
    }

    /// Get first AAAA record
    pub fn get_first_aaaa(&self) -> Option<[u8; 16]> {
        self.get_aaaa_records().into_iter().next()
    }
}

// ============================================================================
// DNS Resolver
// ============================================================================

/// DNS resolver state
pub struct DnsResolver {
    /// Transaction ID counter
    txid: u16,
    /// Cache
    cache: DnsCache,
}

impl DnsResolver {
    /// Create a new resolver
    pub fn new() -> Self {
        Self {
            txid: 0,
            cache: DnsCache::new(),
        }
    }

    /// Get next transaction ID
    fn next_txid(&mut self) -> u16 {
        self.txid = self.txid.wrapping_add(1);
        self.txid
    }

    /// Build a DNS query
    pub fn build_query(&mut self, name: &str, qtype: DnsRecordType) -> DnsPacket {
        DnsPacket::new_query(self.next_txid(), name, qtype)
    }

    /// Process DNS response
    pub fn process_response(&mut self, packet: &DnsPacket) -> Option<Vec<DnsRecord>> {
        // Check for errors
        let rcode = packet.header.rcode();
        if rcode != DnsRcode::NoError {
            return None;
        }

        // Add answers to cache
        for record in &packet.answers {
            self.cache.add(record);
        }

        Some(packet.answers.clone())
    }

    /// Look up in cache
    pub fn lookup_cache(&self, name: &str, qtype: DnsRecordType) -> Option<Vec<DnsRecord>> {
        self.cache.get(name, qtype)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DNS Cache
// ============================================================================

/// DNS cache entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Domain name
    pub name: String,
    /// Record type
    pub rtype: u16,
    /// Record data
    pub record: DnsRecord,
    /// Expiry time (seconds since epoch)
    pub expires: u64,
}

impl DnsCacheEntry {
    /// Check if expired
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires
    }
}

/// DNS cache
pub struct DnsCache {
    /// Cache entries
    entries: Vec<DnsCacheEntry>,
    /// Maximum entries
    max_entries: usize,
}

impl DnsCache {
    /// Create a new cache
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 256,
        }
    }

    /// Add a record to cache
    pub fn add(&mut self, record: &DnsRecord) {
        // Remove expired entries
        let now = 0; // Would use actual time
        self.entries.retain(|e| !e.is_expired(now));

        // Add new entry
        if self.entries.len() >= self.max_entries {
            // Remove oldest entry
            self.entries.remove(0);
        }

        let expires = record.ttl as u64;
        self.entries.push(DnsCacheEntry {
            name: record.name.clone(),
            rtype: record.rtype,
            record: record.clone(),
            expires,
        });
    }

    /// Look up a record
    pub fn get(&self, name: &str, qtype: DnsRecordType) -> Option<Vec<DnsRecord>> {
        let now = 0; // Would use actual time
        
        let results: Vec<DnsRecord> = self.entries.iter()
            .filter(|e| {
                e.name == name && 
                (e.rtype == qtype.as_u16() || qtype == DnsRecordType::ANY) &&
                !e.is_expired(now)
            })
            .map(|e| e.record.clone())
            .collect();

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    /// Clear cache
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

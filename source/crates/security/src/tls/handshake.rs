//! TLS Handshake Messages
//!
//! Implements the TLS handshake protocol messages.

use alloc::vec;
use crate::tls::error::TlsError;
use alloc::vec::Vec;

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = TlsError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            _ => Err(TlsError::DecodeError),
        }
    }
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}

impl TlsVersion {
    pub const SSL3: Self = TlsVersion { major: 3, minor: 0 };
    pub const TLS10: Self = TlsVersion { major: 3, minor: 1 };
    pub const TLS11: Self = TlsVersion { major: 3, minor: 2 };
    pub const TLS12: Self = TlsVersion { major: 3, minor: 3 };
    pub const TLS13: Self = TlsVersion { major: 3, minor: 4 };

    pub fn new(major: u8, minor: u8) -> Self {
        TlsVersion { major, minor }
    }

    pub fn from_code(code: u16) -> Self {
        TlsVersion {
            major: (code >> 8) as u8,
            minor: (code & 0xFF) as u8,
        }
    }

    pub fn to_code(&self) -> u16 {
        ((self.major as u16) << 8) | (self.minor as u16)
    }

    pub fn is_tls12(&self) -> bool {
        self.major == 3 && self.minor == 3
    }
}

impl Default for TlsVersion {
    fn default() -> Self {
        Self::TLS12
    }
}

/// TLS compression method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null = 0,
}

impl Default for CompressionMethod {
    fn default() -> Self {
        CompressionMethod::Null
    }
}

/// TLS extension
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

/// ClientHello message
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// TLS version
    pub version: TlsVersion,
    /// Random bytes (32 bytes)
    pub random: [u8; 32],
    /// Session ID (may be empty)
    pub session_id: Vec<u8>,
    /// Cipher suites (list of u16 codes)
    pub cipher_suites: Vec<u16>,
    /// Compression methods
    pub compression_methods: Vec<u8>,
    /// Extensions
    pub extensions: Vec<TlsExtension>,
}

impl ClientHello {
    /// Create a new ClientHello with default values
    pub fn new() -> Self {
        ClientHello {
            version: TlsVersion::TLS12,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![
                0xC02C, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
                0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
            ],
            compression_methods: vec![0], // null only
            extensions: Vec::new(),
        }
    }

    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Version
        result.push(self.version.major);
        result.push(self.version.minor);

        // Random (32 bytes)
        result.extend_from_slice(&self.random);

        // Session ID
        result.push(self.session_id.len() as u8);
        result.extend_from_slice(&self.session_id);

        // Cipher suites
        result.extend_from_slice(&(self.cipher_suites.len() as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            result.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression methods
        result.push(self.compression_methods.len() as u8);
        result.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let ext_bytes: Vec<u8> = self.extensions.iter().flat_map(|e| {
                let mut ext = Vec::new();
                ext.extend_from_slice(&e.extension_type.to_be_bytes());
                ext.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
                ext.extend_from_slice(&e.data);
                ext
            }).collect();
            result.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            result.extend_from_slice(&ext_bytes);
        } else {
            result.extend_from_slice(&0u16.to_be_bytes());
        }

        result
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        let mut pos = 0;

        // Version
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let version = TlsVersion::new(data[pos], data[pos + 1]);
        pos += 2;

        // Random
        if pos + 32 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Session ID
        if pos + 1 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let sid_len = data[pos] as usize;
        pos += 1;
        if pos + sid_len > data.len() {
            return Err(TlsError::DecodeError);
        }
        let session_id = data[pos..pos + sid_len].to_vec();
        pos += sid_len;

        // Cipher suites
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + cs_len > data.len() {
            return Err(TlsError::DecodeError);
        }
        let mut cipher_suites = Vec::new();
        for i in (0..cs_len).step_by(2) {
            cipher_suites.push(u16::from_be_bytes([data[pos + i], data[pos + i + 1]]));
        }
        pos += cs_len;

        // Compression methods
        if pos + 1 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let cm_len = data[pos] as usize;
        pos += 1;
        if pos + cm_len > data.len() {
            return Err(TlsError::DecodeError);
        }
        let compression_methods = data[pos..pos + cm_len].to_vec();
        pos += cm_len;

        // Extensions (optional)
        let extensions = if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let mut extensions = Vec::new();
            let mut ext_pos = 0;
            let ext_data = &data[pos..pos + ext_len];
            while ext_pos + 4 <= ext_len {
                let ext_type = u16::from_be_bytes([ext_data[ext_pos], ext_data[ext_pos + 1]]);
                let ext_data_len = u16::from_be_bytes([ext_data[ext_pos + 2], ext_data[ext_pos + 3]]) as usize;
                ext_pos += 4;
                if ext_pos + ext_data_len <= ext_len {
                    extensions.push(TlsExtension {
                        extension_type: ext_type,
                        data: ext_data[ext_pos..ext_pos + ext_data_len].to_vec(),
                    });
                }
                ext_pos += ext_data_len;
            }
            extensions
        } else {
            Vec::new()
        };

        Ok(ClientHello {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

impl Default for ClientHello {
    fn default() -> Self {
        Self::new()
    }
}

/// ServerHello message
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// TLS version
    pub version: TlsVersion,
    /// Random bytes (32 bytes)
    pub random: [u8; 32],
    /// Session ID
    pub session_id: Vec<u8>,
    /// Cipher suite
    pub cipher_suite: u16,
    /// Compression method
    pub compression_method: u8,
    /// Extensions
    pub extensions: Vec<TlsExtension>,
}

impl ServerHello {
    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Version
        result.push(self.version.major);
        result.push(self.version.minor);

        // Random
        result.extend_from_slice(&self.random);

        // Session ID
        result.push(self.session_id.len() as u8);
        result.extend_from_slice(&self.session_id);

        // Cipher suite
        result.extend_from_slice(&self.cipher_suite.to_be_bytes());

        // Compression method
        result.push(self.compression_method);

        // Extensions
        if !self.extensions.is_empty() {
            let ext_bytes: Vec<u8> = self.extensions.iter().flat_map(|e| {
                let mut ext = Vec::new();
                ext.extend_from_slice(&e.extension_type.to_be_bytes());
                ext.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
                ext.extend_from_slice(&e.data);
                ext
            }).collect();
            result.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            result.extend_from_slice(&ext_bytes);
        } else {
            result.extend_from_slice(&0u16.to_be_bytes());
        }

        result
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        let mut pos = 0;

        // Version
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let version = TlsVersion::new(data[pos], data[pos + 1]);
        pos += 2;

        // Random
        if pos + 32 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Session ID
        if pos + 1 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let sid_len = data[pos] as usize;
        pos += 1;
        if pos + sid_len > data.len() {
            return Err(TlsError::DecodeError);
        }
        let session_id = data[pos..pos + sid_len].to_vec();
        pos += sid_len;

        // Cipher suite
        if pos + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Compression method
        if pos + 1 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let compression_method = data[pos];
        // pos is at end of meaningful data; extensions are skipped.

        // Extensions (skip for now)
        let extensions = Vec::new();

        Ok(ServerHello {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

/// Certificate message
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate chain (DER-encoded X.509 certificates)
    pub certificates: Vec<Vec<u8>>,
}

impl Certificate {
    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Total length of all certificates
        let total_len: usize = self.certificates.iter().map(|c| c.len() + 3).sum();
        result.extend_from_slice(&(total_len as u32).to_be_bytes());

        for cert in &self.certificates {
            result.extend_from_slice(&(cert.len() as u32).to_be_bytes());
            result.extend_from_slice(cert);
        }

        result
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        let mut pos = 0;

        // Total length
        if pos + 3 > data.len() {
            return Err(TlsError::DecodeError);
        }
        let total_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let end = pos + total_len;
        let mut certificates = Vec::new();

        while pos < end {
            if pos + 3 > data.len() {
                return Err(TlsError::DecodeError);
            }
            let cert_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + cert_len > data.len() {
                return Err(TlsError::DecodeError);
            }
            certificates.push(data[pos..pos + cert_len].to_vec());
            pos += cert_len;
        }

        Ok(Certificate { certificates })
    }
}

/// ClientKeyExchange message
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    /// RSA encrypted pre-master secret or DH client params
    pub exchange_keys: Vec<u8>,
}

impl ClientKeyExchange {
    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.exchange_keys.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.exchange_keys);
        result
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::DecodeError);
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return Err(TlsError::DecodeError);
        }
        Ok(ClientKeyExchange {
            exchange_keys: data[2..2 + len].to_vec(),
        })
    }
}

/// Finished message (verify_data)
#[derive(Debug, Clone)]
pub struct Finished {
    /// Verify data
    pub verify_data: [u8; 12],
}

impl Finished {
    /// Create from verify data
    pub fn new(verify_data: [u8; 12]) -> Self {
        Finished { verify_data }
    }

    /// Serialize to bytes
    pub fn encode(&self) -> Vec<u8> {
        self.verify_data.to_vec()
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 12 {
            return Err(TlsError::DecodeError);
        }
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&data[..12]);
        Ok(Finished { verify_data })
    }
}

/// ServerHelloDone message (empty message)
#[derive(Debug, Clone, Default)]
pub struct ServerHelloDone;

impl ServerHelloDone {
    /// Serialize to bytes (empty)
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
}

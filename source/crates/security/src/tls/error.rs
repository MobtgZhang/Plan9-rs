//! TLS Error Types

use alloc::string::String;

/// TLS error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// Invalid TLS version
    InvalidVersion(u16),
    /// Invalid cipher suite
    InvalidCipherSuite(u16),
    /// Invalid certificate
    InvalidCertificate,
    /// Certificate verification failed
    CertificateVerificationFailed(String),
    /// Invalid MAC
    InvalidMac,
    /// Decryption failed
    DecryptionFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Handshake failed
    HandshakeFailed(String),
    /// Connection closed
    ConnectionClosed,
    /// I/O error
    IoError(String),
    /// Alert received
    Alert(AlertLevel, AlertDescription),
    /// Unexpected message
    UnexpectedMessage,
    /// Decode error
    DecodeError,
    /// Internal error
    InternalError(String),
    /// Peer sent close_notify
    CloseNotify,
    /// Record overflow
    RecordOverflow,
    /// No application protocol
    NoApplicationProtocol,
}

impl TlsError {
    /// Get the TLS alert code
    pub fn alert_code(&self) -> Option<(AlertLevel, AlertDescription)> {
        match self {
            TlsError::InvalidCertificate => Some((AlertLevel::Fatal, AlertDescription::BadCertificate)),
            TlsError::CertificateVerificationFailed(_) => {
                Some((AlertLevel::Fatal, AlertDescription::CertificateUnknown))
            }
            TlsError::InvalidMac => Some((AlertLevel::Fatal, AlertDescription::BadRecordMac)),
            TlsError::DecryptionFailed => {
                Some((AlertLevel::Fatal, AlertDescription::DecryptError))
            }
            TlsError::UnexpectedMessage => {
                Some((AlertLevel::Fatal, AlertDescription::UnexpectedMessage))
            }
            TlsError::DecodeError => Some((AlertLevel::Fatal, AlertDescription::DecodeError)),
            TlsError::RecordOverflow => Some((AlertLevel::Fatal, AlertDescription::RecordOverflow)),
            TlsError::CloseNotify => Some((AlertLevel::CloseNotify, AlertDescription::CloseNotify)),
            _ => None,
        }
    }
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlsError::InvalidVersion(v) => write!(f, "invalid TLS version: {:04x}", v),
            TlsError::InvalidCipherSuite(c) => write!(f, "invalid cipher suite: {:04x}", c),
            TlsError::InvalidCertificate => write!(f, "invalid certificate"),
            TlsError::CertificateVerificationFailed(msg) => {
                write!(f, "certificate verification failed: {}", msg)
            }
            TlsError::InvalidMac => write!(f, "invalid MAC"),
            TlsError::DecryptionFailed => write!(f, "decryption failed"),
            TlsError::EncryptionFailed => write!(f, "encryption failed"),
            TlsError::HandshakeFailed(msg) => write!(f, "handshake failed: {}", msg),
            TlsError::ConnectionClosed => write!(f, "connection closed"),
            TlsError::IoError(msg) => write!(f, "I/O error: {}", msg),
            TlsError::Alert(level, desc) => {
                write!(f, "TLS alert: {:?} - {:?}", level, desc)
            }
            TlsError::UnexpectedMessage => write!(f, "unexpected TLS message"),
            TlsError::DecodeError => write!(f, "TLS decode error"),
            TlsError::InternalError(msg) => write!(f, "internal TLS error: {}", msg),
            TlsError::CloseNotify => write!(f, "close notify"),
            TlsError::RecordOverflow => write!(f, "record overflow"),
            TlsError::NoApplicationProtocol => write!(f, "no application protocol"),
        }
    }
}

/// TLS alert level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    /// Warning alert
    Warning = 1,
    /// Fatal alert
    Fatal = 2,
    /// Close notify
    CloseNotify = 0,
}

impl TryFrom<u8> for AlertLevel {
    type Error = TlsError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(AlertLevel::Warning),
            2 => Ok(AlertLevel::Fatal),
            _ => Err(TlsError::DecodeError),
        }
    }
}

/// TLS alert descriptions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl TryFrom<u8> for AlertDescription {
    type Error = TlsError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AlertDescription::CloseNotify),
            10 => Ok(AlertDescription::UnexpectedMessage),
            20 => Ok(AlertDescription::BadRecordMac),
            21 => Ok(AlertDescription::DecryptionFailed),
            22 => Ok(AlertDescription::RecordOverflow),
            30 => Ok(AlertDescription::DecompressionFailure),
            40 => Ok(AlertDescription::HandshakeFailure),
            41 => Ok(AlertDescription::NoCertificate),
            42 => Ok(AlertDescription::BadCertificate),
            43 => Ok(AlertDescription::UnsupportedCertificate),
            44 => Ok(AlertDescription::CertificateRevoked),
            45 => Ok(AlertDescription::CertificateExpired),
            46 => Ok(AlertDescription::CertificateUnknown),
            47 => Ok(AlertDescription::IllegalParameter),
            48 => Ok(AlertDescription::UnknownCa),
            49 => Ok(AlertDescription::AccessDenied),
            50 => Ok(AlertDescription::DecodeError),
            51 => Ok(AlertDescription::DecryptError),
            60 => Ok(AlertDescription::ExportRestriction),
            70 => Ok(AlertDescription::ProtocolVersion),
            71 => Ok(AlertDescription::InsufficientSecurity),
            80 => Ok(AlertDescription::InternalError),
            90 => Ok(AlertDescription::UserCanceled),
            100 => Ok(AlertDescription::NoRenegotiation),
            110 => Ok(AlertDescription::UnsupportedExtension),
            111 => Ok(AlertDescription::CertificateUnobtainable),
            112 => Ok(AlertDescription::UnrecognizedName),
            113 => Ok(AlertDescription::BadCertificateStatusResponse),
            114 => Ok(AlertDescription::BadCertificateHashValue),
            115 => Ok(AlertDescription::UnknownPskIdentity),
            116 => Ok(AlertDescription::CertificateRequired),
            120 => Ok(AlertDescription::NoApplicationProtocol),
            _ => Err(TlsError::DecodeError),
        }
    }
}

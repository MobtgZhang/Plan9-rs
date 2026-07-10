//! TLS (Transport Layer Security) Module
//!
//! Implements TLS 1.2 protocol for secure communication.


extern crate alloc;

pub mod error;
pub mod prf;
pub mod handshake;
pub mod record;

pub use error::{TlsError, AlertLevel, AlertDescription};
pub use prf::{
    CipherSuite, BulkCipher, MacAlgorithm, 
    ExpandedKeys, MASTER_SECRET_SIZE, PREMASTER_SECRET_SIZE,
    compute_master_secret, compute_key_block, tls10_prf,
};
pub use handshake::{
    HandshakeType, ClientHello, ServerHello, Certificate, 
    ClientKeyExchange, Finished, ServerHelloDone, TlsVersion,
};
pub use record::{RecordLayer, ContentType};

/// TLS 1.2 protocol version
pub const TLS_1_2: u16 = 0x0303;

/// TLS result type
pub type TlsResult<T> = core::result::Result<T, TlsError>;

/// TLS connection role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Start,
    ExpectServerHello,
    ExpectCertificate,
    ExpectServerKeyExchange,
    ExpectServerHelloDone,
    ProcessingClientKeyExchange,
    ExpectChangeCipherSpec,
    ExpectFinished,
    HandshakeComplete,
    ApplicationData,
    Closed,
    Error,
}

impl Default for State {
    fn default() -> Self {
        State::Start
    }
}

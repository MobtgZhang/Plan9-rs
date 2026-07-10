//! IPsec Module
//!
//! Provides IPsec protocol implementation including:
//! - Security Association Database (SAD)
//! - Security Policy Database (SPD)
//! - Encapsulating Security Payload (ESP)
//! - Authentication Header (AH)
//!
//! Reference: Plan 9 libsec/port/


extern crate alloc;

pub mod sad;
pub mod spd;
pub mod esp;
pub mod ah;

pub use sad::{SecurityAssociation, SadEntry, SadDatabase};
pub use spd::{SecurityPolicy, SpdEntry, SpdDatabase, PolicyAction, IpCidr};
pub use esp::{EspHeader, EspTrailer, EspPacket};
pub use ah::{AhHeader, AhPacket};

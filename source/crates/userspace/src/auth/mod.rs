//! Authentication Module
//!
//! Provides authentication commands for Plan 9.

pub mod factotum;
pub mod authsrv;
pub mod auth_proxy;
pub mod login;
pub mod passwd;
pub mod keyfs;
pub mod secstore;
pub mod rsagen;
pub mod convkeys;
pub mod crypto;
pub mod conv;
pub mod rpc;
pub mod challenge;
pub mod newns;
pub mod p9sk1;  // P9SK1 protocol implementation

pub use auth_proxy::{AuthError, Authenticator, AuthInfo, AuthGetkey, AuthRpc};
pub use newns::{newns, NewnsResult, readnvram, authdial, userpasswd, userpasswd_default,
    NVREADMAX, factotum_rpc, auth_via_factotum};
pub use p9sk1::{P9SK1Authenticator, P9SK1_QID, AuthMessage, AuthMsgType,
    create_ticket, verify_ticket, password_to_key};

//! Server Processes Crate
//!
//! Provides file, process, and authentication server implementations.

#![no_std]

extern crate alloc;

pub mod fs;
pub mod proc;
pub mod auth;
pub mod refcount;
pub mod intmap;
pub mod reqpool;
pub mod tree;
pub mod dirread;
pub mod hasperm;
pub mod p9session;
pub mod p9server;
pub mod net;
pub mod venti;
pub mod rio;

pub use fs::{FileServer, MountTable, MountEntry};
pub use proc::{ProcServer, ProcTable, ProcInfo, ProcState};
pub use auth::{AuthServer, AuthError, Key, KeyType};
pub use refcount::{Ref, Rc};
pub use intmap::Intmap;
pub use reqpool::{ReqPool, PendingRequest, RequestState, ReqPoolError};
pub use tree::{Tree, File, Dir, Qid, qidtype, FileMode, TreeError};
pub use dirread::{DirReader, DirReadError, opendirfile, readdirfile, closedirfile};
pub use hasperm::{hasperm, can_read, can_write, can_execute, PermResult, is_owner, is_group};
pub use p9session::{P9Session, OpenMode, FidEntry, FidPool, SessionState, ProtocolVersion};
pub use net::protocol::{P9Msg, P9Codec, P9Error, Stat, Qid as NetQid};
pub use venti::{VentiServer, VentiServerConfig, VentiServerStats, VentiCache, VentiPacket, VentiError, Score, BlockType};

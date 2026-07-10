//! Acme Editor Library
//!
//! Acme is a minimalist text editor and integrated development environment
//! for Plan 9, featuring a simple UI model based on mouse gestures
//! and a 9P filesystem interface.
//!
//! ## Architecture
//!
//! - `Window`: The basic editing unit containing a text buffer and a tag
//! - `Column`: A vertical container for windows
//! - `Row`: A horizontal container for columns
//! - `Xfid`: 9P file system operations
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/acme/`

pub mod text;
pub mod window;
pub mod column;
pub mod row;
pub mod exec;
pub mod xfid;
pub mod edit;
pub mod look;
pub mod regx;
pub mod fsys;

pub use text::Text;
pub use window::Window;
pub use column::Column;
pub use row::Row;
pub use exec::Executor;
pub use xfid::Xfid;
pub use edit::Editor;
pub use look::Look;

/// Default column count
pub const DEFAULT_NCOL: i32 = 2;

/// Maximum file name length
pub const MAXFN: usize = 256;

/// Maximum tag length
pub const MAXTAG: usize = 256;

/// Default auto-indent setting
pub const DEFAULT_AUTOINDENT: bool = true;

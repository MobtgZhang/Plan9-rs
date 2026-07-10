//! Display subsystem types for the drivers crate.
//!
//! Provides connector detection, EDID parsing, and standard video mode tables.

pub mod connector;
pub mod edid;
pub mod mode;

pub use connector::{ConnectorKind, connector_name, detect_connector};
pub use edid::EdidInfo;
pub use mode::{DisplayMode, COMMON_MODES, find_mode, best_mode};

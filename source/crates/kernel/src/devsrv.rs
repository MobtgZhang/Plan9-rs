//! Srv Device - Service Device
//!
//! The srv device provides access to kernel services through the file system.
//! It allows processes to open service connections and interact with them.
//!
//! Reference: Plan 9 sys/src/9/port/devsrv.c

// use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::boxed::Box;

use crate::dev::{Dev, Chan, Qid, DirEntry, qidtype, Error as DevError, devtype};
use crate::plan9_common::sync::Spinlock;
// use crate::block::Block;

// Type alias for convenience - using different name to avoid conflict
type DevResult<T> = core::result::Result<T, DevError>;

// ============================================================================
// Srv Device Structure
// ============================================================================

/// Srv device
pub struct SrvDev {
    /// Device state
    state: Spinlock<SrvState>,
}

/// Service entry
#[derive(Clone)]
pub struct SrvEntry {
    /// Service name
    name: String,
    /// Service description
    description: String,
    /// Whether service is active
    active: bool,
}

/// Srv device state
#[derive(Clone)]
struct SrvState {
    /// Registered services
    services: Vec<SrvEntry>,
    /// Next service ID
    next_id: u32,
}

impl SrvDev {
    /// Create a new srv device
    pub fn new() -> Self {
        Self {
            state: Spinlock::new(SrvState {
                services: Vec::new(),
                next_id: 1,
            }),
        }
    }

    /// Register a service
    pub fn register_service(&self, name: &str, description: &str) -> u32 {
        let mut state = self.state.lock();
        let id = state.next_id;
        state.next_id += 1;
        state.services.push(SrvEntry {
            name: String::from(name),
            description: String::from(description),
            active: true,
        });
        id
    }

    /// Unregister a service
    pub fn unregister_service(&self, name: &str) -> bool {
        let mut state = self.state.lock();
        if let Some(pos) = state.services.iter().position(|s| s.name == name) {
            state.services.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get a service by name
    pub fn get_service(&self, name: &str) -> Option<SrvEntry> {
        let state = self.state.lock();
        state.services.iter().find(|s| s.name == name).cloned()
    }

    /// List all services
    pub fn list_services(&self) -> Vec<String> {
        let state = self.state.lock();
        state.services.iter().map(|s| s.name.clone()).collect()
    }
}

impl Clone for SrvDev {
    fn clone(&self) -> Self {
        // Note: Cloning SrvDev creates a new handle to the same underlying state
        // We just wrap the same Spinlock in a new struct
        Self {
            state: Spinlock::new(self.state.lock().clone()),
        }
    }
}

impl Default for SrvDev {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Dev Implementation
// ============================================================================

impl Dev for SrvDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, DevError> {
        Ok(Chan::new(
            devtype::MNT,
            Qid::new(0, 0, qidtype::DIR),
            0,
        ))
    }

    fn walk(&mut self, chan: &mut Chan, name: &str) -> Result<Option<Qid>, DevError> {
        let state = self.state.lock();
        
        // Check if service exists
        if let Some(_service) = state.services.iter().find(|s| s.name == name) {
            chan.qid = Qid::new(
                0,
                0,
                0,
            );
            Ok(Some(chan.qid))
        } else {
            Err(DevError::Enoent)
        }
    }

    fn open(&mut self, chan: &mut Chan, mode: u8) -> Result<(), DevError> {
        chan.mode = mode;
        Ok(())
    }

    fn create(&mut self, _chan: &mut Chan, _name: &str, _mode: u8, _perm: u32) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn close(&mut self, _chan: &mut Chan) {
    }

    fn read(&mut self, _chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, DevError> {
        let state = self.state.lock();

        let mut total = 0;

        for (i, service) in state.services.iter().enumerate() {
            if (i as u64) < offset {
                continue;
            }

            let entry = format!("{}\n", service.name);
            let entry_bytes = entry.as_bytes();

            if total + entry_bytes.len() > buf.len() {
                break;
            }

            buf[total..total + entry_bytes.len()].copy_from_slice(entry_bytes);
            total += entry_bytes.len();
        }

        Ok(total)
    }

    fn write(&mut self, _chan: &mut Chan, _buf: &[u8], _offset: u64) -> Result<usize, DevError> {
        Err(DevError::Eperm)
    }

    fn stat(&mut self, chan: &mut Chan) -> Result<DirEntry, DevError> {
        Ok(DirEntry {
            dev: devtype::MNT,
            qid: chan.qid,
            mode: 0o0555 | 0o40000,
            atime: 0,
            mtime: 0,
            length: 0,
            name: b"srv".to_vec(),
        })
    }

    fn wstat(&mut self, _chan: &mut Chan, _dir: &DirEntry) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn remove(&mut self, _chan: &mut Chan) -> Result<(), DevError> {
        Err(DevError::Eperm)
    }

    fn dev_char(&self) -> char {
        's'
    }

    fn name(&self) -> &'static str {
        "srv"
    }
}

// ============================================================================
// Global Srv Device Instance
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static SRV_DEVICE: AtomicPtr<SrvDev> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the srv device
pub fn init_srv() {
    let dev = Box::new(SrvDev::new());
    
    // Register default services
    dev.register_service("cons", "Console service");
    dev.register_service("fs", "File system service");
    dev.register_service("auth", "Authentication service");
    
    let ptr = Box::into_raw(dev);
    SRV_DEVICE.store(ptr, Ordering::SeqCst);
}

/// Get the srv device
pub fn srv_device() -> &'static SrvDev {
    unsafe { &*SRV_DEVICE.load(Ordering::SeqCst) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv_creation() {
        let srv = SrvDev::new();
        assert!(srv.list_services().is_empty());
    }

    #[test]
    fn test_register_service() {
        let srv = SrvDev::new();
        let id = srv.register_service("test", "Test service");
        assert_eq!(id, 1);
        
        let services = srv.list_services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0], "test");
    }

    #[test]
    fn test_unregister_service() {
        let srv = SrvDev::new();
        srv.register_service("test", "Test service");
        
        assert!(srv.unregister_service("test"));
        assert!(srv.list_services().is_empty());
        
        assert!(!srv.unregister_service("nonexistent"));
    }

    #[test]
    fn test_get_service() {
        let srv = SrvDev::new();
        srv.register_service("test", "Test service");
        
        let service = srv.get_service("test");
        assert!(service.is_some());
        assert_eq!(service.unwrap().description, "Test service");
        
        assert!(srv.get_service("nonexistent").is_none());
    }
}

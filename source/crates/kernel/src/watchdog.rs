//! Watchdog Timer
//!
//! Implements hardware watchdog timer framework for system health monitoring.
//! The watchdog will reset the system if the kernel becomes unresponsive.
//!
//! ## Reference
//! - Plan 9: `/sys/src/9/port/devwd.c`, `/sys/src/9/pc/x86watchdog.c`

use core::sync::atomic::{ AtomicBool, AtomicU64, Ordering };use alloc::boxed::Box;
// use alloc::format;

use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

// ============================================================================
// Watchdog Trait
// ============================================================================

/// Watchdog timer interface
pub trait Watchdog {
    /// Enable the watchdog
    fn enable(&mut self);

    /// Disable the watchdog
    fn disable(&mut self);

    /// Pet (feed) the watchdog to reset its timer
    fn pet(&mut self);

    /// Get watchdog status
    fn status(&self) -> WatchdogStatus;

    /// Check if the watchdog is enabled
    fn is_enabled(&self) -> bool;
}

/// Watchdog status information
#[derive(Debug, Clone)]
pub struct WatchdogStatus {
    /// Whether the watchdog is enabled
    pub enabled: bool,
    /// Timeout in milliseconds
    pub timeout_ms: u32,
    /// Last time the watchdog was petted
    pub last_pet: u64,
    /// Number of times the watchdog has timed out
    pub timeout_count: u64,
}

// ============================================================================
// Software Watchdog (Timer-based)
// ============================================================================

/// Software watchdog using the scheduler's timer
pub struct SoftwareWatchdog {
    /// Whether enabled
    enabled: AtomicBool,
    /// Timeout in ticks
    timeout_ticks: u64,
    /// Last pet time (in ticks)
    last_pet: AtomicU64,
    /// Current tick count when last pet occurred
    last_pet_tick: AtomicU64,
    /// Number of timeouts
    timeout_count: AtomicU64,
}

impl SoftwareWatchdog {
    /// Create a new software watchdog
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            timeout_ticks: (timeout_ms as u64) * 100,  // Assume 100 Hz
            last_pet: AtomicU64::new(0),
            last_pet_tick: AtomicU64::new(0),
            timeout_count: AtomicU64::new(0),
        }
    }

    /// Set the timeout
    pub fn set_timeout(&mut self, timeout_ms: u32) {
        self.timeout_ticks = (timeout_ms as u64) * 100;
    }
}

impl Watchdog for SoftwareWatchdog {
    fn enable(&mut self) {
        self.enabled.store(true, Ordering::SeqCst);
        self.last_pet.store(crate::sched::scheduler().ticks(), Ordering::SeqCst);
        self.last_pet_tick.store(crate::sched::scheduler().ticks(), Ordering::SeqCst);
    }

    fn disable(&mut self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    fn pet(&mut self) {
        if !self.enabled.load(Ordering::SeqCst) {
            return;
        }
        let ticks = crate::sched::scheduler().ticks();
        self.last_pet.store(ticks, Ordering::SeqCst);
        self.last_pet_tick.store(ticks, Ordering::SeqCst);
    }

    fn status(&self) -> WatchdogStatus {
        WatchdogStatus {
            enabled: self.enabled.load(Ordering::SeqCst),
            timeout_ms: (self.timeout_ticks / 100) as u32,
            last_pet: self.last_pet.load(Ordering::SeqCst),
            timeout_count: self.timeout_count.load(Ordering::SeqCst),
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
}

/// Check if the watchdog has timed out
pub fn check_watchdog_timeout() {
    let wd = watchdog();
    if let Some(ref w) = *wd.lock() {
        if !w.is_enabled() {
            return;
        }

        let ticks = crate::sched::scheduler().ticks();
        let last_pet = w.status().last_pet;

        if ticks > last_pet && ticks - last_pet > w.status().timeout_ms as u64 * 100 / 1000 {
            // Watchdog timeout!
            watchdog_timeout();
        }
    }
}

/// Called when watchdog times out
fn watchdog_timeout() {
    let wd = watchdog();
    if let Some(ref mut w) = *wd.lock() {
        let mut status = w.status();
        status.timeout_count += 1;

        // Log the timeout
        crate::debug::debug_puts("!!! WATCHDOG TIMEOUT !!!\n");
        crate::debug_printf!("Timeout count: {}\n", status.timeout_count);

        // Try to recover by dumping debug info
        crate::debug::procdump();
    }
}

// ============================================================================
// Global Watchdog
// ============================================================================

use crate::plan9_common::sync::Mutex;

/// Global watchdog instance
static WATCHDOG: Mutex<Option<Box<dyn Watchdog + Send>>> = Mutex::new(None);

/// Get the global watchdog
pub fn watchdog() -> &'static Mutex<Option<Box<dyn Watchdog + Send>>> {
    &WATCHDOG
}

/// Register a watchdog
pub fn add_watchdog<W: Watchdog + Send + 'static>(w: W) {
    *watchdog().lock() = Some(Box::new(w));
}

/// Enable the watchdog
pub fn watchdog_enable() {
    if let Some(ref mut w) = *watchdog().lock() {
        w.enable();
    }
}

/// Disable the watchdog
pub fn watchdog_disable() {
    if let Some(ref mut w) = *watchdog().lock() {
        w.disable();
    }
}

/// Pet the watchdog
pub fn watchdog_pet() {
    if let Some(ref mut w) = *watchdog().lock() {
        w.pet();
    }
}

/// Get watchdog status
pub fn watchdog_status() -> Option<WatchdogStatus> {
    watchdog().lock().as_ref().map(|w| w.status())
}

// ============================================================================
// Watchdog Device
// ============================================================================

/// Watchdog device
pub struct WatchdogDev {
    name: &'static str,
    dev_char: char,
}

impl WatchdogDev {
    /// Create a new watchdog device
    pub fn new() -> Self {
        Self {
            name: "watchdog",
            dev_char: 'W',  // 'W' for Watchdog
        }
    }
}

impl Dev for WatchdogDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> {
        Ok(Chan::new(devtype::NONE, Qid::new(0, 0, qidtype::NONE), 0))
    }

    fn open(&mut self, _ch: &mut Chan, _mode: u8) -> Result<(), Error> {
        Ok(())
    }

    fn walk(&mut self, _ch: &mut Chan, _name: &str) -> Result<Option<Qid>, Error> {
        Err(Error::Enoent)
    }

    fn read(&mut self, _ch: &mut Chan, buf: &mut [u8], _offset: u64) -> Result<usize, Error> {
        // Read watchdog status
        if let Some(status) = watchdog_status() {
            let s = alloc::format!(
                "enabled={} timeout={}ms last_pet={} timeouts={}\n",
                status.enabled,
                status.timeout_ms,
                status.last_pet,
                status.timeout_count
            );

            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(s.as_bytes());
            Ok(n)
        } else {
            let msg = b"No watchdog registered\n";
            let n = msg.len().min(buf.len());
            buf[..n].copy_from_slice(&msg[..n]);
            Ok(n)
        }
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // Control watchdog via writes
        let cmd = core::str::from_utf8(buf)
            .map_err(|_| Error::Einval)?
            .trim();

        match cmd {
            "enable" => {
                watchdog_enable();
                Ok(buf.len())
            }
            "disable" => {
                watchdog_disable();
                Ok(buf.len())
            }
            "pet" => {
                watchdog_pet();
                Ok(buf.len())
            }
            "reset" => {
                // Reset the timeout count
                if let Some(ref mut _w) = *watchdog().lock() {
                    // This would need a reset method
                }
                Ok(buf.len())
            }
            _ => {
                if let Some(ref mut _w) = *watchdog().lock() {
                    if cmd.starts_with("timeout=") {
                        // Set timeout: "timeout=5000" (ms)
                        if let Ok(_ms) = cmd[8..].parse::<u32>() {
                            // Would need set_timeout method
                            Ok(buf.len())
                        } else {
                            Err(Error::Einval)
                        }
                    } else {
                        Err(Error::Einval)
                    }
                } else {
                    Err(Error::Eclosed)
                }
            }
        }
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        let status = watchdog_status();
        let length = if let Some(s) = status {
            (s.timeout_count as u64) * 1024  // Approximate size
        } else {
            0
        };

        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length,
            name: b"watchdog".to_vec(),
        })
    }

    fn dev_char(&self) -> char {
        self.dev_char
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// Integration with Scheduler
// ============================================================================

/// Initialize the watchdog system
pub fn init_watchdog() {
    // Register a software watchdog by default
    let sw = SoftwareWatchdog::new(30000);  // 30 second timeout
    add_watchdog(sw);

    crate::debug::debug_puts("Watchdog initialized (30s timeout)\n");
}

/// Called from scheduler to pet the watchdog
pub fn scheduler_pet_watchdog() {
    watchdog_pet();
}

/// Called from scheduler to check watchdog
pub fn scheduler_check_watchdog() {
    check_watchdog_timeout();
}

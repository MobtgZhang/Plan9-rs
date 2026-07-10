//! Performance Profiler
//!
//! Implements kernel and user-space profiling support similar to Plan 9's
//! proftimer and kproftimer mechanisms.
//!
//! ## Reference
//! - Plan 9: `/sys/src/9/port/proc.c` (proftimer)

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::boxed::Box;

use crate::proc::{ Pid, curproc };use crate::dev::{Chan, Qid, Error, devtype, qidtype, Dev, DirEntry};

/// Maximum number of profiling samples
pub const PROF_SAMPLES: usize = 4096;

/// Profiling sample
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProfSample {
    /// Program counter
    pub pc: u64,
    /// Process ID (0 for kernel)
    pub pid: Pid,
    /// Timestamp (in ticks)
    pub timestamp: u64,
    /// CPU state
    pub cpu: u32,
}

/// Kernel profiling configuration
pub struct KprofConfig {
    /// Whether profiling is enabled
    pub enabled: AtomicBool,
    /// Sampling rate (samples per second)
    pub rate: AtomicU64,
    /// Sample count
    pub count: AtomicU64,
    /// Last sample time
    pub last_sample: AtomicU64,
}

impl KprofConfig {
    /// Create new configuration
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            rate: AtomicU64::new(100),  // 100 Hz default
            count: AtomicU64::new(0),
            last_sample: AtomicU64::new(0),
        }
    }

    /// Enable profiling
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable profiling
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// Check if profiling is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Set sampling rate
    pub fn set_rate(&self, rate: u64) {
        self.rate.store(rate, Ordering::SeqCst);
    }

    /// Get current rate
    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::SeqCst)
    }

    /// Get sample count
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }

    /// Increment sample count
    pub fn increment_count(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

/// Kernel profiler
pub struct Kprof {
    /// Configuration
    config: KprofConfig,
    /// Sample buffer (circular)
    samples: [ProfSample; PROF_SAMPLES],
    /// Next sample index
    next: AtomicUsize,
}

impl Kprof {
    /// Create new kernel profiler
    pub fn new() -> Self {
        Self {
            config: KprofConfig::new(),
            samples: [ProfSample {
                pc: 0,
                pid: 0,
                timestamp: 0,
                cpu: 0,
            }; PROF_SAMPLES],
            next: AtomicUsize::new(0),
        }
    }

    /// Record a sample
    /// Called from timer interrupt
    pub fn sample(&mut self, pc: u64) {
        if !self.config.is_enabled() {
            return;
        }

        let idx = self.next.load(Ordering::Relaxed);
        let pid = curproc().map(|p| p.pid).unwrap_or(0);

        // Get current tick count
        let ticks = crate::sched::scheduler().ticks();

        self.samples[idx] = ProfSample {
            pc,
            pid,
            timestamp: ticks,
            cpu: 0,
        };

        // Advance to next slot (circular buffer)
        let next_idx = (idx + 1) % PROF_SAMPLES;
        self.next.store(next_idx, Ordering::Relaxed);

        self.config.increment_count();
    }

    /// Read samples
    pub fn read_samples(&self, buf: &mut [ProfSample]) -> usize {
        let count = self.config.count() as usize;
        let next = self.next.load(Ordering::Relaxed);

        if count == 0 {
            return 0;
        }

        let samples_to_read = count.min(buf.len()).min(PROF_SAMPLES);
        let start = if count >= PROF_SAMPLES {
            next  // Buffer has wrapped, start at next
        } else {
            0     // Buffer not full, start at beginning
        };

        for i in 0..samples_to_read {
            let idx = (start + i) % PROF_SAMPLES;
            buf[i] = self.samples[idx];
        }

        samples_to_read
    }

    /// Get configuration reference
    pub fn config(&self) -> &KprofConfig {
        &self.config
    }

    /// Reset profiler
    pub fn reset(&self) {
        self.config.count.store(0, Ordering::Relaxed);
        self.next.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Global Kernel Profiler
// ============================================================================

use core::sync::atomic::AtomicPtr;

static KPROF: AtomicPtr<Kprof> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize kernel profiler
pub fn init_kprof() {
    let prof = Box::new(Kprof::new());
    KPROF.store(Box::into_raw(prof), Ordering::SeqCst);
}

/// Get global kernel profiler
pub fn kprof() -> &'static Kprof {
    unsafe { &*KPROF.load(Ordering::SeqCst) }
}

/// Get mutable global kernel profiler
pub fn kprof_mut() -> &'static mut Kprof {
    unsafe { &mut *KPROF.load(Ordering::SeqCst) }
}

/// Sample the current program counter
/// Called from timer interrupt
pub fn kprof_sample(pc: u64) {
    kprof_mut().sample(pc);
}

// ============================================================================
// User-Space Profiling Support
// ============================================================================

/// Per-process profiler state
pub struct ProcProf {
    /// Profiling enabled
    enabled: AtomicBool,
    /// Sample buffer
    samples: [ProfSample; PROF_SAMPLES],
    /// Next sample index
    next: AtomicUsize,
    /// Total samples collected
    count: AtomicU64,
}

impl ProcProf {
    /// Create new process profiler
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            samples: [ProfSample {
                pc: 0,
                pid: 0,
                timestamp: 0,
                cpu: 0,
            }; PROF_SAMPLES],
            next: AtomicUsize::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Enable profiling for this process
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable profiling
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Record a sample
    pub fn sample(&mut self, pc: u64, pid: Pid) {
        if !self.is_enabled() {
            return;
        }

        let idx = self.next.load(Ordering::Relaxed);
        let ticks = crate::sched::scheduler().ticks();

        self.samples[idx] = ProfSample {
            pc,
            pid,
            timestamp: ticks,
            cpu: 0,
        };

        let next_idx = (idx + 1) % PROF_SAMPLES;
        self.next.store(next_idx, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Read samples
    pub fn read_samples(&self, buf: &mut [ProfSample]) -> usize {
        let count = self.count.load(Ordering::Relaxed) as usize;
        let next = self.next.load(Ordering::Relaxed);

        if count == 0 {
            return 0;
        }

        let samples_to_read = count.min(buf.len()).min(PROF_SAMPLES);
        let start = if count >= PROF_SAMPLES {
            next
        } else {
            0
        };

        for i in 0..samples_to_read {
            let idx = (start + i) % PROF_SAMPLES;
            buf[i] = self.samples[idx];
        }

        samples_to_read
    }

    /// Reset
    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.next.store(0, Ordering::Relaxed);
        self.enabled.store(false, Ordering::SeqCst);
    }
}

/// Global profiler statistics
pub static PROF_STATS: ProfStats = ProfStats::new();

/// Profiling statistics
pub struct ProfStats {
    /// Total kernel samples
    pub kernel_samples: AtomicU64,
    /// Total user samples
    pub user_samples: AtomicU64,
    /// Sample rate
    pub sample_rate: AtomicU64,
}

impl ProfStats {
    pub const fn new() -> Self {
        Self {
            kernel_samples: AtomicU64::new(0),
            user_samples: AtomicU64::new(0),
            sample_rate: AtomicU64::new(100),
        }
    }

    /// Increment kernel sample
    pub fn inc_kernel_sample(&self) {
        self.kernel_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment user sample
    pub fn inc_user_sample(&self) {
        self.user_samples.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Profiler Device (for reading profile data)
// ============================================================================

/// Profiler device for reading profile data
pub struct ProfDev {
    name: &'static str,
    dev_char: char,
}

impl ProfDev {
    /// Create new profiler device
    pub fn new() -> Self {
        Self {
            name: "prof",
            dev_char: 'P',  // 'P' for profiler
        }
    }
}

impl Dev for ProfDev {
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
        // Read kernel profiling samples
        let mut samples = [ProfSample {
            pc: 0,
            pid: 0,
            timestamp: 0,
            cpu: 0,
        }; PROF_SAMPLES];

        let count = kprof().read_samples(&mut samples);
        let len = (count * core::mem::size_of::<ProfSample>()).min(buf.len());

        // Copy samples to output buffer
        let src = unsafe {
            core::slice::from_raw_parts(
                samples.as_ptr() as *const u8,
                len
            )
        };
        buf[..len].copy_from_slice(src);

        Ok(len)
    }

    fn write(&mut self, _ch: &mut Chan, buf: &[u8], _offset: u64) -> Result<usize, Error> {
        // Control profiler via writes
        // Format: "enable", "disable", "reset", or rate setting
        if buf.starts_with(b"enable") {
            kprof().config().enable();
            Ok(6)
        } else if buf.starts_with(b"disable") {
            kprof().config().disable();
            Ok(7)
        } else if buf.starts_with(b"reset") {
            kprof().reset();
            Ok(5)
        } else if buf.starts_with(b"rate=") {
            // Parse rate: "rate=100"
            if let Ok(rate_str) = core::str::from_utf8(&buf[5..]) {
                let rate_str = rate_str.trim_end_matches(|c| c == '\n' || c == '\r' || c == '\0');
                if let Ok(rate) = rate_str.parse::<u64>() {
                    kprof().config().set_rate(rate);
                    Ok(buf.len())
                } else {
                    Err(Error::Einval)
                }
            } else {
                Err(Error::Einval)
            }
        } else {
            Err(Error::Einval)
        }
    }

    fn stat(&mut self, _ch: &mut Chan) -> Result<DirEntry, Error> {
        let config = kprof().config();
        Ok(DirEntry {
            dev: devtype::NONE,
            qid: Qid::new(0, 0, qidtype::NONE),
            mode: 0o666,
            atime: 0,
            mtime: 0,
            length: config.count() * (core::mem::size_of::<ProfSample>() as u64),
            name: b"prof".to_vec(),
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

/// Called from scheduler to perform profiling
pub fn scheduler_profile_tick(pc: u64) {
    if kprof().config().is_enabled() {
        kprof_sample(pc);
    }
}

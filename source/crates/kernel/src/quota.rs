//! Resource Quota and Limit System
//!
//! Implements Plan 9 style resource limits and quotas:
//! - User resource limits
//! - Process resource limits
//! - Kernel resource watermarks
//! - Memory pressure detection
//!
//! In Plan 9, quotas are enforced through the kernel's resource management
//! and the factotum authentication system rather than a separate quota daemon.

use alloc::boxed::Box;
use crate::plan9_common::sync::Spinlock;

/// Resource types that can be limited
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceType {
    /// Maximum memory in bytes
    Memory,
    /// Maximum file size in bytes
    FileSize,
    /// Maximum number of open files
    OpenFiles,
    /// Maximum number of processes
    Processes,
    /// Maximum CPU time in milliseconds
    CpuTime,
    /// Maximum swap usage in bytes
    SwapUsage,
    /// Maximum disk space in bytes
    DiskSpace,
}

/// Resource limit (soft and hard limits)
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceLimit {
    /// Current (soft) limit
    pub soft: u64,
    /// Maximum (hard) limit
    pub hard: u64,
}

impl ResourceLimit {
    /// Create a new resource limit
    pub fn new(soft: u64, hard: u64) -> Self {
        Self { soft, hard }
    }

    /// Create an unlimited limit
    pub fn unlimited() -> Self {
        Self {
            soft: u64::MAX,
            hard: u64::MAX,
        }
    }

    /// Check if the value exceeds the soft limit
    pub fn exceeds_soft(&self, value: u64) -> bool {
        self.soft != u64::MAX && value > self.soft
    }

    /// Check if the value exceeds the hard limit
    pub fn exceeds_hard(&self, value: u64) -> bool {
        self.hard != u64::MAX && value > self.hard
    }

    /// Try to increase soft limit (must not exceed hard)
    pub fn raise_soft(&mut self, new_soft: u64) -> bool {
        if new_soft <= self.hard {
            self.soft = new_soft;
            true
        } else {
            false
        }
    }
}

/// Per-user resource usage tracking
#[derive(Debug, Clone, Default)]
pub struct UserQuota {
    /// User ID
    pub uid: u32,
    /// Current memory usage in bytes
    pub memory_used: u64,
    /// Maximum memory allowed
    pub memory_limit: ResourceLimit,
    /// Current file size in bytes
    pub file_size_used: u64,
    /// Maximum file size
    pub file_size_limit: ResourceLimit,
    /// Number of open files
    pub open_files: u32,
    /// Maximum open files
    pub open_files_limit: ResourceLimit,
    /// Number of processes
    pub processes: u32,
    /// Maximum processes
    pub processes_limit: ResourceLimit,
    /// Total disk space used in bytes
    pub disk_used: u64,
    /// Maximum disk space
    pub disk_limit: ResourceLimit,
    /// CPU time used in milliseconds
    pub cpu_time: u64,
    /// Maximum CPU time
    pub cpu_time_limit: ResourceLimit,
}

impl UserQuota {
    /// Create a new quota for a user
    pub fn new(uid: u32) -> Self {
        Self {
            uid,
            memory_used: 0,
            memory_limit: ResourceLimit::unlimited(),
            file_size_used: 0,
            file_size_limit: ResourceLimit::unlimited(),
            open_files: 0,
            open_files_limit: ResourceLimit::new(256, 1024),
            processes: 0,
            processes_limit: ResourceLimit::new(64, 256),
            disk_used: 0,
            disk_limit: ResourceLimit::unlimited(),
            cpu_time: 0,
            cpu_time_limit: ResourceLimit::unlimited(),
        }
    }

    /// Check if user can allocate memory
    pub fn can_alloc_memory(&self, bytes: u64) -> bool {
        !self.memory_limit.exceeds_hard(self.memory_used + bytes)
    }

    /// Allocate memory to user quota
    pub fn alloc_memory(&mut self, bytes: u64) -> bool {
        if self.can_alloc_memory(bytes) {
            self.memory_used += bytes;
            true
        } else {
            false
        }
    }

    /// Free memory from user quota
    pub fn free_memory(&mut self, bytes: u64) {
        self.memory_used = self.memory_used.saturating_sub(bytes);
    }

    /// Check if user can open another file
    pub fn can_open_file(&self) -> bool {
        !self.open_files_limit.exceeds_hard(self.open_files as u64 + 1)
    }

    /// Open file (increment counter)
    pub fn open_file(&mut self) -> bool {
        if self.can_open_file() {
            self.open_files += 1;
            true
        } else {
            false
        }
    }

    /// Close file (decrement counter)
    pub fn close_file(&mut self) {
        self.open_files = self.open_files.saturating_sub(1);
    }

    /// Check if user can create another process
    pub fn can_fork(&self) -> bool {
        !self.processes_limit.exceeds_hard(self.processes as u64 + 1)
    }

    /// Fork (increment counter)
    pub fn fork(&mut self) -> bool {
        if self.can_fork() {
            self.processes += 1;
            true
        } else {
            false
        }
    }

    /// Exit process (decrement counter)
    pub fn exit(&mut self) {
        self.processes = self.processes.saturating_sub(1);
    }

    /// Check disk space limit
    pub fn can_use_disk(&self, bytes: u64) -> bool {
        !self.disk_limit.exceeds_hard(self.disk_used + bytes)
    }

    /// Use disk space
    pub fn use_disk(&mut self, bytes: u64) -> bool {
        if self.can_use_disk(bytes) {
            self.disk_used += bytes;
            true
        } else {
            false
        }
    }

    /// Free disk space
    pub fn free_disk(&mut self, bytes: u64) {
        self.disk_used = self.disk_used.saturating_sub(bytes);
    }
}

/// Process resource usage
#[derive(Debug, Clone, Default)]
pub struct ProcResourceUsage {
    /// CPU time in milliseconds
    pub cpu_time: u64,
    /// Memory in bytes
    pub memory: u64,
    /// Number of context switches
    pub context_switches: u64,
    /// Number of file descriptors
    pub file_descriptors: u32,
    /// I/O bytes read
    pub io_read: u64,
    /// I/O bytes written
    pub io_write: u64,
    /// Start time (in clock ticks)
    pub start_time: u64,
}

/// Per-process resource limits
#[derive(Debug, Clone, Default)]
pub struct ProcLimits {
    /// Maximum file size (bytes)
    pub max_file_size: u64,
    /// Maximum memory (bytes)
    pub max_memory: u64,
    /// Maximum stack size (bytes)
    pub max_stack: u64,
    /// Maximum CPU time (ms)
    pub max_cpu_time: u64,
    /// Maximum number of files
    pub max_open_files: u32,
    /// Maximum number of child processes
    pub max_children: u32,
    /// Current working directory
    pub cwd: Option<u32>,
}

impl ProcLimits {
    /// Create default limits
    pub fn default_limits() -> Self {
        Self {
            max_file_size: u64::MAX,
            max_memory: 256 * 1024 * 1024, // 256 MB
            max_stack: 8 * 1024 * 1024,   // 8 MB
            max_cpu_time: u64::MAX,
            max_open_files: 64,
            max_children: 8,
            cwd: None,
        }
    }

    /// Check if a file size is allowed
    pub fn can_write_file(&self, current_size: u64, write_size: u64) -> bool {
        if self.max_file_size == u64::MAX {
            return true;
        }
        current_size + write_size <= self.max_file_size
    }

    /// Check if memory allocation is allowed
    pub fn can_alloc_memory(&self, current: u64, additional: u64) -> bool {
        current + additional <= self.max_memory
    }
}

/// Kernel watermark structure
///
/// Tracks kernel memory usage and triggers actions when thresholds are reached.
#[derive(Debug, Clone, Default)]
pub struct Watermark {
    /// Current usage
    pub current: usize,
    /// Low watermark (action needed)
    pub low: usize,
    /// High watermark (action needed)
    pub high: usize,
    /// Maximum allowed
    pub max: usize,
}

impl Watermark {
    /// Create a new watermark
    pub fn new(low: usize, high: usize, max: usize) -> Self {
        Self {
            current: 0,
            low,
            high,
            max,
        }
    }

    /// Update current usage
    pub fn set(&mut self, current: usize) {
        self.current = current;
    }

    /// Add to current usage
    pub fn add(&mut self, amount: usize) {
        self.current += amount;
    }

    /// Subtract from current usage
    pub fn sub(&mut self, amount: usize) {
        self.current = self.current.saturating_sub(amount);
    }

    /// Check if we're at low watermark (need to start freeing)
    pub fn is_low(&self) -> bool {
        self.current >= self.low
    }

    /// Check if we're at high watermark (urgent freeing needed)
    pub fn is_high(&self) -> bool {
        self.current >= self.high
    }

    /// Check if we've hit the maximum
    pub fn is_max(&self) -> bool {
        self.current >= self.max
    }

    /// Get percentage of max used
    pub fn percent_used(&self) -> u32 {
        if self.max == 0 {
            return 0;
        }
        ((self.current as u64 * 100) / self.max as u64) as u32
    }
}

/// Global quota manager
pub struct QuotaManager {
    /// Per-user quotas
    user_quotas: Spinlock<alloc::vec::Vec<UserQuota>>,
    /// Kernel memory watermark
    kernel_memory: Spinlock<Watermark>,
    /// User memory watermark
    user_memory: Spinlock<Watermark>,
    /// Swap watermark
    swap: Spinlock<Watermark>,
}

impl QuotaManager {
    /// Create a new quota manager
    pub fn new() -> Self {
        Self {
            user_quotas: Spinlock::new(alloc::vec::Vec::new()),
            kernel_memory: Spinlock::new(Watermark::new(
                8 * 1024 * 1024,  // 8 MB low
                16 * 1024 * 1024, // 16 MB high
                32 * 1024 * 1024, // 32 MB max
            )),
            user_memory: Spinlock::new(Watermark::new(
                64 * 1024 * 1024,  // 64 MB low
                128 * 1024 * 1024, // 128 MB high
                256 * 1024 * 1024, // 256 MB max
            )),
            swap: Spinlock::new(Watermark::new(
                256 * 1024 * 1024,   // 256 MB low
                512 * 1024 * 1024,   // 512 MB high
                1024 * 1024 * 1024,  // 1 GB max
            )),
        }
    }

    /// Get or create quota index for a user
    ///
    /// Returns the index of the user's quota in the internal vector.
    /// The quota can be accessed via `user_quotas.lock()[index]`.
    pub fn user_quota_index(&self, uid: u32) -> Option<usize> {
        // First check without mutable borrow
        {
            let quotas = self.user_quotas.lock();
            for (i, quota) in quotas.iter().enumerate() {
                if quota.uid == uid {
                    return Some(i);
                }
            }
        }
        
        // Create new quota
        let mut quotas = self.user_quotas.lock();
        quotas.push(UserQuota::new(uid));
        Some(quotas.len() - 1)
    }

    /// Check if kernel memory is low
    pub fn kernel_memory_low(&self) -> bool {
        self.kernel_memory.lock().is_low()
    }

    /// Check if kernel memory is critical
    pub fn kernel_memory_high(&self) -> bool {
        self.kernel_memory.lock().is_high()
    }

    /// Update kernel memory usage
    pub fn set_kernel_memory(&self, bytes: usize) {
        self.kernel_memory.lock().set(bytes);
    }

    /// Add kernel memory
    pub fn add_kernel_memory(&self, bytes: usize) {
        self.kernel_memory.lock().add(bytes);
    }

    /// Free kernel memory
    pub fn free_kernel_memory(&self, bytes: usize) {
        self.kernel_memory.lock().sub(bytes);
    }

    /// Check if user memory is low
    pub fn user_memory_low(&self) -> bool {
        self.user_memory.lock().is_low()
    }

    /// Check if user memory is critical
    pub fn user_memory_high(&self) -> bool {
        self.user_memory.lock().is_high()
    }

    /// Update user memory usage
    pub fn set_user_memory(&self, bytes: usize) {
        self.user_memory.lock().set(bytes);
    }

    /// Check if swap is low
    pub fn swap_low(&self) -> bool {
        self.swap.lock().is_low()
    }

    /// Check if swap is critical
    pub fn swap_high(&self) -> bool {
        self.swap.lock().is_high()
    }

    /// Get kernel memory watermark
    pub fn kernel_watermark(&self) -> Watermark {
        self.kernel_memory.lock().clone()
    }

    /// Get user memory watermark
    pub fn user_watermark(&self) -> Watermark {
        self.user_memory.lock().clone()
    }

    /// Get swap watermark
    pub fn swap_watermark(&self) -> Watermark {
        self.swap.lock().clone()
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Quota Manager
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static QUOTA_MANAGER: AtomicPtr<QuotaManager> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global quota manager
pub fn init_quota_manager() {
    let ptr = QUOTA_MANAGER.load(Ordering::SeqCst);
    if ptr.is_null() {
        let manager = Box::new(QuotaManager::new());
        let new_ptr = Box::into_raw(manager);
        let _ = QUOTA_MANAGER.compare_exchange(
            core::ptr::null_mut(),
            new_ptr,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

/// Get mutable reference to the global quota manager
fn quota_manager_mut() -> &'static mut QuotaManager {
    let ptr = QUOTA_MANAGER.load(Ordering::SeqCst);
    if ptr.is_null() {
        init_quota_manager();
    }
    unsafe { &mut *QUOTA_MANAGER.load(Ordering::SeqCst) }
}

/// Check if kernel memory pressure is high
pub fn kernel_memory_pressure() -> bool {
    quota_manager_mut().kernel_memory_high()
}

/// Check if user memory pressure is high
pub fn user_memory_pressure() -> bool {
    quota_manager_mut().user_memory_high()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limit() {
        let limit = ResourceLimit::new(100, 200);
        
        assert!(!limit.exceeds_soft(100));
        assert!(limit.exceeds_soft(101));
        
        assert!(!limit.exceeds_hard(200));
        assert!(limit.exceeds_hard(201));
    }

    #[test]
    fn test_resource_limit_unlimited() {
        let limit = ResourceLimit::unlimited();
        
        assert!(!limit.exceeds_soft(u64::MAX - 1));
        assert!(!limit.exceeds_hard(u64::MAX - 1));
    }

    #[test]
    fn test_resource_limit_raise() {
        let mut limit = ResourceLimit::new(100, 200);
        
        // Can raise within hard limit
        assert!(limit.raise_soft(150));
        assert_eq!(limit.soft, 150);
        
        // Cannot raise above hard limit
        assert!(!limit.raise_soft(250));
        assert_eq!(limit.soft, 150);
    }

    #[test]
    fn test_user_quota_memory() {
        let mut quota = UserQuota::new(1000);
        
        // Initially can allocate
        assert!(quota.can_alloc_memory(1024));
        
        // Allocate memory
        assert!(quota.alloc_memory(1024));
        assert_eq!(quota.memory_used, 1024);
        
        // Can allocate more
        assert!(quota.can_alloc_memory(1024));
        
        // Free memory
        quota.free_memory(1024);
        assert_eq!(quota.memory_used, 0);
    }

    #[test]
    fn test_user_quota_open_files() {
        let mut quota = UserQuota::new(1000);
        
        // Open files
        for _ in 0..256 {
            assert!(quota.open_file());
        }
        
        // Should hit hard limit
        assert!(!quota.open_file());
        
        // Close some files
        quota.close_file();
        assert!(quota.open_file());
    }

    #[test]
    fn test_user_quota_processes() {
        let mut quota = UserQuota::new(1000);
        
        // Fork processes
        for _ in 0..64 {
            assert!(quota.fork());
        }
        
        // Should hit soft limit
        assert!(!quota.fork());
        
        // Exit some processes
        quota.exit();
        assert!(quota.fork());
    }

    #[test]
    fn test_watermark() {
        let mut wm = Watermark::new(50, 80, 100);
        
        assert!(!wm.is_low());
        assert!(!wm.is_high());
        
        wm.set(60);
        assert!(wm.is_low());
        assert!(!wm.is_high());
        
        wm.set(85);
        assert!(wm.is_low());
        assert!(wm.is_high());
        
        wm.set(100);
        assert!(wm.is_max());
    }

    #[test]
    fn test_watermark_percent() {
        let mut wm = Watermark::new(50, 80, 100);
        
        wm.set(50);
        assert_eq!(wm.percent_used(), 50);
        
        wm.set(25);
        assert_eq!(wm.percent_used(), 25);
        
        wm.set(0);
        assert_eq!(wm.percent_used(), 0);
    }

    #[test]
    fn test_proc_limits() {
        let limits = ProcLimits::default_limits();
        
        // Can write small file
        assert!(limits.can_write_file(0, 100));
        
        // Can write up to limit
        assert!(limits.can_write_file(0, limits.max_memory));
        
        // Cannot write over limit
        assert!(!limits.can_write_file(0, limits.max_memory + 1));
    }

    #[test]
    fn test_quota_manager() {
        let manager = QuotaManager::new();
        
        // Get quota index for user 1000
        let idx = manager.user_quota_index(1000);
        assert!(idx.is_some());
        
        // Get the quota and check it
        {
            let quota = manager.user_quotas.lock();
            if let Some(q) = quota.get(idx.unwrap()) {
                assert_eq!(q.uid, 1000);
            }
        }
        
        // Check memory watermarks
        assert!(!manager.kernel_memory_low());
        assert!(!manager.user_memory_low());
        
        manager.set_kernel_memory(20 * 1024 * 1024);
        assert!(manager.kernel_memory_high());
    }
}

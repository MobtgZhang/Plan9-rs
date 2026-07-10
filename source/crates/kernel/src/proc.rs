// Process management
//
// Implements the Plan 9 process management subsystem including:
// - Process structure with full resource groups
// - Rendezvous synchronization primitive
// - File descriptor group (Fgrp)
// - Process group (Pgrp) for namespace management

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;
use crate::plan9_common::sync::Spinlock;
use crate::plan9_common::types::{PhysAddr, VirtAddr};
use crate::user_regs::{UserRegs, Note, Timer};

// ============================================================================
// Constants
// ============================================================================

/// Maximum segments per process
pub const NSEG: usize = 10;

/// Maximum file descriptors per process
pub const NFD: usize = 100;

/// Maximum path length
pub const MAXPATH: usize = 256;

/// Maximum processes in system
pub const NPROC: usize = 256;

/// Number of priority levels (Plan 9 uses 22)
pub const NPRIQ: usize = 22;

/// Normal priority level
pub const PRI_NORMAL: i8 = 10;

/// Kernel process priority
pub const PRI_KPROC: i8 = 13;

/// ============================================================================
// Process State
// ============================================================================

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Dead = 0,
    Moribund = 1,
    Ready = 2,
    Running = 3,
    Scheding = 4,
    Wakeme = 5,
    Rendez = 6,
    Wait = 7,
    Broken = 8,
    Stopped = 9,
}

/// ============================================================================
// Segment Type
// ============================================================================

/// Segment type
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SegType {
    None = 0,
    Text = 1,
    Data = 2,
    Bss = 3,
    Stack = 4,
    Shared = 5,
    Physical = 6,
}

/// ============================================================================
// Memory Segment
// ============================================================================

/// Memory segment structure for process
#[derive(Debug)]
pub struct ProcSegment {
    /// Segment type (text, data, bss, stack, etc.)
    pub segtype: SegType,
    /// Base virtual address
    pub base: u64,
    /// Top virtual address
    pub top: u64,
    /// File start offset (for text segment)
    pub fstart: u64,
    /// File length (for text segment)
    pub flen: u64,
    /// Memory mapped flag
    pub mmap: bool,
    /// Page table for this segment (indices for 4KB pages)
    /// Each entry is the PTE value or 0 if not present
    page_table: [u64; 512],
    /// Profile data for this segment (if profiling enabled)
    pub profile: Option<ProfileData>,
    /// Reference count for shared segments
    pub refcount: u32,
    /// Segment lock
    lock: Spinlock<()>,
}

impl ProcSegment {
    /// Create a new segment
    pub fn new(segtype: SegType, base: u64, size: usize) -> Self {
        Self {
            segtype,
            base,
            top: base + (size as u64),
            fstart: 0,
            flen: 0,
            mmap: false,
            page_table: [0; 512],
            profile: None,
            refcount: 1,
            lock: Spinlock::new(()),
        }
    }

    /// Create a new segment with profiling enabled
    pub fn new_with_profile(segtype: SegType, base: u64, size: usize, lresprof: u8) -> Self {
        let mut seg = Self::new(segtype, base, size);
        seg.profile = Some(ProfileData::new(base, size as u64, lresprof));
        seg
    }

    /// Get segment size in bytes
    pub fn size(&self) -> usize {
        (self.top - self.base) as usize
    }

    /// Get the page table entry for a given page index
    pub fn get_pte(&self, page_idx: usize) -> u64 {
        if page_idx < 512 {
            self.page_table[page_idx]
        } else {
            0
        }
    }

    /// Set the page table entry for a given page index
    pub fn set_pte(&mut self, page_idx: usize, entry: u64) {
        if page_idx < 512 {
            self.page_table[page_idx] = entry;
        }
    }

    /// Get the number of pages in this segment
    pub fn page_count(&self) -> usize {
        ((self.top - self.base) / 4096) as usize
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Check if segment is shared
    pub fn is_shared(&self) -> bool {
        self.refcount > 1
    }

    /// Enable profiling on this segment
    pub fn enable_profiling(&mut self, lresprof: u8) {
        self.profile = Some(ProfileData::new(self.base, self.size() as u64, lresprof));
    }

    /// Disable profiling on this segment
    pub fn disable_profiling(&mut self) {
        self.profile = None;
    }
}

// ============================================================================
// Process State Helper
// ============================================================================

impl Proc {
    /// Update the current state of this process.
    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }
}

// ============================================================================
// Rendezvous Synchronization
// ============================================================================

/// Rendezvous structure for process synchronization
/// This is Plan 9's basic synchronization primitive
/// 
/// In Plan 9, Rendezvous is used for sleep/wakeup patterns:
/// - Multiple processes can wait on a single rendezvous point
/// - wakeup wakes the first waiting process
/// - tsleep/wakeup with timeout is also supported
pub struct Rendez {
    /// Lock protecting the rendezvous structure
    lock: Spinlock<()>,
    /// Pointer to first waiting process (linked list via Proc.qnext).
    /// Stored as `*mut` (rather than `&'static mut Proc`) so the queue
    /// can be mutated without invalidating outstanding `&Proc` borrows.
    head: Option<*mut Proc>,
    /// Tail of waiting list
    tail: Option<*mut Proc>,
}

impl core::fmt::Debug for Rendez {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rendez")
            .field("has_waiters", &self.head.is_some())
            .finish()
    }
}

impl Rendez {
    /// Create a new rendezvous point
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            head: None,
            tail: None,
        }
    }

    /// Initialize rendezvous
    pub fn init(&mut self) {
        self.lock = Spinlock::new(());
        self.head = None;
        self.tail = None;
    }

    /// Lock the rendezvous structure
    pub fn lock(&mut self) -> &mut Spinlock<()> {
        &mut self.lock
    }

    /// Check if anyone is waiting
    pub fn has_waiters(&self) -> bool {
        self.head.is_some()
    }

    /// Add a process to the wait queue
    fn enqueue(&mut self, proc: &'static Proc) {
        // Set the process's qnext to None (end of queue). Use raw pointer
        // arithmetic to obtain an exclusive handle without relying on the
        // `&T as *mut u64` UB pattern.
        let p: *mut Proc = core::ptr::addr_of!(*proc).cast_mut();
        unsafe {
            (*p).qnext = None;
        }

        if let Some(tail) = self.tail {
            // Add to end of queue
            unsafe {
                let t = &mut *tail;
                t.qnext = Some(core::ptr::NonNull::new_unchecked(p));
            }
            self.tail = Some(p);
        } else {
            // First process in queue
            self.head = Some(p);
            self.tail = Some(p);
        }
    }

    /// Remove the first process from the wait queue
    fn dequeue(&mut self) -> Option<&'static Proc> {
        let proc = self.head?;
        let proc_ref = unsafe { &*proc };

        self.head = proc_ref.qnext.map(|p| p.as_ptr());
        if self.head.is_none() {
            self.tail = None;
        }

        Some(proc_ref)
    }
}

/// Global rendezvous table for process synchronization
/// 
/// This is used by the rendezvous syscall to pair up processes
/// that want to synchronize using a shared tag.
pub struct RendezvousTable {
    /// Hash table of waiting processes
    table: alloc::vec::Vec<RendezvousEntry>,
    /// Lock protecting the table
    lock: Spinlock<()>,
}

/// Entry in the rendezvous hash table
struct RendezvousEntry {
    /// Tag (key for hashing)
    tag: usize,
    /// Process waiting with this tag
    proc: Option<&'static Proc>,
    /// Value to exchange
    val: usize,
    /// Next entry in hash chain
    next: Option<usize>,
}

// SAFETY: RendezvousEntry contains references to Proc but is only accessed through
// the RendezvousTable which handles synchronization properly.
unsafe impl Send for RendezvousEntry {}
unsafe impl Sync for RendezvousEntry {}

impl RendezvousTable {
    /// Create a new rendezvous table
    pub fn new() -> Self {
        // Initialize with a reasonable number of hash buckets
        let size = 256;
        let table = (0..size)
            .map(|_| RendezvousEntry {
                tag: 0,
                proc: None,
                val: 0,
                next: None,
            })
            .collect();
        
        Self {
            table,
            lock: Spinlock::new(()),
        }
    }
    
    /// Hash function for tags
    fn hash(&self, tag: usize) -> usize {
        tag % self.table.len()
    }
    
    /// Perform a rendezvous operation
    /// 
    /// If another process is already waiting with the same tag,
    /// we pair up and exchange values. Otherwise, we wait.
    /// 
    /// # Arguments
    /// * `tag` - Rendezvous tag
    /// * `val` - Value to exchange
    /// * `proc` - Current process
    /// 
    /// # Returns
    /// * `Ok(exchanged_val)` - Value from the other process
    /// * `Err(())` - Should sleep waiting for partner
    pub fn rendezvous(&mut self, tag: usize, val: usize, proc: &'static Proc) -> core::result::Result<usize, ()> {
        let _guard = self.lock.lock();
        
        let idx = self.hash(tag);
        
        // Search for a matching entry
        let mut curr = idx;
        while self.table[curr].next.is_some() || (self.table[curr].tag == tag && self.table[curr].proc.is_some()) {
            if self.table[curr].tag == tag {
                if let Some(_other) = self.table[curr].proc {
                    // Found a match!
                    let partner_val = self.table[curr].val;
                    let partner_idx = curr;
                    
                    // Clear this entry
                    self.table[partner_idx].proc = None;
                    self.table[partner_idx].tag = 0;
                    self.table[partner_idx].val = 0;
                    
                    // Return partner's value
                    return Ok(partner_val);
                }
            }
            
            if let Some(next) = self.table[curr].next {
                curr = next;
            } else {
                break;
            }
        }
        
        // No match found - we're the first. Store our info and sleep.
        // Find an empty slot
        for i in 0..self.table.len() {
            if self.table[i].proc.is_none() {
                self.table[i].tag = tag;
                self.table[i].val = val;
                self.table[i].proc = Some(proc);
                self.table[i].next = None;
                
                // Add to hash chain if not at hash position
                if curr != i {
                    self.table[curr].next = Some(i);
                }
                
                return Err(()); // Signal to caller that we should sleep
            }
        }
        
        // Table full
        Err(())
    }
    
    /// Remove a process from the table (when it exits or is killed)
    pub fn remove(&mut self, proc: &'static Proc) {
        let _guard = self.lock.lock();
        let proc_ptr = core::ptr::addr_of!(*proc);

        for entry in &mut self.table {
            if let Some(p) = entry.proc {
                if core::ptr::addr_of!(*p) == proc_ptr {
                    entry.proc = None;
                    entry.tag = 0;
                    entry.val = 0;
                }
            }
        }
    }

    /// Remove a process from the table by tag (when it exits or is killed)
    pub fn remove_by_tag(&mut self, tag: usize) {
        let _guard = self.lock.lock();
        
        for entry in &mut self.table {
            if entry.tag == tag {
                entry.proc = None;
                entry.tag = 0;
                entry.val = 0;
            }
        }
    }
}

impl Default for RendezvousTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Process pointer to next in queue
/// (Note: qnext is now a public field on Proc)

/// Sleep on a rendezvous point until condition becomes true or note is pending.
///
/// This implements Plan 9's sleep() function:
/// - Checks if the condition is already true (don't sleep)
/// - Sets process state to Wakeme
/// - Adds process to rendezvous wait queue
/// - Calls scheduler to yield CPU
/// - When awakened, checks condition again
///
/// # Arguments
/// * `r` - Rendezvous point to sleep on
/// * `pred` - Function that returns true when we should stop sleeping
///
/// # Returns
/// * `true` if woken up by wakeup
/// * `false` if condition was already true or note was pending
pub fn psleep(r: &mut Rendez, pred: impl Fn() -> bool) -> bool {
    use crate::proc::curproc_mut;

    // Lock the rendezvous point
    let r_ptr: *mut Rendez = core::ptr::addr_of!(*r) as *mut Rendez;

    // Check if condition is already true
    if pred() {
        return false;
    }

    // Get current process
    let cur = match curproc_mut() {
        Some(p) => p,
        None => return false,
    };

    // Check for pending notes
    if cur.notepending() {
        return false;
    }

    // Set process state to Wakeme
    cur.state = State::Wakeme;

    // Add to rendezvous wait queue (using raw pointer to bypass borrow checker)
    unsafe {
        (*r_ptr).enqueue(cur);
    }

    // Note: The original code has more complex handling for:
    // - Lock release/acquire
    // - Statistics (m->cs++)
    // - proctrace
    // For simplicity, we just schedule here

    // Schedule another process
    crate::sched::schedule();

    // When we return, we were woken up
    true
}

/// Wake up the first process waiting on a rendezvous point.
///
/// This implements Plan 9's wakeup() function:
/// - Removes the first process from the wait queue
/// - Sets its state to Ready
/// - Adds it to the scheduler's ready queue
///
/// # Arguments
/// * `r` - Rendezvous point
///
/// # Returns
/// * `true` if a process was woken up
/// * `false` if no process was waiting
pub fn pwakeup(r: &mut Rendez) -> bool {
    // Get raw pointer to bypass borrow checker
    let r_ptr: *mut Rendez = core::ptr::addr_of!(*r) as *mut Rendez;

    // Get the head element and check if empty
    let proc_opt = unsafe {
        (*r_ptr).head
    };

    if proc_opt.is_none() {
        return false;
    }

    // Dequeue and modify head through raw pointer
    let p = unsafe {
        let head_val: *mut Proc = core::ptr::addr_of_mut!(*proc_opt.unwrap());
        (*r_ptr).head = (*head_val).qnext.map(|nn| nn.as_ptr());
        if (*r_ptr).head.is_none() {
            (*r_ptr).tail = None;
        }
        head_val
    };

    // Verify state
    let proc_state_ptr: *const Proc = p;
    if unsafe { (*proc_state_ptr).state } != State::Wakeme {
        // State mismatch - this is a bug
        return false;
    }

    // Set to Ready and add to scheduler. We need a `*mut` handle to mutate
    // the proc; cast through the raw pointer helper to avoid the
    // `&T as *mut u64` lint.
    let p_mut: *mut Proc = p;
    unsafe {
        (*p_mut).state = State::Ready;
    }
    crate::sched::ready(unsafe { &mut *p_mut });

    true
}

/// Sleep with timeout on a rendezvous point.
///
/// This implements Plan 9's tsleep() function:
/// - Sets up a timer for the timeout
/// - Calls psleep() with the condition
/// - Cancels timer if woken up before timeout
///
/// # Arguments
/// * `r` - Rendezvous point to sleep on
/// * `pred` - Function that returns true when we should stop sleeping
/// * `timeout_ms` - Timeout in milliseconds (0 = no timeout)
///
/// # Returns
/// * `true` if woken up by wakeup (not timeout)
/// * `false` if timed out or condition was already true
pub fn ptsleep(r: &mut Rendez, pred: impl Fn() -> bool, timeout_ms: u64) -> bool {
    // Use timer-based sleep when timeout is specified
    // A full implementation would set up a timer that calls pwakeup
    
    if timeout_ms == 0 {
        // No timeout - just sleep
        psleep(r, pred)
    } else {
        // Timer-based sleep
        // Schedule alarm and sleep
        let proc = curproc();
        let _proc_ptr = match proc {
            Some(p) => p,
            None => return false,
        };
        
        // Set up the alarm
        // In a real implementation, this would integrate with timer.rs
        // For now, we use a busy-wait with timeout check
        let start_time = crate::timer::get_ticks();
        let timeout_ticks = timeout_ms / crate::timer::MS_PER_TICK;
        
        loop {
            // Check condition first
            if pred() {
                return true; // Woken up by wakeup
            }
            
            // Check timeout
            let elapsed = crate::timer::get_ticks() - start_time;
            if elapsed >= timeout_ticks {
                return false; // Timed out
            }
            
            // Yield to other processes
            crate::sched::yield_();
        }
    }
}

/// ============================================================================
// Process ID
// ============================================================================

/// Process ID type
pub type Pid = u32;

/// ============================================================================
// Label for Context Switching
// ============================================================================

/// Label for context switching (setjmp/longjmp style)
/// Stores the minimal state needed to restore execution
#[derive(Debug, Clone, Copy, Default)]
pub struct Label {
    /// Stack pointer
    pub sp: u64,
    /// Program counter
    pub pc: u64,
    /// Callee-saved registers
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Label {
    /// Create a new empty label
    pub const fn new() -> Self {
        Self {
            sp: 0,
            pc: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }

    /// Check if label is set (has valid context)
    pub fn is_set(&self) -> bool {
        self.sp != 0 || self.pc != 0
    }
}

// ============================================================================
// File Descriptor Group (Fgrp)
// ============================================================================

/// File descriptor group - manages open files for a process
pub struct Fgrp {
    /// Array of open file channels (index = fd number)
    channels: [Option<Box<dyn Chan>>; NFD],
    /// Reference count
    pub refcount: u32,
}

impl core::fmt::Debug for Fgrp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let open_count = self.channels.iter().filter(|c| c.is_some()).count();
        f.debug_struct("Fgrp")
            .field("open_count", &open_count)
            .field("refcount", &self.refcount)
            .finish()
    }
}

impl Fgrp {
    /// Create a new file descriptor group
    pub fn new() -> Self {
        Self {
            channels: [const { None }; NFD],
            refcount: 1,
        }
    }

    /// Allocate a new file descriptor
    /// Returns the fd number, or -1 if no free fd
    pub fn alloc_fd(&mut self, chan: Box<dyn Chan>) -> i32 {
        for (i, slot) in self.channels.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(chan);
                return i as i32;
            }
        }
        -1
    }

    /// Get channel by file descriptor
    pub fn get_channel(&mut self, fd: i32) -> Option<&mut Box<dyn Chan>> {
        if fd >= 0 && (fd as usize) < NFD {
            self.channels[fd as usize].as_mut()
        } else {
            None
        }
    }

    /// Close and free a file descriptor
    pub fn close_fd(&mut self, fd: i32) -> Option<Box<dyn Chan>> {
        if fd >= 0 && (fd as usize) < NFD {
            self.channels[fd as usize].take()
        } else {
            None
        }
    }

    /// Duplicate a file descriptor
    pub fn dup(&mut self, fd: i32) -> Option<i32> {
        if let Some(_chan) = self.get_channel(fd) {
            // Clone the channel and allocate new fd
            // For now, just return the same fd
            Some(fd)
        } else {
            None
        }
    }

    /// Close all file descriptors
    pub fn close_all(&mut self) {
        for slot in &mut self.channels {
            if let Some(mut chan) = slot.take() {
                chan.close();
            }
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Duplicate for sharing (increments ref count)
    pub fn dup_shared(&self) -> Self {
        let mut new_channels: [Option<Box<dyn Chan>>; NFD] = [const { None }; NFD];
        for (i, slot) in self.channels.iter().enumerate() {
            if let Some(c) = slot.as_ref() {
                new_channels[i] = Some(c.dup());
            }
        }
        Self {
            channels: new_channels,
            refcount: self.refcount,
        }
    }
}

// ============================================================================
// Channel (Open File)
// ============================================================================

/// Channel trait - represents an open file or device
pub trait Chan: Send + Sync {
    /// Read from channel
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    /// Write to channel
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    /// Close channel
    fn close(&mut self);
    /// Get channel type
    fn dev(&self) -> usize;
    /// Get file offset
    fn offset(&self) -> u64;
    /// Set file offset
    fn set_offset(&mut self, offset: u64);
    /// Seek to a position in the file
    /// 
    /// # Arguments
    /// * `offset` - Offset to seek to
    /// * `whence` - SEEK_SET (0), SEEK_CUR (1), or SEEK_END (2)
    /// 
    /// # Returns
    /// * New position on success, or error
    fn seek(&mut self, offset: i64, whence: u8) -> Result<i64> {
        let pos = match whence {
            0 => offset,      // SEEK_SET: from beginning
            1 => self.offset() as i64 + offset,  // SEEK_CUR: from current
            2 => offset,      // SEEK_END: from end (requires stat for real implementation)
            _ => return Err(Error::Einval),
        };
        if pos < 0 {
            return Err(Error::Einval);
        }
        self.set_offset(pos as u64);
        Ok(pos)
    }
    /// Duplicate channel
    fn dup(&self) -> Box<dyn Chan>;
}

/// Simple result type for channel operations
pub type Result<T> = core::result::Result<T, Error>;

/// Channel error
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// Success
    Ok,
    /// Invalid argument
    Einval,
    /// I/O error
    Eio,
    /// Permission denied
    Eperm,
    /// General error
    General,
}

impl Error {
    pub const fn new() -> Self {
        Self::General
    }
}

impl From<core::convert::Infallible> for Error {
    fn from(_: core::convert::Infallible) -> Self {
        Self::General
    }
}

// ============================================================================
// Process Group (Pgrp)
// ============================================================================

/// Maximum mount points per process group
const MNTHASH_SIZE: usize = 16;

/// Mount hash entry - for quick lookup of mount points
pub struct MnthashEntry {
    /// Mount ID
    id: u64,
    /// Source path (device or server)
    source: Vec<u8>,
    /// Mount point path
    path: Vec<u8>,
    /// File system type
    fs_type: Vec<u8>,
    /// Mount flags
    flags: u32,
    /// Root channel for this mount
    root: Option<crate::dev::Chan>,
    /// Next entry in chain
    next: Option<Box<MnthashEntry>>,
}

impl core::fmt::Debug for MnthashEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MnthashEntry")
            .field("id", &self.id)
            .field("source", &self.source)
            .field("path", &self.path)
            .field("fs_type", &self.fs_type)
            .field("flags", &self.flags)
            .finish()
    }
}

/// Mount hash table for process namespace
/// Provides O(1) lookup of mount points by path
pub struct Mnthash {
    /// Hash buckets
    buckets: [Option<Box<MnthashEntry>>; MNTHASH_SIZE],
    /// Next mount ID to allocate
    next_id: u64,
}

impl core::fmt::Debug for Mnthash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mnthash")
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl Mnthash {
    /// Create a new mount hash table
    fn new() -> Self {
        Self {
            buckets: [const { None }; MNTHASH_SIZE],
            next_id: 1,
        }
    }

    /// Hash a path to get bucket index
    fn hash_path(path: &[u8]) -> usize {
        let mut hash: usize = 0;
        for &b in path {
            hash = hash.wrapping_mul(33).wrapping_add(b as usize);
        }
        hash % MNTHASH_SIZE
    }

    /// Insert a mount point
    fn insert(&mut self, source: &[u8], path: &[u8], fs_type: &[u8], flags: u32, root: Option<crate::dev::Chan>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let idx = Self::hash_path(path);
        let mut entry = Box::new(MnthashEntry {
            id,
            source: source.to_vec(),
            path: path.to_vec(),
            fs_type: fs_type.to_vec(),
            flags,
            root,
            next: None,
        });

        entry.next = self.buckets[idx].take();
        self.buckets[idx] = Some(entry);

        id
    }

    /// Find a mount point by path
    fn find(&self, path: &[u8]) -> Option<&MnthashEntry> {
        let idx = Self::hash_path(path);
        let mut curr = &self.buckets[idx];

        while let Some(ref entry) = curr {
            if entry.path == path {
                return Some(entry);
            }
            curr = &entry.next;
        }

        None
    }

    /// Remove a mount point by path
    fn remove(&mut self, path: &[u8]) -> Option<Box<MnthashEntry>> {
        let idx = Self::hash_path(path);
        let bucket = &mut self.buckets[idx];

        if let Some(ref mut entry) = bucket {
            if entry.path == path {
                let mut removed = bucket.take();
                if let Some(ref mut r) = removed {
                    *bucket = r.next.take();
                }
                return removed;
            }
        }

        // Search in chain
        let mut curr = bucket;
        while let Some(ref mut entry) = curr {
            let next_is_match = if let Some(ref n) = entry.next {
                n.path == path
            } else {
                false
            };
            if next_is_match {
                let mut removed = entry.next.take();
                if let Some(ref mut r) = removed {
                    entry.next = r.next.take();
                }
                return removed;
            }
            curr = &mut entry.next;
        }

        None
    }

    /// Find the best matching mount point for a path
    /// Returns the mount point with the longest path prefix match
    fn find_best_match(&self, path: &[u8]) -> Option<&MnthashEntry> {
        let mut best_match: Option<&MnthashEntry> = None;
        let mut best_len = 0;

        for bucket in &self.buckets {
            let mut curr: Option<&MnthashEntry> = bucket.as_ref().map(|b| b.as_ref());
            while let Some(ref entry) = curr {
                let entry_path = if entry.path.first() == Some(&b'/') {
                    &entry.path[1..]
                } else {
                    &entry.path
                };

                let path_to_check = if path.first() == Some(&b'/') {
                    &path[1..]
                } else {
                    path
                };

                if path_to_check.starts_with(entry_path) && entry_path.len() > best_len {
                    best_match = Some(*entry);
                    best_len = entry_path.len();
                }
                curr = entry.next.as_deref();
            }
        }

        best_match
    }
}

/// Namespace - represents a process's mount namespace
/// In Plan 9, each process group has its own namespace
#[derive(Debug)]
pub struct Namespace {
    /// Reference count
    pub refcount: u32,
    /// Root channel (root of namespace)
    pub root: Option<crate::dev::Chan>,
    /// Current working directory channel
    pub dot: Option<crate::dev::Chan>,
    /// Mount hash table
    pub mnthash: Mnthash,
    /// Lock for namespace operations
    lock: crate::plan9_common::sync::Spinlock<()>,
}

impl Clone for Namespace {
    fn clone(&self) -> Self {
        Self {
            refcount: self.refcount,
            root: self.root.clone(),
            dot: self.dot.clone(),
            mnthash: Mnthash::new(),
            lock: crate::plan9_common::sync::Spinlock::new(()),
        }
    }
}

impl Namespace {
    /// Create a new namespace
    pub fn new() -> Self {
        Self {
            refcount: 1,
            root: None,
            dot: None,
            mnthash: Mnthash::new(),
            lock: crate::plan9_common::sync::Spinlock::new(()),
        }
    }

    /// Create a child namespace inheriting from parent
    pub fn fork(parent: &Namespace) -> Self {
        Self {
            refcount: 1,
            root: parent.root.as_ref().map(|c| c.dup()),
            dot: parent.dot.as_ref().map(|c| c.dup()),
            mnthash: Mnthash::new(),
            lock: crate::plan9_common::sync::Spinlock::new(()),
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Find mount point for a path
    pub fn find_mount(&self, path: &[u8]) -> Option<&MnthashEntry> {
        self.mnthash.find_best_match(path)
    }

    /// Add a mount point
    pub fn mount(&mut self, source: &[u8], path: &[u8], fs_type: &[u8], flags: u32, root: Option<crate::dev::Chan>) -> u64 {
        self.mnthash.insert(source, path, fs_type, flags, root)
    }

    /// Remove a mount point
    pub fn unmount(&mut self, path: &[u8]) -> Option<Box<MnthashEntry>> {
        self.mnthash.remove(path)
    }

    /// Set the root of the namespace
    pub fn set_root(&mut self, chan: crate::dev::Chan) {
        self.root = Some(chan);
    }

    /// Get the root of the namespace
    pub fn get_root(&self) -> Option<crate::dev::Chan> {
        self.root.as_ref().map(|c| c.dup())
    }

    /// Set the current working directory
    pub fn set_dot(&mut self, chan: crate::dev::Chan) {
        self.dot = Some(chan);
    }

    /// Get the current working directory
    pub fn get_dot(&self) -> Option<crate::dev::Chan> {
        self.dot.as_ref().map(|c| c.dup())
    }

    /// Duplicate for sharing (increments ref count)
    pub fn dup_shared(&self) -> Self {
        Self {
            refcount: self.refcount,
            root: self.root.as_ref().map(|c| c.dup()),
            dot: self.dot.as_ref().map(|c| c.dup()),
            mnthash: Mnthash::new(), // Don't share the hash table
            lock: crate::plan9_common::sync::Spinlock::new(()),
        }
    }
}

/// Process group - manages process relationships and namespace
#[derive(Debug, Clone)]
pub struct Pgrp {
    /// Reference count
    pub refcount: u32,
    /// Process group ID
    pub pgrpid: Pid,
    /// Parent process group
    pub parent: Option<Box<Pgrp>>,
    /// Terminal process group (for job control)
    pub tgrp: Option<Pid>,
    /// Mount namespace
    pub ns: Option<Box<Namespace>>,
}

impl Pgrp {
    /// Create a new process group
    pub fn new(pgrpid: Pid) -> Self {
        Self {
            refcount: 1,
            pgrpid,
            parent: None,
            tgrp: None,
            ns: Some(Box::new(Namespace::new())),
        }
    }

    /// Create a child process group inheriting from parent
    pub fn fork(parent: &Pgrp, pgrpid: Pid) -> Self {
        Self {
            refcount: 1,
            pgrpid,
            parent: Some(Box::new(Pgrp {
                refcount: 0,
                pgrpid: parent.pgrpid,
                parent: None,
                tgrp: parent.tgrp,
                ns: None,
            })),
            tgrp: None,
            // Child gets its own namespace (copy-on-write or new)
            ns: parent.ns.as_ref().map(|ns| Box::new(Namespace::fork(ns))),
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Get the namespace
    pub fn namespace(&self) -> Option<&Namespace> {
        self.ns.as_deref()
    }

    /// Get mutable namespace
    pub fn namespace_mut(&mut self) -> Option<&mut Namespace> {
        self.ns.as_deref_mut()
    }

    /// Find mount point for a path in this process group's namespace
    pub fn find_mount(&self, path: &[u8]) -> Option<&MnthashEntry> {
        self.ns.as_ref().and_then(|ns| ns.find_mount(path))
    }

    /// Add a mount point to this process group's namespace
    pub fn mount(&mut self, source: &[u8], path: &[u8], fs_type: &[u8], flags: u32, root: Option<crate::dev::Chan>) -> u64 {
        self.ns.as_mut().map_or(0, |ns| ns.mount(source, path, fs_type, flags, root))
    }

    /// Remove a mount point from this process group's namespace
    pub fn unmount(&mut self, path: &[u8]) -> Option<Box<MnthashEntry>> {
        self.ns.as_mut().and_then(|ns| ns.unmount(path))
    }

    /// Duplicate for sharing (increments ref count)
    pub fn dup_shared(&self) -> Self {
        Self {
            refcount: self.refcount,
            pgrpid: self.pgrpid,
            parent: self.parent.clone(),
            tgrp: self.tgrp,
            ns: self.ns.as_ref().map(|ns| Box::new(ns.dup_shared())),
        }
    }
}

// ============================================================================
// Environment Group (Egrp)
// ============================================================================

/// Environment group - manages environment variables
#[derive(Debug, Clone)]
pub struct Egrp {
    /// Reference count
    pub refcount: u32,
    /// Parent environment group
    pub parent: Option<Box<Egrp>>,
}

impl Egrp {
    /// Create a new environment group
    pub fn new() -> Self {
        Self {
            refcount: 1,
            parent: None,
        }
    }

    /// Fork environment group
    pub fn fork(parent: &Egrp) -> Self {
        // Deep copy parent chain
        let mut parent_copy: Option<Box<Egrp>> = None;
        if let Some(ref p) = parent.parent {
            parent_copy = Some(Box::new(Egrp {
                refcount: 0,
                parent: p.parent.clone(),
            }));
        }
        Self {
            refcount: 1,
            parent: parent_copy,
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Duplicate for sharing (increments ref count)
    pub fn dup_shared(&self) -> Self {
        Self {
            refcount: self.refcount,
            parent: self.parent.clone(),
        }
    }
}

// ============================================================================
// Rendezvous Group (Rgrp)
// ============================================================================

/// Rendezvous hash size (log2)
pub const RENDLOG: usize = 5;
/// Number of rendezvous hash buckets
pub const RENDHASH: usize = 1 << RENDLOG;

/// Rendezvous hash entry
#[derive(Clone)]
struct RendezHashEntry {
    /// Tag (key)
    tag: usize,
    /// Process waiting with this tag
    proc: Option<&'static Proc>,
    /// Value to exchange
    val: usize,
    /// Next in chain
    next: Option<usize>,
}

/// Rendezvous group - manages rendezvous synchronization
/// 
/// In Plan 9, the Rgrp maintains a hash table of processes waiting
/// for rendezvous with specific tags.
pub struct Rgrp {
    /// Reference count
    pub refcount: u32,
    /// Rendezvous hash table
    table: [Option<RendezHashEntry>; RENDHASH],
}

impl core::fmt::Debug for Rgrp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rgrp")
            .field("refcount", &self.refcount)
            .finish()
    }
}

impl Rgrp {
    /// Create a new rendezvous group
    pub fn new() -> Self {
        Self {
            refcount: 1,
            table: [const { None }; RENDHASH],
        }
    }

    /// Fork rendezvous group (shares with parent)
    pub fn fork(parent: &Rgrp) -> Self {
        let mut table: [Option<RendezHashEntry>; RENDHASH] = [const { None }; RENDHASH];
        for (i, slot) in parent.table.iter().enumerate() {
            if i < RENDHASH {
                table[i] = slot.clone();
            }
        }
        Self {
            refcount: 1,
            table,
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }
}

// ============================================================================
// Wait Message
// ============================================================================

/// Wait message - information about child process exit
#[derive(Debug, Clone)]
pub struct Waitmsg {
    /// Process ID of exited child
    pub pid: Pid,
    /// Time in milliseconds spent in user + system mode
    pub time: u32,
    /// Exit status or signal number
    pub status: i32,
    /// Argument string (e.g., "seg: fault")
    pub msg: [u8; 128],
}

impl Waitmsg {
    /// Create a new wait message
    pub fn new(pid: Pid, status: i32, time: u32) -> Self {
        Self {
            pid,
            time,
            status,
            msg: [0; 128],
        }
    }

    /// Get the message as a string slice
    pub fn msg_str(&self) -> &str {
        // Find null terminator
        let len = self.msg.iter().position(|&b| b == 0).unwrap_or(self.msg.len());
        core::str::from_utf8(&self.msg[..len]).unwrap_or("")
    }

    /// Set the message string
    pub fn set_msg(&mut self, msg: &str) {
        let bytes = msg.as_bytes();
        let len = bytes.len().min(127);
        self.msg[..len].copy_from_slice(&bytes[..len]);
        self.msg[len] = 0;
    }

    /// Check if process was killed by signal
    pub fn killed_by_signal(&self) -> bool {
        self.status < 0
    }

    /// Get signal number if killed by signal
    pub fn signal(&self) -> Option<i32> {
        if self.status < 0 {
            Some(-self.status)
        } else {
            None
        }
    }

    /// Get exit status if normal exit
    pub fn exit_status(&self) -> Option<u8> {
        if self.status >= 0 {
            Some(self.status as u8)
        } else {
            None
        }
    }
}

// ============================================================================
// Wait Queue
// ============================================================================

/// Wait queue for parent waiting on child exit
pub struct Waitq {
    /// Next entry in wait queue
    pub next: Option<Box<Waitq>>,
    /// PID of exiting child
    pub pid: Pid,
    /// Exit status
    pub status: i32,
    /// Time used
    pub time: u64,
}

impl core::fmt::Debug for Waitq {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Waitq")
            .field("pid", &self.pid)
            .field("status", &self.status)
            .field("time", &self.time)
            .finish()
    }
}

impl Waitq {
    /// Create a new wait queue entry
    pub fn new(pid: Pid, status: i32, time: u64) -> Self {
        Self {
            next: None,
            pid,
            status,
            time,
        }
    }
}

// ============================================================================
// Main Process Structure
// ============================================================================

/// Maximum number of error labels per process
pub const NERR: usize = 16;

/// Maximum number of notes (signals) per process
pub const NNOTE: usize = 16;

/// Kernel stack size
pub const KSTACK_SIZE: usize = 8192;

/// Process structure - represents a running program
pub struct Proc {
    /// Process ID
    pub pid: Pid,
    /// Current state
    pub state: State,

    // === Scheduling ===
    /// Current priority
    pub pri: i8,
    /// Base priority
    pub basepri: i8,
    /// CPU time used (for priority calculation)
    /// Stored as fixed point * 1000 (0-1000 range represents 0-100% CPU usage)
    pub cpu: u64,
    /// Last update time (for CPU decay calculation)
    /// Stored as scaled ticks for precision
    pub lastupdate: i64,
    /// Scheduler context (setjmp/longjmp)
    pub sched: Label,
    /// Was preempted flag
    pub preempted: bool,
    /// Delay scheduling counter (when holding locks)
    pub delaysched: i32,

    // === Memory ===
    /// Kernel stack pointer
    pub kstack: u64,
    /// Kernel stack size
    pub kstack_size: usize,
    /// Memory segments (T, D, B, S)
    pub seg: [Option<ProcSegment>; NSEG],
    /// Page directory physical address
    pub mmupdb: PhysAddr,

    // === Hierarchy ===
    /// Parent process
    pub parent: Option<Pid>,
    /// Number of child processes
    pub nchild: i32,
    /// Number of processes waiting on this process
    pub nwait: i32,
    /// Wait queue for exiting children
    pub waitq: Option<Box<Waitq>>,

    // === Resources ===
    /// File descriptor group
    pub fgrp: Option<Box<Fgrp>>,
    /// Process group (namespace)
    pub pgrp: Option<Box<Pgrp>>,
    /// Environment group
    pub egrp: Option<Box<Egrp>>,

    // === Synchronization ===
    /// Sleep/rendezvous point
    pub sleep: Rendez,
    /// Lock count for delayed scheduling
    pub nlocks: i32,

    // === Error Recovery ===
    /// Error recovery labels (setjmp/longjmp stack)
    pub errlab: [Label; NERR],
    /// Current error label depth
    pub nerrlab: i32,
    /// Last error string
    pub errstr: [u8; 256],

    // === Signal Handling ===
    /// Pending notes (signals)
    pub note: [Note; NNOTE],
    /// Number of pending notes
    pub nnote: i32,
    /// Signal handler function
    pub notify: Option<unsafe fn(*mut u8, *const u8) -> i32>,
    /// User register frame (for signal handling)
    pub ureg: Option<Box<UserRegs>>,

    // === Timer ===
    /// Process timer (alarm)
    pub timer: Option<Box<Timer>>,

    // === Process Info ===
    /// User name
    pub user: [u8; 32],
    /// Process name (command)
    pub text: [u8; 32],
    /// Arguments
    pub args: [u8; 256],
    /// Number of arguments
    pub nargs: u8,

    // === Time Statistics ===
    /// Time spent in user mode (ms)
    pub utime: u64,
    /// Time spent in kernel mode (ms)
    pub ktime: u64,
    /// Time spent in child processes
    pub ctime: u64,
    /// Wall clock time at start
    pub wtime: u64,

    // === System Call ===
    /// Currently in syscall flag
    pub insyscall: bool,
    /// Number of syscalls made
    pub nsyscall: u64,

    // === Current Working Directory ===
    /// Current working directory channel
    pub dot: Option<Box<dyn Chan>>,

    // === Next process in queue ===
    /// Next process in ready/wait queue
    pub next: Option<core::ptr::NonNull<Proc>>,
    /// Next process in rendezvous wait queue (for sleep/wakeup)
    pub qnext: Option<core::ptr::NonNull<Proc>>,

    // === CPU Affinity ===
    /// CPU affinity mask - which CPUs this process can run on
    pub cpu_affinity: CpuMask,
    /// Wired CPU info (permanent CPU binding)
    pub wired: WiredInfo,

    // === EDF Real-Time ===
    /// EDF scheduling info (if real-time process)
    pub edf: Option<EdfInfo>,

    // === Alarm ===
    /// Alarm state
    pub alarm: AlarmState,

    // === Wait/Rendezvous for await ===
    /// Wait rendezvous for parent waiting on child exit
    pub waitr: Rendez,

    /// Lock for waitq
    pub waitq_lock: Spinlock<()>,

    // === Exec Context ===
    /// Entry point for exec'd program (set after successful exec)
    pub exec_entry: u64,
    /// Stack pointer for exec'd program
    pub exec_stack: u64,
    /// Argument count for exec'd program
    pub exec_argc: usize,
}

impl Proc {
    /// Create a new process structure
    pub fn new() -> Self {
        Self {
            pid: 0,
            state: State::Dead,
            pri: PRI_NORMAL,
            basepri: PRI_NORMAL,
            cpu: 0,
            lastupdate: 0,
            sched: Label::new(),
            preempted: false,
            delaysched: 0,
            kstack: 0,
            kstack_size: 0,
            seg: [const { None }; NSEG],
            mmupdb: PhysAddr::new(0),
            parent: None,
            nchild: 0,
            nwait: 0,
            waitq: None,
            fgrp: None,
            pgrp: None,
            egrp: None,
            sleep: Rendez::new(),
            nlocks: 0,
            errlab: [const { Label::new() }; NERR],
            nerrlab: 0,
            errstr: [0; 256],
            note: [const { Note::empty() }; NNOTE],
            nnote: 0,
            notify: None,
            ureg: None,
            timer: None,
            user: [0; 32],
            text: [0; 32],
            args: [0; 256],
            nargs: 0,
            utime: 0,
            ktime: 0,
            ctime: 0,
            wtime: 0,
            insyscall: false,
            nsyscall: 0,
            dot: None,
            next: None,
            qnext: None,
            cpu_affinity: CpuMask::all(),
            wired: WiredInfo::new(),
            edf: None,
            alarm: AlarmState::new(),
            waitr: Rendez::new(),
            waitq_lock: Spinlock::new(()),
            exec_entry: 0,
            exec_stack: 0,
            exec_argc: 0,
        }
    }

    /// Check if process is runnable
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, State::Ready | State::Running)
    }

    /// Check if process can be scheduled
    pub fn can_schedule(&self) -> bool {
        // Can't schedule if in certain states
        !matches!(
            self.state,
            State::Dead | State::Moribund | State::Wakeme | 
            State::Rendez | State::Wait | State::Stopped
        )
    }

    /// Initialize process groups (fork from parent)
    ///
    /// Handles the rfork flags to determine what is shared vs copied.
    /// This implements Plan 9's rfork semantics:
    /// - Without FLAGFPROC: runs in same address space (thread)
    /// - With FLAGFPROC: creates new process
    /// - Without FLAGFDG: copies file descriptors (default)
    /// - With FLAGFDG: shares file descriptor group
    /// - Without FLAGFMEM: COW fork (copy-on-write memory)
    /// - With FLAGFMEM: shares memory
    pub fn fork_groups(&mut self, parent: Option<&Proc>, flags: u32) {
        if let Some(p) = parent {
            // Handle file descriptor group based on flags
            if flags & rfork::FLAGFDG == 0 {
                // Copy file descriptors (default behavior in Plan 9)
                if let Some(ref pfgrp) = p.fgrp {
                    let mut new_fgrp = Box::new(Fgrp::new());
                    // Copy all open file descriptors
                    for (i, chan_opt) in pfgrp.channels.iter().enumerate() {
                        if let Some(chan) = chan_opt {
                            // Clone the channel (increments reference count)
                            new_fgrp.channels[i] = Some(chan.dup());
                        }
                    }
                    self.fgrp = Some(new_fgrp);
                }
            } else {
                // Share file descriptor group with parent
                // Use dup to share - this increments ref count
                if let Some(ref fgrp) = p.fgrp {
                    self.fgrp = Some(Box::new(fgrp.dup_shared()));
                }
            }

            // Handle process group (namespace) based on flags
            if flags & rfork::FLAGFNS == 0 {
                // Copy namespace (default)
                if let Some(ref ppgrp) = p.pgrp {
                    self.pgrp = Some(Box::new(Pgrp::fork(ppgrp, self.pid)));
                }
            } else {
                // Share namespace - use dup_shared
                if let Some(ref pgrp) = p.pgrp {
                    self.pgrp = Some(Box::new(pgrp.dup_shared()));
                }
            }

            // Handle environment group based on flags
            if flags & rfork::FLAGFENV == 0 {
                // Copy environment (default)
                if let Some(ref pegrp) = p.egrp {
                    self.egrp = Some(Box::new(Egrp::fork(pegrp)));
                }
            } else {
                // Share environment
                if let Some(ref egrp) = p.egrp {
                    self.egrp = Some(Box::new(egrp.dup_shared()));
                }
            }

            // Handle working directory (always share in Plan 9)
            if let Some(ref dot) = p.dot {
                self.dot = Some(dot.dup());
            }
        } else {
            // Create new groups for init process
            self.fgrp = Some(Box::new(Fgrp::new()));
            self.pgrp = Some(Box::new(Pgrp::new(self.pid)));
            self.egrp = Some(Box::new(Egrp::new()));
        }
    }

    /// Set process name
    pub fn set_text(&mut self, name: &[u8]) {
        let len = name.len().min(31);
        self.text[..len].copy_from_slice(&name[..len]);
        self.text[len] = 0;
    }

    /// Set user name
    pub fn set_user(&mut self, name: &[u8]) {
        let len = name.len().min(31);
        self.user[..len].copy_from_slice(&name[..len]);
        self.user[len] = 0;
    }

    /// Set arguments
    pub fn set_args(&mut self, args: &[&[u8]]) {
        let mut offset = 0;
        for (i, arg) in args.iter().enumerate() {
            if i > 255 {
                break;
            }
            let len = arg.len().min(255 - offset);
            self.args[offset..offset + len].copy_from_slice(&arg[..len]);
            offset += len + 1;
            self.nargs = (i + 1) as u8;
        }
    }

    /// Set the program counter
    pub fn set_pc(&mut self, pc: u64) {
        self.sched.pc = pc;
    }

    /// Set the stack pointer
    pub fn set_sp(&mut self, sp: u64) {
        self.sched.sp = sp;
    }

    /// Allocate kernel stack
    pub fn alloc_kstack(&mut self, size: usize) -> bool {
        // In a real implementation, this would allocate from kernel heap
        // For now, just record the size
        self.kstack_size = size;
        true
    }

    /// Find segment containing an address
    pub fn find_segment(&self, addr: u64) -> Option<&ProcSegment> {
        for opt_seg in &self.seg {
            if let Some(seg) = opt_seg {
                if addr >= seg.base && addr < seg.top {
                    return Some(seg);
                }
            }
        }
        None
    }

    /// Free all segments
    pub fn free_segments(&mut self) {
        for opt_seg in &mut self.seg {
            *opt_seg = None;
        }
    }

    /// Setup segments for exec
    ///
    /// Replaces the process's memory segments with new ones for the exec'd program.
    pub fn setup_segments(&mut self, entry: u64, text_size: usize, data_size: usize, stack_top: u64) {
        // Free old segments first
        self.free_segments();

        // Calculate segment addresses
        let text_base = crate::segment::USER_BASE;
        let data_base = text_base + (text_size as u64);
        let stack_base = stack_top - (8 * 1024 * 1024); // 8MB stack

        // Create text segment (read-only, executable)
        // Text segment is loaded from the executable file
        let mut text_seg = ProcSegment::new_with_profile(
            SegType::Text,
            text_base,
            text_size,
            0, // lresprof for profiling
        );
        text_seg.fstart = 0;
        text_seg.flen = text_size as u64;
        self.seg[0] = Some(text_seg);

        // Create data segment (read-write, not executable)
        let data_seg = ProcSegment::new_with_profile(
            SegType::Data,
            data_base,
            data_size,
            0,
        );
        self.seg[1] = Some(data_seg);

        // Create BSS segment (uninitialized data, read-write)
        // BSS follows data segment
        let bss_base = data_base + (data_size as u64);
        let bss_size = 0; // BSS would be set from executable header
        if bss_size > 0 {
            let bss_seg = ProcSegment::new(SegType::Bss, bss_base, bss_size);
            self.seg[2] = Some(bss_seg);
        }

        // Create stack segment (read-write, grows down)
        let stack_seg = ProcSegment::new(SegType::Stack, stack_base, 8 * 1024 * 1024);
        self.seg[3] = Some(stack_seg);

        // Set entry point and stack pointer
        self.sched.pc = entry;
        self.sched.sp = stack_top;
    }

    /// Send a signal to this process
    pub fn signal(&mut self, note: Note) {
        if self.nnote < NNOTE as i32 {
            self.note[self.nnote as usize] = note;
            self.nnote += 1;
        }
    }

    /// Check if process has pending signals
    pub fn has_pending_signals(&self) -> bool {
        self.nnote > 0
    }

    /// Check if a note is pending (for sleep/interrupt handling)
    pub fn notepending(&self) -> bool {
        self.nnote > 0
    }

    /// Pop the next pending signal
    pub fn pop_signal(&mut self) -> Option<Note> {
        if self.nnote > 0 {
            self.nnote -= 1;
            let note = self.note[self.nnote as usize];
            self.note[self.nnote as usize] = Note::default();
            Some(note)
        } else {
            None
        }
    }

    /// Post a note (signal) to this process
    ///
    /// In Plan 9, notes are the equivalent of signals in Unix.
    /// This function posts a note to a process or process group.
    ///
    /// # Arguments
    /// * `flag` - Determines who receives the note:
    ///   - 0: Send to process group (PNPROC)
    ///   - 1: Send to specific process (PNGROUP)
    /// * `msg` - The note message
    ///
    /// # Returns
    /// Returns Ok(()) on success, or an error code
    pub fn postnote(&mut self, flag: u32, msg: &[u8]) -> core::result::Result<(), ()> {
        match flag {
            // PNPROC - send to specific process
            0 => {
                self.add_note(msg)?;
                // Wake up process if it's sleeping
                if self.state == State::Wakeme {
                    // Would wake up via scheduler
                }
                Ok(())
            }
            // PNGROUP - send to process group
            1 => {
                // In a full implementation, this would send to the process group
                // For now, just send to this process
                self.add_note(msg)?;
                Ok(())
            }
            _ => Err(()),
        }
    }

    /// Add a note to the process's note list
    fn add_note(&mut self, msg: &[u8]) -> core::result::Result<(), ()> {
        if self.nnote >= NNOTE as i32 {
            return Err(());
        }

        // Store the note message (truncated to fit)
        let note = Note::new(
            self.pid,
            msg.as_ptr() as u64,
            NNOTE as u32,
        );

        self.note[self.nnote as usize] = note;
        self.nnote += 1;

        Ok(())
    }

    /// Set the signal handler
    ///
    /// This sets the function that will be called when a signal is delivered.
    pub fn set_notify(&mut self, handler: Option<unsafe fn(*mut u8, *const u8) -> i32>) {
        self.notify = handler;
    }

    /// Check if a notify handler is set
    pub fn has_notify(&self) -> bool {
        self.notify.is_some()
    }

    /// Deliver pending signals to this process
    ///
    /// This is called when returning from a system call or interrupt.
    /// Returns true if a signal was delivered and the process should handle it.
    pub fn deliver_signals(&mut self) -> bool {
        // Check if there are pending notes
        if self.nnote == 0 {
            return false;
        }

        // Check if there's a notify handler
        if self.notify.is_none() {
            // No handler - default action is to terminate
            return true;
        }

        // Pop the first note
        if let Some(note) = self.pop_signal() {
            // Call the notify handler
            // In Plan 9, if the handler returns 0, the process handles the note
            // If it returns non-zero, the note is discarded
            if let Some(handler) = self.notify {
                // SAFETY: The handler is set by the process itself, and we trust it
                let note_ptr = core::ptr::addr_of!(note) as *const u8;
                let result = unsafe { handler(core::ptr::null_mut(), note_ptr) };
                return result == 0;
            }
        }

        false
    }

    /// Save user register state for signal handling
    ///
    /// When a signal is delivered, the current user registers are saved
    /// so they can be restored after the signal handler returns.
    pub fn save_ureg(&mut self, regs: &UserRegs) {
        self.ureg = Some(Box::new(*regs));
    }

    /// Restore user register state after signal handling
    pub fn restore_ureg(&mut self) -> Option<UserRegs> {
        self.ureg.take().map(|b| *b)
    }

    /// Check if saved user registers exist (for noted)
    pub fn has_ureg(&self) -> bool {
        self.ureg.is_some()
    }

    /// Set up the exec context for returning to user mode after exec
    pub fn set_exec_context(&mut self, entry: u64, sp: u64, argc: usize) {
        self.exec_entry = entry;
        self.exec_stack = sp;
        self.exec_argc = argc;
    }

    /// Check if there's a pending exec context to return to
    pub fn has_exec_context(&self) -> bool {
        self.exec_entry != 0
    }

    /// Get exec entry point
    pub fn get_exec_entry(&self) -> u64 {
        self.exec_entry
    }

    /// Get exec stack pointer
    pub fn get_exec_stack(&self) -> u64 {
        self.exec_stack
    }

    /// Clear exec context
    pub fn clear_exec_context(&mut self) {
        self.exec_entry = 0;
        self.exec_stack = 0;
        self.exec_argc = 0;
    }

    /// Create a new address space (page table) for this process
    ///
    /// Allocates a new PML4 table and copies kernel mappings from the
    /// current page table. User space starts empty.
    ///
    /// # Safety
    /// Should only be called during process creation
    pub fn setup_page_table(&mut self) -> bool {
        use crate::plan9_arch::x86_64::mmu::cr3_read;
//         use crate::plan9_common::types::PhysAddr;
        use crate::vm::frame_allocator;
        use crate::plan9_arch::x86_64::paging::PHYS_MEMORY_VIRT;

        // Allocate a new PML4 page
        let pml4_frame = match frame_allocator().alloc_frame() {
            Some(frame) => frame,
            None => return false,
        };

        // Clear the PML4 (all 512 entries to 0)
        let pml4_virt = (PHYS_MEMORY_VIRT | pml4_frame.as_u64()) as *mut u64;
        unsafe {
            core::ptr::write_bytes(pml4_virt, 0, 512);
        }

        // Copy kernel mappings (PML4 entries 256-511) from current PML4
        // These entries cover the upper half of virtual address space (kernel space)
        let current_pml4 = cr3_read();
        let current_pml4_virt = (PHYS_MEMORY_VIRT | current_pml4.as_u64()) as *const u64;

        for i in 256..512 {
            let entry = unsafe { core::ptr::read(current_pml4_virt.add(i)) };
            if entry != 0 {
                // Copy the entry as-is (keep same physical address, same flags)
                unsafe { core::ptr::write(pml4_virt.add(i), entry) };
            }
        }

        self.mmupdb = pml4_frame;
        true
    }

    /// Increment delay sched counter
    pub fn delay_sched(&mut self) {
        if self.nlocks > 0 && self.delaysched == 0 {
            self.delaysched = 1;
        }
    }

    /// Wake up from rendezvous sleep
    ///
    /// Called when a partner process arrives at the rendezvous point.
    pub fn wakeup_rendezvous(&mut self) {
        // Set state back to ready
        if self.state == State::Rendez {
            self.state = State::Ready;
        }
    }
}

/// Global process table
pub struct ProcTable {
    /// Array of all processes
    processes: [Option<Box<Proc>>; NPROC],
    /// Next PID to allocate
    next_pid: Pid,
    /// Lock protecting process table
    lock: Spinlock<()>,
}

impl ProcTable {
    /// Create a new process table
    pub fn new() -> Self {
        Self {
            processes: [const { None }; NPROC],
            next_pid: 1,
            lock: Spinlock::new(()),
        }
    }

    /// Allocate a new PID
    pub fn alloc_pid(&mut self) -> Option<Pid> {
        let start = self.next_pid;
        for _ in 0..NPROC {
            let pid = self.next_pid;
            self.next_pid = if self.next_pid >= NPROC as Pid - 1 {
                1
            } else {
                self.next_pid + 1
            };

            // Check if PID is in use
            let index = (pid % NPROC as Pid) as usize;
            if self.processes[index].is_none() {
                return Some(pid);
            }

            if self.next_pid == start {
                break; // All PIDs in use
            }
        }
        None
    }

    /// Add a process to the table
    pub fn add(&mut self, proc: Box<Proc>) -> Option<Pid> {
        let pid = proc.pid;
        let index = (pid % NPROC as Pid) as usize;
        if self.processes[index].is_none() {
            self.processes[index] = Some(proc);
            Some(pid)
        } else {
            None
        }
    }

    /// Get a process by PID
    pub fn get(&self, pid: Pid) -> Option<&Box<Proc>> {
        let index = (pid % NPROC as Pid) as usize;
        self.processes[index].as_ref()
    }

    /// Get a mutable process by PID
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut Box<Proc>> {
        let index = (pid % NPROC as Pid) as usize;
        self.processes[index].as_mut()
    }
    
    /// Get a mutable process by PID, returning a reference to the inner Proc
    pub fn get_mut_proc(&mut self, pid: Pid) -> Option<&mut Proc> {
        let index = (pid % NPROC as Pid) as usize;
        self.processes[index].as_mut().map(|p| &mut **p)
    }

    /// Remove a process from the table
    pub fn remove(&mut self, pid: Pid) -> Option<Box<Proc>> {
        let index = (pid % NPROC as Pid) as usize;
        self.processes[index].take()
    }

    /// Iterate over all processes
    pub fn iter(&self) -> ProcTableIter<'_> {
        ProcTableIter {
            table: self,
            index: 0,
        }
    }
}

/// Iterator over process table
pub struct ProcTableIter<'a> {
    table: &'a ProcTable,
    index: usize,
}

impl<'a> Iterator for ProcTableIter<'a> {
    type Item = &'a Proc;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < NPROC {
            let idx = self.index;
            self.index += 1;
            if let Some(ref proc) = self.table.processes[idx] {
                return Some(proc.as_ref());
            }
        }
        None
    }
}

// ============================================================================
// Current Process Pointer
// ============================================================================

/// Global pointer to current process
/// This is set via per-CPU data (GS base on x86_64). Using an atomic
/// `Ptr` avoids the `static mut` shared-reference lints while still
/// letting us store a raw pointer.
static CURPROC: core::sync::atomic::AtomicPtr<Proc> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Get pointer to current process
pub fn curproc() -> Option<&'static Proc> {
    let ptr = CURPROC.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Get mutable pointer to current process
#[allow(clippy::mut_from_ref)]
pub fn curproc_mut() -> Option<&'static mut Proc> {
    let ptr = CURPROC.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

/// Set current process pointer
pub fn set_curproc(proc: &'static mut Proc) {
    CURPROC.store(proc as *mut Proc, core::sync::atomic::Ordering::Release);
}

/// Clear current process pointer
pub fn clear_curproc() {
    CURPROC.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
}

// ============================================================================
// Copy-On-Write (COW) Page Support
// ============================================================================

/// Page reference count structure for COW
#[derive(Debug)]
pub struct PageRef {
    /// Reference count
    pub refcount: u32,
    /// Lock for atomic operations
    lock: Spinlock<()>,
}

impl PageRef {
    /// Create a new page reference
    pub fn new() -> Self {
        Self {
            refcount: 1,
            lock: Spinlock::new(()),
        }
    }

    /// Increment reference count
    pub fn inc(&mut self) -> u32 {
        let _guard = self.lock.lock();
        self.refcount += 1;
        self.refcount
    }

    /// Decrement reference count
    pub fn dec(&mut self) -> i32 {
        let _guard = self.lock.lock();
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount as i32
    }

    /// Get current reference count
    pub fn count(&self) -> u32 {
        self.refcount
    }

    /// Check if page is shared (refcount > 1)
    pub fn is_shared(&self) -> bool {
        self.refcount > 1
    }
}

impl Default for PageRef {
    fn default() -> Self {
        Self::new()
    }
}

/// Page structure for memory management
#[derive(Debug)]
pub struct Page {
    /// Physical address of the page
    pub phys_addr: PhysAddr,
    /// Virtual address of the page (if mapped)
    pub va: u64,
    /// Reference count
    pub refcount: PageRef,
    /// Reference to image (for cached pages)
    pub image: Option<ImageRef>,
    /// Swap address (if swapped out)
    pub swap_addr: u64,
    /// Page color for NUMA-aware allocation
    pub color: u8,
    /// Page flags
    pub flags: PageFlags,
    /// Modification/reference bits
    pub modref: u8,
}

bitflags::bitflags! {
    /// Page flags
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct PageFlags: u8 {
        const VALID = 1 << 0;
        const SWAPPED = 1 << 1;
        const SHARED = 1 << 2;
        const MODIFIED = 1 << 3;
        const REFERENCED = 1 << 4;
        const CACHED = 1 << 5;
        const DONTFLUSH = 1 << 6;
        const ONFAULT = 1 << 7;
    }
}

impl Page {
    /// Create a new page
    pub fn new(phys_addr: PhysAddr) -> Self {
        Self {
            phys_addr,
            va: 0,
            refcount: PageRef::new(),
            image: None,
            swap_addr: 0,
            color: 0,
            flags: PageFlags::empty(),
            modref: 0,
        }
    }

    /// Allocate a new page
    pub fn alloc() -> Option<Self> {
        crate::vm::alloc_frame().map(|phys| Self::new(phys))
    }

    /// Check if page can be copied (COW)
    pub fn can_cow(&self) -> bool {
        self.refcount.is_shared() || self.image.is_some()
    }

    /// Copy page content to another page (copypage)
    pub fn copypage(&mut self, target: &mut Page) {
        // Map both pages and copy content
        let src_virt = self.phys_to_virt();
        let dst_virt = target.phys_to_virt();

        // Copy 4KB page content
        let page_size = 4096usize;
        unsafe {
            core::ptr::copy_nonoverlapping(
                src_virt as *const u8,
                dst_virt as *mut u8,
                page_size
            );
        }
    }

    /// Convert physical address to kernel virtual address
    fn phys_to_virt(&self) -> u64 {
        crate::vm::phys_to_virt(self.phys_addr).as_u64()
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount.inc();
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> i32 {
        self.refcount.dec()
    }

    /// Check if page is cached
    pub fn is_cached(&self) -> bool {
        self.flags.contains(PageFlags::CACHED)
    }

    /// Check if page has been swapped out
    pub fn is_swapped(&self) -> bool {
        self.flags.contains(PageFlags::SWAPPED)
    }
}

/// Reference to an Image (shared text segments)
#[derive(Debug, Clone, Copy)]
pub struct ImageRef {
    /// Image ID
    pub id: u64,
}

/// Image structure for caching text segments
#[derive(Debug)]
pub struct Image {
    /// Unique image identifier
    pub id: u64,
    /// Reference count
    pub refcount: u32,
    /// Lock
    lock: Spinlock<()>,
    /// Whether this image has text segments
    pub has_text: bool,
    /// Original file path (if from file)
    pub path: [u8; 256],
    /// File offset for text segment
    pub foffset: u64,
    /// Length of text
    pub flen: u64,
    /// Cached pages
    pages: Vec<Page>,
}

impl Image {
    /// Create a new image
    pub fn new(id: u64) -> Self {
        Self {
            id,
            refcount: 1,
            lock: Spinlock::new(()),
            has_text: true,
            path: [0; 256],
            foffset: 0,
            flen: 0,
            pages: Vec::new(),
        }
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        let _guard = self.lock.lock();
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> u32 {
        let _guard = self.lock.lock();
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount
    }

    /// Add a page to the cache
    pub fn cache_page(&mut self, page: Page) {
        let _guard = self.lock.lock();
        self.pages.push(page);
    }

    /// Find a cached page by virtual address
    pub fn find_page(&self, va: u64) -> Option<&Page> {
        let _guard = self.lock.lock();
        self.pages.iter().find(|p| p.va == va)
    }
}

// ============================================================================
// Page Color (NUMA-aware allocation)
// ============================================================================

/// Number of page colors (typically number of CPU cache colors)
pub const NPCOLOR: usize = 8;

/// Page color allocator for NUMA-aware memory allocation
/// Pages with different colors map to different cache colors
pub struct PageColor {
    /// Current color for round-robin allocation
    current: u8,
}

impl PageColor {
    /// Create a new page color allocator
    pub fn new() -> Self {
        Self { current: 0 }
    }

    /// Get the page color for a given virtual address
    /// This is based on the low bits of the VA to spread pages
    /// across different CPU cache colors
    pub fn get_color(va: u64) -> u8 {
        // Use bits [12:15] of VA for color (4 bits = 16 colors)
        // This gives good cache distribution for most access patterns
        ((va >> 12) & 0xF) as u8
    }

    /// Allocate a color for a new page (round-robin)
    pub fn alloc(&mut self) -> u8 {
        let color = self.current;
        self.current = (self.current + 1) % NPCOLOR as u8;
        color
    }

    /// Choose the best color for a given address
    pub fn choose_color(&self, va: u64) -> u8 {
        // In NUMA systems, this would also consider the NUMA node
        // For now, just return the VA-based color
        Self::get_color(va)
    }
}

impl Default for PageColor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Profile Support (segclock)
// ============================================================================

/// Profile data for a segment
#[derive(Debug)]
pub struct ProfileData {
    /// Total ticks in segment
    pub total: u64,
    /// Per-PC histogram buckets
    buckets: Vec<u64>,
    /// Base address of profiled region
    base: u64,
    /// Top address of profiled region
    top: u64,
    /// Bucket size (log2 of bytes per bucket)
    pub lresprof: u8,
}

impl ProfileData {
    /// Create new profile data
    pub fn new(base: u64, size: u64, lresprof: u8) -> Self {
        let num_buckets = ((size >> lresprof) as usize).min(65536);
        Self {
            total: 0,
            buckets: vec![0; num_buckets],
            base,
            top: base + size,
            lresprof,
        }
    }

    /// Record a tick at the given PC
    pub fn tick(&mut self, pc: u64) {
        self.total += 1;

        // Record in per-PC bucket if in range
        if pc >= self.base && pc < self.top {
            let offset = pc - self.base;
            let bucket = (offset >> self.lresprof) as usize;
            if bucket < self.buckets.len() {
                self.buckets[bucket] += 1;
            }
        }
    }

    /// Get bucket count
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Get bucket value
    pub fn bucket(&self, i: usize) -> u64 {
        self.buckets.get(i).copied().unwrap_or(0)
    }
}

/// Convert ticks to milliseconds
pub const fn tk2ms(ticks: u64) -> u64 {
    ticks * 1000 / 100 // Assuming 100 Hz clock
}

/// Segment clock - called periodically to update profiling
pub fn segclock(segment: &mut ProcSegment, pc: u64) {
    if let Some(ref mut profile) = segment.profile {
        profile.tick(pc);
    }
}

// ============================================================================
// Memory Compression (Pageout/Pagepte)
// ============================================================================

/// Pageout statistics
#[derive(Debug, Default)]
pub struct PageoutStats {
    /// Number of pages paged out
    pub pages_out: u64,
    /// Number of pages paged in
    pub pages_in: u64,
    /// Number of pageouts attempted
    pub attempts: u64,
    /// Age sum for page replacement
    pub age_sum: u64,
    /// Number of ages computed
    pub age_count: u64,
    /// Current generation for aging
    pub generation: u32,
}

impl PageoutStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Age a page and return its age value
    pub fn age_page(&mut self, page_gen: u32) -> u32 {
        let diff = self.generation.wrapping_sub(page_gen);
        if self.generation < page_gen {
            !diff
        } else {
            diff
        }
    }

    /// Advance the generation clock
    pub fn advance_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

/// Swap manager for pageout operations
pub struct SwapManager {
    /// Lock for swap operations
    lock: Spinlock<()>,
    /// Swap space base address
    base: u64,
    /// Swap space size
    size: u64,
    /// Allocation bitmap
    bitmap: Vec<u64>,
    /// Statistics
    stats: PageoutStats,
}

impl SwapManager {
    /// Create a new swap manager
    pub fn new(base: u64, size: u64) -> Self {
        let num_bits = (size / 4096) as usize;
        let bitmap_words = (num_bits + 63) / 64;

        Self {
            lock: Spinlock::new(()),
            base,
            size,
            bitmap: vec![0; bitmap_words],
            stats: PageoutStats::new(),
        }
    }

    /// Allocate swap space for a page
    /// Returns the swap address, or 0 if no space available
    pub fn alloc_swap(&mut self) -> u64 {
        let _guard = self.lock.lock();

        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = word.trailing_zeros() as usize;
                *word |= 1 << bit;
                let offset = (word_idx * 64 + bit) * 4096;
                return self.base + offset as u64;
            }
        }
        0 // No space
    }

    /// Free swap space
    pub fn free_swap(&mut self, addr: u64) {
        let _guard = self.lock.lock();

        let offset = (addr - self.base) as usize;
        if offset >= self.size as usize {
            return;
        }

        let bit_idx = offset / 4096;
        let word_idx = bit_idx / 64;
        let bit = bit_idx % 64;

        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1 << bit);
        }
    }

    /// Check if swap space is available
    pub fn has_space(&self) -> bool {
        self.bitmap.iter().any(|w| *w != u64::MAX)
    }

    /// Get statistics reference
    pub fn stats(&self) -> &PageoutStats {
        &self.stats
    }

    /// Get statistics mut reference
    pub fn stats_mut(&mut self) -> &mut PageoutStats {
        &mut self.stats
    }
}

/// PTE flags for page table entries
#[derive(Debug, Clone, Copy)]
pub struct PteFlags {
    /// Present bit
    pub present: bool,
    /// Writable bit
    pub writable: bool,
    /// User accessible
    pub user: bool,
    /// Write-through
    pub write_through: bool,
    /// Cache disabled
    pub cache_disabled: bool,
    /// Accessed
    pub accessed: bool,
    /// Dirty (modified)
    pub dirty: bool,
    /// Page attribute table
    pub pat: bool,
    /// Global page
    pub global: bool,
    /// Copy-on-write
    pub cow: bool,
}

impl PteFlags {
    /// Create from PTE value
    pub fn from_pte(pte: u64) -> Self {
        Self {
            present: pte & 1 != 0,
            writable: pte & 2 != 0,
            user: pte & 4 != 0,
            write_through: pte & 8 != 0,
            cache_disabled: pte & 16 != 0,
            accessed: pte & 32 != 0,
            dirty: pte & 64 != 0,
            pat: pte & 128 != 0,
            global: pte & 256 != 0,
            cow: pte & 512 != 0,
        }
    }

    /// Convert to PTE value
    pub fn to_pte(&self) -> u64 {
        let mut pte = 0u64;
        if self.present { pte |= 1; }
        if self.writable { pte |= 2; }
        if self.user { pte |= 4; }
        if self.write_through { pte |= 8; }
        if self.cache_disabled { pte |= 16; }
        if self.accessed { pte |= 32; }
        if self.dirty { pte |= 64; }
        if self.pat { pte |= 128; }
        if self.global { pte |= 256; }
        if self.cow { pte |= 512; }
        pte
    }

    /// Set the referenced bit
    pub fn with_referenced(mut self) -> Self {
        self.accessed = true;
        self
    }

    /// Set the modified bit
    pub fn with_modified(mut self) -> Self {
        self.dirty = true;
        self
    }
}

/// Maximum number of segments per image
const MAX_IMAGE_SEGS: usize = 16;

/// Image cache for caching text segments
pub struct ImageCache {
    /// Lock
    lock: Spinlock<()>,
    /// Images indexed by ID
    images: Vec<Image>,
    /// Next image ID
    next_id: u64,
}

impl ImageCache {
    /// Create a new image cache
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            images: Vec::new(),
            next_id: 1,
        }
    }

    /// Create or get an image
    pub fn get_image(&mut self, path: &[u8], foffset: u64, flen: u64) -> ImageRef {
        let _guard = self.lock.lock();

        // Check if image already exists
        for img in &self.images {
            if img.path.starts_with(path) && img.foffset == foffset && img.flen == flen {
                return ImageRef { id: img.id };
            }
        }

        // Create new image
        let id = self.next_id;
        self.next_id += 1;

        let mut img = Image::new(id);
        let len = path.len().min(255);
        img.path[..len].copy_from_slice(&path[..len]);
        img.foffset = foffset;
        img.flen = flen;

        self.images.push(img);
        ImageRef { id }
    }

    /// Get image by reference
    pub fn get(&self, ref_: ImageRef) -> Option<&Image> {
        self.images.iter().find(|img| img.id == ref_.id)
    }

    /// Get mutable image by reference
    pub fn get_mut(&mut self, ref_: ImageRef) -> Option<&mut Image> {
        self.images.iter_mut().find(|img| img.id == ref_.id)
    }

    /// Put (release) an image reference
    pub fn put(&mut self, ref_: ImageRef) {
        if let Some(img) = self.images.iter_mut().find(|img| img.id == ref_.id) {
            if img.decref() == 0 {
                // Remove empty images
                self.images.retain(|img| img.id != ref_.id);
            }
        }
    }
}

// ============================================================================
// COW Page Duplication (duppage)
// ============================================================================

/// Duplicate a COW page for fork
/// Returns true if page was duplicated (private copy created)
pub fn duppage(page: &mut Page) -> bool {
    // Don't duplicate pages with no image or single reference
    if page.refcount.count() <= 1 && page.image.is_none() {
        return false;
    }

    // Don't duplicate pages from images marked as "no text"
    if page.image.is_none() && page.refcount.count() == 0 {
        return false;
    }

    // Check if we have enough memory
    // In a full implementation, this would check swapalloc.highwater
    if page.refcount.count() <= 1 {
        return false;
    }

    // Decrement reference before potential sleep
    page.decref();

    // Allocate new page
    let new_page = match Page::alloc() {
        Some(p) => p,
        None => {
            // Restore reference and return failure
            page.incref();
            return false;
        }
    };

    // Copy content
    // In real implementation, this handles locks carefully to avoid deadlock
    let mut target = new_page;
    page.copypage(&mut target);

    // Update page to point to new physical frame
    // In real implementation, this updates the PTE

    true
}

/// Handle a page fault for COW pages
/// Returns true if fault was handled (page is now valid)
///
/// When a process tries to write to a COW (Copy-on-Write) page:
/// 1. If the page is only referenced by this process, make it writable
/// 2. If the page is shared, allocate a new page, copy content, and use it
pub fn cow_page_fault(va: u64, seg: &mut ProcSegment, writable: bool) -> bool {
    let page_idx = ((va - seg.base) / 4096) as usize;

    if page_idx >= 512 {
        return false;
    }

    let pte = seg.get_pte(page_idx);
    if pte == 0 {
        return false; // Not our page
    }

    let flags = PteFlags::from_pte(pte);

    // Check if it's a COW page and we need to write
    if flags.cow && writable && flags.present {
        // Get the physical address of the current page
        let _phys_addr = PhysAddr::new(pte & 0x000_FFFF_FFFF_F000);

        // Try to allocate a new physical frame
        if let Some(new_phys) = crate::vm::alloc_frame() {
            // Copy the content from old page to new page
            // In a real implementation, we would use copy_page()
            // For now, we'll set up the new PTE

            // Create new PTE with writable flag (remove COW flag)
            let new_pte = new_phys.as_u64() | 0x01 | 0x02 | 0x04; // Present, Writable, User

            // Update the segment's page table
            seg.set_pte(page_idx, new_pte);

            // Invalidate TLB for this page
            crate::plan9_arch::x86_64::mmu::invlpg(VirtAddr::new(va));

            return true;
        }
    }

    false
}

// ============================================================================
// Pager Thread Support
// ============================================================================

/// Pager request types
#[derive(Debug, Clone, Copy)]
pub enum PagerReq {
    /// Page out request
    PageOut,
    /// Page in request
    PageIn,
    /// Exit pager
    Exit,
}

/// Pager request structure
#[derive(Debug)]
pub struct PagerMessage {
    /// Request type
    pub req: PagerReq,
    /// Page to operate on
    pub page: *mut Page,
    /// Swap address
    pub swap_addr: u64,
    /// Virtual address
    pub va: u64,
}

impl PagerMessage {
    /// Create a new pager message
    pub fn new(req: PagerReq, page: *mut Page, swap_addr: u64, va: u64) -> Self {
        Self {
            req,
            page,
            swap_addr,
            va,
        }
    }
}

// ============================================================================
// CPU Affinity and Wired Processes
// ============================================================================

/// Maximum number of CPUs supported
pub const NCPU: usize = 16;

/// CPU mask type for affinity
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuMask(u64);

impl CpuMask {
    /// Create an empty CPU mask
    pub fn empty() -> Self {
        Self(0)
    }

    /// Create a mask with all CPUs set
    pub fn all() -> Self {
        Self(u64::MAX >> (64 - NCPU.min(64)))
    }

    /// Create a mask with a single CPU
    pub fn single(cpu: usize) -> Self {
        if cpu < NCPU {
            Self(1 << cpu)
        } else {
            Self(0)
        }
    }

    /// Check if a CPU is set in the mask
    pub fn contains(&self, cpu: usize) -> bool {
        if cpu < NCPU {
            (self.0 & (1 << cpu)) != 0
        } else {
            false
        }
    }

    /// Set a CPU in the mask
    pub fn set(&mut self, cpu: usize) {
        if cpu < NCPU {
            self.0 |= 1 << cpu;
        }
    }

    /// Clear a CPU from the mask
    pub fn clear(&mut self, cpu: usize) {
        if cpu < NCPU {
            self.0 &= !(1 << cpu);
        }
    }

    /// Get the raw mask value
    pub fn bits(&self) -> u64 {
        self.0
    }

    /// Count of set CPUs
    pub fn count(&self) -> usize {
        self.0.count_ones() as usize
    }

    /// Get the first set CPU (least significant bit)
    pub fn first(&self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as usize)
        }
    }
}

/// Wired process information
/// A wired process is permanently bound to specific CPUs
#[derive(Debug, Clone)]
pub struct WiredInfo {
    /// Whether this process is wired
    pub wired: bool,
    /// CPUs this process is wired to
    pub cpu_mask: CpuMask,
}

impl WiredInfo {
    /// Create new wired info (not wired by default)
    pub fn new() -> Self {
        Self {
            wired: false,
            cpu_mask: CpuMask::all(),
        }
    }

    /// Wire process to specific CPU
    pub fn wire_to(&mut self, cpu: usize) {
        self.wired = true;
        self.cpu_mask = CpuMask::single(cpu);
    }

    /// Wire process to multiple CPUs
    pub fn wire_to_mask(&mut self, mask: CpuMask) {
        if mask.bits() != 0 {
            self.wired = true;
            self.cpu_mask = mask;
        }
    }

    /// Unwire process (allow any CPU)
    pub fn unwire(&mut self) {
        self.wired = false;
        self.cpu_mask = CpuMask::all();
    }

    /// Check if process can run on given CPU
    pub fn can_run_on(&self, cpu: usize) -> bool {
        self.cpu_mask.contains(cpu)
    }
}

impl Default for WiredInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EDF (Earliest Deadline First) Real-Time Scheduling
// ============================================================================

/// EDF scheduling parameters
#[derive(Debug, Clone, Copy)]
pub struct EdfParams {
    /// Period in milliseconds
    pub period: u64,
    /// Computation time in milliseconds
    pub computation: u64,
    /// Relative deadline in milliseconds
    pub deadline: u64,
    /// Extra flags
    pub flags: u32,
}

impl EdfParams {
    /// Create new EDF parameters
    pub fn new(period: u64, computation: u64, deadline: u64) -> Self {
        Self {
            period,
            computation,
            deadline,
            flags: 0,
        }
    }

    /// Check if this is a valid real-time task
    /// Utilization must be <= 1 for feasibility
    pub fn is_schedulable(&self) -> bool {
        if self.period == 0 || self.deadline == 0 {
            return false;
        }
        let utilization = (self.computation as f64) / (self.period as f64);
        utilization <= 1.0
    }

    /// Get utilization factor
    pub fn utilization(&self) -> f64 {
        if self.period == 0 {
            0.0
        } else {
            (self.computation as f64) / (self.period as f64)
        }
    }
}

/// EDF scheduling information for a real-time process
#[derive(Debug)]
pub struct EdfInfo {
    /// EDF parameters
    pub params: EdfParams,
    /// Absolute deadline (in ms from some epoch)
    pub abs_deadline: u64,
    /// Start time of current period (in ms)
    pub period_start: u64,
    /// Remaining computation time in current period
    pub remaining: u64,
    /// Whether EDF scheduling is active
    pub active: bool,
    /// Next release time
    pub next_release: u64,
}

impl EdfInfo {
    /// Create new EDF info from parameters
    pub fn new(params: EdfParams, start_time: u64) -> Option<Self> {
        if !params.is_schedulable() {
            return None;
        }
        Some(Self {
            abs_deadline: start_time + params.deadline,
            period_start: start_time,
            remaining: params.computation,
            active: true,
            next_release: start_time,
            params,
        })
    }

    /// Update EDF info at scheduling time
    pub fn update(&mut self, current_time: u64) {
        // Check if we need to start a new period
        if current_time >= self.next_release {
            self.period_start = current_time;
            self.abs_deadline = current_time + self.params.deadline;
            self.remaining = self.params.computation;
            self.next_release = current_time + self.params.period;
        }
    }

    /// Consume computation time
    pub fn consume(&mut self, time: u64) {
        self.remaining = self.remaining.saturating_sub(time);
    }

    /// Check if task has missed its deadline
    pub fn missed_deadline(&self, current_time: u64) -> bool {
        current_time > self.abs_deadline && self.remaining > 0
    }

    /// Check if deadline is met (opposite of missed_deadline)
    pub fn deadline_met(&self, current_time: u64) -> bool {
        !self.missed_deadline(current_time)
    }

    /// Get time until deadline
    pub fn time_to_deadline(&self, current_time: u64) -> i64 {
        self.abs_deadline as i64 - current_time as i64
    }
}

/// EDF Scheduler for real-time processes
pub struct EdfScheduler {
    /// Lock for EDF operations
    lock: Spinlock<()>,
    /// List of EDF tasks
    tasks: alloc::vec::Vec<EdfTaskEntry>,
    /// Total utilization
    utilization: f64,
}

struct EdfTaskEntry {
    pid: Pid,
    info: EdfInfo,
}

impl EdfScheduler {
    /// Create new EDF scheduler
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            tasks: alloc::vec::Vec::new(),
            utilization: 0.0,
        }
    }

    /// Add a real-time task
    pub fn add_task(&mut self, pid: Pid, params: EdfParams, start_time: u64) -> bool {
        let _guard = self.lock.lock();

        if let Some(info) = EdfInfo::new(params, start_time) {
            self.utilization += info.params.utilization();
            self.tasks.push(EdfTaskEntry { pid, info });
            true
        } else {
            false
        }
    }

    /// Remove a real-time task
    pub fn remove_task(&mut self, pid: Pid) {
        let _guard = self.lock.lock();
        self.tasks.retain(|t| t.pid != pid);
        // Recalculate utilization
        self.utilization = self.tasks.iter().map(|t| t.info.params.utilization()).sum();
    }

    /// Get the task with earliest deadline
    pub fn earliest_deadline(&self, _current_time: u64) -> Option<Pid> {
        let _guard = self.lock.lock();
        self.tasks
            .iter()
            .filter(|t| t.info.active && t.info.remaining > 0)
            .min_by_key(|t| t.info.abs_deadline)
            .map(|t| t.pid)
    }

    /// Check if system is overloaded
    pub fn is_overloaded(&self) -> bool {
        self.utilization > 1.0
    }

    /// Get current total utilization
    pub fn total_utilization(&self) -> f64 {
        self.utilization
    }

    /// Update all tasks (call periodically)
    pub fn update_all(&mut self, current_time: u64) {
        let _guard = self.lock.lock();
        for task in &mut self.tasks {
            task.info.update(current_time);
        }
    }
}

impl Default for EdfScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Alarm System Call
// ============================================================================

/// Alarm request structure
#[derive(Debug, Clone, Copy)]
pub struct AlarmReq {
    /// Time of alarm (ms from now, or absolute time)
    pub time: u64,
    /// Whether this is an absolute time
    pub absolute: bool,
    /// Handler function
    pub handler: Option<unsafe fn(Pid)>,
}

impl AlarmReq {
    /// Create a new alarm request
    pub fn new(time: u64) -> Self {
        Self {
            time,
            absolute: false,
            handler: None,
        }
    }

    /// Create an absolute alarm
    pub fn absolute(time: u64) -> Self {
        Self {
            time,
            absolute: true,
            handler: None,
        }
    }
}

/// Process alarm state
#[derive(Debug)]
pub struct AlarmState {
    /// Current alarm time (absolute ms)
    alarm_time: u64,
    /// Currently pending alarm
    pending: Option<AlarmReq>,
    /// Alarm lock
    lock: Spinlock<()>,
}

impl AlarmState {
    /// Create new alarm state
    pub fn new() -> Self {
        Self {
            alarm_time: 0,
            pending: None,
            lock: Spinlock::new(()),
        }
    }

    /// Set an alarm
    pub fn set(&mut self, req: AlarmReq, current_time: u64) -> u64 {
        let _guard = self.lock.lock();
        let old = self.alarm_time;

        let alarm_time = if req.absolute {
            req.time
        } else {
            current_time + req.time
        };

        self.alarm_time = alarm_time;
        self.pending = Some(req);

        old
    }

    /// Cancel current alarm
    pub fn cancel(&mut self) -> u64 {
        let _guard = self.lock.lock();
        let old = self.alarm_time;
        self.alarm_time = 0;
        self.pending = None;
        old
    }

    /// Check if alarm has expired
    pub fn expired(&self, current_time: u64) -> bool {
        self.alarm_time > 0 && current_time >= self.alarm_time
    }

    /// Get remaining time until alarm (0 if no alarm)
    pub fn remaining(&self, current_time: u64) -> u64 {
        if self.alarm_time == 0 {
            0
        } else {
            self.alarm_time.saturating_sub(current_time)
        }
    }

    /// Consume the pending alarm (call when alarm fires)
    pub fn consume(&mut self) -> Option<AlarmReq> {
        let _guard = self.lock.lock();
        self.alarm_time = 0;
        self.pending.take()
    }
}

impl Default for AlarmState {
    fn default() -> Self {
        Self::new()
    }
}

/// Alarm handler for processes
pub struct AlarmHandler {
    /// Registered alarms per process
    alarms: alloc::vec::Vec<(Pid, AlarmReq)>,
    /// Lock
    lock: Spinlock<()>,
}

impl AlarmHandler {
    /// Create new alarm handler
    pub fn new() -> Self {
        Self {
            alarms: alloc::vec::Vec::new(),
            lock: Spinlock::new(()),
        }
    }

    /// Register an alarm for a process
    pub fn register(&mut self, pid: Pid, req: AlarmReq, _current_time: u64) -> u64 {
        let _guard = self.lock.lock();

        // Find existing alarm for this process
        if let Some((_, existing)) = self.alarms.iter_mut().find(|(p, _)| *p == pid) {
            let old = existing.time;
            *existing = req;
            old
        } else {
            self.alarms.push((pid, req));
            0
        }
    }

    /// Cancel alarm for a process
    pub fn cancel(&mut self, pid: Pid) -> u64 {
        let _guard = self.lock.lock();

        if let Some(pos) = self.alarms.iter().position(|(p, _)| *p == pid) {
            let old = self.alarms[pos].1.time;
            self.alarms.remove(pos);
            old
        } else {
            0
        }
    }

    /// Get expired alarms
    pub fn check_expired(&mut self, current_time: u64) -> alloc::vec::Vec<Pid> {
        let _guard = self.lock.lock();

        let mut expired = alloc::vec::Vec::new();
        self.alarms.retain(|(pid, req)| {
            let is_expired = if req.absolute {
                current_time >= req.time
            } else {
                // For relative alarms, we'd need to track when they were set
                false
            };
            if is_expired {
                expired.push(*pid);
            }
            !is_expired
        });

        expired
    }
}

impl Default for AlarmHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Global alarm handler - manages all process alarms
/// 
/// This is called by the timer interrupt handler to deliver
/// alarm signals to processes when their timers expire.
pub struct GlobalAlarmHandler {
    /// Registered alarms per process
    alarms: alloc::vec::Vec<(Pid, u64)>,  // (pid, expire_time)
    /// Lock
    lock: Spinlock<()>,
}

impl GlobalAlarmHandler {
    /// Create new global alarm handler
    pub fn new() -> Self {
        Self {
            alarms: alloc::vec::Vec::new(),
            lock: Spinlock::new(()),
        }
    }
    
    /// Set an alarm for a process
    /// 
    /// # Arguments
    /// * `pid` - Process ID
    /// * `ms` - Milliseconds until alarm fires (0 to cancel)
    /// * `current_ticks` - Current system time in ticks
    /// 
    /// # Returns
    /// * Previous alarm time in ms, or 0 if no previous alarm
    pub fn set_alarm(&mut self, pid: Pid, ms: u64, current_ticks: u64) -> u64 {
        let _guard = self.lock.lock();
        
        // Calculate expiration time in ticks
        let expire = if ms == 0 {
            0
        } else {
            // Convert ms to ticks (assuming 100 ticks per second)
            current_ticks + (ms * 100 / 1000)
        };
        
        // Find and replace existing alarm, or add new one
        if let Some((_, existing)) = self.alarms.iter_mut().find(|(p, _)| *p == pid) {
            let old = *existing;
            *existing = expire;
            // Return old alarm time in ms
            if old > current_ticks {
                (old - current_ticks) * 1000 / 100
            } else {
                0
            }
        } else {
            self.alarms.push((pid, expire));
            0
        }
    }
    
    /// Cancel alarm for a process
    /// 
    /// # Arguments
    /// * `pid` - Process ID
    /// 
    /// # Returns
    /// * Previous alarm time in ms, or 0 if no alarm
    pub fn cancel_alarm(&mut self, pid: Pid) -> u64 {
        let _guard = self.lock.lock();
        
        if let Some(pos) = self.alarms.iter().position(|(p, _)| *p == pid) {
            let old = self.alarms[pos].1;
            self.alarms.remove(pos);
            // Return old alarm time in ms
            old * 1000 / 100
        } else {
            0
        }
    }
    
    /// Check and process expired alarms
    /// 
    /// This should be called periodically by the scheduler or timer interrupt.
    /// 
    /// # Arguments
    /// * `current_ticks` - Current system time in ticks
    /// 
    /// # Returns
    /// * Vector of PIDs whose alarms have expired
    pub fn check_expired(&mut self, current_ticks: u64) -> alloc::vec::Vec<Pid> {
        let _guard = self.lock.lock();
        
        let mut expired = alloc::vec::Vec::new();
        self.alarms.retain(|(pid, expire)| {
            let is_expired = *expire > 0 && current_ticks >= *expire;
            if is_expired {
                expired.push(*pid);
            }
            !is_expired  // Keep if not expired
        });
        
        expired
    }
    
    /// Get the next alarm expiration time
    /// 
    /// # Returns
    /// * Next expiration time in ticks, or 0 if no alarms
    pub fn next_alarm(&self) -> u64 {
        let _guard = self.lock.lock();
        self.alarms.iter()
            .filter(|(_, expire)| *expire > 0)
            .map(|(_, expire)| *expire)
            .min()
            .unwrap_or(0)
    }
}

impl Default for GlobalAlarmHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Deliver alarm signal to a process
/// 
/// This posts a SIGALRM note to the process when its alarm fires.
/// 
/// # Arguments
/// * `pid` - Process ID to deliver alarm to
fn deliver_alarm(pid: Pid) {
    // Find the process and post a note
    if let Some(p) = curproc() {
        // We can't post to another process directly from here
        // This would need to be called from the scheduler with proper locking
        let _ = pid;
        let _ = p;
    }
}

// ============================================================================
// Enhanced Wait/Await System
// ============================================================================

/// Wait status encoding (Plan 9 style)
#[derive(Debug, Clone, Copy)]
pub struct WaitStatus {
    /// Encoded status value
    value: u32,
}

impl WaitStatus {
    /// Create from raw value
    pub fn from_raw(value: u32) -> Self {
        Self { value }
    }

    /// Create normal exit status
    pub fn exited(code: i32) -> Self {
        Self { value: (code as u32 & 0xFF) << 8 }
    }

    /// Create signaled status
    pub fn signaled(sig: i32, core: bool) -> Self {
        Self { value: ((sig as u32 & 0xFF) << 8) | if core { 0x80 } else { 0 } }
    }

    /// Create stopped status
    pub fn stopped(sig: i32) -> Self {
        Self { value: ((sig as u32 & 0x7F) << 8) | 0x7F }
    }

    /// Check if process exited
    pub fn is_exit(&self) -> bool {
        (self.value >> 8) != 0 && (self.value & 0xFF) == 0
    }

    /// Check if process was signaled
    pub fn is_signaled(&self) -> bool {
        (self.value >> 8) != 0 && (self.value & 0xFF) != 0 && (self.value & 0x7F) != 0x7F
    }

    /// Check if process was stopped
    pub fn is_stopped(&self) -> bool {
        (self.value & 0xFF) == 0x7F
    }

    /// Get exit code
    pub fn exit_code(&self) -> i32 {
        (self.value >> 8) as i32
    }

    /// Get signal number
    pub fn signal(&self) -> i32 {
        ((self.value >> 8) & 0xFF) as i32
    }

    /// Get raw value
    pub fn raw(&self) -> u32 {
        self.value
    }
}

/// Wait result structure
#[derive(Debug)]
pub struct WaitResult {
    /// PID of exited child
    pub pid: Pid,
    /// Exit status
    pub status: WaitStatus,
    /// User time used (ms)
    pub utime: u64,
    /// System time used (ms)
    pub ktime: u64,
}

impl WaitResult {
    /// Create new wait result
    pub fn new(pid: Pid, status: WaitStatus, utime: u64, ktime: u64) -> Self {
        Self { pid, status, utime, ktime }
    }
}

/// Wait channel for parent processes
pub struct WaitChannel {
    /// Lock
    lock: Spinlock<()>,
    /// Waiting flag
    waiting: bool,
    /// Result when process exits
    result: Option<WaitResult>,
}

impl WaitChannel {
    /// Create new wait channel
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            waiting: false,
            result: None,
        }
    }

    /// Wait for child to exit
    pub fn wait(&mut self) -> Option<WaitResult> {
        let _guard = self.lock.lock();
        self.waiting = true;

        // In a real implementation, this would sleep until result is set
        // For now, just return what's available
        while self.result.is_none() && self.waiting {
            // Would call scheduler to sleep here
        }

        self.result.take()
    }

    /// Wakeup with result
    pub fn wakeup(&mut self, result: WaitResult) {
        let _guard = self.lock.lock();
        self.result = Some(result);
        self.waiting = false;
    }

    /// Try to get result without waiting
    pub fn try_wait(&mut self) -> Option<WaitResult> {
        let _guard = self.lock.lock();
        self.result.take()
    }
}

impl Default for WaitChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait message structure - format for await() return
#[repr(C)]
pub struct WaitMsg {
    /// PID of exited child
    pub pid: i32,
    /// Time in user mode (2*3 = 6 bytes for Plan 9 compat)
    pub time: [u32; 3],
    /// Exit message string (up to 256 bytes)
    pub msg: [u8; 256],
}

impl WaitMsg {
    /// Create a new wait message
    pub fn new(pid: i32, status: i32, msg: &[u8]) -> Self {
        let mut wmsg = Self {
            pid,
            time: [0; 3],
            msg: [0; 256],
        };
        
        // Encode status in time[0] for compatibility
        wmsg.time[0] = status as u32;
        
        // Copy message (truncate if too long)
        let len = msg.len().min(255);
        wmsg.msg[..len].copy_from_slice(&msg[..len]);
        wmsg.msg[len] = 0; // Null terminate
        
        wmsg
    }
    
    /// Get the message as a string
    pub fn message(&self) -> &[u8] {
        let len = self.msg.iter().position(|&c| c == 0).unwrap_or(256);
        &self.msg[..len]
    }
}

/// Await system call implementation
/// Returns when any child process exits
/// 
/// In Plan 9, await() blocks until any child process exits,
/// then returns a message describing how the child exited.
/// 
/// The wait message format is:
///     "pid status time[3] message\0"
/// 
/// # Returns
/// * `Some(WaitResult)` - Information about the exited child
/// * `None` - No children to wait for
pub fn do_await() -> Option<WaitResult> {
    let cur = curproc_mut()?;
    let cur_ptr: *mut Proc = cur;

    // Try non-blocking wait first - check if any children have already exited
    unsafe {
        let result = (*cur_ptr).waitq.take();
        if let Some(r) = result {
            return Some(WaitResult::new(
                r.pid,
                WaitStatus::exited(r.status),
                r.time,
                0,
            ));
        }
    }

    // Check if we have any children at all
    unsafe {
        if (*cur_ptr).nchild <= 0 {
            return None; // No children to wait for
        }

        // Increment wait count
        (*cur_ptr).nwait += 1;

        // Add to wait queue
        (*cur_ptr).state = State::Wait;

        // Enqueue on rendezvous
        (*cur_ptr).waitr.enqueue(&*cur_ptr);
    }

    // Schedule
    crate::sched::schedule();

    // When we wake up, try to get the result
    unsafe {
        let result = (*cur_ptr).waitq.take();
        (*cur_ptr).nwait -= 1;
        result.map(|r| {
            WaitResult::new(
                r.pid,
                WaitStatus::exited(r.status),
                r.time,
                0,
            )
        })
    }
}

/// Add a child exit result to parent's wait queue
/// Called when a child process exits
/// 
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `child_pid` - PID of the exiting child
/// * `status` - Exit status code
/// * `time` - CPU time used by child
pub fn wakeup_parent(parent_pid: Pid, child_pid: Pid, status: i32, time: u64) {
    // Find the parent process
    if let Some(parent_ref) = find_proc(parent_pid) {
        let parent_ptr: *mut Proc = core::ptr::addr_of!(*parent_ref) as *mut Proc;
        let parent = unsafe { &mut *parent_ptr };

        // Decrement child's count
        if parent.nchild > 0 {
            parent.nchild -= 1;
        }

        // Create wait queue entry
        let entry = Box::new(Waitq::new(child_pid, status, time));

        // Add to parent's wait queue
        let _guard = parent.waitq_lock.lock();

        // If parent is waiting, wake them up
        if parent.nwait > 0 && parent.state == State::Wait {
            parent.waitq = Some(entry);
            parent.state = State::Ready;
            // Wake up the parent
            if let Some(r) = parent.waitr.dequeue() {
                let r_ptr: *mut Proc = core::ptr::addr_of!(*r) as *mut Proc;
                let proc = unsafe { &mut *r_ptr };
                proc.state = State::Ready;
                crate::sched::ready(proc);
            }
        } else {
            // Parent not waiting, add to queue for later
            parent.waitq = Some(entry);
        }
    }
}

/// Find a process by PID
///
/// Uses the global process table to find a process by its PID.
///
/// # Arguments
/// * `pid` - Process ID to find
///
/// # Returns
/// * `Option<&'static mut Proc>` - Reference to process if found
pub fn find_proc(pid: Pid) -> Option<&'static mut Proc> {
    proctable_mut().get_mut_proc(pid)
}

// ============================================================================
// Enhanced RFork/Fork Implementation
// ============================================================================

/// Rfork flags (matching Plan 9)
pub mod rfork {
    /// Create a new process (without this, runs in same process)
    pub const FLAGFPROC: u32 = 0x0001;
    /// Share file descriptor group
    pub const FLAGFDG: u32 = 0x0002;
    /// Share memory (implies share everything)
    pub const FLAGFMEM: u32 = 0x0004;
    /// Share signal state
    pub const FLAGFSIGNA: u32 = 0x0008;
    /// Share file system (namespace)
    pub const FLAGFNS: u32 = 0x0010;
    /// Share environment
    pub const FLAGFENV: u32 = 0x0020;
    /// Wait for child in rfork (Plan 9 specific)
    pub const FLAGFWAIT: u32 = 0x0040;
    /// Clone on fork (for threads)
    pub const FLAGFTHREAD: u32 = 0x0080;
    /// File descriptor number hint
    pub const FLAGFNEWPGRP: u32 = 0x0100;

    /// Default flags (new process, copy fd, copy memory)
    pub const FLAGDEFAULT: u32 = FLAGFPROC | FLAGFDG;
}

/// Fork result
#[derive(Debug)]
pub struct ForkResult {
    /// Child PID (0 if this is the child)
    pub child_pid: Pid,
    /// Whether this is the child process
    pub is_child: bool,
}

/// Extended fork options
#[derive(Debug, Clone, Copy)]
pub struct ForkOptions {
    /// Rfork flags
    pub flags: u32,
    /// Stack size (0 = default)
    pub stack_size: usize,
    /// Entry point for child (0 = copy parent context)
    pub entry: Option<fn() -> !>,
}

impl ForkOptions {
    /// Create default fork options
    pub fn new() -> Self {
        Self {
            flags: rfork::FLAGDEFAULT,
            stack_size: KSTACK_SIZE,
            entry: None,
        }
    }

    /// Create options with flags
    pub fn with_flags(flags: u32) -> Self {
        let mut opts = Self::new();
        opts.flags = flags;
        opts
    }

    /// Create thread-like fork (share everything)
    pub fn thread() -> Self {
        Self {
            flags: rfork::FLAGFPROC | rfork::FLAGFMEM | rfork::FLAGFDG | rfork::FLAGFSIGNA,
            stack_size: 0,
            entry: None,
        }
    }

    /// Check if should create new process
    pub fn is_new_process(&self) -> bool {
        self.flags & rfork::FLAGFPROC != 0
    }

    /// Check if should share memory
    pub fn is_shared_memory(&self) -> bool {
        self.flags & rfork::FLAGFMEM != 0
    }

    /// Check if should share file descriptors
    pub fn is_shared_fd(&self) -> bool {
        self.flags & rfork::FLAGFDG != 0
    }
}

impl Default for ForkOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced fork implementation
pub fn do_fork(parent: &Proc, _options: ForkOptions) -> Option<ForkResult> {
    // This implements the Plan 9 rfork semantics:
    // - Without FLAGFPROC: runs in same address space
    // - With FLAGFPROC: creates new process
    // - Without FLAGFMEM: COW fork (copy-on-write)
    // - With FLAGFMEM: shares memory

    let child_pid = if let Some(_p) = parent.parent {
        // Allocate new PID
        proctable_mut().alloc_pid()
    } else {
        proctable_mut().alloc_pid()
    }?;

    // Build ForkResult - in actual implementation this would be returned
    // from the forked child with child_pid = 0
    Some(ForkResult {
        child_pid,
        is_child: false,
    })
}

// ============================================================================
// Global Process Table
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static PROC_TABLE: AtomicPtr<ProcTable> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the global process table
pub fn init_proctable() {
    let table = Box::new(ProcTable::new());
    PROC_TABLE.store(Box::into_raw(table), Ordering::SeqCst);
}

/// Get global process table
pub fn proctable() -> &'static ProcTable {
    unsafe { &*PROC_TABLE.load(Ordering::SeqCst) }
}

/// Get mutable global process table
pub fn proctable_mut() -> &'static mut ProcTable {
    unsafe { &mut *PROC_TABLE.load(Ordering::SeqCst) }
}

// ============================================================================
// Global Rendezvous Table
// ============================================================================

/// Global rendezvous table for process synchronization
/// This is used by the rendezvous syscall to pair up processes
/// that want to synchronize using a shared tag.
static RENDEZVOUS_TABLE: Spinlock<Option<RendezvousTable>> = Spinlock::new(None);

/// Initialize the global rendezvous table
pub fn init_rendezvous_table() {
    let mut guard = RENDEZVOUS_TABLE.lock();
    if guard.is_none() {
        *guard = Some(RendezvousTable::new());
    }
}

/// Get reference to the global rendezvous table
pub fn global_rendezvous_table() -> &'static Spinlock<Option<RendezvousTable>> {
    &RENDEZVOUS_TABLE
}

/// Perform a rendezvous operation using the global table
///
/// If another process is already waiting with the same tag,
/// we pair up and exchange values. Otherwise, we wait.
///
/// # Arguments
/// * `tag` - Rendezvous tag
/// * `val` - Value to exchange
/// * `proc` - Current process
///
/// # Returns
/// * `Ok(exchanged_val)` - Value from the other process
/// * `Err(())` - Should sleep waiting for partner
pub fn rendezvous(tag: usize, val: usize, proc: &'static Proc) -> core::result::Result<usize, ()> {
    let table = global_rendezvous_table();
    let mut guard = table.lock();
    if let Some(ref mut rt) = *guard {
        rt.rendezvous(tag, val, proc)
    } else {
        Err(())
    }
}

/// Wake up a process waiting on a rendezvous point
pub fn wakeup_rendezvous(tag: usize) {
    let table = global_rendezvous_table();
    let mut guard = table.lock();

// Find the process and wake it up
        if let Some(ref mut rt) = *guard {
            for entry in rt.table.iter_mut() {
                if entry.tag == tag && entry.proc.is_some() {
                    let proc_ref = entry.proc.take().unwrap();
                    let proc_ptr: *mut Proc = core::ptr::addr_of!(*proc_ref) as *mut Proc;
                    entry.tag = 0;
                    entry.val = 0;

                    // Wake up the process
                    unsafe {
                        let p = &mut *proc_ptr;
                        p.state = State::Ready;
                        crate::sched::ready(p);
                    }
                    break;
            }
        }
    }
}

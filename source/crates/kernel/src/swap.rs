//! Swap management system
//!
//! Implements the Plan 9 style swap management:
//! - Swap space allocation/deallocation
//! - Pageout daemon (pager) for writing pages to disk
//! - Pagein handling for bringing pages back from disk
//!
//! Reference: Plan 9 `swap.c`

use crate::plan9_common::sync::Spinlock;
use crate::proc::Rendez;

/// Swap allocation structure
pub struct SwapAlloc {
    /// Swap map - bit array indicating which slots are in use
    /// Each entry represents one page (BY2PG bytes)
    swmap: Option<alloc::vec::Vec<u8>>,
    /// Pointer to end of swap map
    top: usize,
    /// Current allocation pointer
    alloc_ptr: usize,
    /// Last allocated position (for first-fit)
    last: usize,
    /// Number of free swap slots
    free: usize,
    /// Rendezvous point for pager synchronization
    r: Rendez,
}

impl SwapAlloc {
    /// Create new swap allocator
    pub fn new(swap_pages: usize) -> Self {
        // Initialize swap map with all slots free (0)
        let swmap = alloc::vec![0u8; swap_pages];
        
        Self {
            top: swap_pages,
            alloc_ptr: 0,
            last: 0,
            free: swap_pages,
            swmap: Some(swmap),
            r: Rendez::new(),
        }
    }

    /// Check if swap is initialized
    pub fn is_initialized(&self) -> bool {
        self.swmap.is_some()
    }

    /// Get number of free swap slots
    pub fn free_count(&self) -> usize {
        self.free
    }

    /// Allocate a swap slot
    ///
    /// Returns the swap offset (in bytes) of the allocated slot,
    /// or `usize::MAX` if no slots are available.
    pub fn alloc(&mut self) -> usize {
        let swmap = match &mut self.swmap {
            Some(m) => m,
            None => return usize::MAX,
        };

        if self.free == 0 {
            return usize::MAX;
        }

        // First-fit allocation - find first free slot after last
        let mut idx = self.last;
        for _ in 0..self.top {
            if swmap[idx] == 0 {
                // Found a free slot
                swmap[idx] = 1;
                self.free -= 1;
                self.last = idx;
                // Convert to byte offset (each slot = one page = BY2PG bytes)
                return idx * BY2PG;
            }
            idx = (idx + 1) % self.top;
        }

        usize::MAX
    }

    /// Free a swap slot
    ///
    /// # Arguments
    /// * `daddr` - Swap offset in bytes (returned from alloc())
    pub fn free(&mut self, daddr: usize) {
        let swmap = match &mut self.swmap {
            Some(m) => m,
            None => return,
        };

        let idx = daddr / BY2PG;
        if idx >= self.top {
            return;
        }

        if swmap[idx] > 0 {
            swmap[idx] -= 1;
            self.free += 1;
            
            // Update last pointer if we freed a slot before current last
            if idx < self.last {
                self.last = idx;
            }
        }
    }

    /// Increment reference count on a swap slot
    pub fn inc_ref(&mut self, daddr: usize) {
        let swmap = match &mut self.swmap {
            Some(m) => m,
            None => return,
        };

        let idx = daddr / BY2PG;
        if idx < self.top && swmap[idx] < 255 {
            swmap[idx] += 1;
        }
    }

    /// Get reference count on a swap slot
    pub fn ref_count(&self, daddr: usize) -> u8 {
        let swmap = match &self.swmap {
            Some(m) => m,
            None => return 0,
        };

        let idx = daddr / BY2PG;
        if idx < self.top {
            swmap[idx]
        } else {
            0
        }
    }
}

/// Page size in bytes (4KB)
const BY2PG: usize = 4096;

/// Generation-based page aging
#[derive(Default)]
struct GenState {
    /// Current generation clock
    genclock: u64,
    /// Average generation age
    genage: u64,
    /// Sum of ages (for averaging)
    gensum: u64,
    /// Count of pages (for averaging)
    gencount: u64,
}

/// Page to be written to swap
struct SwapPage {
    /// Physical address of the page
    pa: usize,
    /// Swap offset
    swap_addr: usize,
    /// Reference count (for COW)
    refcnt: u8,
    /// Modification/reference bits
    modref: u8,
    /// Generation number (for aging)
    gen: u64,
}

/// Swap statistics
pub struct SwapStats {
    /// Total swap pages
    pub total: usize,
    /// Free swap pages
    pub free: usize,
    /// Pages swapped out
    pub swapped_out: u64,
    /// Pages swapped in
    pub swapped_in: u64,
    /// Number of pageouts performed
    pub pageouts: u64,
    /// Number of pageins performed
    pub pageins: u64,
}

impl Default for SwapStats {
    fn default() -> Self {
        Self {
            total: 0,
            free: 0,
            swapped_out: 0,
            swapped_in: 0,
            pageouts: 0,
            pageins: 0,
        }
    }
}

/// Swap manager - manages all swap operations
pub struct SwapManager {
    /// Swap allocator
    alloc: Spinlock<SwapAlloc>,
    /// Generation state for aging
    gen: Spinlock<GenState>,
    /// Statistics
    stats: Spinlock<SwapStats>,
    /// Flag indicating if pager thread should run
    pager_kicked: Spinlock<bool>,
}

impl SwapManager {
    /// Create a new swap manager
    pub fn new(swap_pages: usize) -> Self {
        Self {
            alloc: Spinlock::new(SwapAlloc::new(swap_pages)),
            gen: Spinlock::new(GenState::default()),
            stats: Spinlock::new(SwapStats {
                total: swap_pages,
                free: swap_pages,
                ..Default::default()
            }),
            pager_kicked: Spinlock::new(false),
        }
    }

    /// Check if swap is available
    pub fn is_available(&self) -> bool {
        self.alloc.lock().is_initialized()
    }

    /// Allocate a swap slot for a page
    ///
    /// Returns the swap offset, or `usize::MAX` if no space available.
    pub fn alloc_swap(&self) -> usize {
        let mut alloc = self.alloc.lock();
        let result = alloc.alloc();
        
        if result != usize::MAX {
            let mut stats = self.stats.lock();
            stats.free = alloc.free_count();
        }
        
        result
    }

    /// Free a swap slot
    pub fn free_swap(&self, swap_addr: usize) {
        let mut alloc = self.alloc.lock();
        alloc.free(swap_addr);
        
        let mut stats = self.stats.lock();
        stats.free = alloc.free_count();
    }

    /// Get current swap statistics
    pub fn stats(&self) -> SwapStats {
        *self.stats.lock()
    }

    /// Kick the pager to start pageout operations
    ///
    /// This is called when memory is running low and pages need to be
    /// written to swap.
    pub fn kick_pager(&self) {
        let mut kicked = self.pager_kicked.lock();
        if !*kicked {
            *kicked = true;
            // TODO: Wake up pager thread
            // wakeup(&self.pager_rendez);
        }
    }

    /// Advance generation clock (called periodically)
    pub fn tick(&self) {
        let mut gen = self.gen.lock();
        gen.genclock += 1;
        
        if gen.gencount > 0 {
            gen.genage = gen.gensum / gen.gencount;
        } else {
            gen.genage = 0;
        }
        gen.gensum = 0;
        gen.gencount = 0;
    }

    /// Record page age for statistics
    pub fn record_age(&self, age: u64) {
        let mut gen = self.gen.lock();
        gen.gensum += age;
        gen.gencount += 1;
    }

    /// Check if a page should be paged out based on age
    pub fn should_pageout(&self, page_age: u64) -> bool {
        let gen = self.gen.lock();
        page_age > gen.genage
    }
}

// ============================================================================
// Pageout Daemon (Pager)
// ============================================================================

/// The pageout daemon (pager) thread
///
/// This runs as a kernel thread and is responsible for:
/// 1. Monitoring memory pressure
/// 2. Selecting pages to swap out
/// 3. Writing pages to the swap device
/// 4. Updating page table entries to point to swap
///
/// The pager is kicked by `kick_pager()` when memory is low.
pub struct Pager {
    /// Swap manager
    swap: Spinlock<SwapManager>,
    /// List of pages to be written (physical addresses)
    iolist: Spinlock<alloc::vec::Vec<usize>>,
    /// Index into iolist for current I/O
    ioptr: Spinlock<usize>,
    /// Maximum pages to write in one batch
    max_batch: usize,
}

impl Pager {
    /// Create a new pager
    pub fn new(swap_pages: usize) -> Self {
        Self {
            swap: Spinlock::new(SwapManager::new(swap_pages)),
            iolist: Spinlock::new(alloc::vec::Vec::with_capacity(64)),
            ioptr: Spinlock::new(0),
            max_batch: 64,
        }
    }

    /// Main pager loop
    ///
    /// This would typically run as a kernel thread. It waits for memory
    /// pressure, then iterates through processes and their segments to
    /// find pages that should be paged out.
    ///
    /// # Returns
    /// Never returns - this is a daemon loop.
    pub fn run(&self) -> ! {
        loop {
            // Check if kicked
            let kicked = *self.pager_kicked.lock();
            if !kicked {
                // TODO: Sleep until kicked
                // sleep(&self.swap.lock().rendez, ...);
                continue;
            }

            // Process pages to page out
            self.pageout_loop();

            // Reset kick flag
            *self.pager_kicked.lock() = false;
        }
    }

    /// Main pageout processing loop
    fn pageout_loop(&self) {
        // Tick the generation clock
        self.swap.lock().tick();

        // TODO: Iterate through processes and segments
        // For each segment:
        //   - Check if segment is swappable
        //   - Walk page tables looking for clean pages to evict
        //   - Add physical addresses to iolist

        // If we have pages to write, do the I/O
        self.execute_io();
    }

    /// Execute pageout I/O
    fn execute_io(&self) {
        let mut iolist = self.iolist.lock();
        let mut ioptr = self.ioptr.lock();
        
        let pages: alloc::vec::Vec<usize> = iolist.drain(..).collect();
        *ioptr = 0;
        
        drop(iolist);

        for pa in pages {
            // TODO: Write page to swap device
            // This would call the block device driver
            
            // Update statistics
            let mut stats = self.stats.lock();
            stats.swapped_out += 1;
            stats.pageouts += 1;
        }
    }

    /// Add a page to the pageout list
    pub fn add_page(&self, pa: usize) {
        let mut iolist = self.iolist.lock();
        if iolist.len() < self.max_batch {
            iolist.push(pa);
        }
    }

    /// Check if there are pages to page out
    pub fn needs_pageout(&self) -> bool {
        !self.iolist.lock().is_empty()
    }

    fn pager_kicked(&self) -> bool {
        *self.pager_kicked.lock()
    }
}

// ============================================================================
// Global Swap Manager Instance
// ============================================================================

use core::sync::atomic::{AtomicPtr, Ordering};

static SWAP_MANAGER: AtomicPtr<SwapManager> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the swap manager with the given number of swap pages
pub fn init_swap(swap_pages: usize) {
    let manager = Box::new(SwapManager::new(swap_pages));
    let ptr = Box::into_raw(manager);
    SWAP_MANAGER.store(ptr, Ordering::SeqCst);
}

/// Get reference to the global swap manager
pub fn swap_manager() -> &'static SwapManager {
    unsafe { &*SWAP_MANAGER.load(Ordering::SeqCst) }
}

/// Check if swap is available
pub fn swap_available() -> bool {
    let m = swap_manager();
    m.is_available()
}

/// Allocate a swap slot
pub fn alloc_swap() -> usize {
    swap_manager().alloc_swap()
}

/// Free a swap slot
pub fn free_swap(swap_addr: usize) {
    swap_manager().free_swap(swap_addr)
}

/// Kick the pager
pub fn kick_pager() {
    swap_manager().kick_pager();
}

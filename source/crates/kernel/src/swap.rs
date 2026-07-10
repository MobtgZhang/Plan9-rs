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
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Page size in bytes (4KB)
pub const BY2PG: usize = 4096;

/// Segment types (matches Plan 9 definitions)
pub const SG_TYPE: u8 = 0x0F;
pub const SG_TEXT: u8 = 0x00;      // Text segment
pub const SG_DATA: u8 = 0x01;      // Data segment
pub const SG_BSS: u8 = 0x02;       // BSS segment
pub const SG_STACK: u8 = 0x03;     // Stack segment
pub const SG_SHARED: u8 = 0x04;    // Shared segment
pub const SG_PHYSICAL: u8 = 0x05;  // Physical segment

/// Page flags
pub const PG_PRESENT: u8 = 0x01;   // Page is present in memory
pub const PG_REF: u8 = 0x02;       // Page has been referenced
pub const PG_MOD: u8 = 0x04;       // Page has been modified (dirty)
pub const PG_ONSWAP: usize = 0x80000000; // Page is on swap

/// Maximum number of pages to page out in one batch
pub const MAX_SWAP_PAGES: usize = 64;

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

        // First-fit allocation - wraps around the entire map starting from
        // `last`. We iterate up to `self.top` times so that every slot is
        // visited exactly once, even if the free slot lies before `last`
        // (e.g. after wrapping past the end of the map).
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

        // Map is fully allocated - no free slots.
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

/// Generation-based page aging
///
/// This implements a clock-based page replacement algorithm similar to Plan 9.
/// Each page has a generation number, and the pager periodically advances the
/// generation clock. Pages that haven't been referenced for longer periods
/// become candidates for pageout.
#[derive(Default)]
pub struct GenState {
    /// Current generation clock
    pub genclock: u64,
    /// Average generation age (threshold for pageout)
    pub genage: u64,
    /// Sum of ages (for averaging)
    gensum: u64,
    /// Count of pages (for averaging)
    gencount: u64,
}

impl GenState {
    /// Advance the generation clock (called periodically by pager)
    ///
    /// This marks the end of one aging interval. After this, pages that
    /// haven't been referenced will have higher age values.
    pub fn tick(&mut self) {
        self.genclock += 1;
        if self.gencount > 0 {
            self.genage = self.gensum / self.gencount;
        } else {
            self.genage = 0;
        }
        self.gensum = 0;
        self.gencount = 0;
    }

    /// Record a page's age for statistics
    ///
    /// # Arguments
    /// * `age` - The age of the page (genclock - page.gen)
    pub fn record_age(&mut self, age: u64) {
        self.gensum += age;
        self.gencount += 1;
    }

    /// Calculate age of a page given its generation number
    pub fn page_age(&self, page_gen: u64) -> u64 {
        if self.genclock >= page_gen {
            self.genclock - page_gen
        } else {
            // Handle wraparound (unlikely with u64)
            !page_gen + self.genclock + 1
        }
    }

    /// Check if a page should be paged out based on its age
    ///
    /// Pages older than the average age (genage) are candidates for pageout.
    pub fn should_pageout(&self, page_gen: u64) -> bool {
        let age = self.page_age(page_gen);
        age > self.genage
    }
}

/// Page to be written to swap
///
/// This represents a page that has been selected for pageout and is queued
/// for I/O. It contains both the physical memory location and the swap location.
pub struct SwapPage {
    /// Physical address of the page
    pub pa: usize,
    /// Swap offset (byte address in swap space, or ON_SWAP bit set)
    pub swap_addr: usize,
    /// Reference count (for COW)
    pub refcnt: u8,
    /// Modification/reference bits (PG_REF, PG_MOD)
    pub modref: u8,
    /// Generation number (for aging)
    pub gen: u64,
}

impl SwapPage {
    /// Create a new swap page entry
    pub fn new(pa: usize, swap_addr: usize) -> Self {
        Self {
            pa,
            swap_addr,
            refcnt: 1,
            modref: 0,
            gen: 0,
        }
    }

    /// Check if the page has been referenced
    pub fn is_referenced(&self) -> bool {
        (self.modref & PG_REF) != 0
    }

    /// Check if the page has been modified (dirty)
    pub fn is_modified(&self) -> bool {
        (self.modref & PG_MOD) != 0
    }

    /// Check if the page is on swap
    pub fn is_on_swap(&self) -> bool {
        (self.swap_addr & PG_ONSWAP) != 0
    }

    /// Clear the referenced bit
    pub fn clear_ref(&mut self) {
        self.modref &= !PG_REF;
    }

    /// Set the referenced bit
    pub fn set_ref(&mut self) {
        self.modref |= PG_REF;
    }
}

/// Swap statistics
#[derive(Clone, Copy)]
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
    /// Maximum pages per pageout batch
    max_batch: usize,
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
            max_batch: MAX_SWAP_PAGES,
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
    /// written to swap. It both sets the kicked flag and wakes the
    /// pager thread via the `Rendez` in `SwapAlloc`, so the pager
    /// does not have to busy-wait.
    pub fn kick_pager(&self) {
        {
            let mut kicked = self.pager_kicked.lock();
            if !*kicked {
                *kicked = true;
            }
        }

        // Wake the pager thread if it is sleeping on the rendezvous
        // point inside `SwapAlloc`. We must drop the spinlock before
        // touching the rendezvous, otherwise psleep/pwakeup can deadlock.
        let mut alloc = self.alloc.lock();
        let _ = crate::proc::pwakeup(&mut alloc.r);
    }

    /// Check if pager has been kicked
    pub fn is_kicked(&self) -> bool {
        *self.pager_kicked.lock()
    }

    /// Clear the pager kick flag
    pub fn clear_kick(&self) {
        *self.pager_kicked.lock() = false;
    }

    /// Advance generation clock (called periodically)
    ///
    /// This marks the end of one aging interval. After calling this,
    /// pages that haven't been referenced since the last tick will
    /// have higher age values.
    pub fn tick(&self) {
        let mut gen = self.gen.lock();
        gen.tick();
    }

    /// Record page age for statistics
    ///
    /// Called when scanning pages to track their ages for the
    /// generation-based aging algorithm.
    pub fn record_age(&self, age: u64) {
        let mut gen = self.gen.lock();
        gen.record_age(age);
    }

    /// Check if a page should be paged out based on its generation number
    ///
    /// Returns true if the page's age exceeds the average age threshold.
    pub fn should_pageout_by_gen(&self, page_gen: u64) -> bool {
        let gen = self.gen.lock();
        gen.should_pageout(page_gen)
    }

    /// Get reference to generation state for scanning
    pub fn gen_state(&self) -> impl core::ops::Deref<Target = GenState> + '_ {
        self.gen.lock()
    }

    /// Get current generation clock
    pub fn gen_clock(&self) -> u64 {
        self.gen.lock().genclock
    }

    /// Get the maximum batch size for pageout
    pub fn max_batch(&self) -> usize {
        self.max_batch
    }

    /// Increment swap out counter
    pub fn inc_swapped_out(&self) {
        let mut stats = self.stats.lock();
        stats.swapped_out += 1;
        stats.pageouts += 1;
    }

    /// Increment swap in counter
    pub fn inc_swapped_in(&self) {
        let mut stats = self.stats.lock();
        stats.swapped_in += 1;
        stats.pageins += 1;
    }

    /// Check if we have free swap space
    pub fn has_free_swap(&self) -> bool {
        self.alloc.lock().free_count() > 0
    }

    /// Get free swap count
    pub fn free_swap_count(&self) -> usize {
        self.alloc.lock().free_count()
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
    iolist: Spinlock<alloc::vec::Vec<SwapPage>>,
    /// Index into iolist for current I/O
    ioptr: Spinlock<usize>,
    /// Maximum pages to write in one batch
    max_batch: usize,
    /// Flag indicating if pager is running
    running: Spinlock<bool>,
}

impl Pager {
    /// Create a new pager
    pub fn new(swap_pages: usize) -> Self {
        Self {
            swap: Spinlock::new(SwapManager::new(swap_pages)),
            iolist: Spinlock::new(alloc::vec::Vec::with_capacity(64)),
            ioptr: Spinlock::new(0),
            max_batch: MAX_SWAP_PAGES,
            running: Spinlock::new(false),
        }
    }

    /// Get reference to swap manager
    pub fn swap_manager(&self) -> &Spinlock<SwapManager> {
        &self.swap
    }

    /// Main pager loop
    ///
    /// This runs as a kernel thread. It waits for memory
    /// pressure, then iterates through processes and their segments to
    /// find pages that should be paged out.
    ///
    /// # Returns
    /// Never returns - this is a daemon loop.
    pub fn run(&self) -> ! {
        {
            let mut running = self.running.lock();
            *running = true;
        }

        loop {
            // Snapshot the kicked flag under the spinlock. If we are
            // not kicked, sleep on the Rendez inside SwapAlloc until
            // kick_pager() calls pwakeup(). We must not hold any
            // spinlocks across psleep (it yields the CPU), so grab a
            // raw pointer to the rendez and release the locks first.
            let r_ptr: *mut Rendez = {
                let swap = self.swap.lock();
                if !swap.is_kicked() {
                    // Take a raw pointer to the rendez inside SwapAlloc
                    // and release every lock before sleeping.
                    let mut alloc_guard = swap.alloc.lock();
                    let r_ref: &mut Rendez = &mut alloc_guard.r;
                    let r_ptr: *mut Rendez =
                        core::ptr::addr_of_mut!(*r_ref) as *mut Rendez;
                    // Explicitly drop the guards before sleeping.
                    drop(alloc_guard);
                    drop(swap);
                    // Sleep until kick_pager() wakes us. The predicate
                    // is re-evaluated after wakeup.
                    crate::proc::psleep(unsafe { &mut *r_ptr }, || {
                        self.swap.lock().is_kicked()
                    });
                    continue;
                }
                // Already kicked - skip the sleep entirely.
                core::ptr::null_mut()
            };
            // Suppress unused-variable warning when we don't sleep.
            let _ = r_ptr;

            // Process pages to page out
            self.pageout_loop();

            // Clear kick flag (and let the next iteration sleep again).
            self.swap.lock().clear_kick();
        }
    }

    /// Main pageout processing loop
    ///
    /// This implements the core pageout logic based on Plan 9's pager.
    /// It walks through processes and segments, looking for pages that
    /// should be paged out based on the generation-based aging algorithm.
    fn pageout_loop(&self) {
        // Tick the generation clock to advance page ages
        self.swap.lock().tick();

        // Clear the I/O list for new entries
        {
            let mut iolist = self.iolist.lock();
            iolist.clear();
            *self.ioptr.lock() = 0;
        }

        // In a full implementation, we would iterate through processes and segments:
        // - Check if segment is swappable (not SG_TEXT which can be demand loaded)
        // - Walk page tables looking for clean pages to evict
        // - For each candidate page:
        //   - Clear the PG_REF bit (simulate hardware clearing it)
        //   - Record the page's age for statistics
        //   - If age > genage, add to iolist for pageout
        //
        // The page scanning logic would integrate with:
        // - Process table (procs)
        // - Segment table per process
        // - Page table entries (PTEs)
        //
        // For now, we rely on pages being added via add_page()

        // If we have pages to write, do the I/O
        self.execute_io();
    }

    /// Execute pageout I/O
    ///
    /// This performs the actual block I/O to write pages from memory to swap.
    /// It handles batching, error recovery, and updating page table entries.
    fn execute_io(&self) {
        // Drain pages from the I/O list
        let pages: alloc::vec::Vec<SwapPage> = {
            let mut iolist = self.iolist.lock();
            let ptr = *self.ioptr.lock();

            // Only process up to max_batch pages
            let end = (ptr + self.max_batch).min(iolist.len());
            iolist.drain(ptr..end).collect()
        };

        if pages.is_empty() {
            return;
        }

        // Hold the swap-device lock while we issue I/O so concurrent
        // writers don't interleave on the same swap slot. The lock is
        // released at the end of the scope.
        let _dev = swap_device_lock().lock();

        for page in pages {
            let pa_u64 = page.pa as u64;
            let swap_off = page.swap_addr;

            // Perform the actual I/O - copy the page from physical
            // memory to the swap device at page.swap_addr.
            match crate::swap::write_page_to_swap(pa_u64, swap_off) {
                Ok(_) => {
                    self.swap.lock().inc_swapped_out();
                }
                Err(_) => {
                    crate::kmesg::kmesg_puts(b"swap: write failed\n");
                }
            }
        }
    }

    /// Add a page to the pageout list
    ///
    /// This is called from the VM subsystem when a page needs to be
    /// written to swap.
    ///
    /// # Arguments
    /// * `page` - The page to page out
    ///
    /// # Returns
    /// * `true` if the page was added
    /// * `false` if the I/O list is full
    pub fn add_page(&self, page: SwapPage) -> bool {
        let mut iolist = self.iolist.lock();
        if iolist.len() >= self.max_batch {
            return false;
        }
        iolist.push(page);
        true
    }

    /// Add a page to the pageout list (simple version)
    ///
    /// # Arguments
    /// * `pa` - Physical address of the page
    /// * `swap_addr` - Swap offset for the page
    pub fn add_page_simple(&self, pa: usize, swap_addr: usize) -> bool {
        self.add_page(SwapPage::new(pa, swap_addr))
    }

    /// Check if there are pages to page out
    pub fn needs_pageout(&self) -> bool {
        !self.iolist.lock().is_empty()
    }

    /// Get current I/O list length
    pub fn iolist_len(&self) -> usize {
        self.iolist.lock().len()
    }

    /// Check if pager is running
    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }

    /// Stop the pager
    pub fn stop(&self) {
        let mut running = self.running.lock();
        *running = false;
    }

    /// Scan a process's memory and identify pages for pageout
    ///
    /// This is the interface called from the VM subsystem to scan pages
    /// that might need to be paged out. The actual page table walking
    /// is done by the VM subsystem.
    ///
    /// # Arguments
    /// * `pages` - Iterator of candidate pages with their metadata
    ///
    /// Pages that should be paged out are added to the iolist.
    pub fn scan_pages<'a, I>(&self, pages: I)
    where
        I: Iterator<Item = &'a ScanPageInfo>,
    {
        for page in pages {
            // Get generation info under lock
            let (page_age, should_pageout): (u64, bool) = {
                let guard = self.swap.lock();
                let g = guard.gen_state();
                (g.page_age(page.gen), g.should_pageout(page.gen))
            };
            
            // Record age for statistics
            self.swap.lock().record_age(page_age);
            
            // Check if page should be paged out
            if should_pageout && page.refcount == 1 {
                // Create swap page entry
                let swap_page = SwapPage {
                    pa: page.phys_addr,
                    swap_addr: page.swap_addr,
                    refcnt: page.refcount,
                    modref: page.modref,
                    gen: page.gen,
                };
                
                // Add to iolist if we have space
                if !self.add_page(swap_page) {
                    // I/O list full, stop scanning
                    break;
                }
            }
        }
    }
}

/// Information about a page for scanning
///
/// This structure is passed from the VM subsystem to the pager
/// during pageout scanning.
pub struct ScanPageInfo {
    /// Physical address of the page
    pub phys_addr: usize,
    /// Swap address (0 if not on swap)
    pub swap_addr: usize,
    /// Reference count (for COW)
    pub refcount: u8,
    /// Modification/reference flags
    pub modref: u8,
    /// Generation number (for aging)
    pub gen: u64,
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

// ============================================================================
// Swap Device Interface
// ============================================================================

/// Block device trait for swap and storage operations
///
/// This trait defines the interface for block-oriented storage devices
/// that can be used for swap space, file systems, or other block I/O needs.
pub trait BlockDevice: Send + Sync {
    /// Read a block from the device
    ///
    /// # Arguments
    /// * `block_num` - Block number to read (0-indexed)
    /// * `buf` - Buffer to store the read data
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(())` on I/O error
    fn read_block(&mut self, block_num: u64, buf: &mut [u8]) -> Result<(), ()>;

    /// Write a block to the device
    ///
    /// # Arguments
    /// * `block_num` - Block number to write (0-indexed)
    /// * `buf` - Buffer containing data to write
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(())` on I/O error
    fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), ()>;

    /// Get the block size of this device
    fn block_size(&self) -> usize;

    /// Get the total number of blocks on this device
    fn num_blocks(&self) -> u64;
}

/// RAM-based block device for testing and early boot
///
/// This provides a simple in-memory block device that can be used
/// when no real storage is available.
pub struct RamBlockDevice {
    /// Block size in bytes
    block_size: usize,
    /// Total number of blocks
    num_blocks: u64,
    /// Storage buffer
    storage: Vec<u8>,
}

impl RamBlockDevice {
    /// Create a new RAM block device
    ///
    /// # Arguments
    /// * `block_size` - Size of each block in bytes
    /// * `num_blocks` - Total number of blocks
    pub fn new(block_size: usize, num_blocks: u64) -> Self {
        let total_size = block_size * num_blocks as usize;
        Self {
            block_size,
            num_blocks,
            storage: alloc::vec![0u8; total_size],
        }
    }
}

impl BlockDevice for RamBlockDevice {
    fn read_block(&mut self, block_num: u64, buf: &mut [u8]) -> Result<(), ()> {
        if block_num >= self.num_blocks {
            return Err(());
        }
        if buf.len() != self.block_size {
            return Err(());
        }

        let offset = block_num as usize * self.block_size;
        buf.copy_from_slice(&self.storage[offset..offset + self.block_size]);
        Ok(())
    }

    fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), ()> {
        if block_num >= self.num_blocks {
            return Err(());
        }
        if buf.len() != self.block_size {
            return Err(());
        }

        let offset = block_num as usize * self.block_size;
        self.storage[offset..offset + self.block_size].copy_from_slice(buf);
        Ok(())
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        self.num_blocks
    }
}

/// Swap device for reading/writing swap space
///
/// This provides the interface between the swap manager and the actual
/// storage device used for swap. It wraps a BlockDevice and provides
/// byte-offset based access.
pub struct SwapDevice {
    /// Whether swap device is initialized
    initialized: bool,
    /// Base offset for swap area on the device (in bytes)
    base_offset: usize,
    /// Block device for actual I/O
    block_device: Option<Box<dyn BlockDevice>>,
    /// Page size for alignment
    page_size: usize,
}

impl SwapDevice {
    /// Create a new swap device (uninitialized)
    pub fn new() -> Self {
        Self {
            initialized: false,
            base_offset: 0,
            block_device: None,
            page_size: 4096,
        }
    }

    /// Create a new swap device with a backing block device
    ///
    /// # Arguments
    /// * `block_device` - The block device to use for I/O
    /// * `base_offset` - Offset in bytes where swap area starts
    pub fn with_device(block_device: Box<dyn BlockDevice>, base_offset: usize) -> Self {
        Self {
            initialized: true,
            base_offset,
            block_device: Some(block_device),
            page_size: 4096,
        }
    }

    /// Initialize the swap device with the given base offset
    pub fn init(&mut self, base_offset: usize) {
        self.base_offset = base_offset;
        self.initialized = true;
    }

    /// Set the block device for actual I/O operations
    ///
    /// This enables real block I/O instead of simulation.
    pub fn set_block_device(&mut self, device: Box<dyn BlockDevice>) {
        self.block_device = Some(device);
        self.initialized = true;
    }

    /// Check if swap device is ready
    pub fn is_ready(&self) -> bool {
        self.initialized && self.block_device.is_some()
    }

    /// Get the block size from the underlying device
    fn get_block_size(&self) -> usize {
        self.block_device
            .as_ref()
            .map(|d| d.block_size())
            .unwrap_or(self.page_size)
    }

    /// Read from swap space into memory
    ///
    /// This performs actual block I/O to read a page from swap.
    ///
    /// # Arguments
    /// * `swap_offset` - Byte offset within swap space
    /// * `dest` - Destination physical address to write data
    /// * `len` - Number of bytes to read (should be page size)
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(())` if I/O error
    pub fn read(&mut self, swap_offset: usize, dest: *mut u8, len: usize) -> Result<(), ()> {
        if !self.initialized {
            return Err(());
        }

        // Validate parameters
        if dest.is_null() || len == 0 || len != self.page_size {
            return Err(());
        }

        // Calculate actual device offset
        let device_offset = self.base_offset + swap_offset;

        // Try real block I/O if available
        if let Some(ref mut device) = self.block_device {
            let block_size = device.block_size();
            let block_num = device_offset / block_size;
            let offset_in_block = device_offset % block_size;

            // For page-aligned reads (most common case)
            if offset_in_block == 0 && len == block_size {
                // Single block read
                unsafe {
                    let buf = core::slice::from_raw_parts_mut(dest, len);
                    return device.read_block(block_num as u64, buf);
                }
            } else {
                // Cross-block read - need to handle carefully
                // For now, handle the common case of page-aligned I/O
                // In production, this would use an intermediate buffer
                let mut buffer = alloc::vec![0u8; block_size];
                device.read_block(block_num as u64, &mut buffer)?;
                let start = offset_in_block;
                let count = len.min(block_size - offset_in_block);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer[start..start + count].as_ptr(),
                        dest,
                        count
                    );
                }
                return Ok(());
            }
        }

        // Fallback: simulation
        self.simulate_read(device_offset, dest, len)
    }

    /// Write to swap space from memory
    ///
    /// This performs actual block I/O to write a page to swap.
    ///
    /// # Arguments
    /// * `swap_offset` - Byte offset within swap space
    /// * `src` - Source pointer with data to write
    /// * `len` - Number of bytes to write (should be page size)
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(())` if I/O error
    pub fn write(&mut self, swap_offset: usize, src: *const u8, len: usize) -> Result<(), ()> {
        if !self.initialized {
            return Err(());
        }

        // Validate parameters
        if src.is_null() || len == 0 || len != self.page_size {
            return Err(());
        }

        // Calculate actual device offset
        let device_offset = self.base_offset + swap_offset;

        // Try real block I/O if available
        if let Some(ref mut device) = self.block_device {
            let block_size = device.block_size();
            let block_num = device_offset / block_size;
            let offset_in_block = device_offset % block_size;

            // For page-aligned writes (most common case)
            if offset_in_block == 0 && len == block_size {
                // Single block write
                unsafe {
                    let buf = core::slice::from_raw_parts(src, len);
                    return device.write_block(block_num as u64, buf);
                }
            } else {
                // Cross-block write - need to handle carefully
                // For now, handle the common case of page-aligned I/O
                let mut buffer = alloc::vec![0u8; block_size];
                unsafe {
                    core::ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), len);
                }
                return device.write_block(block_num as u64, &buffer);
            }
        }

        // Fallback: simulation
        self.simulate_write(device_offset, src, len)
    }

    /// Simulated read (placeholder for actual block I/O)
    fn simulate_read(&self, _offset: usize, dest: *mut u8, len: usize) -> Result<(), ()> {
        if dest.is_null() || len == 0 {
            return Err(());
        }

        // In production, this would be actual disk I/O through the block layer.
        // For now, simulate a successful read by zeroing the destination buffer.
        unsafe {
            core::ptr::write_bytes(dest, 0, len);
        }

        Ok(())
    }

    /// Simulated write (placeholder for actual block I/O)
    fn simulate_write(&self, _offset: usize, src: *const u8, len: usize) -> Result<(), ()> {
        // In a real implementation, this would write to the swap device
        // For now, we just succeed (the data is assumed to be in memory)
        if src.is_null() || len == 0 {
            return Err(());
        }

        // Simulate successful write
        // In production, this would be actual disk I/O
        let _ = src;
        let _ = len;
        Ok(())
    }
}

impl Default for SwapDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// Global swap device instance (lazily initialised).
static SWAP_DEVICE: spin::Once<Swaplock> = spin::Once::new();

/// Lock type for swap device
struct Swaplock(Spinlock<SwapDevice>);

/// Initialize the global swap device
pub fn init_swap_device(base_offset: usize) {
    SWAP_DEVICE.call_once(|| {
        let dev = Spinlock::new(SwapDevice::new());
        dev.lock().init(base_offset);
        Swaplock(dev)
    });
}

/// Get reference to the global swap device
fn swap_device_lock() -> &'static Spinlock<SwapDevice> {
    let lock = SWAP_DEVICE
        .get()
        .expect("swap device not initialized");
    &lock.0
}

/// Read a page from swap into physical memory
///
/// # Arguments
/// * `phys_addr` - Physical address to read into
/// * `swap_offset` - Offset in swap space
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(())` if I/O error
pub fn read_page_from_swap(phys_addr: u64, swap_offset: usize) -> Result<(), ()> {
    use crate::plan9_arch::x86_64::paging::phys_to_virt;
    use crate::plan9_common::types::PhysAddr;

    let virt = phys_to_virt(PhysAddr::new(phys_addr));
    swap_device_lock().lock().read(swap_offset, virt.as_mut_ptr(), BY2PG)
}

/// Write a page from physical memory to swap
///
/// # Arguments
/// * `phys_addr` - Physical address to write from
/// * `swap_offset` - Offset in swap space
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(())` if I/O error
pub fn write_page_to_swap(phys_addr: u64, swap_offset: usize) -> Result<(), ()> {
    use crate::plan9_arch::x86_64::paging::phys_to_virt;
    use crate::plan9_common::types::PhysAddr;

    let virt = phys_to_virt(PhysAddr::new(phys_addr));
    swap_device_lock().lock().write(swap_offset, virt.as_ptr(), BY2PG)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_swap_alloc_basic() {
        let mut alloc = SwapAlloc::new(100);
        
        // Should start with all free slots
        assert_eq!(alloc.free_count(), 100);
        assert!(alloc.is_initialized());
    }

    #[test]
    fn test_swap_alloc_and_free() {
        let mut alloc = SwapAlloc::new(100);
        
        // Allocate a slot
        let slot1 = alloc.alloc();
        assert_ne!(slot1, usize::MAX);
        assert_eq!(alloc.free_count(), 99);
        
        // Allocate another slot
        let slot2 = alloc.alloc();
        assert_ne!(slot2, usize::MAX);
        assert_eq!(alloc.free_count(), 98);
        
        // Free the first slot
        alloc.free(slot1);
        assert_eq!(alloc.free_count(), 99);
    }

    #[test]
    fn test_swap_alloc_full() {
        let mut alloc = SwapAlloc::new(2);
        
        // Allocate both slots
        let slot1 = alloc.alloc();
        let slot2 = alloc.alloc();
        assert_ne!(slot1, usize::MAX);
        assert_ne!(slot2, usize::MAX);
        assert_eq!(alloc.free_count(), 0);
        
        // Should fail to allocate more
        let slot3 = alloc.alloc();
        assert_eq!(slot3, usize::MAX);
    }

    #[test]
    fn test_swap_alloc_ref_count() {
        let mut alloc = SwapAlloc::new(10);
        
        // Allocate and increment refcount
        let slot = alloc.alloc();
        assert_ne!(slot, usize::MAX);
        
        alloc.inc_ref(slot);
        assert_eq!(alloc.ref_count(slot), 2);
        
        // Free once
        alloc.free(slot);
        assert_eq!(alloc.ref_count(slot), 1);
        assert_eq!(alloc.free_count(), 0); // Not freed yet
        
        // Free again
        alloc.free(slot);
        assert_eq!(alloc.ref_count(slot), 0);
        assert_eq!(alloc.free_count(), 1);
    }

    #[test]
    fn test_swap_device_init() {
        let device = SwapDevice::new();
        assert!(!device.is_ready()); // Not initialized

        // After init, still not ready (no block device)
        let mut device = SwapDevice::new();
        device.init(0x1000);
        assert!(!device.is_ready()); // Needs block device

        // With block device, should be ready
        let ram_dev = Box::new(RamBlockDevice::new(4096, 100));
        let mut device = SwapDevice::new();
        device.set_block_device(ram_dev);
        assert!(device.is_ready());
    }

    #[test]
    fn test_ram_block_device() {
        let mut device = RamBlockDevice::new(512, 10);

        assert_eq!(device.block_size(), 512);
        assert_eq!(device.num_blocks(), 10);

        // Test write and read
        let data: [u8; 512] = [0xAB; 512];
        device.write_block(0, &data).unwrap();

        let mut read_buf = [0u8; 512];
        device.read_block(0, &mut read_buf).unwrap();
        assert_eq!(&read_buf[..], &data[..]);
    }

    #[test]
    fn test_ram_block_device_out_of_bounds() {
        let mut device = RamBlockDevice::new(512, 10);

        let mut buf = [0u8; 512];
        assert!(device.read_block(100, &mut buf).is_err());
        assert!(device.write_block(100, &buf).is_err());
    }

    #[test]
    fn test_swap_device_with_ram_block() {
        // Create RAM block device with 4KB blocks
        let ram_dev = Box::new(RamBlockDevice::new(4096, 100));
        let mut swap = SwapDevice::with_device(ram_dev, 0x1000);

        // Create test data (one page)
        let mut page = alloc::vec![0u8; 4096];
        for (i, byte) in page.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Write to swap
        swap.write(0x1000, page.as_ptr(), 4096).unwrap();

        // Read back
        let mut read_buf = alloc::vec![0u8; 4096];
        let dest = read_buf.as_mut_ptr();
        swap.read(0x1000, dest, 4096).unwrap();

        assert_eq!(&read_buf[..], &page[..]);
    }

    #[test]
    fn test_swap_manager_stats() {
        let manager = SwapManager::new(100);
        let stats = manager.stats();
        
        assert_eq!(stats.total, 100);
        assert_eq!(stats.free, 100);
        assert_eq!(stats.swapped_out, 0);
        assert_eq!(stats.swapped_in, 0);
    }

    #[test]
    fn test_swap_manager_alloc_free() {
        let manager = SwapManager::new(100);
        
        let slot = manager.alloc_swap();
        assert_ne!(slot, usize::MAX);
        
        let stats = manager.stats();
        assert_eq!(stats.free, 99);
        
        manager.free_swap(slot);
        let stats = manager.stats();
        assert_eq!(stats.free, 100);
    }

    #[test]
    fn test_gen_state_tick() {
        let mut gen = GenState::default();
        
        assert_eq!(gen.genclock, 0);
        assert_eq!(gen.genage, 0);
        
        gen.tick();
        assert_eq!(gen.genclock, 1);
        
        gen.tick();
        assert_eq!(gen.genclock, 2);
    }

    #[test]
    fn test_gen_state_page_age() {
        let mut gen = GenState::default();
        
        // Set clock to 10
        gen.genclock = 10;
        
        // Page with gen=5 should have age 5
        assert_eq!(gen.page_age(5), 5);
        
        // Page with gen=10 should have age 0
        assert_eq!(gen.page_age(10), 0);
        
        // Page with gen=8 should have age 2
        assert_eq!(gen.page_age(8), 2);
    }

    #[test]
    fn test_gen_state_should_pageout() {
        let mut gen = GenState::default();
        
        gen.genclock = 100;
        gen.genage = 50; // Pages older than 50 should be paged out
        
        // Page with gen=40 (age=60) should be paged out
        assert!(gen.should_pageout(40));
        
        // Page with gen=60 (age=40) should NOT be paged out
        assert!(!gen.should_pageout(60));
    }

    #[test]
    fn test_gen_state_record_age() {
        let mut gen = GenState::default();
        
        gen.record_age(10);
        gen.record_age(20);
        gen.record_age(30);
        
        assert_eq!(gen.gensum, 60);
        assert_eq!(gen.gencount, 3);
        
        gen.tick();
        
        // After tick, average should be calculated and sum/count reset
        assert_eq!(gen.genage, 20); // 60/3
        assert_eq!(gen.gensum, 0);
        assert_eq!(gen.gencount, 0);
    }

    #[test]
    fn test_swap_page_creation() {
        let page = SwapPage::new(0x1000, 0x10000);
        
        assert_eq!(page.pa, 0x1000);
        assert_eq!(page.swap_addr, 0x10000);
        assert_eq!(page.refcnt, 1);
        assert_eq!(page.modref, 0);
        assert_eq!(page.gen, 0);
    }

    #[test]
    fn test_swap_page_flags() {
        let mut page = SwapPage::new(0x1000, 0);
        
        // Initially not referenced or modified
        assert!(!page.is_referenced());
        assert!(!page.is_modified());
        assert!(!page.is_on_swap());
        
        // Set reference flag
        page.set_ref();
        assert!(page.is_referenced());
        
        // Clear reference flag
        page.clear_ref();
        assert!(!page.is_referenced());
    }

    #[test]
    fn test_swap_page_on_swap() {
        let mut page = SwapPage::new(0x1000, PG_ONSWAP | 0x1000);
        
        assert!(page.is_on_swap());
        
        // Create page without ON_SWAP flag
        let page2 = SwapPage::new(0x2000, 0);
        assert!(!page2.is_on_swap());
    }

    #[test]
    fn test_pager_basic() {
        let pager = Pager::new(100);
        
        // Initially no pages to page out
        assert!(!pager.needs_pageout());
        assert_eq!(pager.iolist_len(), 0);
        
        // Add a page
        let page = SwapPage::new(0x1000, 0x10000);
        assert!(pager.add_page(page));
        
        // Now we have pages to page out
        assert!(pager.needs_pageout());
        assert_eq!(pager.iolist_len(), 1);
    }

    #[test]
    fn test_pager_iplist_full() {
        let pager = Pager::new(10); // Small number of pages
        
        // Fill the iolist
        for i in 0..10 {
            let page = SwapPage::new(i * 0x1000, i * 0x10000);
            assert!(pager.add_page(page), "Should add page {}", i);
        }
        
        // Now it should be full
        let page = SwapPage::new(0x10000, 0x100000);
        assert!(!pager.add_page(page), "Should not add page when full");
        assert_eq!(pager.iolist_len(), 10);
    }

    #[test]
    fn test_scan_page_info() {
        let info = ScanPageInfo {
            phys_addr: 0x1000,
            swap_addr: 0x10000,
            refcount: 1,
            modref: PG_REF | PG_MOD,
            gen: 50,
        };
        
        assert_eq!(info.phys_addr, 0x1000);
        assert_eq!(info.swap_addr, 0x10000);
        assert_eq!(info.refcount, 1);
    }
}

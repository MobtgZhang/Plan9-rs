//! Block Buffer Management
//!
//! Implements Plan 9's Block structure for buffered I/O.
//! Block is the fundamental unit of I/O in Plan 9's network and disk subsystems.
//!
//! Reference: sys/src/9/port/portdat.h, allocb.c

use alloc::vec::Vec;
use alloc::boxed::Box;
use crate::plan9_common::sync::Spinlock;

// ============================================================================
// Block Constants
// ============================================================================

/// Block allocation size (2KB default)
pub const BLOCK_SIZE: usize = 2048;

/// Block magic number for debugging
pub const BLOCK_MAGIC: u32 = 0x424C4F43; // "BLOC"

/// Block flags
pub const B_INTR: u16 = 0x0001;    // Interrupt pending
pub const B_SIMPLE: u16 = 0x0002;   // Simple block (not from pool)
pub const B_DELIM: u16 = 0x0004;   // Delimited message
pub const B_SHUTDOWN: u16 = 0x0008; // Block at end of I/O
pub const B_HANGUP: u16 = 0x0010;   // Hangup/error
pub const B_RUNT: u16 = 0x0020;     // Length is unreliable
pub const B_FREE: u16 = 0x0040;     // Block is on free list
pub const B_BORROW: u16 = 0x0080;    // Borrowed from another pool
pub const B_CHAIN: u16 = 0x0100;    // Consists of multiple blocks
pub const B_HEADER: u16 = 0x0200;   // Header-only block

// ============================================================================
// Block Structure
// ============================================================================

/// Block - buffered I/O data structure
///
/// A Block is the basic unit of data transfer in Plan 9. It consists of
/// a buffer with read (rp) and write (wp) pointers, allowing for
/// incremental consumption and production of data.
///
/// Memory layout:
/// ```
/// base -----> lim
///            |
///            rp    wp
/// ```
pub struct Block {
    /// Reference count
    pub refcount: i32,
    /// Next block in chain/list
    pub next: Option<Box<Block>>,
    /// List pointer (for B_LIST flag)
    pub list: Option<Box<Block>>,
    /// First valid data byte (read pointer)
    pub rp: usize,
    /// First free byte (write pointer)
    pub wp: usize,
    /// One past last byte of buffer
    pub lim: usize,
    /// First byte of buffer
    pub base: usize,
    /// Custom free function (if non-null)
    pub freefn: Option<fn(&mut Block)>,
    /// Block flags
    pub flag: u16,
    /// IP checksum of complete packet (minus media header)
    pub checksum: u16,
    /// Magic number for debugging
    pub magic: u32,
}

impl Block {
    /// Create a new Block with allocated buffer
    pub fn new(size: usize) -> Option<Box<Self>> {
        // Align size to block size
        let size = if size < BLOCK_SIZE { BLOCK_SIZE } else { size };
        
        // Allocate buffer
        let layout = alloc::alloc::Layout::from_size_align(size, 8)
            .ok()?;
        
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        if ptr.is_null() {
            return None;
        }
        
        let base = ptr as usize;
        let lim = base + size;
        
        Some(Box::new(Block {
            refcount: 1,
            next: None,
            list: None,
            rp: base,
            wp: base,
            lim,
            base,
            freefn: None,
            flag: 0,
            checksum: 0,
            magic: BLOCK_MAGIC,
        }))
    }

    /// Create a Block wrapping existing memory
    pub fn from_ptr(base: usize, size: usize) -> Option<Box<Self>> {
        if base == 0 {
            return None;
        }
        
        Some(Box::new(Block {
            refcount: 1,
            next: None,
            list: None,
            rp: base,
            wp: base,
            lim: base + size,
            base,
            freefn: None,
            flag: B_HEADER,
            checksum: 0,
            magic: BLOCK_MAGIC,
        }))
    }

    /// Create a Block for a specific device buffer
    pub fn with_buffer(data: Vec<u8>) -> Option<Box<Self>> {
        let base = data.as_ptr() as usize;
        let size = data.len();
        
        Some(Box::new(Block {
            refcount: 1,
            next: None,
            list: None,
            rp: base,
            wp: base,
            lim: base + size,
            base,
            freefn: Some(|_b| {
                // This would need the original Vec to drop properly
                // In practice, you'd use a custom free function
            }),
            flag: B_SIMPLE,
            checksum: 0,
            magic: BLOCK_MAGIC,
        }))
    }

    /// Get the length of data in the block
    pub fn len(&self) -> usize {
        self.wp.saturating_sub(self.rp)
    }

    /// Check if block is empty
    pub fn is_empty(&self) -> bool {
        self.rp >= self.wp
    }

    /// Get remaining space in block
    pub fn remaining(&self) -> usize {
        self.lim.saturating_sub(self.wp)
    }

    /// Check if block is full
    pub fn is_full(&self) -> bool {
        self.wp >= self.lim
    }

    /// Get pointer to read position
    pub fn data_ptr(&self) -> *const u8 {
        self.rp as *const u8
    }

    /// Get mutable pointer to read position
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.rp as *mut u8
    }

    /// Get pointer to write position
    pub fn write_ptr(&mut self) -> *mut u8 {
        self.wp as *mut u8
    }

    /// Increment reference count
    pub fn incref(&mut self) {
        self.refcount += 1;
    }

    /// Decrement reference count
    pub fn decref(&mut self) -> i32 {
        self.refcount -= 1;
        self.refcount
    }

    /// Check if block is free
    pub fn is_free(&self) -> bool {
        (self.flag & B_FREE) != 0
    }

    /// Set free flag
    pub fn set_free(&mut self, free: bool) {
        if free {
            self.flag |= B_FREE;
        } else {
            self.flag &= !B_FREE;
        }
    }

    /// Verify block magic
    pub fn verify_magic(&self) -> bool {
        self.magic == BLOCK_MAGIC
    }

    /// Allocate a new block from heap
    pub fn alloc(size: usize) -> Option<Box<Self>> {
        Self::new(size)
    }

    /// Free a block
    pub fn free_block(mut block: Box<Self>) {
        // Call custom free function if set
        if let Some(free_fn) = block.freefn {
            free_fn(&mut block);
        }
        
        // Free the underlying buffer
        if block.base != 0 && (block.flag & B_SIMPLE) == 0 && (block.flag & B_HEADER) == 0 {
            let layout = alloc::alloc::Layout::from_size_align(
                block.lim - block.base,
                8
            ).unwrap();
            unsafe {
                alloc::alloc::dealloc(block.base as *mut u8, layout);
            }
        }
    }

    /// Reset block pointers for reuse
    pub fn reset(&mut self) {
        self.rp = self.base;
        self.wp = self.base;
        self.flag = 0;
        self.next = None;
        self.list = None;
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        // Only free buffer if not simple/header block
        if self.base != 0 && (self.flag & B_SIMPLE) == 0 && (self.flag & B_HEADER) == 0 {
            let size = self.lim - self.base;
            let layout = alloc::alloc::Layout::from_size_align(size, 8).unwrap();
            unsafe {
                alloc::alloc::dealloc(self.base as *mut u8, layout);
            }
        }
    }
}

// ============================================================================
// Block Operations
// ============================================================================

/// Pull up data from following blocks into this block
/// 
/// Ensures at least n bytes are contiguous in this block by pulling
/// data from linked blocks if necessary.
/// 
/// Returns Ok(()) if successful, Err(()) if not enough data
pub fn pullupblock(b: &mut Block, n: usize) -> Result<(), ()> {
    // If we already have n bytes, nothing to do
    if b.len() >= n {
        return Ok(());
    }
    
    // Try to pull from next block
    let next_ptr_opt = match b.next.as_mut() {
        Some(next) => Some(core::ptr::addr_of_mut!(**next)),
        None => None,
    };
    
    if let Some(next_ptr) = next_ptr_opt {
        // Move data from next block to fill this block
        let needed = n - b.len();
        let available = unsafe { (*next_ptr).len() };
        let to_copy = needed.min(available);
        
        // Copy data
        unsafe {
            let dst = b.wp as *mut u8;
            let src = (*next_ptr).rp as *const u8;
            core::ptr::copy_nonoverlapping(src, dst, to_copy);
        }
        
        b.wp += to_copy;
        unsafe { (*next_ptr).rp += to_copy };
        
        return Ok(());
    }
    
    Err(())
}

/// Pad block to specified size
/// 
/// If block is smaller than size, allocate a new block with padding
/// and link them together.
pub fn padblock(b: Option<Box<Block>>, size: usize) -> Option<Box<Block>> {
    let b = b?;
    let n = b.len();
    
    if n >= size {
        return Some(b);
    }
    
    // Allocate padding block
    let mut pad = Block::new(size - n)?;
    pad.rp = pad.base;
    pad.wp = pad.base + (size - n);
    pad.flag |= B_SIMPLE;
    
    // Link padding before original
    pad.next = Some(b);
    
    Some(pad)
}

/// Trim n bytes from front of block
pub fn trimblock(b: Option<Box<Block>>, offset: usize, n: usize) -> Option<Box<Block>> {
    let mut b = b?;
    
    if offset + n > b.len() {
        return None;
    }
    
    b.rp += offset;
    
    if n < b.len() - offset {
        // Create new block with trimmed data
        let mut new_block = Block::new(n)?;
        unsafe {
            let src = b.rp as *const u8;
            let dst = new_block.wp as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, n);
        }
        new_block.wp += n;
        new_block.next = b.next.take();
        return Some(new_block);
    }
    
    // Return original with adjusted pointers
    Some(b)
}

/// Concatenate blocks into single block
pub fn concatblock(blks: Vec<Box<Block>>) -> Option<Box<Block>> {
    // Calculate total size
    let total_size: usize = blks.iter().map(|b| b.len()).sum();
    
    if total_size == 0 {
        return Some(Block::new(BLOCK_SIZE)?);
    }
    
    // Allocate combined block
    let mut result = Block::new(total_size)?;
    
    // Copy data from all blocks
    for blk in blks {
        let len = blk.len();
        if len > 0 {
            unsafe {
                let src = blk.rp as *const u8;
                let dst = result.wp as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, len);
            }
            result.wp += len;
        }
        // Drop the block (will free its buffer since we copied)
    }
    
    Some(result)
}

/// Pack block by combining chained blocks
pub fn packblock(b: &mut Block) {
    if b.next.is_none() {
        return;
    }
    
    loop {
        // Get pointer to next block
        let next_ptr_opt = match b.next.as_ref() {
            Some(next) => Some(core::ptr::addr_of!(**next) as *mut Block),
            None => None,
        };
        
        let next_ptr = match next_ptr_opt {
            Some(p) => p,
            None => break,
        };
        
        let len = unsafe { (*next_ptr).len() };
        if len == 0 {
            // Empty block, remove it
            unsafe {
                let empty_next = (*next_ptr).next.take();
                let b_next_ptr = core::ptr::addr_of_mut!((*b).next);
                (*b_next_ptr) = empty_next;
            }
            continue;
        }

        // Check if we have room
        if b.remaining() < len {
            break;
        }

        // Copy data from next block
        unsafe {
            let src = (*next_ptr).rp as *const u8;
            let dst = b.wp as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, len);
        }
        b.wp += len;

        // Remove the next block
        unsafe {
            let b_next_ptr = core::ptr::addr_of_mut!((*b).next);
            (*b_next_ptr) = (*next_ptr).next.take();
        }
    }
}

/// Copy a block (deep copy)
pub fn copyblock(b: &Block) -> Option<Box<Block>> {
    let len = b.len();
    let mut new_block = Block::new(len.max(BLOCK_SIZE))?;

    if len > 0 {
        unsafe {
            let src = b.rp as *const u8;
            let dst = new_block.wp as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, len);
        }
        new_block.wp += len;
    }
    
    new_block.flag = b.flag;
    Some(new_block)
}

/// Adjust read pointer (for peeking)
pub fn adjblock(b: &mut Block, n: i32) {
    if n >= 0 {
        let n = n as usize;
        b.rp = (b.rp + n).min(b.wp);
    } else {
        let n = (-n) as usize;
        b.rp = b.rp.saturating_sub(n);
    }
}

// ============================================================================
// Block Pool
// ============================================================================

/// Block pool for efficient allocation
pub struct BlockPool {
    /// Free blocks
    free_list: Spinlock<Vec<Box<Block>>>,
    /// Pool size
    pool_size: usize,
    /// Block size for this pool
    block_size: usize,
}

impl BlockPool {
    /// Create a new block pool
    pub const fn new(block_size: usize) -> Self {
        Self {
            free_list: Spinlock::new(Vec::new()),
            pool_size: 0,
            block_size,
        }
    }

    /// Get a block from the pool
    pub fn get(&self) -> Option<Box<Block>> {
        // Try free list first
        if let Some(mut block) = self.free_list.lock().pop() {
            block.reset();
            return Some(block);
        }
        
        // Allocate new block
        Block::new(self.block_size)
    }

    /// Return a block to the pool
    pub fn put(&self, block: Box<Block>) {
        if self.pool_size < 100 {  // Limit pool size
            self.free_list.lock().push(block);
        }
        // Otherwise, let it be deallocated
    }

    /// Pre-allocate blocks in the pool
    pub fn prealloc(&self, count: usize) {
        let mut free = self.free_list.lock();
        for _ in 0..count {
            if let Some(block) = Block::new(self.block_size) {
                free.push(block);
            }
        }
    }
}

// ============================================================================
// Global Block Pool
// ============================================================================

/// Global block pool for general use
pub static GLOBAL_BLOCK_POOL: BlockPool = BlockPool::new(BLOCK_SIZE);

/// Allocate a block from the global pool
pub fn allocb(size: usize) -> Option<Box<Block>> {
    if size <= BLOCK_SIZE {
        GLOBAL_BLOCK_POOL.get()
    } else {
        Block::new(size)
    }
}

/// Free a block back to the appropriate pool
pub fn freeb(block: Box<Block>) {
    if block.base == 0 {
        return;
    }
    
    let flag = block.flag;
    
    // If simple block, just drop
    if (flag & B_SIMPLE) != 0 || (flag & B_HEADER) != 0 {
        return;
    }
    
    // If from global pool size, return to pool
    if block.lim - block.base <= BLOCK_SIZE {
        GLOBAL_BLOCK_POOL.put(block);
    } else {
        // Let it be freed
    }
}

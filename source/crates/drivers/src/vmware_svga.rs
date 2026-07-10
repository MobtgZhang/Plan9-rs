//! VMware SVGA II Virtual Graphics Driver
//!
//! Implements support for VMware SVGA II virtual graphics device.
//! This provides accelerated 2D graphics for virtualized environments.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// SVGA error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvgaError {
    /// Invalid command
    InvalidCommand,
    /// Invalid operation
    InvalidOp,
    /// Out of memory
    OutOfMemory,
    /// Invalid fence
    InvalidFence,
    /// Device not initialized
    NotInitialized,
    /// Timeout
    Timeout,
}

impl SvgaError {
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => SvgaError::InvalidCommand,
            1 => SvgaError::InvalidOp,
            2 => SvgaError::OutOfMemory,
            3 => SvgaError::InvalidFence,
            _ => SvgaError::InvalidOp,
        }
    }
}

/// SVGA result type
pub type SvgaResult<T> = Result<T, SvgaError>;

/// SVGA II registers (offset from MMIO base)
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum SvgaReg {
    /// ID
    Id = 0,
    /// Enable
    Enable = 1,
    /// Width
    Width = 2,
    /// Height
    Height = 3,
    /// Max width
    MaxWidth = 4,
    /// Max height
    MaxHeight = 5,
    /// Virtual width
    VirtualWidth = 6,
    /// Virtual height
    VirtualHeight = 7,
    /// BPP
    Bpp = 8,
    /// Pixel format
    PixelFormat = 9,
    /// Commands
    Commands = 10,
    /// Num displays
    NumDisplays = 11,
    /// Memory size
    MemSize = 12,
    /// VRAM size
    Vramsize = 13,
    /// FIFO size
    FifoSize = 14,
    /// Fifo min size
    FifoMinSize = 15,
    /// Fifo next command
    FifoNextCmd = 16,
    /// FIFO stop
    FifoStop = 17,
    /// Pitch
    Pitch = 18,
    /// Display ID
    DisplayId = 19,
    /// Display is primary
    DisplayIsPrimary = 20,
    /// Pitch 2
    Pitch2 = 21,
    /// Fifo health
    FifoHealth = 22,
    /// FIFO 3
    Fifo3 = 23,
    /// Invalid
    Invalid = 31,
    /// Sync
    Sync = 1000,
    /// FIFO
    Fifo = 1001,
    /// Cursor
    Cursor = 1002,
    /// Cursor 3
    Cursor3 = 1003,
    /// Cursor 4
    Cursor4 = 1004,
    /// DAC
    Dac = 1005,
    /// Primary
    Primary = 1006,
}

/// SVGA device ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvgaId {
    /// Invalid
    Invalid = 0,
    /// SVGA II
    SvgaII = 2,
}

impl SvgaId {
    pub fn from_u32(val: u32) -> Self {
        match val {
            2 => SvgaId::SvgaII,
            _ => SvgaId::Invalid,
        }
    }
}

/// SVGA FIFO commands
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum SvgaFifoCmd {
    /// Invalid
    Invalid = 0,
    /// Define cursor
    DefineCursor = 1,
    /// Define alpha cursor
    DefineAlphaCursor = 2,
    /// Update
    Update = 3,
    /// Define screen
    DefineScreen = 4,
    /// Set eu led
    SetEuLed = 5,
    /// Set scan line
    SetScanLine = 6,
    /// Define coherence block
    DefineCoherenceBlock = 7,
    /// Define coherence type
    DefineCoherenceType = 8,
    /// Define cursor 3
    DefineCursor3 = 9,
    /// Define alpha cursor 3
    DefineAlphaCursor3 = 10,
    /// Update 3
    Update3 = 11,
    /// Define screen 3
    DefineScreen3 = 12,
    /// Set multiple screens
    SetMultipleScreens = 13,
    /// Set display mode
    SetDisplayMode = 14,
    /// Set pixel blit
    SetPixelBlit = 15,
    /// Set color blit
    SetColorBlit = 16,
    /// Set copy blit
    SetCopyBlit = 17,
    /// Define cursor 4
    DefineCursor4 = 18,
    /// Define alpha cursor 4
    DefineAlphaCursor4 = 19,
    /// Update 4
    Update4 = 20,
    /// Define screen 4
    DefineScreen4 = 21,
    /// Update 5
    Update5 = 22,
    /// Define cursor 5
    DefineCursor5 = 23,
    /// Define alpha cursor 5
    DefineAlphaCursor5 = 24,
    /// Update 5
    Update5FullScreen = 25,
    /// Increase watermark
    IncreaseWatermark = 26,
}

/// Screen definition flags
#[derive(Debug, Clone, Copy)]
pub struct ScreenFlags(u32);

impl ScreenFlags {
    pub const NONE: ScreenFlags = ScreenFlags(0);
    pub const SCREEN: ScreenFlags = ScreenFlags(1 << 0);
    pub const FULLSCREEN: ScreenFlags = ScreenFlags(1 << 1);
    pub const PRIMSECOND: ScreenFlags = ScreenFlags(1 << 2);
    pub const ALLFLAGS: ScreenFlags = ScreenFlags(0xFFFFFFFF);
}

/// SVGA screen definition
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SvgaScreen {
    /// Definition flags
    pub flags: u32,
    /// X position
    pub x: u32,
    /// Y position
    pub y: u32,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
    /// BPP
    pub bpp: u32,
}

/// SVGA cursor definition
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SvgaCursor {
    /// Hot X
    pub hot_x: u16,
    /// Hot Y
    pub hot_y: u16,
    /// Width
    pub width: u16,
    /// Height
    pub height: u16,
}

/// SVGA FIFO
pub struct SvgaFifo {
    /// Minimum size
    min_size: u32,
    /// Maximum size
    max_size: u32,
    /// Current size
    size: u32,
    /// Read pointer
    read: AtomicU32,
    /// Write pointer
    write: AtomicU32,
    /// Command buffer
    commands: *mut u32,
    /// Semaphore
    sem: *mut u32,
}

impl SvgaFifo {
    /// Get next command location
    pub fn next_cmd(&self) -> u32 {
        self.read.load(Ordering::SeqCst)
    }
    
    /// Get stop location
    pub fn stop(&self) -> u32 {
        self.write.load(Ordering::SeqCst)
    }
    
    /// Commit command
    pub fn commit(&self, count: u32) {
        let new_write = (self.write.load(Ordering::SeqCst) + count) % self.size;
        self.write.store(new_write, Ordering::SeqCst);
    }
}

/// SVGA device
pub struct SvgaDevice {
    /// MMIO base address
    mmio_base: usize,
    /// FIFO base address
    fifo_base: usize,
    /// Is initialized
    initialized: AtomicBool,
    /// Current width
    width: u32,
    /// Current height
    height: u32,
    /// Current BPP
    bpp: u32,
    /// Pitch
    pitch: u32,
    /// Framebuffer
    framebuffer: usize,
    /// VRAM size
    vram_size: usize,
}

impl SvgaDevice {
    /// Create a new SVGA device
    pub fn new(mmio_base: usize, fifo_base: usize) -> Self {
        Self {
            mmio_base,
            fifo_base,
            initialized: AtomicBool::new(false),
            width: 0,
            height: 0,
            bpp: 0,
            pitch: 0,
            framebuffer: 0,
            vram_size: 0,
        }
    }
    
    /// Read a register
    fn read_reg(&self, reg: SvgaReg) -> u32 {
        let offset = reg as usize * 4;
        unsafe {
            core::ptr::read_volatile((self.mmio_base + offset) as *const u32)
        }
    }
    
    /// Write a register
    fn write_reg(&self, reg: SvgaReg, value: u32) {
        let offset = reg as usize * 4;
        unsafe {
            core::ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
    }
    
    /// Initialize the device
    pub fn init(&mut self) -> SvgaResult<()> {
        // Read ID to verify device
        let id = self.read_reg(SvgaReg::Id);
        if id != SvgaId::SvgaII as u32 {
            return Err(SvgaError::NotInitialized);
        }
        
        // Read capabilities
        let width = self.read_reg(SvgaReg::Width);
        let height = self.read_reg(SvgaReg::Height);
        let bpp = self.read_reg(SvgaReg::Bpp);
        
        self.width = width;
        self.height = height;
        self.bpp = bpp;
        
        // Read framebuffer info
        let vram_size = self.read_reg(SvgaReg::Vramsize);
        self.vram_size = vram_size as usize;
        
        // Read pitch
        self.pitch = self.read_reg(SvgaReg::Pitch);
        
        // Enable the device
        self.write_reg(SvgaReg::Enable, 1);
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// Set video mode
    pub fn set_mode(&mut self, width: u32, height: u32, bpp: u32) -> SvgaResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(SvgaError::NotInitialized);
        }
        
        // Check if mode is supported
        let max_width = self.read_reg(SvgaReg::MaxWidth);
        let max_height = self.read_reg(SvgaReg::MaxHeight);
        
        if width > max_width || height > max_height {
            return Err(SvgaError::InvalidOp);
        }
        
        // Set virtual resolution
        self.write_reg(SvgaReg::VirtualWidth, width);
        self.write_reg(SvgaReg::VirtualHeight, height);
        
        // Set BPP
        self.write_reg(SvgaReg::Bpp, bpp);
        
        // Set actual resolution
        self.write_reg(SvgaReg::Width, width);
        self.write_reg(SvgaReg::Height, height);
        
        // Update local state
        self.width = width;
        self.height = height;
        self.bpp = bpp;
        self.pitch = width * (bpp / 8);
        
        Ok(())
    }
    
    /// Get current width
    pub fn width(&self) -> u32 {
        self.width
    }
    
    /// Get current height
    pub fn height(&self) -> u32 {
        self.height
    }
    
    /// Get current BPP
    pub fn bpp(&self) -> u32 {
        self.bpp
    }
    
    /// Get pitch
    pub fn pitch(&self) -> u32 {
        self.pitch
    }
    
    /// Get framebuffer address
    pub fn framebuffer(&self) -> usize {
        self.framebuffer
    }
    
    /// Write pixel to framebuffer
    pub fn write_pixel(&self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        
        let offset = (y * self.pitch + x * (self.bpp / 8)) as usize;
        let ptr = (self.framebuffer + offset) as *mut u32;
        unsafe {
            core::ptr::write_volatile(ptr, color);
        }
    }
    
    /// Read pixel from framebuffer
    pub fn read_pixel(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        
        let offset = (y * self.pitch + x * (self.bpp / 8)) as usize;
        let ptr = (self.framebuffer + offset) as *const u32;
        unsafe {
            core::ptr::read_volatile(ptr)
        }
    }
    
    /// Fill rectangle
    pub fn fill_rect(&self, x: u32, y: u32, width: u32, height: u32, color: u32) {
        let x_end = (x + width).min(self.width);
        let y_end = (y + height).min(self.height);
        
        for row in y..y_end {
            for col in x..x_end {
                self.write_pixel(col, row, color);
            }
        }
    }
    
    /// Update screen
    pub fn update(&mut self, x: u32, y: u32, width: u32, height: u32) {
        // Write to FIFO
        let cmd = [
            SvgaFifoCmd::Update as u32,
            x,
            y,
            width,
            height,
        ];
        
        let fifo_ptr = self.fifo_base as *mut u32;
        for (i, &val) in cmd.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(fifo_ptr.add(i), val);
            }
        }
        
        // Sync
        self.write_reg(SvgaReg::Sync, 1);
    }
    
    /// Define screen
    pub fn define_screen(&mut self, screen_id: u32, x: u32, y: u32, width: u32, height: u32) {
        let cmd = [
            SvgaFifoCmd::DefineScreen as u32,
            screen_id,
            ScreenFlags::SCREEN.0,
            x,
            y,
            width,
            height,
            self.bpp,
        ];
        
        let fifo_ptr = self.fifo_base as *mut u32;
        for (i, &val) in cmd.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(fifo_ptr.add(i), val);
            }
        }
    }
    
    /// Define cursor
    pub fn define_cursor(&mut self, id: u32, hot_x: u16, hot_y: u16, width: u16, height: u16, data: &[u32]) {
        let mut cmd = Vec::with_capacity(5 + data.len());
        cmd.push(SvgaFifoCmd::DefineCursor as u32);
        cmd.push(id);
        cmd.push(((hot_y as u32) << 16) | (hot_x as u32));
        cmd.push(((height as u32) << 16) | (width as u32));
        cmd.push(data.len() as u32);
        cmd.extend_from_slice(data);
        
        let fifo_ptr = self.fifo_base as *mut u32;
        for (i, &val) in cmd.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(fifo_ptr.add(i), val);
            }
        }
    }
    
    /// Define alpha cursor
    pub fn define_alpha_cursor(&mut self, id: u32, hot_x: u16, hot_y: u16, width: u16, height: u16, data: &[u32]) {
        let mut cmd = Vec::with_capacity(5 + data.len());
        cmd.push(SvgaFifoCmd::DefineAlphaCursor as u32);
        cmd.push(id);
        cmd.push(((hot_y as u32) << 16) | (hot_x as u32));
        cmd.push(((height as u32) << 16) | (width as u32));
        cmd.push(data.len() as u32);
        cmd.extend_from_slice(data);
        
        let fifo_ptr = self.fifo_base as *mut u32;
        for (i, &val) in cmd.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(fifo_ptr.add(i), val);
            }
        }
    }
    
    /// Blit (copy) operation
    pub fn blit(&mut self, src_x: u32, src_y: u32, dst_x: u32, dst_y: u32, width: u32, height: u32) {
        let cmd = [
            SvgaFifoCmd::SetCopyBlit as u32,
            (src_y << 16) | src_x,
            (dst_y << 16) | dst_x,
            (height << 16) | width,
        ];
        
        let fifo_ptr = self.fifo_base as *mut u32;
        for (i, &val) in cmd.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(fifo_ptr.add(i), val);
            }
        }
    }
    
    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
}

/// Color utilities
pub mod color {
    /// Create RGBA color
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
        ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }
    
    /// Create RGB color
    pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
        rgba(r, g, b, 255)
    }
    
    /// Extract red
    pub fn red(c: u32) -> u8 {
        (c >> 16) as u8
    }
    
    /// Extract green
    pub fn green(c: u32) -> u8 {
        (c >> 8) as u8
    }
    
    /// Extract blue
    pub fn blue(c: u32) -> u8 {
        c as u8
    }
    
    /// Extract alpha
    pub fn alpha(c: u32) -> u8 {
        (c >> 24) as u8
    }
    
    /// Common colors
    pub const BLACK: u32 = rgb(0, 0, 0);
    pub const WHITE: u32 = rgb(255, 255, 255);
    pub const RED: u32 = rgb(255, 0, 0);
    pub const GREEN: u32 = rgb(0, 255, 0);
    pub const BLUE: u32 = rgb(0, 0, 255);
    pub const YELLOW: u32 = rgb(255, 255, 0);
    pub const CYAN: u32 = rgb(0, 255, 255);
    pub const MAGENTA: u32 = rgb(255, 0, 255);
}

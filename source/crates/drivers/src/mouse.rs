//! PS/2 Mouse Driver
//!
//! Implements mouse driver following Plan 9's mouse.c and devmouse.c
//! Reference: sys/src/9/pc/mouse.c, sys/src/9/port/devmouse.c
//!
//! This driver handles PS/2 mouse input, including:
//! - Mouse initialization and configuration
//! - Mouse packet parsing (3-byte or 4-byte protocols)
//! - Button state tracking
//! - Cursor position and acceleration
//! - Interrupt handling

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

// ============================================================================
// PS/2 Mouse Constants
// ============================================================================

/// PS/2 Mouse Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseCommand {
    /// Set resolution
    SetResolution = 0xE8,
    /// Set scaling
    SetScaling = 0xE6,
    /// Set sample rate
    SetSampleRate = 0xF3,
    /// Enable data reporting
    EnableReporting = 0xF4,
    /// Disable data reporting
    DisableReporting = 0xF5,
    /// Set remote mode
    SetRemoteMode = 0xF0,
    /// Read ID
    ReadId = 0xF2,
    /// Reset
    Reset = 0xFF,
}

/// PS/2 Mouse Responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseResponse {
    Ack = 0xFA,
    Error = 0xFC,
    Id = 0x00,
}

/// Mouse ID values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseId {
    Standard = 0x00,
    IntelliMouse = 0x03,
    ExplorerMouse = 0x04,
    IntelliMouse4 = 0x04,  // Different protocol
}

/// Mouse button flags (from Plan 9)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseButtons {
    pub bits: u8,
}

impl MouseButtons {
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    pub const fn left(self) -> Self {
        Self { bits: self.bits | 1 }
    }

    pub const fn middle(self) -> Self {
        Self { bits: self.bits | 2 }
    }

    pub const fn right(self) -> Self {
        Self { bits: self.bits | 4 }
    }

    pub const fn fourth(self) -> Self {
        Self { bits: self.bits | 8 }
    }

    pub const fn fifth(self) -> Self {
        Self { bits: self.bits | 16 }
    }

    pub fn is_left(&self) -> bool {
        (self.bits & 1) != 0
    }

    pub fn is_middle(&self) -> bool {
        (self.bits & 2) != 0
    }

    pub fn is_right(&self) -> bool {
        (self.bits & 4) != 0
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }
}

// ============================================================================
// Mouse State
// ============================================================================

/// Mouse state
pub struct MouseState {
    /// Mouse enabled
    pub enabled: AtomicBool,
    /// Sample rate
    pub sample_rate: u8,
    /// Resolution
    pub resolution: u8,
    /// Scaling
    pub scaling: u8,
    /// Mouse ID
    pub id: MouseId,
    /// Buttons state
    pub buttons: UnsafeCell<MouseButtons>,
    /// Accumulated X movement
    pub dx: UnsafeCell<i32>,
    /// Accumulated Y movement
    pub dy: UnsafeCell<i32>,
    /// Accumulated Z movement (scroll)
    pub dz: UnsafeCell<i32>,
    /// Current X position
    pub x: AtomicI32,
    /// Current Y position
    pub y: AtomicI32,
    /// Last X position
    pub lastx: AtomicI32,
    /// Last Y position
    pub lasty: AtomicI32,
    /// Movement counter
    pub counter: AtomicU8,
}

impl MouseState {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            sample_rate: AtomicU8::new(100),
            resolution: AtomicU8::new(4),
            scaling: AtomicU8::new(1),
            id: MouseId::Standard,
            buttons: UnsafeCell::new(MouseButtons::new()),
            dx: UnsafeCell::new(0),
            dy: UnsafeCell::new(0),
            dz: UnsafeCell::new(0),
            x: AtomicI32::new(0),
            y: AtomicI32::new(0),
            lastx: AtomicI32::new(0),
            lasty: AtomicI32::new(0),
            counter: AtomicU8::new(0),
        }
    }

    pub fn reset(&mut self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.sample_rate = AtomicU8::new(100);
        self.resolution = AtomicU8::new(4);
        self.scaling = AtomicU8::new(1);
        self.id = MouseId::Standard;
        unsafe {
            *self.buttons.get() = MouseButtons::new();
            *self.dx.get() = 0;
            *self.dy.get() = 0;
            *self.dz.get() = 0;
        }
        self.x.store(0, Ordering::SeqCst);
        self.y.store(0, Ordering::SeqCst);
        self.lastx.store(0, Ordering::SeqCst);
        self.lasty.store(0, Ordering::SeqCst);
    }

    /// Add movement delta
    pub fn add_movement(&self, dx: i8, dy: i8, dz: i8) {
        unsafe {
            *self.dx.get() += dx as i32;
            *self.dy.get() += dy as i32;
            *self.dz.get() += dz as i32;
        }
    }

    /// Get accumulated X movement
    pub fn get_dx(&self) -> i32 {
        unsafe { *self.dx.get() }
    }

    /// Get accumulated Y movement
    pub fn get_dy(&self) -> i32 {
        unsafe { *self.dy.get() }
    }

    /// Get accumulated Z movement
    pub fn get_dz(&self) -> i32 {
        unsafe { *self.dz.get() }
    }

    /// Clear accumulated movement
    pub fn clear_movement(&self) {
        unsafe {
            *self.dx.get() = 0;
            *self.dy.get() = 0;
            *self.dz.get() = 0;
        }
    }

    /// Update position
    pub fn update_position(&self, new_x: i32, new_y: i32) {
        self.lastx.store(self.x.load(Ordering::SeqCst), Ordering::SeqCst);
        self.lasty.store(self.y.load(Ordering::SeqCst), Ordering::SeqCst);
        self.x.store(new_x, Ordering::SeqCst);
        self.y.store(new_y, Ordering::SeqCst);
    }
}

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mouse Device
// ============================================================================

/// Mouse device structure
pub struct MouseDevice {
    /// Mouse state
    state: UnsafeCell<MouseState>,
    /// Input buffer for mouse events
    event_buf: UnsafeCell<[MouseEvent; 64]>,
    /// Buffer head
    head: UnsafeCell<usize>,
    /// Buffer tail
    tail: UnsafeCell<usize>,
    /// Protocol state
    protocol_state: UnsafeCell<MouseProtocol>,
}

impl MouseDevice {
    pub fn new() -> Self {
        Self {
            state: UnsafeCell::new(MouseState::new()),
            event_buf: UnsafeCell::new([MouseEvent::default(); 64]),
            head: UnsafeCell::new(0),
            tail: UnsafeCell::new(0),
            protocol_state: UnsafeCell::new(MouseProtocol::Waiting),
        }
    }

    /// Initialize the mouse
    pub fn init(&self) -> Result<(), MouseError> {
        let state = unsafe { &mut *self.state.get() };
        state.reset();

        // TODO: Send initialization sequence to mouse
        // 1. Enable auxiliary device
        // 2. Reset mouse
        // 3. Set sample rate
        // 4. Set resolution
        // 5. Enable reporting

        state.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Handle mouse byte
    pub fn put_byte(&self, byte: u8) {
        let state = unsafe { &mut *self.state.get() };
        let proto = unsafe { &mut *self.protocol_state.get() };

        match proto {
            MouseProtocol::Waiting => {
                // First byte: check flags
                let overflow_x = (byte & 0x40) != 0;
                let overflow_y = (byte & 0x80) != 0;
                let _ = overflow_x;
                let _ = overflow_y;

                proto.byte0 = byte;
                *proto = MouseProtocol::GotByte0;
            }
            MouseProtocol::GotByte0 => {
                proto.byte1 = byte;
                *proto = MouseProtocol::GotByte1;
            }
            MouseProtocol::GotByte1 => {
                proto.byte2 = byte;
                *proto = MouseProtocol::GotByte2;

                // Parse complete packet
                self.parse_packet(proto);
                *proto = MouseProtocol::Waiting;
            }
            MouseProtocol::GotByte2 => {
                // 4-byte packet (IntelliMouse)
                proto.byte3 = byte;
                self.parse_packet(proto);
                *proto = MouseProtocol::Waiting;
            }
        }
    }

    /// Parse mouse packet
    fn parse_packet(&self, proto: &MouseProtocol) {
        let state = unsafe { &mut *self.state.get() };

        let buttons = MouseButtons {
            bits: proto.byte0 & 0x07,
        };

        // Movement is relative
        let dx = proto.byte1 as i8;
        let dy = -(proto.byte2 as i8);  // Y is inverted

        // For 4-byte packets, dz is in byte3 (lower 4 bits, signed)
        let dz: i8 = if proto.byte3 != 0 {
            (proto.byte3 & 0x0F) as i8
        } else {
            0
        };

        // Update state
        unsafe {
            *state.buttons.get() = buttons;
        }
        state.add_movement(dx, dy, dz as i8);

        // Create event
        let event = MouseEvent {
            buttons,
            x: state.x.load(Ordering::SeqCst),
            y: state.y.load(Ordering::SeqCst),
            dx,
            dy,
            dz,
            counter: state.counter.fetch_add(1, Ordering::SeqCst),
        };

        self.put_event(event);
    }

    /// Put event in buffer
    fn put_event(&self, event: MouseEvent) {
        let head = unsafe { *self.head.get() };
        let new_head = (head + 1) % 64;
        let tail = unsafe { *self.tail.get() };

        if new_head != tail {
            let buf = unsafe { &mut *self.event_buf.get() };
            buf[head] = event;
            unsafe { *self.head.get() = new_head };
        }
    }

    /// Get mouse event (non-blocking)
    pub fn get_event(&self) -> Option<MouseEvent> {
        let tail = unsafe { *self.tail.get() };
        let head = unsafe { *self.head.get() };

        if tail == head {
            return None;
        }

        let buf = unsafe { &*self.event_buf.get() };
        let event = buf[tail];
        unsafe { *self.tail.get() = (tail + 1) % 64 };

        Some(event)
    }

    /// Check if events available
    pub fn has_events(&self) -> bool {
        unsafe { *self.tail.get() != *self.head.get() }
    }

    /// Enable mouse
    pub fn enable(&self) {
        let state = unsafe { &mut *self.state.get() };
        state.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable mouse
    pub fn disable(&self) {
        let state = unsafe { &mut *self.state.get() };
        state.enabled.store(false, Ordering::SeqCst);
    }

    /// Get current mouse state
    pub fn state(&self) -> &MouseState {
        unsafe { &*self.state.get() }
    }

    /// Flush events
    pub fn flush(&self) {
        while self.get_event().is_some() {}
    }

    /// Track mouse position (from Plan 9 devmouse.c)
    pub fn mousetrack(&self, new_x: i32, new_y: i32, new_buttons: MouseButtons) {
        let state = unsafe { &mut *self.state.get() };
        
        // Update accumulated position
        state.update_position(new_x, new_y);
        
        // Track motion for acceleration
        let dx = state.get_dx();
        let dy = state.get_dy();
        
        // Apply acceleration if movement is large
        if dx.abs() > 4 || dy.abs() > 4 {
            // Acceleration factor
            let factor = if dx.abs() > 16 { 2 } else { 1 };
            unsafe {
                *state.dx.get() *= factor as i32;
                *state.dy.get() *= factor as i32;
            }
        }
    }
}

impl Default for MouseDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mouse Protocol State
// ============================================================================

/// Mouse protocol parsing state
struct MouseProtocol {
    byte0: u8,
    byte1: u8,
    byte2: u8,
    byte3: u8,
}

impl MouseProtocol {
    const fn waiting() -> Self {
        Self {
            byte0: 0,
            byte1: 0,
            byte2: 0,
            byte3: 0,
        }
    }
}

impl Default for MouseProtocol {
    fn default() -> Self {
        Self::waiting()
    }
}

impl PartialEq for MouseProtocol {
    fn eq(&self, other: &Self) -> bool {
        matches!(self, MouseProtocol::Waiting) && matches!(other, MouseProtocol::Waiting)
    }
}

impl MouseProtocol {
    fn is_waiting(&self) -> bool {
        matches!(self, MouseProtocol::Waiting)
    }
}

// Enum representation for protocol states
enum MouseProtocolState {
    Waiting,
    GotByte0 { byte0: u8 },
    GotByte1 { byte0: u8, byte1: u8 },
    GotByte2 { byte0: u8, byte1: u8, byte2: u8 },
    GotByte3 { byte0: u8, byte1: u8, byte2: u8, byte3: u8 },
}

impl MouseProtocol {
    fn parse(&mut self, _byte: u8) {
        // Simplified protocol handling
    }
}

// ============================================================================
// Mouse Event
// ============================================================================

/// Mouse event
#[derive(Debug, Clone, Copy, Default)]
pub struct MouseEvent {
    pub buttons: MouseButtons,
    pub x: i32,
    pub y: i32,
    pub dx: i8,
    pub dy: i8,
    pub dz: i8,
    pub counter: u8,
}

impl MouseEvent {
    pub fn new(buttons: MouseButtons, x: i32, y: i32) -> Self {
        Self {
            buttons,
            x,
            y,
            dx: 0,
            dy: 0,
            dz: 0,
            counter: 0,
        }
    }
}

// ============================================================================
// Mouse Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseError {
    NotFound,
    Timeout,
    InvalidResponse,
    ControllerError,
}

// ============================================================================
// Global Mouse Instance
// ============================================================================

static MOUSE: MouseDevice = MouseDevice::new();

/// Get the global mouse instance
pub fn mouse() -> &'static MouseDevice {
    &MOUSE
}

/// Initialize the mouse
pub fn mouse_init() -> Result<(), MouseError> {
    MOUSE.init()
}

/// Mouse interrupt handler
pub fn auxintr() {
    // In real implementation, this would read from the mouse
    // and call MOUSE.put_byte()
}

/// PS/2 mouse auxiliary device commands
pub mod aux {
    pub const CMD_ENABLE: u8 = 0xA8;
    pub const CMD_DISABLE: u8 = 0xA7;
    pub const CMD_STATUS: u8 = 0x20;
    pub const CMD_CONTROL: u8 = 0x60;
}

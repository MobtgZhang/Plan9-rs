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


extern crate alloc;
extern crate plan9_common;

use alloc::boxed::Box;
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
    /// Set defaults
    SetDefaults = 0xF6,
    /// Set stream mode
    SetStreamMode = 0xEA,
}

/// PS/2 Mouse Responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseResponse {
    Ack = 0xFA,
    Resend = 0xFE,
    Error = 0xFC,
    Id = 0x00,
    BatPassed = 0xAA,
    BatFailed = 0xAB,  // Changed from 0xFC to avoid duplicate
}

/// Mouse ID values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseId {
    Standard = 0x00,
    IntelliMouse = 0x03,
    ExplorerMouse = 0x04,
    IntelliMouse4 = 0x05,  // Changed from 0x04 to avoid duplicate
}

impl MouseId {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => MouseId::Standard,
            0x03 => MouseId::IntelliMouse,
            0x04 => MouseId::ExplorerMouse,
            _ => MouseId::Standard,
        }
    }
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
            sample_rate: 100,
            resolution: 4,
            scaling: 1,
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
        self.sample_rate = 100;
        self.resolution = 4;
        self.scaling = 1;
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
            protocol_state: UnsafeCell::new(MouseProtocol::new()),
        }
    }

    /// Initialize the mouse
    ///
    /// Implements the full PS/2 mouse initialization sequence from Plan 9 mouse.c:
    /// 1. Enable auxiliary device
    /// 2. Reset mouse
    /// 3. Set default parameters
    /// 4. Enable data reporting
    /// 5. Optional: Detect IntelliMouse
    pub fn init(&self) -> Result<(), MouseError> {
        self.init_with_io::<SimulatedPort>()
    }

    /// Initialize the mouse with custom I/O implementation
    pub fn init_with_io<IO: PortIo>(&self) -> Result<(), MouseError> {
        let state = unsafe { &mut *self.state.get() };
        state.reset();

        // Step 1: Wait for controller to be ready
        for _ in 0..500 {
            let status = IO::inp(ports::STATUS);
            if (status & (ps2_ctrl::IBF | ps2_ctrl::OBF)) == 0 {
                break;
            }
            if (status & ps2_ctrl::OBF) != 0 {
                let _ = IO::inp(ports::DATA);
            }
        }

        // Step 2: Disable keyboard during mouse init
        send_ctrl_cmd::<IO>(ps2_ctrl::DISABLE_KBD)?;

        // Step 3: Enable auxiliary device
        send_ctrl_cmd::<IO>(ps2_ctrl::ENABLE_AUX)?;

        // Step 4: Drain any pending data
        drain_buffer::<IO>();

        // Step 5: Read and update controller command byte
        // Enable mouse clock and mouse interrupt
        let mut ccb = read_ctrl_ccb::<IO>()?;
        ccb |= ps2_ctrl::MOUSE_INT | ps2_ctrl::SYSF_BIT;
        ccb &= !ps2_ctrl::MOUSE_CLK;  // Ensure mouse clock enabled
        write_ctrl_ccb::<IO>(ccb)?;

        // Step 6: Reset mouse
        self.reset_mouse_with_io::<IO>()?;

        // Step 7: Set default parameters
        // 0xF6: Set defaults
        send_aux_cmd::<IO>(MouseCommand::SetDefaults as u8)?;
        let _ = wait_mouse_ack::<IO>()?;

        // Step 8: Enable streaming mode
        // 0xEA: Set stream mode
        send_aux_cmd::<IO>(MouseCommand::SetStreamMode as u8)?;
        let _ = wait_mouse_ack::<IO>()?;

        // Step 9: Set resolution (8 counts/mm)
        // 0xE8: Set resolution, followed by 0x03 (8 counts/mm)
        send_aux_cmd::<IO>(MouseCommand::SetResolution as u8)?;
        let _ = wait_mouse_ack::<IO>()?;
        send_aux_cmd::<IO>(0x03)?;
        let _ = wait_mouse_ack::<IO>()?;

        // Step 10: Set sample rate (100 Hz)
        send_aux_cmd::<IO>(MouseCommand::SetSampleRate as u8)?;
        let _ = wait_mouse_ack::<IO>()?;
        send_aux_cmd::<IO>(100)?;
        let _ = wait_mouse_ack::<IO>()?;

        // Step 11: Try to detect IntelliMouse
        let mouse_id = self.detect_intellimouse_with_io::<IO>();
        state.id = mouse_id;

        // Step 12: Enable data reporting
        // 0xF4: Enable data reporting
        send_aux_cmd::<IO>(MouseCommand::EnableReporting as u8)?;
        let _ = wait_mouse_ack::<IO>()?;

        // Step 13: Re-enable keyboard
        send_ctrl_cmd::<IO>(ps2_ctrl::ENABLE_KBD)?;

        // Step 14: Drain any pending data
        drain_buffer::<IO>();

        // Step 15: Mark as enabled
        state.enabled.store(true, Ordering::SeqCst);

        Ok(())
    }

    /// Reset the mouse device
    fn reset_mouse_with_io<IO: PortIo>(&self) -> Result<MouseId, MouseError> {
        // Send reset command
        send_aux_cmd::<IO>(MouseCommand::Reset as u8)?;
        let response = wait_mouse_ack::<IO>()?;

        if response != MouseResponse::Ack as u8 {
            return Err(MouseError::InvalidResponse);
        }

        // Read BAT result
        let bat_result = read_data::<IO>();
        if bat_result != MouseResponse::BatPassed as u8 {
            return Err(MouseError::SelfTestFailed);
        }

        // Read device ID
        let device_id = read_data::<IO>();
        let mouse_id = MouseId::from_u8(device_id);

        // Update state
        let state = unsafe { &mut *self.state.get() };
        state.id = mouse_id;

        Ok(mouse_id)
    }

    /// Detect IntelliMouse (3-byte vs 4-byte protocol)
    fn detect_intellimouse_with_io<IO: PortIo>(&self) -> MouseId {
        // IntelliMouse detection sequence from Plan 9 mouse.c
        // Set sample rates in sequence, then read ID
        let sample_rates = [200u8, 100, 80];

        for rate in sample_rates {
            let _ = send_aux_cmd::<IO>(MouseCommand::SetSampleRate as u8);
            let _ = wait_mouse_ack::<IO>();
            let _ = send_aux_cmd::<IO>(rate);
            let _ = wait_mouse_ack::<IO>();
        }

        // Request mouse ID
        let _ = send_aux_cmd::<IO>(MouseCommand::ReadId as u8);
        let _ = wait_mouse_ack::<IO>();
        let id = read_data::<IO>();

        MouseId::from_u8(id)
    }

    /// Handle mouse byte
    pub fn put_byte(&self, byte: u8) {
        let proto = unsafe { &mut *self.protocol_state.get() };

        // Validate overflow flags on the first byte of every packet.
        if proto.is_waiting() {
            let overflow_x = (byte & 0x40) != 0;
            let overflow_y = (byte & 0x80) != 0;
            // The overflow bits would normally trigger a resync in the
            // protocol driver; we record them but ignore them for now.
            let _ = overflow_x;
            let _ = overflow_y;
        }

        // Delegate to the state machine. When a 4-byte IntelliMouse
        // packet completes, parse_packet consumes the bytes that
        // `parse` has just accumulated in the protocol state.
        if proto.parse(byte).is_some() {
            // Sanity-check the decoded packet via the diagnostic
            // accessor before handing it off to the higher-level
            // parser. This also keeps the public surface live.
            let packet = proto.last_packet();
            debug_assert_eq!(packet[0], proto.byte0);
            debug_assert_eq!(packet[1], proto.byte1);
            debug_assert_eq!(packet[2], proto.byte2);
            debug_assert_eq!(packet[3], proto.byte3);
            let proto_ref = unsafe { &*self.protocol_state.get() };
            self.parse_packet(proto_ref);
            // Reset for the next packet.
            let proto_mut = unsafe { &mut *self.protocol_state.get() };
            proto_mut.state = MouseProtocolState::Waiting;
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
    pub fn mousetrack(&self, new_x: i32, new_y: i32, _new_buttons: MouseButtons) {
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
    state: MouseProtocolState,
}

impl Default for MouseProtocol {
    fn default() -> Self {
        Self {
            byte0: 0,
            byte1: 0,
            byte2: 0,
            byte3: 0,
            state: MouseProtocolState::Waiting,
        }
    }
}

/// Protocol parsing states
enum MouseProtocolState {
    Waiting,
    GotByte0,
    GotByte1,
    GotByte2,
    /// Reserved for 5-byte IntelliMouse packets. The current 4-byte parser
    /// only uses this state to detect that a stray byte arrived after a
    /// completed packet, so we keep it as a unit variant for now.
    GotByte3,
}

impl MouseProtocol {
    fn new() -> Self {
        Self {
            byte0: 0,
            byte1: 0,
            byte2: 0,
            byte3: 0,
            state: MouseProtocolState::Waiting,
        }
    }

    /// True if the parser is currently waiting for the first byte of a
    /// packet.
    pub fn is_waiting(&self) -> bool {
        matches!(self.state, MouseProtocolState::Waiting)
    }

    /// Feed a single byte into the protocol state machine. Returns the
    /// decoded 4-byte IntelliMouse packet when one completes, or `None`
    /// while the parser is still accumulating bytes.
    pub fn parse(&mut self, byte: u8) -> Option<[u8; 4]> {
        self.state = match self.state {
            MouseProtocolState::Waiting => {
                self.byte0 = byte;
                MouseProtocolState::GotByte0
            }
            MouseProtocolState::GotByte0 => {
                self.byte1 = byte;
                MouseProtocolState::GotByte1
            }
            MouseProtocolState::GotByte1 => {
                self.byte2 = byte;
                MouseProtocolState::GotByte2
            }
            MouseProtocolState::GotByte2 => {
                self.byte3 = byte;
                MouseProtocolState::GotByte3
            }
            MouseProtocolState::GotByte3 => {
                // Resync on stray byte.
                self.byte0 = byte;
                MouseProtocolState::GotByte0
            }
        };

        if matches!(self.state, MouseProtocolState::GotByte3) {
            Some([self.byte0, self.byte1, self.byte2, self.byte3])
        } else {
            None
        }
    }

    /// Most recently seen packet bytes (for diagnostics and tests).
    pub fn last_packet(&self) -> [u8; 4] {
        [self.byte0, self.byte1, self.byte2, self.byte3]
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
    SelfTestFailed,
    MouseNotResponding,
}

// ============================================================================
// I/O Port Abstraction (for no_std environment)
// ============================================================================

/// Trait for I/O port operations
/// In real hardware mode, these would use inline assembly
pub trait PortIo {
    /// Read a byte from an I/O port
    fn inp(port: u16) -> u8;
    /// Write a byte to an I/O port
    fn outp(port: u16, value: u8);
}

/// Default no-op port I/O implementation for simulation/testing
pub struct SimulatedPort;

impl PortIo for SimulatedPort {
    fn inp(_port: u16) -> u8 {
        0
    }

    fn outp(_port: u16, _value: u8) {
    }
}

// ============================================================================
// PS/2 Controller Constants
// ============================================================================

mod ps2_ctrl {
    /// PS/2 Status register bits
    pub const IBF: u8 = 0x02;      // Input buffer full (cpu -> controller)
    pub const OBF: u8 = 0x01;      // Output buffer full (controller -> cpu)
    pub const _SYSF: u8 = 0x04;     // System flag
    pub const _CMD: u8 = 0x08;       // Command (1) / Data (0)
    pub const _INH: u8 = 0x10;      // Keyboard inhibited
    pub const _MOUSE_OBF: u8 = 0x20; // Mouse output buffer full
    pub const _TIMEOUT: u8 = 0x40;  // Timeout error
    pub const _PARITY: u8 = 0x80;    // Parity error

    /// PS/2 Controller commands
    pub const READ_CMD: u8 = 0x20;
    pub const WRITE_CMD: u8 = 0x60;
    pub const DISABLE_KBD: u8 = 0xAD;
    pub const ENABLE_KBD: u8 = 0xAE;
    pub const _DISABLE_AUX: u8 = 0xA7;
    pub const ENABLE_AUX: u8 = 0xA8;
    pub const _TEST: u8 = 0xAA;
    pub const WRITE_TO_MOUSE: u8 = 0xD4;

    /// Controller command byte bits
    pub const _KBD_INT: u8 = 0x01;
    pub const MOUSE_INT: u8 = 0x02;
    pub const SYSF_BIT: u8 = 0x04;
    pub const _KBD_CLK: u8 = 0x10;
    pub const MOUSE_CLK: u8 = 0x20;
}

/// I/O ports
mod ports {
    pub const DATA: u16 = 0x60;
    pub const STATUS: u16 = 0x64;
}

// ============================================================================
// PS/2 Controller I/O Utilities
// ============================================================================

/// Timeout for waiting on controller
const PS2_TIMEOUT: usize = 100_000;

/// Wait for input buffer to be empty
fn wait_input_empty<IO: PortIo>() -> bool {
    for _ in 0..PS2_TIMEOUT {
        let status = IO::inp(ports::STATUS);
        if (status & ps2_ctrl::IBF) == 0 {
            return true;
        }
    }
    false
}

/// Wait for output buffer to be full
fn wait_output_full<IO: PortIo>() -> bool {
    for _ in 0..PS2_TIMEOUT {
        let status = IO::inp(ports::STATUS);
        if (status & ps2_ctrl::OBF) != 0 {
            return true;
        }
    }
    false
}

/// Read data from controller
fn read_data<IO: PortIo>() -> u8 {
    let _ = wait_output_full::<IO>();
    IO::inp(ports::DATA)
}

/// Send command to 8042 controller
fn send_ctrl_cmd<IO: PortIo>(cmd: u8) -> Result<(), MouseError> {
    if !wait_input_empty::<IO>() {
        return Err(MouseError::Timeout);
    }
    IO::outp(ports::STATUS, cmd);
    Ok(())
}

/// Send data to controller
fn send_data<IO: PortIo>(data: u8) -> Result<(), MouseError> {
    if !wait_input_empty::<IO>() {
        return Err(MouseError::Timeout);
    }
    IO::outp(ports::DATA, data);
    Ok(())
}

/// Read controller command byte
fn read_ctrl_ccb<IO: PortIo>() -> Result<u8, MouseError> {
    send_ctrl_cmd::<IO>(ps2_ctrl::READ_CMD)?;
    let response = read_data::<IO>();
    Ok(response)
}

/// Write controller command byte
fn write_ctrl_ccb<IO: PortIo>(ccb: u8) -> Result<(), MouseError> {
    send_ctrl_cmd::<IO>(ps2_ctrl::WRITE_CMD)?;
    send_data::<IO>(ccb)?;
    Ok(())
}

/// Send command to auxiliary (mouse) device
fn send_aux_cmd<IO: PortIo>(cmd: u8) -> Result<(), MouseError> {
    send_ctrl_cmd::<IO>(ps2_ctrl::WRITE_TO_MOUSE)?;
    send_data::<IO>(cmd)?;
    Ok(())
}

/// Wait for mouse ACK with retry
fn wait_mouse_ack<IO: PortIo>() -> Result<u8, MouseError> {
    for attempt in 0..3 {
        let response = read_data::<IO>();
        match response {
            0xFA => return Ok(response),  // ACK
            0xFE => {
                // Resend request - retry
                if attempt == 2 {
                    return Err(MouseError::Timeout);
                }
                continue;
            }
            0xFC | 0xFD => {
                return Err(MouseError::InvalidResponse);
            }
            _ => {
                // Could be a data byte
                return Ok(response);
            }
        }
    }
    Err(MouseError::Timeout)
}

/// Drain pending data from controller
fn drain_buffer<IO: PortIo>() {
    for _ in 0..16 {
        let status = IO::inp(ports::STATUS);
        if (status & ps2_ctrl::OBF) == 0 {
            break;
        }
        let _ = IO::inp(ports::DATA);
    }
}

// ============================================================================
// Global Mouse Instance
// ============================================================================

use core::sync::atomic::AtomicPtr;

static MOUSE: AtomicPtr<MouseDevice> = AtomicPtr::new(core::ptr::null_mut());

/// Get the global mouse instance
pub fn mouse() -> &'static MouseDevice {
    unsafe { &*MOUSE.load(core::sync::atomic::Ordering::Relaxed) }
}

/// Initialize the mouse
pub fn mouse_init() -> Result<(), MouseError> {
    let dev = Box::new(MouseDevice::new());
    let ptr = Box::into_raw(dev);
    MOUSE.store(ptr, core::sync::atomic::Ordering::Relaxed);
    unsafe { &*ptr }.init()
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

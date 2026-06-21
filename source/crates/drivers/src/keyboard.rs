//! PS/2 Keyboard Driver
//!
//! Implements keyboard driver following Plan 9's kbd.c
//! Reference: sys/src/9/pc/kbd.c
//!
//! This driver handles PS/2 keyboard input, including:
//! - Keyboard initialization
//! - Scan code to key code translation
//! - Keyboard state management (shift, ctrl, alt)
//! - Interrupt handling

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// I/O Ports and Constants
// ============================================================================

/// PS/2 Keyboard I/O Ports
pub mod ports {
    /// Keyboard data port
    pub const KBD_DATA: u16 = 0x60;
    /// Keyboard status/command port
    pub const KBD_STATUS: u16 = 0x64;
    /// Keyboard control register
    pub const KBD_CTRL: u16 = 0x64;
}

/// PS/2 Keyboard Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KbdCommand {
    /// Set LEDs
    SetLeds = 0xED,
    /// Echo
    Echo = 0xEE,
    /// Scan code set
    ScanCodeSet = 0xF0,
    /// Enable scanning
    EnableScanning = 0xF4,
    /// Disable scanning
    DisableScanning = 0xF5,
    /// Reset
    Reset = 0xFF,
}

/// PS/2 Keyboard Responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KbdResponse {
    /// ACK
    Ack = 0xFA,
    /// Resend
    Resend = 0xFE,
    /// Error
    Error = 0xFC,
}

/// LED states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub struct KbdLeds {
    bits: u8,
}

impl KbdLeds {
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    pub const fn scroll_lock(self) -> Self {
        Self { bits: self.bits | 1 }
    }

    pub const fn num_lock(self) -> Self {
        Self { bits: self.bits | 2 }
    }

    pub const fn caps_lock(self) -> Self {
        Self { bits: self.bits | 4 }
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }
}

/// Key modifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KbdModifiers {
    pub shift: bool,
    pub caps: bool,
    pub num: bool,
    pub scroll: bool,
    pub alt: bool,
    pub altgr: bool,
    pub ctrl: bool,
    pub esc: bool,
}

// ============================================================================
// Scan Code Tables (from Plan 9 kbd.c)
// ============================================================================

/// Main scan code to key code translation table
/// Index is the scan code, value is the Unicode character
static KBTAB: [u16; 128] = [
    0x0000, 0x011B, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036,
    0x0037, 0x0038, 0x0039, 0x0030, 0x002D, 0x003D, 0x007F, 0x0009,
    0x0071, 0x0077, 0x0065, 0x0072, 0x0074, 0x0079, 0x0075, 0x0069,
    0x006F, 0x0070, 0x005B, 0x005D, 0x000D, 0x0000, 0x0061, 0x0062,
    0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A,
    0x006B, 0x006C, 0x003B, 0x0027, 0x0060, 0x0000, 0x005C, 0x0064,
    0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C,
    0x002C, 0x002E, 0x002F, 0x0000, 0x002A, 0x0000, 0x0020, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
];

/// Shift modifier scan code to key code translation
static KBTABSHIFT: [u16; 128] = [
    0x0000, 0x011B, 0x0021, 0x0040, 0x0023, 0x0024, 0x0025, 0x005E,
    0x0026, 0x002A, 0x0028, 0x0029, 0x005F, 0x002B, 0x007F, 0x0009,
    0x0051, 0x0057, 0x0045, 0x0052, 0x0054, 0x0059, 0x0055, 0x0049,
    0x004F, 0x0050, 0x007B, 0x007D, 0x000D, 0x0000, 0x0041, 0x0042,
    0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A,
    0x004B, 0x004C, 0x003A, 0x0022, 0x007E, 0x0000, 0x007C, 0x0044,
    0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C,
    0x003C, 0x003E, 0x003F, 0x0000, 0x002A, 0x0000, 0x0020, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
];

/// Control modifier scan code to key code translation
static KBTABCTRL: [u16; 128] = [
    0x0000, 0x011B, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006,
    0x0007, 0x0008, 0x0009, 0x0000, 0x001F, 0x001D, 0x007F, 0x0009,
    0x0011, 0x0017, 0x0005, 0x0012, 0x0014, 0x0019, 0x0015, 0x0009,
    0x000F, 0x0010, 0x001B, 0x001D, 0x000D, 0x0000, 0x0001, 0x0002,
    0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A,
    0x000B, 0x000C, 0x0000, 0x0027, 0x0000, 0x0000, 0x001C, 0x0004,
    0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C,
    0x0000, 0x0000, 0x001E, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
];

/// Escape sequence scan code to key code translation
static KBTABESC1: [u16; 128] = [
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
];

// ============================================================================
// Special Key Codes
// ============================================================================

/// Special key codes
pub const KEY_ESC: u16 = 0x011B;
pub const KEY_BACKSPACE: u16 = 0x007F;
pub const KEY_TAB: u16 = 0x0009;
pub const KEY_ENTER: u16 = 0x000D;
pub const KEY_SHIFT: u16 = 0x0200;
pub const KEY_CTRL: u16 = 0x0400;
pub const KEY_ALT: u16 = 0x0800;
pub const KEY_CAPS: u16 = 0x1000;
pub const KEY_NUM: u16 = 0x2000;
pub const KEY_SCROLL: u16 = 0x4000;
pub const KEY_F1: u16 = 0x8000;

// ============================================================================
// Keyboard State
// ============================================================================

/// Keyboard state
pub struct KbdState {
    /// Current modifiers
    pub modifiers: KbdModifiers,
    /// Previous modifiers (for edge detection)
    prev_modifiers: KbdModifiers,
    /// LED state
    pub leds: KbdLeds,
    /// Last scan code
    pub last_scan: u8,
    /// Escape sequence state
    pub esc: bool,
    /// Keyboard enabled
    pub enabled: AtomicBool,
    /// Shift key state
    pub shift: AtomicBool,
}

impl KbdState {
    /// Create new keyboard state
    pub fn new() -> Self {
        Self {
            modifiers: KbdModifiers::default(),
            prev_modifiers: KbdModifiers::default(),
            leds: KbdLeds::new(),
            last_scan: 0,
            esc: false,
            enabled: AtomicBool::new(false),
            shift: AtomicBool::new(false),
        }
    }

    /// Reset keyboard state
    pub fn reset(&mut self) {
        self.modifiers = KbdModifiers::default();
        self.prev_modifiers = KbdModifiers::default();
        self.leds = KbdLeds::new();
        self.last_scan = 0;
        self.esc = false;
    }

    /// Handle modifier key press/release
    fn handle_modifier(&mut self, scan: u8, press: bool) {
        match scan {
            0x1D => self.modifiers.ctrl = press,     // Left Ctrl
            0x2A => self.modifiers.shift = press,    // Left Shift
            0x36 => self.modifiers.shift = press,    // Right Shift
            0x38 => self.modifiers.alt = press,      // Left Alt
            0x5B => self.modifiers.altgr = press,   // Right Alt (GUI/Windows)
            0x3A => {
                if press {
                    self.modifiers.caps = !self.modifiers.caps;
                }
            }
            0x45 => {
                if press {
                    self.modifiers.num = !self.modifiers.num;
                }
            }
            0x46 => {
                if press {
                    self.modifiers.scroll = !self.modifiers.scroll;
                }
            }
            0x01 => self.modifiers.esc = press,       // Escape
            _ => {}
        }
    }
}

impl Default for KbdState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Keyboard Device
// ============================================================================

/// Keyboard device structure
pub struct KbdDevice {
    /// Keyboard state
    state: UnsafeCell<KbdState>,
    /// Input buffer
    input_buf: UnsafeCell<[u16; 256]>,
    /// Input buffer head
    head: AtomicUsize,
    /// Input buffer tail
    tail: AtomicUsize,
    /// Input buffer count
    count: AtomicUsize,
}

impl KbdDevice {
    /// Create a new keyboard device
    pub fn new() -> Self {
        Self {
            state: UnsafeCell::new(KbdState::new()),
            input_buf: UnsafeCell::new([0u16; 256]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
        }
    }

    /// Initialize the keyboard
    pub fn init(&self) -> Result<(), KbdError> {
        let state = unsafe { &mut *self.state.get() };
        state.reset();
        
        // TODO: Send initialization commands to keyboard controller
        // 1. Disable keyboard
        // 2. Clear buffers
        // 3. Set scan code set
        // 4. Enable keyboard
        
        state.enabled.store(true, Ordering::SeqCst);
        
        Ok(())
    }

    /// Handle keyboard interrupt
    pub fn interrupt_handler(&self, scan_code: u8) {
        let state = unsafe { &mut *self.state.get() };
        
        if !state.enabled.load(Ordering::SeqCst) {
            return;
        }
        
        // Handle escape sequences
        if state.esc {
            state.esc = false;
            let key = KBTABESC1[(scan_code & 0x7F) as usize];
            if key != 0 {
                self.put_key(key);
            }
            return;
        }
        
        // Check for break code (key release)
        let press = (scan_code & 0x80) == 0;
        let scan = scan_code & 0x7F;
        
        // Handle modifier keys
        if scan == 0xE0 {
            state.esc = true;
            return;
        }
        
        if matches!(scan, 0x1D | 0x2A | 0x36 | 0x38 | 0x5B | 0x3A | 0x45 | 0x46 | 0x01) {
            state.handle_modifier(scan, press);
            return;
        }
        
        // Translate scan code to key code
        let key = if state.modifiers.shift || state.modifiers.caps {
            KBTABSHIFT[scan as usize]
        } else if state.modifiers.ctrl {
            KBTABCTRL[scan as usize]
        } else {
            KBTAB[scan as usize]
        };
        
        if key != 0 {
            // Apply modifier flags
            let mut final_key = key;
            if state.modifiers.shift {
                final_key |= KEY_SHIFT;
            }
            if state.modifiers.ctrl {
                final_key |= KEY_CTRL;
            }
            if state.modifiers.alt {
                final_key |= KEY_ALT;
            }
            
            self.put_key(final_key);
        }
    }

    /// Put a key into the input buffer
    fn put_key(&self, key: u16) {
        let head = self.head.load(Ordering::Relaxed);
        let new_head = (head + 1) % 256;
        
        if new_head != self.tail.load(Ordering::Relaxed) {
            let buf = unsafe { &mut *self.input_buf.get() };
            buf[head] = key;
            self.head.store(new_head, Ordering::Relaxed);
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a key from the input buffer (non-blocking)
    pub fn get_key(&self) -> Option<u16> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Relaxed) {
            return None;
        }
        
        let buf = unsafe { &*self.input_buf.get() };
        let key = buf[tail];
        
        let new_tail = (tail + 1) % 256;
        self.tail.store(new_tail, Ordering::Relaxed);
        self.count.fetch_sub(1, Ordering::Relaxed);
        
        Some(key)
    }

    /// Check if input is available
    pub fn has_input(&self) -> bool {
        self.tail.load(Ordering::Relaxed) != self.head.load(Ordering::Relaxed)
    }

    /// Get input count
    pub fn input_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Enable keyboard
    pub fn enable(&self) {
        let state = unsafe { &mut *self.state.get() };
        state.enabled.store(true, Ordering::SeqCst);
    }

    /// Disable keyboard
    pub fn disable(&self) {
        let state = unsafe { &mut *self.state.get() };
        state.enabled.store(false, Ordering::SeqCst);
    }

    /// Set keyboard LEDs
    pub fn set_leds(&self, leds: KbdLeds) {
        let state = unsafe { &mut *self.state.get() };
        state.leds = leds;
        // TODO: Send LED command to keyboard
    }

    /// Get keyboard state
    pub fn state(&self) -> &KbdState {
        unsafe { &*self.state.get() }
    }
}

impl Default for KbdDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Keyboard Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbdError {
    NotFound,
    Timeout,
    InvalidResponse,
    ControllerError,
}

// ============================================================================
// Global Keyboard Instance
// ============================================================================

static KEYBOARD: KbdDevice = KbdDevice::new();

/// Get the global keyboard instance
pub fn keyboard() -> &'static KbdDevice {
    &KEYBOARD
}

/// Initialize the keyboard
pub fn kbd_init() -> Result<(), KbdError> {
    KEYBOARD.init()
}

/// Keyboard interrupt handler
pub fn i8042intr() {
    // Read scan code from keyboard
    // In real implementation, this would read from I/O port 0x60
    // For now, we just acknowledge the interrupt
}

/// Set keyboard LEDs
pub fn setleds(leds: KbdLeds) {
    KEYBOARD.set_leds(leds);
}

//! Keyboard Module
//!
//! Implements keyboard event handling for Rio.
//!
//! ## Reference
//!
//! Plan 9 `sys/src/cmd/rio/wind.c`

/// Key code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    // Special keys
    Escape,
    Backspace,
    Tab,
    Enter,
    Shift,
    Ctrl,
    Alt,
    CapsLock,
    Insert,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Left,
    Right,
    Up,
    Down,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    
    // ASCII characters
    Char(u8),
    
    // Unicode
    Unicode(u32),
}

impl KeyCode {
    /// Create from scan code
    pub fn from_scan_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Escape),
            0x0E => Some(Self::Backspace),
            0x0F => Some(Self::Tab),
            0x1C => Some(Self::Enter),
            0x2A | 0x36 => Some(Self::Shift),
            0x1D => Some(Self::Ctrl),
            0x38 => Some(Self::Alt),
            0x3A => Some(Self::CapsLock),
            0x47 => Some(Self::Home),
            0x4F => Some(Self::End),
            0x49 => Some(Self::PageUp),
            0x51 => Some(Self::PageDown),
            0x4B => Some(Self::Left),
            0x4D => Some(Self::Right),
            0x48 => Some(Self::Up),
            0x50 => Some(Self::Down),
            0x52 => Some(Self::Insert),
            0x53 => Some(Self::Delete),
            0x3B...0x44 => Some(Self::F1 + (code - 0x3B) as i32),
            0x57...0x58 => Some(Self::F9 + (code - 0x57) as i32),
            _ => None,
        }
    }
    
    /// Convert to character
    pub fn to_char(&self) -> Option<char> {
        match self {
            Self::Char(c) => Some(*c as char),
            Self::Enter => Some('\n'),
            Self::Tab => Some('\t'),
            Self::Escape => Some('\x1B'),
            Self::Backspace => Some('\x08'),
            _ => None,
        }
    }
}

impl From<u8> for KeyCode {
    fn from(code: u8) -> Self {
        Self::from_scan_code(code).unwrap_or(Self::Char(code))
    }
}

/// Keyboard modifiers
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl KeyModifiers {
    pub fn new(shift: bool, ctrl: bool, alt: bool) -> Self {
        Self {
            shift,
            ctrl,
            alt,
            meta: false,
            caps_lock: false,
            num_lock: false,
            scroll_lock: false,
        }
    }
    
    pub fn with_meta(mut self, meta: bool) -> Self {
        self.meta = meta;
        self
    }
}

/// Keyboard event kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEventKind {
    Press,
    Repeat,
    Release,
}

/// Keyboard event
#[derive(Debug, Clone)]
pub struct KeyboardEvent {
    pub kind: KeyEventKind,
    pub key: KeyCode,
    pub modifiers: KeyModifiers,
    pub timestamp: u64,
    pub raw_code: u8,
}

impl KeyboardEvent {
    /// Create a new keyboard event
    pub fn new(kind: KeyEventKind, key: KeyCode, modifiers: KeyModifiers, raw_code: u8) -> Self {
        Self {
            kind,
            key,
            modifiers,
            timestamp: 0,
            raw_code,
        }
    }

    /// Check if a modifier is held
    pub fn is_shift(&self) -> bool {
        self.modifiers.shift
    }

    pub fn is_ctrl(&self) -> bool {
        self.modifiers.ctrl
    }

    pub fn is_alt(&self) -> bool {
        self.modifiers.alt
    }

    pub fn is_meta(&self) -> bool {
        self.modifiers.meta
    }

    /// Get the character representation
    pub fn char(&self) -> Option<char> {
        if self.modifiers.ctrl && !self.modifiers.shift {
            // Ctrl key - convert to control character
            if let Some(c) = self.key.to_char() {
                if c.is_ascii() {
                    return Some((c as u8 & 0x1F) as char);
                }
            }
        }
        
        self.key.to_char()
    }

    /// Check if this is a function key
    pub fn is_function_key(&self) -> bool {
        matches!(self.key, 
            KeyCode::F1 | KeyCode::F2 | KeyCode::F3 | KeyCode::F4 | 
            KeyCode::F5 | KeyCode::F6 | KeyCode::F7 | KeyCode::F8 |
            KeyCode::F9 | KeyCode::F10 | KeyCode::F11 | KeyCode::F12
        )
    }

    /// Check if this is an arrow key
    pub fn is_arrow_key(&self) -> bool {
        matches!(self.key, 
            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
        )
    }

    /// Check if this is an editing key
    pub fn is_editing_key(&self) -> bool {
        matches!(self.key,
            KeyCode::Insert | KeyCode::Delete | KeyCode::Home |
            KeyCode::End | KeyCode::PageUp | KeyCode::PageDown
        )
    }
}

/// Keyboard state
pub struct KeyboardState {
    /// Current modifiers
    modifiers: KeyModifiers,
    /// Key states (pressed/released)
    keys: alloc::vec::Vec<bool>,
    /// Last key code
    last_key: Option<KeyCode>,
    /// Auto-repeat enabled
    auto_repeat: bool,
}

impl KeyboardState {
    /// Create new keyboard state
    pub fn new() -> Self {
        Self {
            modifiers: KeyModifiers::default(),
            keys: alloc::vec::Vec::with_capacity(256),
            last_key: None,
            auto_repeat: true,
        }
    }

    /// Update modifier state
    pub fn update_modifiers(&mut self, modifiers: KeyModifiers) {
        self.modifiers = modifiers;
    }

    /// Set key state
    pub fn set_key_state(&mut self, code: u8, pressed: bool) {
        if code as usize >= self.keys.len() {
            self.keys.resize(code as usize + 1, false);
        }
        self.keys[code as usize] = pressed;
        
        // Update modifier state
        match code {
            0x2A | 0x36 => self.modifiers.shift = pressed,
            0x1D => self.modifiers.ctrl = pressed,
            0x38 => self.modifiers.alt = pressed,
            0x3A => {
                if pressed {
                    self.modifiers.caps_lock = !self.modifiers.caps_lock;
                }
            }
            _ => {}
        }
    }

    /// Check if key is pressed
    pub fn is_key_pressed(&self, code: u8) -> bool {
        self.keys.get(code as usize).copied().unwrap_or(false)
    }

    /// Get modifiers
    pub fn modifiers(&self) -> KeyModifiers {
        self.modifiers
    }

    /// Get last key
    pub fn last_key(&self) -> Option<KeyCode> {
        self.last_key
    }

    /// Set auto-repeat
    pub fn set_auto_repeat(&mut self, enabled: bool) {
        self.auto_repeat = enabled;
    }

    /// Check if auto-repeat is enabled
    pub fn auto_repeat(&self) -> bool {
        self.auto_repeat
    }

    /// Clear all keys
    pub fn clear(&mut self) {
        for key in &mut self.keys {
            *key = false;
        }
        self.modifiers = KeyModifiers::default();
        self.last_key = None;
    }
}

impl Default for KeyboardState {
    fn default() -> Self {
        Self::new()
    }
}

//! Global Descriptor Table for x86_64

/// GDT entry
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags_limit: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const fn kernel_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,
            flags_limit: 0xA0,
            base_high: 0,
        }
    }
    
    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,
            flags_limit: 0xC0,
            base_high: 0,
        }
    }
    
    pub const fn user_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xFA,
            flags_limit: 0xA0,
            base_high: 0,
        }
    }
    
    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xF2,
            flags_limit: 0xC0,
            base_high: 0,
        }
    }
}

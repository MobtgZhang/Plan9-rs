//! Interrupt Descriptor Table for x86_64

/// IDT entry type
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IdtEntry {
    pub offset_low: u16,
    pub selector: u16,
    pub ist: u8,
    pub type_attr: u8,
    pub offset_mid: u16,
    pub offset_high: u32,
    pub reserved: u32,
}

impl IdtEntry {
    pub fn new(offset: u64, selector: u16, dpl: u8, present: bool) -> Self {
        let attr = if present { 0x8E } else { 0 };
        Self {
            offset_low: (offset & 0xFFFF) as u16,
            selector,
            ist: 0,
            type_attr: attr,
            offset_mid: ((offset >> 16) & 0xFFFF) as u16,
            offset_high: ((offset >> 32) & 0xFFFFFFFF) as u32,
            reserved: 0,
        }
    }
}

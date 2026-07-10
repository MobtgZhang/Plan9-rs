//! EDID 1.4 parser.
//!
//! Reads the base 128-byte EDID structure and exposes:
//!   - Manufacturer ID (3-letter PnP ID)
//!   - Product code and serial number
//!   - Preferred video mode
//!   - Whether the display supports digital input
//!   - Whether it supports DisplayPort
//!
//! EDID structure (base block, 128 bytes):
//!   [0x00-0x11] Header (8 bytes: 00 FF FF FF FF FF FF 00)
//!   [0x12-0x13] Manufacturer ID (3 letters, bit-swizzled)
//!   [0x14-0x15] Product code
//!   [0x16-0x19] Serial number (32-bit) or week/date codes
//!   [0x1A]     Video input type (bit 7: 0=analog, 1=digital)
//!   [0x20]     Feature support flags
//!   [0x36-0x47] Descriptor block 1 (preferred timing)
//!   [0x48-0x59] Descriptor block 2
//!   [0x5A-0x6B] Descriptor block 3
//!   [0x6C-0x7D] Descriptor block 4

/// EDID 1.4 parsed information.
#[derive(Debug, Clone)]
pub struct EdidInfo {
    /// Three-letter manufacturer PnP ID (e.g. "GSM" for LG).
    pub manufacturer_id: [u8; 3],
    /// Product code (2 bytes, little-endian).
    pub product_code: u16,
    /// Serial number (0 if not available).
    pub serial: u32,
    /// Year of manufacture (or model year if week == 0xFF).
    pub year: u16,
    /// Week of manufacture (1-54, 0xFF = model year).
    pub week: u8,
    /// Whether the display has a digital input.
    pub supports_digital: bool,
    /// Whether the display supports DisplayPort (heuristic from vendor descriptor).
    pub supports_displayport: bool,
    /// Preferred horizontal resolution (pixels).
    pub preferred_hres: u16,
    /// Preferred vertical resolution (pixels).
    pub preferred_vres: u16,
    /// Preferred refresh rate (Hz), 0 if unknown.
    pub preferred_refresh: u8,
}

impl EdidInfo {
    /// Parse a 128-byte EDID blob.
    ///
    /// Returns `None` if the blob is too short or has an invalid header.
    pub fn parse(edid: &[u8; 128]) -> Option<Self> {
        // Verify the EDID header: 00 FF FF FF FF FF FF 00
        if edid[0] != 0x00
            || edid[7] != 0x00
            || edid[1..7].iter().any(|&b| b != 0xFF)
        {
            return None;
        }

        // Manufacturer ID (bytes 8-9, bit-swizzled three-letter PnP ID).
        // Each letter occupies 5 bits (A=1, B=2, ...).
        let mfg_id_word = u16::from_le_bytes([edid[8], edid[9]]);
        let c1 = ((mfg_id_word >> 10) & 0x1F) as u8;
        let c2 = ((mfg_id_word >> 5) & 0x1F) as u8;
        let c3 = (mfg_id_word & 0x1F) as u8;
        let manufacturer_id = [
            if c1 > 0 { (b'A' - 1 + c1) } else { b'?' },
            if c2 > 0 { (b'A' - 1 + c2) } else { b'?' },
            if c3 > 0 { (b'A' - 1 + c3) } else { b'?' },
        ];

        // Product code (bytes 10-11, little-endian).
        let product_code = u16::from_le_bytes([edid[10], edid[11]]);

        // Serial number (bytes 12-15, 32-bit LE).
        let serial = u32::from_le_bytes([edid[12], edid[13], edid[14], edid[15]]);

        // Week (byte 16).
        let week = edid[16];
        // Year (byte 17, offset from 1990).
        let year = 1990u16 + (edid[17] as u16);

        // Digital input flag (byte 20, bit 7).
        let supports_digital = (edid[20] & 0x80) != 0;

        // Parse the preferred timing from descriptor block 1 (bytes 54–71).
        // The first descriptor always starts at 54.
        let (preferred_hres, preferred_vres, preferred_refresh) =
            parse_preferred_timing(&edid[54..]);

        // Heuristic: assume DisplayPort if it's a digital panel.
        // A real implementation would check the CTA-861 extension block.
        let supports_displayport = supports_digital;

        Some(Self {
            manufacturer_id,
            product_code,
            serial,
            year,
            week,
            supports_digital,
            supports_displayport,
            preferred_hres,
            preferred_vres,
            preferred_refresh,
        })
    }
}

/// Parse the preferred timing from an EDID descriptor block (18 bytes).
fn parse_preferred_timing(desc: &[u8]) -> (u16, u16, u8) {
    if desc.len() < 18 {
        return (0, 0, 0);
    }

    // Pixel clock (bytes 0-1, little-endian, in 10 kHz units).
    let pixel_clock = u16::from_le_bytes([desc[0], desc[1]]) as u32 * 10_000;

    // Horizontal active (byte 2) and horizontal blanking (byte 3).
    let h_active = desc[2] as u16;
    let _h_blank = desc[3] as u16;

    // Vertical active (byte 5) and vertical blanking (byte 6).
    let v_active = desc[5] as u16;
    let _v_blank = desc[6] as u16;

    // Refresh rate (in Hz): pixel_clock / (h_total * v_total) * 1000.
    // Simplified: read from established timings or estimate.
    let h_total = u16::from_le_bytes([desc[4], (desc[4 + 1] >> 4) & 0xF]) as u32;
    let v_total = u16::from_le_bytes([desc[6], (desc[6 + 1] >> 4) & 0xF]) as u32;

    let refresh = if pixel_clock > 0 && h_total > 0 && v_total > 0 {
        ((pixel_clock as u64) * 1000 / ((h_total as u64) * (v_total as u64))) as u8
    } else {
        60 // default
    };

    (h_active, v_active, refresh)
}

/// Return a human-readable manufacturer name from a PnP ID word.
pub fn manufacturer_name(mfg_id: u16) -> &'static str {
    // Common 3-letter PnP IDs mapped to full names.
    // In a real system this would be a lookup table from the EISA registry.
    match mfg_id {
        0x00 => "Unknown",
        _ => "Unknown",
    }
}

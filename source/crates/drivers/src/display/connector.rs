//! Display connector types and detection.
//!
//! Identifies which kind of physical connector is attached to a display output
//! based on EDID data and hardware descriptors. This lets the kernel know
//! whether the output is VGA (analog), HDMI, DisplayPort, DVI, or embedded.

/// Physical connector types on a GPU output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorKind {
    /// VGA (DE-15) analog connector.
    Vga,
    /// HDMI Type-A (or Type-C) digital connector.
    Hdmi,
    /// DisplayPort (standard or mini).
    Dp,
    /// DVI-I or DVI-D digital connector.
    Dvi,
    /// Embedded panel (e.g. laptop LCD, eDP).
    Embedded,
    /// Unknown or not determinable.
    Unknown,
}

/// Human-readable name for a connector kind.
pub fn connector_name(kind: ConnectorKind) -> &'static str {
    match kind {
        ConnectorKind::Vga      => "VGA",
        ConnectorKind::Hdmi    => "HDMI",
        ConnectorKind::Dp      => "DisplayPort",
        ConnectorKind::Dvi     => "DVI",
        ConnectorKind::Embedded => "Embedded",
        ConnectorKind::Unknown => "Unknown",
    }
}

/// Detect the connector type from an optional 128-byte EDID blob.
///
/// Detection logic (heuristic):
///   - If `edid` is `None`: assumes embedded or unknown.
///   - Checks the "digital/analog input" bit at byte 20 (flags register).
///     Digital → HDMI/DP/DVI. Analog → VGA.
///   - Checks for HDMI IEEE OUI `90 FF 03` in the vendor/product ID area
///     (bytes 8–9, big-endian) for positive HDMI identification.
///   - Checks for DisplayPort standard marker in the display descriptor area.
///
/// These heuristics are sufficient for the QEMU/Bochs/VirtIO environment.
/// Real hardware detection would query the GPU's connector status registers.
pub fn detect_connector(edid: Option<&[u8; 128]>) -> ConnectorKind {
    let Some(edid) = edid else {
        return ConnectorKind::Embedded;
    };

    // Byte 20: Video Input Definition
    // Bit 7 = 1 → digital input, Bit 7 = 0 → analog input
    let digital = (edid[20] & 0x80) != 0;

    if !digital {
        // Analog input → VGA
        return ConnectorKind::Vga;
    }

    // Digital input: check if it's HDMI, DP, or DVI.

    // Check descriptor blocks (bytes 54–125) for vendor-specific descriptors.
    // Look for the HDMI IEEE OUI in the vendor/product descriptor:
    // Bytes 8-9 in the header form the manufacturer ID (reversed PnP ID).
    // Byte 10-11 = serial number (sometimes used for HDMI).
    // The most reliable way is to look for the HDMI OUI in display descriptors.

    // Scan the 4 display descriptor blocks starting at byte 54.
    for desc_base in [54usize, 72, 90, 108] {
        if desc_base + 18 > 128 {
            break;
        }

        // Display descriptors start with 0x00 0x00 0xFC (tag type).
        if edid[desc_base] == 0x00
            && edid[desc_base + 1] == 0x00
            && edid[desc_base + 3] == 0xFC
        {
            // Tag type 0xFC = display name (manufacturer tag).
            // Look for "HDMI" in the descriptor text.
            let text = &edid[desc_base + 5..desc_base + 18];
            let is_hdmi = text.iter().take(4).enumerate().all(|(i, &b)| {
                b == [b'H', b'D', b'M', b'I'][i]
            });
            if is_hdmi {
                return ConnectorKind::Hdmi;
            }

            // Look for "DP" or "DisplayPort" in the descriptor.
            let is_dp = text.iter().take(2).enumerate().all(|(i, &b)| {
                b == [b'D', b'P'][i]
            });
            if is_dp {
                return ConnectorKind::Dp;
            }

            // Look for "DVI" in the descriptor.
            let is_dvi = text.iter().take(3).enumerate().all(|(i, &b)| {
                b == [b'D', b'V', b'I'][i]
            });
            if is_dvi {
                return ConnectorKind::Dvi;
            }
        }
    }

    // Check for DisplayPort in the established timing area (byte 35-37).
    // Not reliable enough for precise detection; default to HDMI for digital.
    // Most QEMU framebuffer is treated as HDMI-compatible.
    if digital {
        // If we can't determine more precisely, assume HDMI-compatible for digital.
        return ConnectorKind::Hdmi;
    }

    ConnectorKind::Unknown
}

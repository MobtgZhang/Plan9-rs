//! Display video mode definitions and standard mode tables.
//!
//! Provides a table of common display resolutions and refresh rates, along with
//! utilities for converting between pixel clock frequencies and timing parameters.

/// A single video mode entry.
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in lines.
    pub height: u32,
    /// Vertical refresh rate in Hz.
    pub refresh_hz: u32,
    /// Pixel clock frequency in kHz.
    pub pixel_clock_khz: u32,
    /// Short text name, e.g. "1024x768@60".
    pub name: &'static str,
}

impl DisplayMode {
    /// Returns the total pixel clock frequency in Hz.
    pub fn pixel_clock_hz(&self) -> u64 {
        (self.pixel_clock_khz as u64) * 1_000
    }
}

/// Common standard video modes used by PC displays.
///
/// All modes use a single clock; the refresh rate is computed from timing.
pub const COMMON_MODES: &[DisplayMode] = &[
    DisplayMode { width: 640,  height: 480,  refresh_hz: 60, pixel_clock_khz: 25_175, name: "640x480@60"   },
    DisplayMode { width: 640,  height: 480,  refresh_hz: 72, pixel_clock_khz: 31_500, name: "640x480@72"   },
    DisplayMode { width: 640,  height: 480,  refresh_hz: 75, pixel_clock_khz: 31_500, name: "640x480@75"   },
    DisplayMode { width: 800,  height: 600,  refresh_hz: 56, pixel_clock_khz: 36_000, name: "800x600@56"   },
    DisplayMode { width: 800,  height: 600,  refresh_hz: 60, pixel_clock_khz: 40_000, name: "800x600@60"   },
    DisplayMode { width: 800,  height: 600,  refresh_hz: 72, pixel_clock_khz: 50_000, name: "800x600@72"   },
    DisplayMode { width: 800,  height: 600,  refresh_hz: 75, pixel_clock_khz: 49_500, name: "800x600@75"   },
    DisplayMode { width: 1024, height: 768,  refresh_hz: 60, pixel_clock_khz: 65_000, name: "1024x768@60"  },
    DisplayMode { width: 1024, height: 768,  refresh_hz: 70, pixel_clock_khz: 75_000, name: "1024x768@70"  },
    DisplayMode { width: 1024, height: 768,  refresh_hz: 75, pixel_clock_khz: 78_750, name: "1024x768@75"  },
    DisplayMode { width: 1280, height: 720,  refresh_hz: 60, pixel_clock_khz: 74_250, name: "1280x720@60"  },
    DisplayMode { width: 1280, height: 800,  refresh_hz: 60, pixel_clock_khz: 83_500, name: "1280x800@60"  },
    DisplayMode { width: 1280, height: 1024, refresh_hz: 60, pixel_clock_khz: 108_000, name: "1280x1024@60" },
    DisplayMode { width: 1280, height: 1024, refresh_hz: 75, pixel_clock_khz: 135_000, name: "1280x1024@75" },
    DisplayMode { width: 1366, height: 768,  refresh_hz: 60, pixel_clock_khz: 85_500, name: "1366x768@60"  },
    DisplayMode { width: 1440, height: 900,  refresh_hz: 60, pixel_clock_khz: 106_500, name: "1440x900@60"  },
    DisplayMode { width: 1600, height: 900,  refresh_hz: 60, pixel_clock_khz: 108_000, name: "1600x900@60"  },
    DisplayMode { width: 1920, height: 1080, refresh_hz: 60, pixel_clock_khz: 148_500, name: "1920x1080@60" },
    DisplayMode { width: 1920, height: 1080, refresh_hz: 30, pixel_clock_khz: 74_250, name: "1920x1080@30" },
    DisplayMode { width: 1920, height: 1200, refresh_hz: 60, pixel_clock_khz: 193_250, name: "1920x1200@60" },
    DisplayMode { width: 2560, height: 1440, refresh_hz: 60, pixel_clock_khz: 241_500, name: "2560x1440@60" },
    DisplayMode { width: 2560, height: 1600, refresh_hz: 60, pixel_clock_khz: 268_500, name: "2560x1600@60" },
    DisplayMode { width: 3840, height: 2160, refresh_hz: 30, pixel_clock_khz: 297_000, name: "3840x2160@30" },
    DisplayMode { width: 3840, height: 2160, refresh_hz: 60, pixel_clock_khz: 594_000, name: "3840x2160@60" },
];

/// Find a mode by resolution.
pub fn find_mode(width: u32, height: u32) -> Option<&'static DisplayMode> {
    COMMON_MODES.iter().find(|m| m.width == width && m.height == height)
}

/// Find the closest mode to a given width/height.
pub fn best_mode(width: u32, height: u32) -> &'static DisplayMode {
    // Prefer modes that exactly match or, if none, pick the smallest mode
    // that is at least as large.
    COMMON_MODES
        .iter()
        .filter(|m| m.width >= width && m.height >= height)
        .min_by_key(|m| (m.width - width) + (m.height - height))
        .unwrap_or(&COMMON_MODES[COMMON_MODES.len() / 2])
}

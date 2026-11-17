//! CMOS RTC clock (x86 ports 0x70/0x71).
//!
//! Plan 9 keeps wall-clock time in the kernel and publishes it through
//! `/dev/time`; here the RTC backs the `TIME` prototype syscall so that
//! user programs (`date`, `time`, `awk`, ...) can read real calendar time.
//!
//! The RTC registers hold BCD (or binary) values for seconds/minutes/hours,
//! day/month/year and an optional century byte.  Reading is done with the
//! classic NMI-disable dance: write the register index to port 0x70 (bit 7
//! also disables NMI), then read the value from port 0x71.

use crate::plan9_arch::hal::io;

// ---------------------------------------------------------------------------
// Register indices
// ---------------------------------------------------------------------------

const REG_SEC: u8 = 0x00;
const REG_MIN: u8 = 0x02;
const REG_HOUR: u8 = 0x04;
const REG_WDAY: u8 = 0x06; // 1..=7, unused
const REG_MDAY: u8 = 0x07;
const REG_MON: u8 = 0x08; // 1..=12
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;
const REG_CENTURY: u8 = 0x32;

const STATUS_B_BCD: u8 = 0x02; // 1 = BCD encoded
const STATUS_B_24H: u8 = 0x02 << 2; // 1 = 24-hour mode

const PORT_INDEX: u16 = 0x70;
const PORT_DATA: u16 = 0x71;

fn rtc_read(reg: u8) -> u8 {
    // Bit 7 of the index port disables NMI while reading; keep the
    // convention (0x80) used by Plan 9 and restore it afterwards.
    io::outb(PORT_INDEX, 0x80 | reg);
    let v = io::inb(PORT_DATA);
    io::outb(PORT_INDEX, 0x70); // re-enable NMI, last index = 0x70 (status A)
    v
}

/// Wait for the update-in-progress flag to clear so a read cannot straddle
/// the RTC's internal update.
fn rtc_update_in_progress() -> bool {
    io::outb(PORT_INDEX, 0x80 | REG_STATUS_A);
    let a = io::inb(PORT_DATA);
    io::outb(PORT_INDEX, 0x70);
    a & 0x80 != 0
}

fn bcd_to_bin(v: u8) -> u8 {
    (v & 0x0F) + ((v >> 4) * 10)
}

/// Read one consistent snapshot of the clock.
struct RtcTime {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
}

fn read_time() -> Option<RtcTime> {
    // Two reads with a stable check: keep re-reading until the values
    // settle (equivalent to waiting for UIP to be low).
    let mut prev = [0u8; 6];
    let mut cur = [0u8; 6];
    for _ in 0..100 {
        while rtc_update_in_progress() {}
        let regs = [REG_SEC, REG_MIN, REG_HOUR, REG_MDAY, REG_MON, REG_YEAR];
        for (i, r) in regs.iter().enumerate() {
            cur[i] = rtc_read(*r);
        }
        if cur == prev && cur[0] != 0xFF {
            break;
        }
        prev = cur;
    }

    let status_b = rtc_read(REG_STATUS_B);
    let bcd = status_b & STATUS_B_BCD == 0;

    let mut vals = [0u32; 6];
    for i in 0..6 {
        vals[i] = if bcd { bcd_to_bin(cur[i]) as u32 } else { cur[i] as u32 };
    }

    // Hour: bit 7 marks PM in 12-hour mode.
    let mut hour = vals[2];
    if status_b & STATUS_B_24H == 0 {
        let pm = hour & 0x80 != 0;
        hour &= 0x7F;
        if bcd {
            hour = bcd_to_bin(hour as u8) as u32;
        }
        if pm && hour < 12 {
            hour += 12;
        } else if !pm && hour == 12 {
            hour = 0;
        }
    }

    // Century byte is optional; assume 20xx when it reads implausible.
    let century_raw = rtc_read(REG_CENTURY);
    let century = if bcd { bcd_to_bin(century_raw) as u32 } else { century_raw as u32 };
    let century = if century >= 19 && century <= 21 { century } else { 20 };

    let year = century * 100 + vals[5];
    Some(RtcTime {
        year,
        month: vals[4],
        day: vals[3],
        hour,
        min: vals[1],
        sec: vals[0],
    })
}

/// Convert a civil date to days since the Unix epoch (1970-01-01),
/// Howard Anton's day-number algorithm.
fn days_from_civil(y: u32, m: u32, d: u32) -> i64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // Mar=0 .. Feb=11
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Seconds since the Unix epoch, read from the CMOS RTC.
///
/// Returns `None` on non-x86 targets (no port I/O) or when the RTC
/// reports an invalid date.
pub fn now_unix() -> Option<i64> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        // No CMOS RTC on MMIO-only boards: derive a wall clock from the
        // generic timer (boot epoch, 2026-01-01) so `date` and file
        // timestamps stay monotonic and plausible.
        let boot_epoch: i64 = 1767225600; // 2026-01-01T00:00:00Z
        Some(boot_epoch + crate::plan9_arch::aarch64::timer::ms_since_boot() as i64)
    }
    #[cfg(target_arch = "x86_64")]
    {
        let t = read_time()?;
        if !(1..=12).contains(&t.month) || !(1..=31).contains(&t.day) || t.year < 2000 {
            return None;
        }
        let days = days_from_civil(t.year, t.month, t.day);
        Some(days * 86400 + (t.hour as i64) * 3600 + (t.min as i64) * 60 + t.sec as i64)
    }
}

//! Date Command
//!
//! Implementation of the date command.

use std::env;

pub fn run_date(_args: &[String]) -> i32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Simple date format
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    let total_days = now / 86400;
    let remaining = now % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Calculate year/month/day (simplified)
    let mut year = 1970;
    let mut days_left = total_days as i64;

    while days_left >= 365 {
        let leap = if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) { 366 } else { 365 };
        if days_left >= leap {
            days_left -= leap;
            year += 1;
        } else {
            break;
        }
    }

    let is_leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let month_days = if is_leap { [31,29,31,30,31,30,31,31,30,31,30,31] }
                     else { [31,28,31,30,31,30,31,31,30,31,30,31] };

    let mut month = 0;
    for (i, &d) in month_days.iter().enumerate() {
        if days_left < d as i64 {
            month = i;
            break;
        }
        days_left -= d as i64;
    }

    let day = days_left + 1;
    let weekday = (total_days + 4) % 7;

    println!("{} {} {:>2} {:>2}:{:>02}:{:>02} {}",
             days[weekday as usize], months[month], day, hours, minutes, seconds, year);

    0
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_date(&args);
    std::process::exit(status);
}

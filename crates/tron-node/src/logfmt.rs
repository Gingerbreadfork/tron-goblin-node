//! Tiny, dependency-free formatting helpers for human-readable logs.
//!
//! The node logs a lot of block numbers and millisecond timestamps; raw,
//! they're hard to read at a glance ("is 83344101 near the tip? what *time*
//! is this block from?"). These render them the way an operator wants to see
//! them — thousands-separated counts, a UTC wall-clock for block timestamps,
//! and coarse "3d 2h"-style durations for how far behind the tip we are.
//!
//! Hand-rolled (no `chrono`/`time`) to match the workspace's zero-dep style;
//! the date math is Howard Hinnant's `civil_from_days` algorithm.

/// Thousands-separated integer: `83344101` → `"83,344,101"`.
pub fn commas(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let bytes = digits.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// Epoch-millis → `"YYYY-MM-DD HH:MM:SSZ"` (UTC). Non-positive input (an
/// unset timestamp) renders as `"—"`.
pub fn utc_millis(ms: i64) -> String {
    if ms <= 0 {
        return "—".to_string();
    }
    let secs = ms / 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}Z")
}

/// Epoch-millis → `"YYYY-MM-DD HH:MM:SS.mmm"` (UTC) — the per-line log
/// timestamp. Like [`utc_millis`] but keeps millisecond precision and drops the
/// `Z` (the whole log stream is UTC). Negative input clamps to the epoch.
pub fn log_timestamp(ms: i64) -> String {
    let ms = ms.max(0);
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}.{millis:03}")
}

/// Epoch-millis → `"HH:MM:SS"` (UTC time-of-day, no date or millis) — the
/// compact per-line timestamp for an interactive terminal, where the date is
/// constant on screen and recorded in the daily log filename. Negative input
/// clamps to the epoch.
pub fn clock(ms: i64) -> String {
    let sod = (ms.max(0) / 1000).rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{hh:02}:{mm:02}:{ss:02}")
}

/// Block chain-time for status lines. Renders `"HH:MM:SS"` when the block is
/// from the same UTC day as `now_ms`, else `"MM-DD HH:MM:SS"` — the year and
/// the `Z` suffix are always dropped (the whole stream is UTC). `now_ms`
/// supplies "today" so a block at the tip shows just a clock while a catch-up
/// block keeps its date. Non-positive `ms` (unset) renders as `"—"`.
pub fn block_time(ms: i64, now_ms: i64) -> String {
    if ms <= 0 {
        return "—".to_string();
    }
    let secs = ms / 1000;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let now_date = civil_from_days((now_ms.max(0) / 1000).div_euclid(86_400));
    if (y, mo, d) == now_date {
        format!("{hh:02}:{mm:02}:{ss:02}")
    } else {
        format!("{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
    }
}

/// Coarse human duration from millis, top two units: `"3d 2h"`, `"5m 12s"`,
/// `"4s"`. Non-positive renders as `"0s"` (treats "block in the future" from
/// minor clock skew as "at tip").
pub fn duration_ms(ms: i64) -> String {
    if ms <= 0 {
        return "0s".to_string();
    }
    let secs = ms / 1000;
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// `(year, month, day)` for a count of days since the Unix epoch.
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commas_groups_by_three() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1_000), "1,000");
        assert_eq!(commas(83_344_101), "83,344,101");
        assert_eq!(commas(-12_345), "-12,345");
    }

    #[test]
    fn utc_millis_renders_known_timestamps() {
        // 1700000000000 ms = 2023-11-14 22:13:20 UTC.
        assert_eq!(utc_millis(1_700_000_000_000), "2023-11-14 22:13:20Z");
        // Epoch.
        assert_eq!(utc_millis(1), "1970-01-01 00:00:00Z");
        // Unset.
        assert_eq!(utc_millis(0), "—");
    }

    #[test]
    fn log_timestamp_keeps_millis_and_drops_z() {
        assert_eq!(log_timestamp(1_700_000_000_123), "2023-11-14 22:13:20.123");
        assert_eq!(log_timestamp(0), "1970-01-01 00:00:00.000");
        assert_eq!(log_timestamp(-5), "1970-01-01 00:00:00.000");
    }

    #[test]
    fn clock_renders_time_of_day_only() {
        // 1700000000000 ms = 2023-11-14 22:13:20 UTC.
        assert_eq!(clock(1_700_000_000_000), "22:13:20");
        assert_eq!(clock(0), "00:00:00");
        assert_eq!(clock(-5), "00:00:00");
    }

    #[test]
    fn block_time_drops_date_when_same_day_else_keeps_month_day() {
        // Block and "now" on the same UTC day → clock only.
        let same_day_now = 1_700_000_000_000 + 3_600_000; // +1h, still 2023-11-14
        assert_eq!(block_time(1_700_000_000_000, same_day_now), "22:13:20");
        // Block from a different (earlier) day → MM-DD HH:MM:SS, no year/Z.
        let later_now = 1_700_000_000_000 + 5 * 86_400_000; // ~2023-11-19
        assert_eq!(block_time(1_700_000_000_000, later_now), "11-14 22:13:20");
        // Unset.
        assert_eq!(block_time(0, later_now), "—");
    }

    #[test]
    fn duration_ms_picks_top_two_units() {
        assert_eq!(duration_ms(0), "0s");
        assert_eq!(duration_ms(-5), "0s");
        assert_eq!(duration_ms(4_000), "4s");
        assert_eq!(duration_ms(65_000), "1m 5s");
        assert_eq!(duration_ms(3_660_000), "1h 1m");
        assert_eq!(duration_ms(90_000_000), "1d 1h");
    }
}

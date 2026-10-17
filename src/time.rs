//! Minimal RFC 3339 timestamps (UTC seconds since the Unix epoch), so the
//! tool needs no date-time dependency.

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`. Case-insensitive, because
/// event values are lowercased on load.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s.get(from..to)?.parse().ok() };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    let mut rest = s.get(19..)?;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest.get(4..6)?.parse().ok()?;
            sign * (hours * 3600 + minutes * 60)
        }
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Formats as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_rfc3339(t: i64) -> String {
    let (date, clock) = split(t);
    format!("{date}T{clock}Z")
}

/// Formats as `YYYY-MM-DD HH:MM:SS`, for humans.
pub fn format_human(t: i64) -> String {
    let (date, clock) = split(t);
    format!("{date} {clock}")
}

/// Formats only the time of day, `HH:MM:SS`.
pub fn format_clock(t: i64) -> String {
    split(t).1
}

fn split(t: i64) -> (String, String) {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}-{m:02}-{d:02}"),
        format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        ),
    )
}

// Howard Hinnant's algorithms for the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn roundtrip() {
        for t in [0, 951_782_400, 1_791_163_323, 4_102_444_800] {
            assert_eq!(parse_rfc3339(&format_rfc3339(t)), Some(t));
        }
    }

    #[test]
    fn fractions_offsets_and_lowercase() {
        let base = parse_rfc3339("2026-10-13T09:14:03Z").unwrap();
        assert_eq!(parse_rfc3339("2026-10-13t09:14:03.123z"), Some(base));
        assert_eq!(parse_rfc3339("2026-10-13T11:14:03+02:00"), Some(base));
        assert_eq!(parse_rfc3339("2026-10-13 09:14:03"), Some(base));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_rfc3339("ayer por la tarde"), None);
        assert_eq!(parse_rfc3339("2026-10-13T09:14:03X"), None);
    }
}
